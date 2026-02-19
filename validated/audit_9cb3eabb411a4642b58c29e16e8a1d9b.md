# Audit Report

## Title
Missing Term Period Validation Allows Premature Term Transitions

## Summary
The AEDPoS consensus contract lacks validation to verify that the configured term period has elapsed before allowing term transitions. While `NeedToChangeTerm()` checks timing during consensus command generation, this check is never re-validated during block validation or execution. A malicious miner can bypass local timing checks to force premature term transitions, causing early treasury releases, reward distributions, and election snapshots.

## Finding Description

The vulnerability exists in a critical gap between command generation and validation/execution flows:

**Root Cause:** The `NeedToChangeTerm()` method performs timing validation by checking if sufficient miners' `ActualMiningTimes` satisfy the term period threshold using `IsTimeToChangeTerm()`. [1](#0-0)  However, this check only occurs in `MainChainConsensusBehaviourProvider.GetConsensusBehaviourToTerminateCurrentRound()` during consensus command generation. [2](#0-1) 

**Missing Validation in Block Validation:** When `ValidateBeforeExecution()` processes NextTerm behavior, it only adds `RoundTerminateValidationProvider` without any timing checks. [3](#0-2) 

The `RoundTerminateValidationProvider.ValidationForNextTerm()` only validates structural correctness (round number increments by 1, InValues are null, term number increments by 1) but performs no timing verification. [4](#0-3) 

Critically, `ConsensusValidationContext` does not contain `periodSeconds` or `blockchainStartTimestamp` parameters needed for timing validation. [5](#0-4) 

**Missing Validation in Execution:** During `ProcessNextTerm()`, the only validation is `TryToUpdateTermNumber()` which merely checks numeric increment without any timing verification. [6](#0-5) [7](#0-6) 

**Attack Vector:** A malicious miner can:
1. Modify node software to bypass the local `NeedToChangeTerm()` check
2. Generate valid `NextTermInput` with properly structured Round for next term
3. Submit block with NextTerm behavior before term period expires (e.g., day 3 of 7-day term)
4. Block passes validation because no timing check exists in validation pipeline
5. `ProcessNextTerm()` executes all economic actions prematurely

## Impact Explanation

**Consensus Timing Invariant Violation:** The attack breaks the fundamental term period invariant that ensures terms last the configured duration (default 604800 seconds = 7 days). Attackers can arbitrarily accelerate term transitions.

**Economic Impact:** Premature term transitions trigger three critical economic actions:

1. **Treasury Release:** `State.TreasuryContract.Release.Send()` distributes treasury funds before the scheduled time. [8](#0-7) 

2. **Mining Reward Donations:** `DonateMiningReward()` calculates and donates mining rewards to Treasury ahead of schedule. [9](#0-8) [10](#0-9) 

3. **Election Snapshot Manipulation:** `State.ElectionContract.TakeSnapshot.Send()` creates election snapshots at incorrect times, affecting staking reward calculations. [11](#0-10) 

All network participants suffer from disrupted economic schedules, incorrect reward timing, and potential manipulation of election outcomes.

## Likelihood Explanation

**Attacker Capabilities:** Requires being in the current miner list, which is realistic:
- Miners are elected through public staking mechanisms
- A compromised or malicious miner is within the threat model
- No special privileges beyond standard miner status required

**Attack Complexity:** Moderate - requires modifying node software to override consensus behavior determination in `GetConsensusBehaviourToTerminateCurrentRound()`, but does not require breaking cryptography or complex state manipulation.

**Execution Practicality:** High - straightforward attack path:
1. Miner produces block during normal operation (e.g., day 3 of 7-day term)
2. Modified node forces NextTerm behavior in consensus extra data
3. Block passes all validation checks (structural only, no timing)
4. Term changes 4 days early

**Detection Difficulty:** Real-time detection is difficult as the block appears structurally valid. Only observable by monitoring term transition frequency against expected schedule.

**Economic Rationality:** Attack cost is zero (already a miner). Potential benefits include manipulating treasury release timing for front-running opportunities or coordinating with governance proposals timed to specific terms.

## Recommendation

Add timing validation to the validation pipeline by:

1. **Extend `ConsensusValidationContext`** to include timing parameters:
```csharp
public class ConsensusValidationContext
{
    // Existing fields...
    public Timestamp BlockchainStartTimestamp { get; set; }
    public long PeriodSeconds { get; set; }
}
```

2. **Modify `ValidateBeforeExecution`** to populate these fields from contract state.

3. **Enhance `RoundTerminateValidationProvider.ValidationForNextTerm()`** to verify timing:
```csharp
private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
{
    var validationResult = ValidationForNextRound(validationContext);
    if (!validationResult.Success) return validationResult;

    // Validate term number increment
    if (validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber)
        return new ValidationResult { Message = "Incorrect term number for next round." };

    // ADD TIMING VALIDATION
    if (!validationContext.BaseRound.NeedToChangeTerm(
        validationContext.BlockchainStartTimestamp,
        validationContext.CurrentTermNumber,
        validationContext.PeriodSeconds))
    {
        return new ValidationResult { Message = "Term period has not elapsed yet." };
    }

    return new ValidationResult { Success = true };
}
```

This ensures the timing invariant is enforced during validation, preventing premature term transitions.

## Proof of Concept

```csharp
[Fact]
public async Task PrematureTermTransition_BypassesValidation_Test()
{
    // Setup: Initialize consensus with 7-day term period
    await AEDPoSContract_FirstRound_BootMiner_Test();
    
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Attack: Force NextTerm on day 3 (before 7-day period expires)
    var prematureTime = BlockchainStartTimestamp.AddDays(3);
    BlockTimeProvider.SetBlockTime(prematureTime);
    
    // Attacker creates valid NextTermInput structure
    var nextTermInput = NextTermInput.Parser.ParseFrom(currentRound.ToByteArray());
    nextTermInput.RoundNumber = currentRound.RoundNumber + 1;
    nextTermInput.TermNumber = currentRound.TermNumber + 1;
    nextTermInput.RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(BootMinerKeyPair));
    
    // Block passes validation (no timing check)
    var transactionResult = await AEDPoSContractStub.NextTerm.SendAsync(nextTermInput);
    transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify premature term transition succeeded
    var newRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.TermNumber.ShouldBe(currentRound.TermNumber + 1);
    
    // Treasury released early, rewards donated early, snapshot taken early
    // All before the configured 7-day period elapsed
}
```

## Notes

This vulnerability represents a fundamental flaw in the validation architecture where timing invariants are assumed to be enforced by honest miners during command generation, but malicious miners can bypass these checks. The separation between command generation (where timing is checked) and validation/execution (where timing is not checked) creates an exploitable gap. The fix requires extending the validation context with timing parameters and enforcing the same `NeedToChangeTerm()` logic during validation that is currently only used during command generation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-243)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }

    /// <summary>
    ///     If periodSeconds == 7:
    ///     1, 1, 1 => 0 != 1 - 1 => false
    ///     1, 2, 1 => 0 != 1 - 1 => false
    ///     1, 8, 1 => 1 != 1 - 1 => true => term number will be 2
    ///     1, 9, 2 => 1 != 2 - 1 => false
    ///     1, 15, 2 => 2 != 2 - 1 => true => term number will be 3.
    /// </summary>
    /// <param name="blockchainStartTimestamp"></param>
    /// <param name="termNumber"></param>
    /// <param name="blockProducedTimestamp"></param>
    /// <param name="periodSeconds"></param>
    /// <returns></returns>
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-90)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L8-41)
```csharp
public class ConsensusValidationContext
{
    public long CurrentTermNumber { get; set; }
    public long CurrentRoundNumber { get; set; }

    /// <summary>
    ///     We can trust this because we already validated the pubkey
    ///     during `AEDPoSExtraDataExtractor.ExtractConsensusExtraData`
    /// </summary>
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();

    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;

    /// <summary>
    ///     Previous round information fetch from StateDb.
    /// </summary>
    public Round PreviousRound { get; set; }

    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
    public LatestPubkeyToTinyBlocksCount LatestPubkeyToTinyBlocksCount { get; set; }

    public AElfConsensusHeaderInformation ExtraData { get; set; }
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L173-173)
```csharp
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L98-105)
```csharp
    private bool TryToUpdateTermNumber(long termNumber)
    {
        var oldTermNumber = State.CurrentTermNumber.Value;
        if (termNumber != 1 && oldTermNumber + 1 != termNumber) return false;

        State.CurrentTermNumber.Value = termNumber;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```
