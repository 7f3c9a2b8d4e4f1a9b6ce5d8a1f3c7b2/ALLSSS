# Audit Report

## Title
Missing Validation for Empty Miner List Enables Permanent Blockchain Halt via NextRound/NextTerm

## Summary
The AEDPoS consensus validation pipeline fails to verify that proposed rounds contain at least one miner. Multiple validation providers check properties of miners (InValue, OutValue, mining order) but do not validate miner existence. This allows a malicious miner to submit an empty round that passes all validations and gets stored, permanently halting the blockchain since no subsequent miner can pass the `MiningPermissionValidationProvider` check.

## Finding Description

The vulnerability exists in the consensus validation pipeline's handling of NextRound and NextTerm transactions. The critical flaw is that validators check properties **of** miners but never check **if** miners exist in the proposed round.

**Validation Context Setup:**

When `ValidateConsensusBeforeExecution` is invoked, it creates a validation context where `BaseRound` is the current state and `ProvidedRound` is the submitted round data. [1](#0-0) [2](#0-1) 

**Root Cause #1 - ContinuousBlocksValidationProvider:**

The condition checks `BaseRound.RealTimeMinersInformation.Count != 1` to skip validation for single-miner chains. When an empty round is submitted, if BaseRound has multiple miners (normal case), the condition evaluates to TRUE (e.g., `5 != 1`), entering the validation block. However, the validation only checks continuous block production limits, not whether ProvidedRound has miners. [3](#0-2) 

**Root Cause #2 - NextRoundMiningOrderValidationProvider:**

When `ProvidedRound.RealTimeMinersInformation` is empty, both `distinctCount` and `Count(m => m.OutValue != null)` equal zero. The equality check `0 == 0` passes validation. [4](#0-3) 

**Root Cause #3 - RoundTerminateValidationProvider:**

For NextRound behavior, the validator checks that `Any(m => m.InValue != null)` returns false to ensure InValues are null for new rounds. When the collection is empty, `Any()` returns false, which is misinterpreted as "all InValues are correctly null" rather than "no miners exist." [5](#0-4) 

**Unconditional Storage:**

After passing validation, `ProcessNextRound` unconditionally stores the empty round via `AddRoundInformation`. [6](#0-5) [7](#0-6) 

**Permanent Blockchain Halt:**

Once the empty round becomes the current round (BaseRound), all subsequent block production attempts fail at `MiningPermissionValidationProvider` because no miner's pubkey can exist in an empty `RealTimeMinersInformation.Keys` collection. [8](#0-7) 

## Impact Explanation

This vulnerability causes **CRITICAL consensus layer failure** with the following impacts:

1. **Permanent Blockchain Halt**: Once an empty round is stored, the blockchain cannot produce any subsequent blocks. Every miner attempting to produce a block will fail validation since `BaseRound.RealTimeMinersInformation.Keys` is empty.

2. **Complete Network DoS**: All consensus operations, transaction processing, cross-chain communications, and state updates cease permanently across the entire network.

3. **Recovery Complexity**: There is no automatic recovery mechanism. Resolution requires emergency hard fork or manual state database intervention to restore the miner list and round information.

4. **Network-Wide Impact**: Unlike vulnerabilities affecting individual accounts or contracts, this impacts every node, miner, and user of the blockchain simultaneously.

The severity is CRITICAL because it:
- Violates the fundamental invariant: "Correct round transitions and miner schedule integrity"
- Causes irreversible consensus failure
- Affects the entire network
- Has no built-in recovery path
- Requires only a single malicious transaction

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round
- Can produce blocks during assigned time slots
- Requires only standard block production privileges (no elevated permissions)

**Attack Complexity:**
The attack is trivially simple:
1. Attacker crafts `NextRoundInput` with empty `RealTimeMinersInformation` dictionary
2. During their mining time slot, submits the malicious transaction
3. Single transaction execution causes permanent halt

**Feasibility:**
The `NextRound()` method is publicly accessible to any miner passing basic validation checks. [9](#0-8) 

**Detection Constraints:**
- Pre-execution validation does not detect empty miner lists
- Post-execution, the attack is immediately obvious (blockchain stops) but recovery is difficult
- No economic barriers prevent execution beyond potential reputation loss

**Likelihood Assessment: MEDIUM-HIGH**
While requiring miner access, the attack is:
- Straightforward to execute (single transaction with crafted input)
- Has no complex preconditions or race conditions
- Requires only one of N miners to be malicious or compromised
- Miners are not assumed to be fully trusted in the threat model

## Recommendation

Add explicit validation to ensure proposed rounds contain at least one miner. Implement checks in multiple layers:

**1. Add validation in RoundTerminateValidationProvider:**
```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Validate round has miners
    if (extraData.Round.RealTimeMinersInformation.Count == 0)
        return new ValidationResult { Message = "Next round must contain at least one miner." };
    
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
        ? new ValidationResult { Message = "Incorrect next round information." }
        : new ValidationResult { Success = true };
}
```

**2. Add validation in NextRoundMiningOrderValidationProvider:**
```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    
    // Ensure round has miners
    if (providedRound.RealTimeMinersInformation.Count == 0)
    {
        validationResult.Message = "Provided round must contain miners.";
        return validationResult;
    }
    
    var distinctCount = providedRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0).Distinct().Count();
    if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound.";
        return validationResult;
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

**3. Add defensive check in AddRoundInformation:**
```csharp
private void AddRoundInformation(Round round)
{
    Assert(round.RealTimeMinersInformation.Count > 0, "Round must contain at least one miner.");
    State.Rounds.Set(round.RoundNumber, round);
    // ... rest of implementation
}
```

## Proof of Concept

```csharp
[Fact]
public async Task EmptyMinerList_Causes_Permanent_Blockchain_Halt()
{
    // Setup: Initialize blockchain with normal miners
    await InitializeConsensusAsync();
    
    // Attacker (as a current miner) crafts malicious NextRound with empty miner list
    var maliciousNextRound = new NextRoundInput
    {
        RoundNumber = 2,
        RealTimeMinersInformation = { }, // EMPTY - This is the attack
        TermNumber = 1,
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(BootMinerKeyPair))
    };
    
    // Attack: Submit empty round - validation should fail but doesn't
    var result = await AEDPoSContractStub.NextRound.SendAsync(maliciousNextRound);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Attack succeeds
    
    // Verify: Empty round is now stored as current round
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.RealTimeMinersInformation.Count.ShouldBe(0); // Confirmed: empty round stored
    
    // Impact: Any subsequent block attempt fails - blockchain permanently halted
    BlockTimeProvider.SetBlockTime(BlockchainStartTimestamp.AddSeconds(8));
    var consensusCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(
        BootMinerKeyPair.PublicKey.ToByteString());
    consensusCommand.ShouldBe(ConsensusCommandProvider.InvalidConsensusCommand); // All miners rejected
    
    // No miner can produce blocks anymore - permanent halt confirmed
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
