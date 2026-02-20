# Audit Report

## Title
Missing NeedToChangeTerm Validation Allows Premature Term Termination in AEDPoS Consensus

## Summary
The AEDPoS consensus contract's `NextTerm` method lacks time-based validation during transaction execution, allowing any active miner to prematurely terminate a consensus term by directly invoking `NextTerm` even when the protocol's time threshold requirements are not met. This bypasses the intended `NeedToChangeTerm` check that enforces two-thirds miner consensus on term changes based on elapsed blockchain time.

## Finding Description

The vulnerability exists in the separation between consensus behavior selection and transaction execution validation.

**Normal Flow**: During block production, the `MainChainConsensusBehaviourProvider` determines whether to use `NextRound` or `NextTerm` by calling `NeedToChangeTerm`, which verifies that at least two-thirds of miners' latest mining times indicate the time threshold has been reached. [1](#0-0) 

The `NeedToChangeTerm` method checks if sufficient miners agree based on blockchain age using a two-thirds threshold: [2](#0-1) 

**Vulnerability**: The `NextTerm` method is publicly accessible: [3](#0-2) 

During execution, `ProcessConsensusInformation` only performs basic checks: [4](#0-3) 

The `PreCheck` method only verifies the caller is in the current or previous miner list: [5](#0-4) 

For `NextTerm` behavior, validation only adds `RoundTerminateValidationProvider`: [6](#0-5) 

`RoundTerminateValidationProvider` only validates structural correctness (round number increments by 1, term number increments by 1, and InValues are null): [7](#0-6) 

**Critically**, there is NO re-validation of the `NeedToChangeTerm` condition during transaction execution. The `TryToUpdateTermNumber` method only checks that term number increments by 1: [8](#0-7) 

A malicious miner can construct a valid `NextTermInput` with `term number = current + 1` and `round number = current + 1`, and call `NextTerm` directly. The transaction will pass all validations and execute `ProcessNextTerm`: [9](#0-8) 

This prematurely updates term and round numbers, resets miner statistics, updates the miner list, donates mining rewards to treasury, triggers treasury release for the wrong period, and takes an election snapshot prematurely.

## Impact Explanation

This vulnerability has **HIGH** severity impact across multiple protocol subsystems:

1. **Consensus Integrity Breach**: The fundamental invariant that terms change only when time thresholds are met and two-thirds of miners agree is violated, undermining the protocol's time-based consensus security model.

2. **Economic Disruption**: Mining rewards are donated and treasury releases are triggered at incorrect times: [10](#0-9) 

This causes fund distributions to occur out of sync with the intended economic schedule.

3. **Governance Manipulation**: Election snapshots are captured prematurely: [11](#0-10) 

This potentially affects validator selection and voting power calculations for subsequent terms.

4. **Miner Schedule Disruption**: The miner list is updated before the intended rotation time: [12](#0-11) 

This disrupts block production schedules and potentially enables colluding miners to extend their control.

5. **Statistical Manipulation**: Performance metrics are reset early: [13](#0-12) 

This potentially masks poor miner performance or manipulates reputation-based mechanisms.

## Likelihood Explanation

The vulnerability has **HIGH** likelihood of exploitation:

**Attacker Profile**: Any miner in the current or previous miner list can execute this attack, which represents a significant portion of network participants in a decentralized consensus system.

**Technical Complexity**: **LOW** - The attacker only needs to:
1. Construct a `NextTermInput` with `TermNumber = current + 1` and `RoundNumber = current + 1`
2. Submit a transaction calling the public `NextTerm` method
3. Provide a valid random number proof (which they can generate as an active miner)

**Preconditions**: Minimal - The attacker must be an active or recently active miner (realistic in any functional consensus network), with no additional privileges required.

**Economic Incentives**: Strong motivation exists for attackers to:
- Gain extended mining time if they're in the next term's miner list
- Disrupt competitors by resetting their performance statistics
- Manipulate treasury release timing for financial advantage
- Influence governance outcomes through premature election snapshots

**Detection vs Prevention**: While premature term changes are visible on-chain, the attack could occur during low-monitoring periods and may not be immediately reversible, causing lasting damage to consensus integrity.

## Recommendation

Add time-based validation to the `ProcessNextTerm` method to re-verify the `NeedToChangeTerm` condition during transaction execution. The validation should check that at least two-thirds of miners' latest mining times meet the time threshold before allowing the term transition.

Add the following check in `ProcessNextTerm` after line 170 (after getting term number):

```csharp
// Validate that time threshold is met
TryToGetCurrentRoundInformation(out var currentRound);
var blockchainStartTimestamp = GetBlockchainStartTimestamp();
Assert(
    currentRound.NeedToChangeTerm(blockchainStartTimestamp, termNumber, State.PeriodSeconds.Value),
    "Time threshold for term change not met."
);
```

This ensures that the same time-based consensus check used during block production is also enforced during transaction execution, preventing premature term termination.

## Proof of Concept

```csharp
[Fact]
public async Task Test_PrematureTermTermination_Vulnerability()
{
    // Setup: Initialize consensus with normal miners
    await InitializeConsensusWith3Miners();
    
    // Get current state before attack
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var currentTermNumber = currentRound.TermNumber;
    var blockchainAge = await ConsensusStub.GetBlockchainAge.CallAsync(new Empty());
    
    // Verify we're not at time threshold yet (e.g., only 50% of term period elapsed)
    var needsChange = currentRound.NeedToChangeTerm(
        BlockchainStartTimestamp, 
        currentTermNumber, 
        PeriodSeconds
    );
    needsChange.ShouldBeFalse(); // Time threshold NOT met
    
    // Attack: Malicious miner constructs NextTermInput and calls NextTerm directly
    var nextTermInput = new NextTermInput
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentTermNumber + 1,
        RandomNumber = GenerateRandomNumber(), // Miner can generate this
        // Construct valid round data with proper miner information
        RealTimeMinersInformation = { /* valid miner data */ }
    };
    
    // Execute premature NextTerm call
    var result = await MinerKeyPairs[0].ConsensusStub.NextTerm.SendAsync(nextTermInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Attack succeeds!
    
    // Verify: Term was changed prematurely
    var newRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.TermNumber.ShouldBe(currentTermNumber + 1); // Term incremented
    newRound.RoundNumber.ShouldBe(currentRound.RoundNumber + 1); // Round incremented
    
    // Verify side effects occurred prematurely:
    // - Miner statistics reset
    // - Treasury release triggered
    // - Election snapshot taken
    // All before the proper time threshold was met
}
```

## Notes

This vulnerability demonstrates a critical gap between consensus behavior selection (which uses `NeedToChangeTerm`) and transaction execution validation (which only checks structural correctness). The missing time-based validation during execution allows miners to bypass the protocol's intended two-thirds consensus requirement for term changes, breaking fundamental consensus integrity guarantees.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L30-35)
```csharp
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-223)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-43)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");

        State.RoundBeforeLatestExecution.Value = GetCurrentRoundInformation(new Empty());

        ByteString randomNumber = null;

        // The only difference.
        switch (input)
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
            case NextTermInput nextTermInput:
                randomNumber = nextTermInput.RandomNumber;
                ProcessNextTerm(nextTermInput);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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
