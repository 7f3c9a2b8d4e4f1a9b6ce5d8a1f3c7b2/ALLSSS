# Audit Report

## Title
Unvalidated ActualMiningTime Allows Manipulation of Term Change Consensus Threshold

## Summary
Miners can submit arbitrary `ActualMiningTime` values in consensus transactions without validation against `Context.CurrentBlockTime`. This allows malicious miners controlling >1/3 of miner slots to prevent term changes indefinitely by submitting timestamps that don't cross the term boundary, breaking the consensus mechanism for governance transitions.

## Finding Description

The vulnerability exists in the AEDPoS consensus contract's handling of `ActualMiningTime` values submitted by miners during block production.

**Root Cause:**

The `ProcessUpdateValue` method directly adds the miner-provided `ActualMiningTime` to permanent storage without verifying it equals the actual block timestamp: [1](#0-0) 

**Missing Validations:**

1. **TimeSlotValidationProvider** only validates that `ActualMiningTime` falls within the miner's expected time slot window, NOT that it equals `Context.CurrentBlockTime`: [2](#0-1) 

2. **UpdateValueValidationProvider** validates signatures and previous values but completely ignores `ActualMiningTime`: [3](#0-2) 

3. **VRF verification** only covers the `randomNumber` field and does not cryptographically bind `ActualMiningTime`: [4](#0-3) 

**Normal Flow vs Exploitation:**

In the honest implementation, `ActualMiningTime` is set to `Context.CurrentBlockTime` during consensus data generation: [5](#0-4) 

However, a malicious miner can modify the `UpdateValueInput.ActualMiningTime` field after generation but before transaction submission. During validation, this manipulated value is recovered into the `baseRound`: [6](#0-5) 

The validation passes as long as the manipulated timestamp falls within the allowed time slot window. Additionally, `ActualMiningTimes` are explicitly cleared from the hash calculation used for validation: [7](#0-6) 

This means the hash-based validation in `ValidateConsensusAfterExecution` cannot detect the manipulation.

**Impact on Term Change Consensus:**

The term change decision uses `NeedToChangeTerm`, which counts how many miners' last `ActualMiningTime` indicates a term change is needed: [8](#0-7) 

This requires a supermajority threshold defined by `MinersCountOfConsent`: [9](#0-8) 

Term change is determined by checking if timestamps cross the term period boundary: [10](#0-9) 

By submitting `ActualMiningTime` values just before the term boundary (even when actual block production occurs after), malicious miners can prevent their timestamps from indicating term change. If >1/3 of miners do this, the 2/3+1 threshold cannot be met, permanently blocking term transitions.

This decision point directly controls whether the system proceeds to `NextTerm` or stays in `NextRound`: [11](#0-10) 

## Impact Explanation

**Severity: High**

This vulnerability breaks fundamental consensus assumptions and has protocol-wide impact:

**Governance Halt:**

Term changes trigger critical governance operations including treasury releases, election snapshots, reward distributions, and miner list updates: [12](#0-11) 

Preventing term changes blocks all these operations indefinitely, freezing:
- Treasury fund releases to stakeholders
- Election snapshots for validator selection  
- Reward distribution mechanisms
- Miner list updates (allowing malicious miners to remain in power)

**Consensus Integrity:**

The attack breaks the liveness property of the consensus mechanism by allowing a minority (>1/3) to halt protocol progression, violating Byzantine fault tolerance assumptions that should tolerate up to 1/3 malicious nodes.

**No Recovery Mechanism:**

There is no automatic recovery path once term changes are blocked, requiring manual intervention or hard fork to resolve.

## Likelihood Explanation

**Probability: High**

The attack is highly feasible due to:

**Low Attacker Requirements:**
- Control of >1/3 of miner nodes (realistic threshold for coordinated attacks)
- No special privileges beyond normal miner operations
- Standard transaction construction capabilities with modified node software

**Trivial Technical Complexity:**
- Attack requires only modifying one timestamp field in `UpdateValueInput` after the consensus contract generates it
- No cryptographic expertise needed
- No sophisticated timing coordination required

**Many Attack Opportunities:**
- Any time a miner's time slot is near the term boundary
- With 7-day terms and 4-second blocks: ~151,200 blocks per term
- Each colluding miner has thousands of opportunities

**No Detection:**
- Manipulated timestamps appear valid (within time slots)
- Hash validation explicitly excludes `ActualMiningTimes`
- No monitoring mechanism to detect timestamp manipulation
- No slashing or penalty for this behavior

**Clear Economic Incentive:**
- Zero cost to execute (just parameter modification in modified node software)
- Benefits include: maintaining miner position, preventing competitive elections, blocking unfavorable governance decisions

## Recommendation

Add validation in `ProcessUpdateValue` to ensure `ActualMiningTime` equals `Context.CurrentBlockTime`:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // Add validation: ActualMiningTime must equal Context.CurrentBlockTime
    Assert(updateValueInput.ActualMiningTime == Context.CurrentBlockTime, 
           "ActualMiningTime must equal the current block time.");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
    // ... rest of the method
}
```

This ensures miners cannot manipulate the timestamp to influence term change decisions.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Setup a chain with multiple miners approaching a term boundary
2. Have one miner produce a block at time T (after term boundary)
3. Modify the `UpdateValueInput.ActualMiningTime` to T-1 (before term boundary)  
4. Submit the transaction and verify it passes validation
5. Verify the stored `ActualMiningTime` is T-1 (not the real block time T)
6. Verify `NeedToChangeTerm` returns false when it should return true
7. Demonstrate that with >1/3 miners doing this, term change is blocked

The vulnerability is confirmed by the code analysis showing no validation exists to prevent this manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-81)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L37-51)
```csharp
    private bool CheckMinerTimeSlot(ConsensusValidationContext validationContext)
    {
        if (IsFirstRoundOfCurrentTerm(out _, validationContext)) return true;
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var latestActualMiningTime = minerInRound.ActualMiningTimes.OrderBy(t => t).LastOrDefault();
        if (latestActualMiningTime == null) return true;
        var expectedMiningTime = minerInRound.ExpectedMiningTime;
        var endOfExpectedTimeSlot =
            expectedMiningTime.AddMilliseconds(validationContext.BaseRound.GetMiningInterval());
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();

        return latestActualMiningTime < endOfExpectedTimeSlot;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L62-63)
```csharp
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L20-20)
```csharp
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L193-193)
```csharp
            checkableMinerInRound.ActualMiningTimes.Clear();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L239-243)
```csharp
    private static bool IsTimeToChangeTerm(Timestamp blockchainStartTimestamp, Timestamp blockProducedTimestamp,
        long termNumber, long periodSeconds)
    {
        return (blockProducedTimestamp - blockchainStartTimestamp).Seconds.Div(periodSeconds) != termNumber - 1;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-35)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
```
