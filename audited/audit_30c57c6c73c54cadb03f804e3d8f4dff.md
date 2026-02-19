### Title
Missing Authorization Check for Extra Block Slot Tiny Block Production

### Summary
The `TimeSlotValidationProvider.CheckMinerTimeSlot()` function at lines 46-48 fails to verify that a miner producing tiny blocks before their expected mining time is actually authorized as the `ExtraBlockProducerOfPreviousRound`. This allows any miner in the current round to produce blocks claiming extra block slot privileges, bypassing the consensus invariant that only the designated extra block producer can mine during this time slot.

### Finding Description

The vulnerability exists in the time slot validation logic for tiny blocks: [1](#0-0) 

When `latestActualMiningTime < expectedMiningTime`, the code assumes the miner is producing tiny blocks for the previous extra block slot and only validates that `latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime()`. However, it never checks if `validationContext.SenderPubkey == validationContext.BaseRound.ExtraBlockProducerOfPreviousRound`.

The consensus command generation correctly enforces this authorization: [2](#0-1) 

And the `IsCurrentMiner()` method properly validates extra block producer authorization: [3](#0-2) 

However, during block validation, only basic validation providers are applied: [4](#0-3) 

Note that for `TinyBlock` behavior, no additional authorization validation provider is added: [5](#0-4) 

The `MiningPermissionValidationProvider` only checks if the miner is in the miner list: [6](#0-5) 

The `PreCheck()` method similarly only validates miner list membership: [7](#0-6) 

And `ProcessTinyBlock()` processes the block without any authorization check: [8](#0-7) 

### Impact Explanation

This vulnerability allows unauthorized miners to produce extra blocks outside their designated time slots, violating the consensus invariant that only the `ExtraBlockProducerOfPreviousRound` can mine during the previous extra block slot period. The concrete impacts are:

1. **Consensus Integrity Violation**: Miners can bypass time slot restrictions and produce blocks when they shouldn't be authorized
2. **Unfair Block Reward Allocation**: Unauthorized miners can earn additional block production rewards by mining more blocks than their fair share
3. **Consensus Disruption**: Multiple miners could attempt to produce blocks simultaneously in the extra block slot, potentially causing forks or consensus delays
4. **Mining Schedule Corruption**: The predictable mining schedule and round transitions could be disrupted, affecting LIB (Last Irreversible Block) calculations and cross-chain operations

### Likelihood Explanation

**Exploitability: HIGH**

**Attacker Capabilities**: Any miner in the current validator set can exploit this vulnerability. The attacker only needs:
- Valid miner credentials (already a consensus participant)
- Ability to produce blocks with custom consensus behavior
- Timing control to mine before their expected time slot

**Attack Complexity: LOW**
1. Attacker produces a block before their expected mining time
2. Sets `Behaviour = TinyBlock` in consensus header information
3. Signs block with their private key
4. Validation passes because:
   - `MiningPermissionValidationProvider` confirms miner is in list ✓
   - `TimeSlotValidationProvider.CheckMinerTimeSlot()` sees `latestActualMiningTime < expectedMiningTime` and assumes it's a valid extra block slot tiny block ✓
   - No check for `ExtraBlockProducerOfPreviousRound` authorization ✗

**Feasibility Conditions**: 
- Current round has started (normal operating condition)
- Attacker is an active miner (realistic for consensus attack)
- Timing attack window exists between previous round end and current round expected time

**Economic Rationality**: Block production rewards make this economically attractive, with minimal cost beyond normal mining operations.

### Recommendation

Add explicit authorization check in `TimeSlotValidationProvider.CheckMinerTimeSlot()`:

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
    {
        // Which means this miner is producing tiny blocks for previous extra block slot.
        // ADD AUTHORIZATION CHECK:
        if (validationContext.SenderPubkey != validationContext.BaseRound.ExtraBlockProducerOfPreviousRound)
            return false;
        return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
    }

    return latestActualMiningTime < endOfExpectedTimeSlot;
}
```

**Test Cases**:
1. Verify unauthorized miner cannot produce tiny blocks before expected time
2. Verify only `ExtraBlockProducerOfPreviousRound` can mine in extra slot
3. Verify validation rejects blocks from wrong miner in extra slot period
4. Add integration test simulating unauthorized extra block attempt

### Proof of Concept

**Initial State**:
- Round N has completed with Miner A as `ExtraBlockProducerOfPreviousRound`
- Round N+1 has started with miners A, B, C
- Miner B's expected mining time is at timestamp T1
- Current time is T0 (before T1 and within previous extra block slot window)

**Attack Steps**:
1. **Miner B** (unauthorized, not the extra block producer) produces a block at time T0
2. Miner B sets consensus header: `Behaviour = TinyBlock`, `SenderPubkey = B's pubkey`
3. Miner B signs the block with their private key

**Validation Flow**:
1. `AEDPoSExtraDataExtractor`: Validates `SenderPubkey == SignerPubkey` → PASS (both are Miner B)
2. `MiningPermissionValidationProvider`: Checks if Miner B is in miner list → PASS
3. `TimeSlotValidationProvider.CheckMinerTimeSlot()`: 
   - Gets Miner B's `latestActualMiningTime` (if any previous blocks)
   - Checks `latestActualMiningTime < expectedMiningTime` → TRUE
   - Assumes Miner B is producing tiny blocks for previous extra block slot
   - Only validates `latestActualMiningTime < GetRoundStartTime()` → PASS
   - **MISSING**: Never checks if Miner B == `ExtraBlockProducerOfPreviousRound` (should be Miner A)
4. `ContinuousBlocksValidationProvider`: Checks continuous block limits → PASS

**Result**: 
- **Expected**: Block should be REJECTED because Miner B is not authorized for extra block slot
- **Actual**: Block is ACCEPTED, allowing Miner B to produce unauthorized extra blocks

**Success Condition**: Unauthorized miner successfully mines blocks outside their time slot, earning additional rewards and violating consensus time slot invariants.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L46-48)
```csharp
        if (latestActualMiningTime < expectedMiningTime)
            // Which means this miner is producing tiny blocks for previous extra block slot.
            return latestActualMiningTime < validationContext.BaseRound.GetRoundStartTime();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-308)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```
