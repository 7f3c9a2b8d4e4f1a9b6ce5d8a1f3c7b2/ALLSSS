### Title
Consensus Order Manipulation via Unvalidated SupposedOrderOfNextRound in Block Headers

### Summary
The `RecoverFromUpdateValue()` function blindly copies `SupposedOrderOfNextRound` values from block headers without validating they were correctly calculated using `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. This allows any block-producing miner to manipulate the mining order for all miners in the next round, affecting consensus integrity, reward distribution, and miner reputation.

### Finding Description

**Root Cause:**

The vulnerability exists in the `RecoverFromUpdateValue()` function which accepts and propagates unvalidated order values: [1](#0-0) 

This function iterates over ALL miners and copies their `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` from the provided Round object without any validation.

**Correct Calculation:**

The correct formula for calculating `SupposedOrderOfNextRound` is implemented in `ApplyNormalConsensusData()`: [2](#0-1) 

The supposed order should be deterministically calculated as `GetAbsModulus(signature.ToInt64(), minersCount) + 1` where: [3](#0-2) 

**Validation Bypass:**

During block validation, `RecoverFromUpdateValue()` is called in both pre-execution and post-execution validation: [4](#0-3) [5](#0-4) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, but does NOT validate `SupposedOrderOfNextRound`: [6](#0-5) 

The hash comparison check in post-execution validation is ineffective because `RecoverFromUpdateValue()` already copied the attacker's values into `currentRound`, making the comparison tautological: [7](#0-6) 

**State Corruption:**

The unvalidated value is directly written to state in `ProcessUpdateValue()`: [8](#0-7) 

This value comes from the block header via `ExtractInformationToUpdateConsensus()`: [9](#0-8) 

### Impact Explanation

**Critical Consensus Manipulation:**

The `SupposedOrderOfNextRound` value determines which miners are considered to have successfully mined in a round: [10](#0-9) 

**Specific Attack Scenarios:**

1. **Reward Theft**: Attacker sets other miners' `SupposedOrderOfNextRound` to 0, marking them as "not mined". These miners are then treated as having missed their time slots, affecting their eligibility for rewards and causing them to receive penalty: [11](#0-10) 

2. **Next Round Order Manipulation**: Miners who "mined" (SupposedOrderOfNextRound != 0) get priority positions based on `FinalOrderOfNextRound`, while others get remaining slots. Attacker can manipulate this to consistently get favorable mining positions: [12](#0-11) 

3. **Evil Miner False Detection**: By manipulating `SupposedOrderOfNextRound` to mark honest miners as not having mined, the attacker can cause them to accumulate `MissedTimeSlots`, potentially leading to them being marked as evil miners: [13](#0-12) 

**Severity: CRITICAL** - This directly compromises consensus integrity, enables systematic reward theft, and allows manipulation of miner reputation across the entire network.

### Likelihood Explanation

**Attacker Capabilities**: Any miner who successfully produces a block (which is expected in normal operation).

**Attack Complexity**: LOW
- Attacker simply modifies the Round object in their block header before broadcasting
- No cryptographic breaking required
- No timing constraints beyond normal block production

**Feasibility Conditions**:
- Attacker must be in the current round's miner list (normal for miners)
- Attacker must produce at least one block (guaranteed during their time slot)
- No special authorization or state setup required

**Detection Difficulty**: HIGH
- The manipulated values pass all existing validations
- The hash check designed to detect tampering is bypassed by the validation logic itself
- No alerts or events flag incorrect order calculations

**Probability**: HIGH - Any malicious miner will discover this during normal block production when they observe that `SupposedOrderOfNextRound` values are not validated.

### Recommendation

**Immediate Fix**: Add validation in `UpdateValueValidationProvider` or before `RecoverFromUpdateValue()` is called to verify that the provided `SupposedOrderOfNextRound` matches the deterministic calculation:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation() or RecoverFromUpdateValue()
var providedOrder = minerInRound.SupposedOrderOfNextRound;
var expectedOrder = GetAbsModulus(minerInRound.Signature.ToInt64(), 
                                  validationContext.BaseRound.RealTimeMinersInformation.Count) + 1;

if (providedOrder != expectedOrder)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = $"Invalid SupposedOrderOfNextRound. Expected: {expectedOrder}, Got: {providedOrder}" 
    };
}
```

**Additional Protections**:
1. Validate ALL miners' `SupposedOrderOfNextRound` values, not just the block producer's
2. Add similar validation for `FinalOrderOfNextRound` after conflict resolution
3. Consider removing `SupposedOrderOfNextRound` from `UpdateValueInput` entirely since it should be deterministically calculated from the signature
4. Add regression tests that attempt to provide mismatched order values

**Code Changes**:
- Modify `RecoverFromUpdateValue()` to recalculate and validate instead of blindly copying
- Or move validation to `UpdateValueValidationProvider` before any state modification
- Ensure validation happens BEFORE `RecoverFromUpdateValue()` modifies the base round

### Proof of Concept

**Initial State**: 
- Round N with 7 miners (addresses M1-M7)
- Attacker is M3 with legitimate mining turn in round N

**Attack Steps**:

1. **Attacker produces block during their time slot**
   - Generates normal signature: `sig = Hash(previousInValue)`
   - Correct calculation would give: `SupposedOrderOfNextRound = GetAbsModulus(sig.ToInt64(), 7) + 1` (e.g., 4)

2. **Attacker modifies Round object in block header**
   - For self (M3): Set `SupposedOrderOfNextRound = 1` (to mine first in next round)
   - For competitors (M1, M2): Set `SupposedOrderOfNextRound = 0` (mark as "not mined")
   - For others: Set arbitrary values or leave as 0

3. **Block propagates to network**
   - `ValidateConsensusBeforeExecution` called
   - `RecoverFromUpdateValue()` copies attacker's values into `baseRound`
   - `UpdateValueValidationProvider` checks pass (doesn't validate order)
   - Other validators pass (use corrupted baseRound)

4. **Block execution**
   - `ProcessUpdateValue()` writes `SupposedOrderOfNextRound = 1` for M3 to state
   - Writes `SupposedOrderOfNextRound = 0` for M1, M2 to state

5. **Post-execution validation**
   - `RecoverFromUpdateValue()` called again with same manipulated values
   - Hash comparison passes (comparing identical manipulated data)
   - Block accepted

**Expected Result**: M3's order should be calculated from signature (e.g., 4), M1 and M2 should have their correct calculated orders

**Actual Result**: M3 has order 1 (first to mine in next round), M1 and M2 marked as having not mined (order 0), will miss rewards and accumulate penalties

**Success Condition**: In round N+1, M3 mines in position 1, while M1 and M2 are relegated to lower positions and marked with increased `MissedTimeSlots` despite having successfully mined in round N.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L43-43)
```csharp
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-56)
```csharp
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-135)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }

    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
```
