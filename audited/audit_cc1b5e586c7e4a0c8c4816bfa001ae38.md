### Title
Incorrect Distinct Check in NextRoundMiningOrderValidationProvider Allows Duplicate Mining Orders Leading to Consensus Failure

### Summary
The `NextRoundMiningOrderValidationProvider` uses `.Distinct()` on `MinerInRound` objects instead of their `FinalOrderOfNextRound` values, failing to detect when multiple miners are assigned the same mining order for the next round. This allows a malicious miner to create invalid round transitions where multiple miners share the same time slot, causing consensus failure and potential chain halt.

### Finding Description

The validation logic in `NextRoundMiningOrderValidationProvider` contains a critical bug at lines 15-16: [1](#0-0) 

The code calls `.Distinct()` on a collection of `MinerInRound` objects, which checks for distinct object instances, not distinct `FinalOrderOfNextRound` values. Since each miner is a different object, this will always count all miners as distinct, even if multiple miners have identical `FinalOrderOfNextRound` values.

**Root Cause**: The validation should check uniqueness of the `FinalOrderOfNextRound` values themselves, not the uniqueness of miner objects.

**Why Existing Protections Fail**:

1. The `UpdateValueValidationProvider` only validates cryptographic fields (OutValue, Signature, PreviousInValue) and does not check `FinalOrderOfNextRound` uniqueness: [2](#0-1) 

2. When `ProcessUpdateValue` applies `TuneOrderInformation`, it blindly updates `FinalOrderOfNextRound` without validation: [3](#0-2) 

3. During next round generation, miners are ordered by `FinalOrderOfNextRound`, and duplicate values cause multiple miners to be assigned the same order: [4](#0-3) 

4. The validation is invoked during NextRound behavior processing: [5](#0-4) 

### Impact Explanation

**Consensus Integrity Failure**: When multiple miners have the same `FinalOrderOfNextRound` value, the next round generation logic assigns them the same `Order` value and `ExpectedMiningTime`. This creates a fundamental consensus violation where multiple miners believe they should produce blocks at the same time slot.

**Chain Halt**: The occupied orders calculation becomes incorrect when duplicates exist: [6](#0-5) 

This leads to miscalculation of available orders for miners who didn't mine in the current round, potentially causing the next round to have invalid miner assignments.

**Affected Parties**: 
- All network participants experience consensus failure
- Block production halts or becomes unpredictable
- The blockchain becomes unstable and potentially unusable

**Severity**: CRITICAL - This directly violates the "miner schedule integrity" invariant and causes complete consensus breakdown.

### Likelihood Explanation

**Attacker Capabilities**: Any active miner in the consensus set can execute this attack during their assigned time slot.

**Attack Complexity**: LOW
1. Miner provides consensus extra data with a manipulated Round object containing duplicate `FinalOrderOfNextRound` values
2. The malicious data is included when generating consensus information: [7](#0-6) 

3. The validation fails to detect the duplicates due to the `.Distinct()` bug
4. The transaction is generated and executed: [8](#0-7) 

**Feasibility**: HIGHLY PRACTICAL
- No special privileges required beyond being an active miner
- Attack can be executed during any UpdateValue operation
- No economic cost beyond normal block production
- Detection is difficult as the validation incorrectly passes

**Probability**: HIGH - The attack is straightforward and the validation bug is deterministic.

### Recommendation

**Immediate Fix**: Modify the validation to check uniqueness of `FinalOrderOfNextRound` values, not miner objects:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Select the order values
    .Distinct()
    .Count();
```

Or use `DistinctBy` (if available in the C# version):
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .DistinctBy(m => m.FinalOrderOfNextRound)
    .Count();
```

**Additional Protections**:
1. Add validation in `UpdateValueValidationProvider` to ensure `FinalOrderOfNextRound` values are within valid range [1, minersCount] and unique
2. Add validation when processing `TuneOrderInformation` to prevent duplicate assignments
3. Add range validation: `FinalOrderOfNextRound` must be between 1 and total miner count

**Test Cases**:
1. Test that validation fails when two miners have the same `FinalOrderOfNextRound`
2. Test that validation fails when `FinalOrderOfNextRound` exceeds miner count
3. Test that validation fails when `FinalOrderOfNextRound` is zero or negative
4. Test normal case where all miners have unique valid orders

### Proof of Concept

**Initial State**:
- Current round with 5 miners (A, B, C, D, E)
- Miners A, B, C have mined blocks (have OutValue)
- Round is ready for NextRound transition

**Attack Steps**:
1. Malicious miner prepares NextRound consensus extra data
2. Manipulates the Round object to set:
   - Miner A: `FinalOrderOfNextRound = 1`
   - Miner B: `FinalOrderOfNextRound = 2`  
   - Miner C: `FinalOrderOfNextRound = 2` (DUPLICATE!)
3. Submits block with this extra data
4. Validation executes:
   ```
   distinctCount = 3 objects (A, B, C are distinct objects)
   minersWithOutValue = 3 (A, B, C)
   3 == 3 → Validation PASSES (incorrectly)
   ```
5. NextRound transaction executes with malicious data
6. Next round generation processes miners ordered by FinalOrderOfNextRound
7. Both miners B and C get assigned Order = 2
8. Consensus failure occurs when both try to mine at the same time

**Expected Result**: Validation should FAIL detecting duplicate order value 2

**Actual Result**: Validation PASSES because `.Distinct()` counts distinct miner objects (3), not distinct order values (2)

**Success Condition**: Next round is accepted with duplicate mining orders, causing consensus failure in subsequent block production.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-86)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L28-32)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                information = GetConsensusExtraDataToPublishOutValue(currentRound, pubkey,
                    triggerInformation);
                if (!isGeneratingTransactions) information.Round = information.Round.GetUpdateValueRound(pubkey);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L164-171)
```csharp
            case AElfConsensusBehaviour.NextRound:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextRound), NextRoundInput.Create(round,randomNumber))
                    }
                };
```
