# Audit Report

## Title
Invalid FinalOrderOfNextRound Values Enable Consensus Disruption Through Malicious Order Assignment

## Summary
Active miners can inject arbitrary `FinalOrderOfNextRound` values (including 0, duplicates, or values exceeding `minersCount`) via the `UpdateValue` method without validation. These values are used directly in next round generation, enabling consensus crashes through missing expected mining orders or creating invalid consensus states that exclude legitimate miners.

## Finding Description

### Root Cause - Unvalidated Order Assignment

The `ProcessUpdateValue` method applies `TuneOrderInformation` values from user input directly to `FinalOrderOfNextRound` without any bounds checking or duplicate validation: [1](#0-0) 

The protobuf definition allows arbitrary `int32` values in the `tune_order_information` map: [2](#0-1) 

### Vulnerable Code Path

When `GenerateNextRoundInformation()` processes the next round, it uses these unvalidated `FinalOrderOfNextRound` values to assign mining orders: [3](#0-2) 

The `occupiedOrders` calculation collects whatever `FinalOrderOfNextRound` values exist, including invalid ones: [4](#0-3) 

### Why Existing Protections Fail

The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with `FinalOrderOfNextRound > 0` matches the count of miners who mined, using `Distinct()` on `MinerInRound` objects (not on order values): [5](#0-4) 

This validation operates on distinct `MinerInRound` objects (compared by reference or all fields), which means two miners with the same `FinalOrderOfNextRound` but different pubkeys are counted as distinct. This fails to detect duplicate order values or out-of-range values.

Additionally, this validator only runs for `NextRound` behavior validation: [6](#0-5) 

It does not validate during `UpdateValue` behavior, where the malicious values are injected.

### Downstream Crash Points

The `BreakContinuousMining` function is called during round generation and expects specific orders to exist: [7](#0-6) 

It uses `.First()` which throws `InvalidOperationException` if orders 1, 2, or `minersCount-1` are missing: [8](#0-7) [9](#0-8) 

## Impact Explanation

**High Severity - Consensus Integrity Violation**

1. **Consensus Execution Crashes**: By setting `FinalOrderOfNextRound` values such that the generated next round lacks required orders (e.g., no miner has order 1, 2, or `minersCount-1`), an attacker causes `BreakContinuousMining` to throw `InvalidOperationException`, crashing consensus execution and halting block production.

2. **Duplicate Orders**: Multiple miners assigned the same order compete for the same time slot, causing conflicting block production schedules and consensus ambiguity.

3. **Invalid Order Values**: 
   - Order = 0 creates a miner scheduled to mine at the current block timestamp (in the past), bypassing time-slot validation
   - Order > `minersCount` creates out-of-range orders that break schedule integrity

4. **Miner Exclusion**: When miners with duplicate `FinalOrderOfNextRound` values are processed in the generation loop, they overwrite each other in the dictionary-based assignment, causing legitimate miners who successfully mined to be excluded from the next round.

**Affected Components**:
- All miners attempting to participate in consensus
- Block production scheduling and time-slot validation  
- Round transition logic and irreversible block height calculation
- Cross-chain verification that depends on valid consensus state

## Likelihood Explanation

**High Probability - Easily Executable by Any Active Miner**

**Attacker Capabilities:**
- Any active miner in the current miner list can call `UpdateValue`: [10](#0-9) 
- The only permission check verifies the sender is a miner: [11](#0-10) 

**Attack Complexity:** LOW
1. Malicious miner constructs `UpdateValueInput` with crafted `TuneOrderInformation` containing invalid values
2. Calls `UpdateValue` during their mining slot
3. Values are stored immediately without validation
4. Next round generation uses these invalid values
5. Consensus crashes or enters invalid state

**Feasibility Conditions:**
- Attacker must be an elected miner (already in consensus participation)
- Single transaction execution required
- No special timing or state requirements beyond being in the miner list
- Economically rational for miners to attack competitors or disrupt consensus

**Detection Constraints:**
- No events or logs specifically indicate malicious `FinalOrderOfNextRound` assignment
- Validation only occurs when `NextRound` is called, after damage is done
- Existing validation is insufficient to catch the exploit

## Recommendation

**Implement strict validation of `TuneOrderInformation` values in `ProcessUpdateValue`:**

1. **Range Validation**: Ensure all order values are within `[1, minersCount]`
2. **Duplicate Detection**: Verify no duplicate order values exist across all miners
3. **Completeness Check**: Ensure all valid orders are assigned without gaps
4. **Early Validation**: Perform this validation when `UpdateValue` is called, before storing values

**Suggested code addition in `ProcessUpdateValue` before line 259:**

```csharp
// Validate TuneOrderInformation
if (updateValueInput.TuneOrderInformation.Any())
{
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    var tunedOrders = new HashSet<int>();
    
    foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    {
        // Check range
        Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
            $"Invalid order {tuneOrder.Value}. Must be between 1 and {minersCount}.");
        
        // Check duplicates
        Assert(tunedOrders.Add(tuneOrder.Value), 
            $"Duplicate order {tuneOrder.Value} detected.");
        
        // Check miner exists
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
            $"Miner {tuneOrder.Key} not in current round.");
    }
}
```

**Additionally, fix `NextRoundMiningOrderValidationProvider`** to validate order values, not just miner count:

```csharp
var orderValues = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .ToList();
var distinctOrderCount = orderValues.Distinct().Count();
if (distinctOrderCount != orderValues.Count)
{
    validationResult.Message = "Duplicate FinalOrderOfNextRound values detected.";
    return validationResult;
}
```

## Proof of Concept

A malicious miner can execute this attack with the following scenario:

**Setup**: 5 total miners in the consensus, 4 miners have mined in current round, 1 has not.

**Attack**: Malicious miner (one of the 4 who mined) calls `UpdateValue` with:
```
TuneOrderInformation = {
    "miner1": 3,
    "miner2": 4,
    "miner3": 5,
    "miner4": 6
}
```

**Result**: 
- Next round generation assigns orders [3, 4, 5, 6] to the 4 miners who mined
- The 1 miner who didn't mine gets order [1] (first available from `ableOrders`)
- No miner has order 2
- `BreakContinuousMining` calls `.First(i => i.Order == 2)` at line 84
- `InvalidOperationException` is thrown: "Sequence contains no matching element"
- Consensus crashes, block production halts

**Test Case**: A complete test would require setting up a full consensus round state, but the crash can be demonstrated by constructing a `Round` object with miners lacking order 2 and calling `BreakContinuousMining`.

## Notes

This vulnerability exists because `TuneOrderInformation` is designed to resolve order conflicts during normal consensus operation, but lacks input validation to prevent malicious miners from injecting invalid values. The validation framework checks only miner counts, not the integrity of order value assignments. This allows consensus disruption through a single malicious transaction from any active miner.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L67-67)
```csharp
        BreakContinuousMining(ref nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-84)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L100-101)
```csharp
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
