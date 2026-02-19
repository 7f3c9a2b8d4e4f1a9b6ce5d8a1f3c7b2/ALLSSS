# Audit Report

## Title
Invalid FinalOrderOfNextRound Values Enable Consensus Disruption Through Malicious Order Assignment

## Summary
A malicious miner can inject arbitrary `FinalOrderOfNextRound` values through the `UpdateValue` method's `TuneOrderInformation` parameter without any validation. These invalid values (including 0, duplicates, or values exceeding `minersCount`) are directly used in next round generation, causing consensus disruption, execution crashes, or miner exclusion.

## Finding Description

**Root Cause - Unvalidated Order Assignment:**

The `ProcessUpdateValue` method directly applies `TuneOrderInformation` from user input to `FinalOrderOfNextRound` without bounds checking or duplicate validation: [1](#0-0) 

The `UpdateValueInput` protobuf allows arbitrary `int32` values in the `tune_order_information` map: [2](#0-1) 

**Vulnerable Execution Path:**

When `GenerateNextRoundInformation` processes the next round, it uses these unvalidated `FinalOrderOfNextRound` values directly to assign mining orders: [3](#0-2) 

The `occupiedOrders` calculation collects whatever values exist, including invalid ones: [4](#0-3) 

**Why Existing Protections Fail:**

The `NextRoundMiningOrderValidationProvider` only checks that the count of miners with `FinalOrderOfNextRound > 0` matches miners who mined, using `Distinct()` on `MinerInRound` objects (not on order values), which fails to detect duplicate order values: [5](#0-4) 

The `UpdateValueValidationProvider` only validates OutValue and Signature fields, not TuneOrderInformation: [6](#0-5) 

**Downstream Crash Points:**

The `BreakContinuousMining` function expects specific orders to exist and uses `First()` which throws `InvalidOperationException` if expected orders are missing: [7](#0-6) [8](#0-7) [9](#0-8) 

## Impact Explanation

**Consensus Integrity Violation (HIGH SEVERITY):**

1. **Duplicate Orders**: Two miners with the same `FinalOrderOfNextRound` value compete for the same time slot, causing block production conflicts and consensus ambiguity.

2. **Missing Orders**: When orders 1 through `minersCount` are not properly assigned, gaps appear in the mining schedule. The `ableOrders` calculation becomes incorrect when `occupiedOrders` contains 0 or values > `minersCount`.

3. **Invalid Order Values**: 
   - Order = 0: Creates a miner scheduled at current block timestamp (in the past), bypassing time-slot validation
   - Order > `minersCount`: Creates out-of-range orders breaking schedule integrity

4. **Consensus Execution Crashes**: The `BreakContinuousMining` function will crash with `InvalidOperationException` if expected orders (1, 2, `minersCount-1`) don't exist due to malicious assignments.

5. **Miner Exclusion**: Miners with duplicate orders overwrite each other in the dictionary-based assignment, causing legitimate miners who successfully mined to be excluded from the next round.

**Affected Components:**
- All miners participating in consensus
- Block production scheduling
- Round transition logic
- LIB height calculation
- Cross-chain verification depending on consensus state

## Likelihood Explanation

**Attacker Capabilities:**
Any active miner can call the public `UpdateValue` method: [10](#0-9) 

The only permission check (`PreCheck`) validates that the sender is in the miner list: [11](#0-10) 

**Attack Complexity: LOW**
1. Malicious miner crafts `UpdateValue` transaction with arbitrary `TuneOrderInformation`
2. Values are stored immediately without validation
3. Next round generation uses these invalid values
4. Consensus breaks or miners are excluded

**Feasibility Conditions:**
- Attacker must be an elected miner (realistic in competitive environment)
- Single transaction execution required
- No special timing requirements
- Economically rational for miners to attack competitors or disrupt consensus

**Probability: HIGH** - Any malicious miner can execute this attack with a single transaction at any time during their mining slot.

## Recommendation

Add comprehensive validation in `ProcessUpdateValue` before applying `TuneOrderInformation`:

```csharp
// Validate TuneOrderInformation before applying
var minersCount = currentRound.RealTimeMinersInformation.Count;
var usedOrders = new HashSet<int>();

foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate order is within valid range
    if (tuneOrder.Value < 1 || tuneOrder.Value > minersCount)
        Assert(false, $"Invalid order value {tuneOrder.Value}. Must be between 1 and {minersCount}");
    
    // Validate no duplicate orders
    if (!usedOrders.Add(tuneOrder.Value))
        Assert(false, $"Duplicate order value {tuneOrder.Value} detected");
    
    // Validate target miner exists and mined
    if (!currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key))
        Assert(false, $"Miner {tuneOrder.Key} not found");
    
    if (currentRound.RealTimeMinersInformation[tuneOrder.Key].OutValue == null)
        Assert(false, $"Miner {tuneOrder.Key} did not mine");
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

Additionally, fix `NextRoundMiningOrderValidationProvider` to check distinct order VALUES:

```csharp
var distinctOrderCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanInjectInvalidOrders_CausesConsensusCrash()
{
    // Setup: Initialize consensus with 5 miners
    var initialMiners = GenerateInitialMiners(5);
    await InitializeConsensus(initialMiners);
    
    // Miner produces first block normally
    var miner1 = initialMiners[0];
    await ProduceNormalBlock(miner1);
    
    // ATTACK: Miner crafts malicious UpdateValue with invalid TuneOrderInformation
    var maliciousInput = new UpdateValueInput
    {
        // ... normal fields ...
        TuneOrderInformation = 
        {
            { initialMiners[1].PublicKey, 0 },        // Invalid: order = 0
            { initialMiners[2].PublicKey, 10 },       // Invalid: order > minersCount
            { initialMiners[3].PublicKey, 3 },        // Valid order
            { initialMiners[4].PublicKey, 3 }         // Duplicate: same order as miner3
        }
    };
    
    // Execute malicious UpdateValue - should be rejected but isn't
    var result = await ConsensusContract.UpdateValue.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // VULNERABILITY: Succeeds
    
    // Trigger NextRound - will crash or produce invalid state
    await MoveToNextRound();
    
    // Verify consensus is broken
    var nextRound = await GetCurrentRound();
    
    // Assertion 1: Duplicate orders exist
    var orders = nextRound.RealTimeMinersInformation.Values.Select(m => m.Order).ToList();
    orders.Count(o => o == 3).ShouldBe(2); // Two miners with same order
    
    // Assertion 2: Invalid order values exist  
    orders.ShouldContain(0);  // Order 0 exists
    orders.ShouldContain(10); // Order > minersCount exists
    
    // Assertion 3: BreakContinuousMining will crash if order 1 or 2 missing
    // This demonstrates the execution failure path
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
    map<string, int32> tune_order_information = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-28)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L40-41)
```csharp
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-79)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L84-84)
```csharp
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L101-101)
```csharp
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
