### Title
FinalOrderOfNextRound Collision Not Detected Due to Incorrect Distinct() Usage in Mining Order Validation

### Summary
The `NextRoundMiningOrderValidationProvider` fails to detect when multiple miners are assigned the same `FinalOrderOfNextRound` value because it applies `Distinct()` to entire `MinerInRound` objects rather than to the order values themselves. This allows malicious miners to create order collisions via `TuneOrderInformation`, resulting in multiple miners being assigned the same mining slot in the next round, causing consensus failure and potential blockchain forks.

### Finding Description

The validation logic in `ValidateHeaderInformation()` contains a critical flaw: [1](#0-0) 

The code applies `Distinct()` to a collection of `MinerInRound` objects. Since protobuf-generated classes implement `Equals()` and `GetHashCode()` based on ALL fields, two different miners with identical `FinalOrderOfNextRound` values but different `pubkey`, `order`, or other fields are still counted as distinct objects. This means if Miner A and Miner B both have `FinalOrderOfNextRound = 5`, the `distinctCount` would be 2, and the validation would pass if 2 miners have `OutValue != null`.

The attack vector exploits the fact that miners can set arbitrary `TuneOrderInformation` values during `UpdateValue` without validation: [2](#0-1) 

The `UpdateValueValidationProvider` does not validate the contents of `TuneOrderInformation`: [3](#0-2) 

When `GenerateNextRoundInformation()` processes the next round, it uses `FinalOrderOfNextRound` values to assign mining orders: [4](#0-3) 

Multiple miners with the same `FinalOrderOfNextRound` will be assigned the same `Order` in the next round, each creating separate dictionary entries with their unique pubkeys but identical order values.

### Impact Explanation

**Consensus Integrity Violation (Critical):**
- Multiple miners are assigned identical mining time slots in the next round
- Both miners have legitimate authority to produce blocks at the same `ExpectedMiningTime`
- The blockchain experiences simultaneous block production at the same height, causing forks

**Blockchain Fork and Instability:**
- When `GetNextMinerPubkey()` determines the current miner, it returns the first miner whose `ExpectedMiningTime > Context.CurrentBlockTime`, but with identical times, selection becomes non-deterministic: [5](#0-4) 

- Different nodes may accept different blocks as valid, fragmenting the network
- The consensus mechanism loses its fundamental property of deterministic block producer selection

**Denial of Service:**
- Any miner can trigger this attack once per round
- Continuous exploitation renders the blockchain inoperable
- Recovery requires manual intervention to exclude malicious miners

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an active miner (member of `RealTimeMinersInformation`)
- No special privileges beyond normal miner status required
- Attack can be executed through the standard `UpdateValue` method

**Attack Complexity: LOW**
- Single transaction with crafted `TuneOrderInformation` map
- No timing requirements or race conditions
- Deterministic outcome - validation will always fail to detect the collision

**Feasibility Conditions:**
- Attacker controls at least one miner identity
- Can execute during any `UpdateValue` in any round
- No economic cost beyond normal mining operations
- Attack succeeds with 100% probability given the validation flaw

**Detection/Operational Constraints:**
- The collision is only detected when `NextRound` is triggered and miners attempt to mine
- By that point, the malicious state is already committed
- No monitoring system can prevent the attack proactively

### Recommendation

**Code-Level Mitigation:**

Replace the validation logic to check for unique `FinalOrderOfNextRound` values:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

This ensures `Distinct()` operates on the order values themselves, not the miner objects.

**Additional Invariant Checks:**

1. Add validation in `UpdateValueValidationProvider` to verify `TuneOrderInformation` values don't create collisions:
   - Check that no two miners end up with the same `FinalOrderOfNextRound`
   - Validate that all assigned orders are within the valid range [1, minersCount]

2. Add a secondary check in `GenerateNextRoundInformation()` to assert all assigned orders are unique before committing the next round.

**Test Cases:**

1. Test case where a miner attempts to set `TuneOrderInformation` creating a collision - should be rejected
2. Test case where two miners legitimately calculate the same `SupposedOrderOfNextRound` - should be resolved and validated correctly
3. Regression test ensuring the corrected validation properly counts unique order values

### Proof of Concept

**Initial State:**
- Round N with 5 active miners: A, B, C, D, E
- All miners have produced blocks (OutValue != null)
- Miners A, B, C, D have already determined their `FinalOrderOfNextRound`: 1, 2, 3, 4 respectively
- Miner E is about to produce a block with `UpdateValue`

**Attack Steps:**

1. Miner E constructs malicious `UpdateValueInput`:
   - `SupposedOrderOfNextRound = 5` (legitimate for themselves)
   - `TuneOrderInformation = { "MinerD": 5 }` (malicious - assigns MinerD the same order as themselves)
   
2. Miner E submits the transaction via `UpdateValue()` method

3. `ProcessUpdateValue()` executes:
   - Sets `MinerE.FinalOrderOfNextRound = 5`
   - Processes `TuneOrderInformation` and sets `MinerD.FinalOrderOfNextRound = 5`
   - Round state now has two miners with `FinalOrderOfNextRound = 5`

4. `NextRound` validation in `NextRoundMiningOrderValidationProvider`:
   - Filters miners: A(1), B(2), C(3), D(5), E(5) - all 5 included
   - `Distinct()` on `MinerInRound` objects returns 5 objects (all have different pubkeys)
   - `distinctCount = 5`
   - Count of miners with `OutValue != null` = 5
   - Validation passes: `5 == 5` ✓

5. `GenerateNextRoundInformation()` creates Round N+1:
   - Assigns MinerD: `Order = 5`
   - Assigns MinerE: `Order = 5`
   - Both miners have identical `ExpectedMiningTime`

**Expected Result:**
Validation should reject the round, detecting that two miners have `FinalOrderOfNextRound = 5`

**Actual Result:**
Validation passes, and Round N+1 has two miners with `Order = 5`, breaking consensus when both attempt to mine simultaneously

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L91-102)
```csharp
    public override StringValue GetNextMinerPubkey(Empty input)
    {
        if (TryToGetCurrentRoundInformation(out var round))
            return new StringValue
            {
                Value = round.RealTimeMinersInformation.Values
                            .FirstOrDefault(m => m.ExpectedMiningTime > Context.CurrentBlockTime)?.Pubkey ??
                        round.RealTimeMinersInformation.Values.First(m => m.IsExtraBlockProducer).Pubkey
            };

        return new StringValue();
    }
```
