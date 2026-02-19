### Title
Integer Overflow Denial of Service in Round Generation via Unbounded FinalOrderOfNextRound Values

### Summary
A malicious miner can set arbitrary `FinalOrderOfNextRound` values for any miner through the `tune_order_information` field in `UpdateValueInput`, including values up to `Int32.MaxValue`. When the next round is generated, the unchecked order value causes integer overflow in the time calculation `miningInterval.Mul(order)`, triggering an `OverflowException` that prevents round generation and halts consensus indefinitely.

### Finding Description

The vulnerability exists in the consensus round generation logic where `FinalOrderOfNextRound` values are used in arithmetic operations without bounds validation.

**Root Cause Location 1 - Missing Input Validation:**
In `ProcessUpdateValue`, the `tune_order_information` map from user input is applied directly to set `FinalOrderOfNextRound` values without any bounds checking: [1](#0-0) 

The protobuf definition allows any `int32` value in this map: [2](#0-1) 

**Root Cause Location 2 - Overflow-Prone Arithmetic:**
During next round generation, the unchecked `FinalOrderOfNextRound` value is used in a multiplication that can overflow: [3](#0-2) 

The `GetMiningInterval()` method returns an `int` (typically 4000 milliseconds): [4](#0-3) 

**Why SafeMath Protection Fails Here:**
The `Mul()` extension method uses checked arithmetic that throws `OverflowException` on overflow: [5](#0-4) 

While this prevents silent overflow, the exception causes transaction failure and consensus disruption.

**Insufficient Validation:**
The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are filled, and checks `PreviousInValue` consistency. It does NOT validate `tune_order_information` bounds: [6](#0-5) 

The `NextRoundMiningOrderValidationProvider` only checks count consistency, not value bounds: [7](#0-6) 

**Attack Execution Path:**
The round generation is called during consensus extra data preparation for the next round: [8](#0-7) 

### Impact Explanation

**Consensus Denial of Service:**
When `FinalOrderOfNextRound` is set to `Int32.MaxValue` (2,147,483,647) and `miningInterval` is 4000, the calculation `4000 * 2,147,483,647 = 8,589,934,588,000` exceeds `Int32.MaxValue`. The `OverflowException` causes the `GenerateNextRoundInformation` call to fail, preventing any miner from producing the next round.

**Protocol-Wide Impact:**
- Consensus completely halts - no blocks can be produced for the next round
- All miners attempting to transition to the next round will fail
- Requires manual intervention or chain restart to recover
- Affects the entire blockchain network, not just individual miners

**Affected Parties:**
- All network participants unable to process transactions
- Miners unable to produce blocks and earn rewards
- Users experiencing service disruption

**Severity Justification:**
This is a **High** severity vulnerability (not Medium as initially suggested) because:
1. Complete consensus halt affects all network operations
2. Attack is trivial for any current miner to execute
3. No special permissions beyond being in the current miner set required
4. Recovery requires manual intervention/coordination

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a current miner (member of the consensus round)
- Can produce at least one block in the current round
- No additional permissions or special access required

**Attack Complexity:**
- **Very Low**: Single transaction with crafted `UpdateValueInput`
- Simply set `tune_order_information[<any_miner_pubkey>] = Int32.MaxValue`
- No timing requirements or race conditions
- Deterministic outcome

**Feasibility Conditions:**
- Attacker is in the active miner set (realistic for a compromised miner)
- No economic barriers - attack cost is just one block production
- Can target any miner's order value, not just their own

**Detection Constraints:**
- Attack is visible on-chain in the `UpdateValue` transaction
- However, damage occurs when next round generation is attempted
- By the time overflow is detected, consensus is already halted

**Probability Assessment:**
- **High Likelihood**: Any malicious or compromised miner can execute this attack
- Multiple miners means multiple potential attack vectors
- Accidental triggering is unlikely (requires intentional extreme values)
- Economic incentives unclear - may be used for griefing or ransom

### Recommendation

**Immediate Fix - Add Bounds Validation:**

Add validation in `ProcessUpdateValue` before applying `tune_order_information`:

```csharp
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
        "Invalid FinalOrderOfNextRound: must be between 1 and miner count");
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
        "Invalid miner pubkey in tune_order_information");
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Additional Validation in Provider:**

Create a dedicated validation provider or enhance `UpdateValueValidationProvider`:

```csharp
// Validate tune_order_information bounds
var minersCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in validationContext.ProvidedRound.RealTimeMinersInformation)
{
    if (tuneOrder.Value.FinalOrderOfNextRound < 1 || 
        tuneOrder.Value.FinalOrderOfNextRound > minersCount)
    {
        return new ValidationResult 
        { 
            Message = $"FinalOrderOfNextRound out of bounds: {tuneOrder.Value.FinalOrderOfNextRound}" 
        };
    }
}
```

**Defense in Depth - Safe Arithmetic in Generation:**

Add overflow protection in `GenerateNextRoundInformation`:

```csharp
try
{
    var expectedTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order));
}
catch (OverflowException)
{
    // Log and use maximum valid timestamp instead of failing
    Context.LogWarning($"Order value {order} too large, using max valid time");
    var expectedTime = currentBlockTimestamp.AddMilliseconds(long.MaxValue);
}
```

**Test Cases:**

1. Test `UpdateValue` with `tune_order_information` containing values < 1 (should fail)
2. Test `UpdateValue` with `tune_order_information` containing values > minersCount (should fail)
3. Test `UpdateValue` with `tune_order_information[key] = Int32.MaxValue` (should fail)
4. Test successful round generation after applying valid tune orders
5. Test that validation happens before state changes (no partial application)

### Proof of Concept

**Initial State:**
- Blockchain with N active miners (e.g., 5 miners)
- Current round R in progress
- Attacker is miner with pubkey `ATTACKER_PUBKEY`
- Target victim is miner with pubkey `VICTIM_PUBKEY`

**Attack Steps:**

1. **Attacker produces a block in round R:**
   - Calls `UpdateValue()` with malicious input
   - Sets `UpdateValueInput.tune_order_information["VICTIM_PUBKEY"] = 2147483647` (Int32.MaxValue)
   - Transaction succeeds, `FinalOrderOfNextRound` for victim is set to Int32.MaxValue

2. **Next miner attempts to transition to round R+1:**
   - Calls consensus behavior `NextRound`
   - `GetConsensusExtraDataForNextRound()` is invoked
   - Calls `GenerateNextRoundInformation(currentRound, ...)`
   - In `Round_Generation.GenerateNextRoundInformation()`:
     * Iterates through miners ordered by `FinalOrderOfNextRound`
     * Reaches victim miner with `order = 2147483647`
     * Executes: `miningInterval.Mul(order)` where `miningInterval = 4000`
     * Calculation: `4000 * 2147483647 = 8,589,934,588,000`
     * This exceeds `Int32.MaxValue` (2,147,483,647)
     * `SafeMath.Mul()` throws `OverflowException`

3. **Result:**
   - Transaction fails with `OverflowException`
   - Next round cannot be generated
   - All subsequent miners attempting `NextRound` will fail with the same error
   - Consensus is halted

**Expected vs Actual:**
- **Expected**: Valid order values are bounded [1, N], round generation succeeds
- **Actual**: Unbounded order value causes overflow, consensus halts

**Success Condition:**
- After attacker's malicious `UpdateValue`, no miner can successfully produce `NextRound` transaction
- Chain stops producing new rounds until manual intervention

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L13-19)
```csharp
    public static int Mul(this int a, int b)
    {
        checked
        {
            return a * b;
        }
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

```
