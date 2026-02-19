### Title
Consensus Halt via Malicious TuneOrderInformation in UpdateValue

### Summary
A malicious miner can inject arbitrary values (e.g., `int.MaxValue`) into the `TuneOrderInformation` field of `UpdateValueInput`, corrupting the `FinalOrderOfNextRound` state for any miner. This causes all subsequent `NextRound` transactions to fail validation, permanently halting consensus as all miners deterministically generate the same invalid next round from the corrupted state.

### Finding Description

The vulnerability exists in the consensus update flow where miners submit `UpdateValueInput` during their time slots.

**Root cause location:** [1](#0-0) 

The `ProcessUpdateValue` method directly assigns arbitrary values from `updateValueInput.TuneOrderInformation` to `currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound` without any validation that these values are within the valid range of `[1, minersCount]`.

**Missing validation:** [2](#0-1) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` correctness. It does not validate the values in `TuneOrderInformation`.

**TuneOrderInformation definition:** [3](#0-2) 

The field is defined as an arbitrary map allowing any int32 values without constraints.

**Propagation to next round:** [4](#0-3) 

When generating the next round, `FinalOrderOfNextRound` from the current round becomes the `Order` in the next round. If `FinalOrderOfNextRound = int.MaxValue`, then `Order = int.MaxValue` and `ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(int.MaxValue))`, resulting in a timestamp approximately 272 years in the future.

**Validation failure:** [5](#0-4) 

When any miner attempts to create a `NextRound` transaction, the validation calls `CheckRoundTimeSlots()` which orders miners by `Order` and verifies equal time intervals. A miner with `Order = int.MaxValue` causes massive time interval deviation, failing the check at line 53-54.

**NextRound validation trigger:** [6](#0-5) 

All `NextRound` transactions are validated through `CheckRoundTimeSlots()`.

### Impact Explanation

**Critical Consensus Halt:**
- Once a malicious miner corrupts `FinalOrderOfNextRound` values via `TuneOrderInformation`, the current round state is permanently corrupted
- When the round needs to transition, all miners call `GenerateNextRoundInformation` which deterministically produces the same invalid next round from the corrupted state
- All `NextRound` transactions fail validation at `CheckRoundTimeSlots()`
- **No miner can successfully produce a valid NextRound block**
- **Consensus permanently halts** - the blockchain cannot progress beyond the current round

**Affected parties:**
- Entire network: all users, applications, and cross-chain operations
- All pending transactions become stuck
- Network requires manual intervention/fork to recover

**Severity justification:**
This is a **CRITICAL** vulnerability because:
1. It causes complete network failure (worse than fund theft)
2. Recovery requires coordinated hard fork/manual intervention
3. Affects entire ecosystem relying on the chain

### Likelihood Explanation

**Attacker capabilities:**
- Must be an active miner in the current round
- No special privileges beyond being a miner needed
- Can execute attack during their normal mining time slot

**Attack complexity:**
- **Trivial execution**: Single transaction with modified `TuneOrderInformation`
- No complex timing or race conditions required
- No need to compromise other miners

**Feasibility conditions:** [7](#0-6) 

The `PreCheck()` only verifies the sender is in the current or previous miner list - no additional authorization required.

**Detection constraints:**
- Attack is not detectable until NextRound transition fails
- By then, state is already corrupted
- No warning or prevention mechanism exists

**Economic rationality:**
- Zero cost attack (normal mining transaction)
- Could be executed by a disgruntled miner, competitor, or attacker who gained miner status
- High impact with minimal investment makes this highly attractive for malicious actors

**Probability: HIGH** - Any of the active miners can execute this at any time with a single transaction.

### Recommendation

**Immediate fix required in ProcessUpdateValue:**

Add validation before applying `TuneOrderInformation`:

```csharp
// In AEDPoSContract_ProcessConsensusInformation.cs, line 259
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    // Validate the tuned order is within valid range
    if (tuneOrder.Value < 1 || tuneOrder.Value > minersCount)
    {
        Context.LogDebug(() => $"Invalid tuned order {tuneOrder.Value} for miner {tuneOrder.Key}");
        continue; // Skip invalid entries
    }
    
    // Validate the target miner exists
    if (!currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key))
    {
        Context.LogDebug(() => $"Miner {tuneOrder.Key} not found in current round");
        continue;
    }
    
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Additional validations to add:**

1. In `UpdateValueValidationProvider`, add check:
   - Verify all `TuneOrderInformation` values are in range `[1, minersCount]`
   - Verify all keys exist in current round's miner list

2. In `NextRoundMiningOrderValidationProvider`, enhance check: [8](#0-7) 

   - Add validation that all `FinalOrderOfNextRound` values are within `[1, minersCount]`
   - Verify no duplicates exist

**Test cases to add:**
1. Test UpdateValue with `TuneOrderInformation` containing `int.MaxValue` - should be rejected
2. Test UpdateValue with `TuneOrderInformation` containing values > minersCount - should be rejected
3. Test UpdateValue with `TuneOrderInformation` for non-existent miner pubkey - should be rejected
4. Test that NextRound fails gracefully if invalid orders somehow persist
5. Test recovery mechanism if state corruption occurs

### Proof of Concept

**Required initial state:**
- Active AEDPoS consensus with multiple miners (e.g., 7 miners)
- Attacker is one of the active miners in current round
- Current round number N, attacker's time slot

**Attack transaction steps:**

1. **Attacker creates malicious UpdateValueInput:**
   - Set normal fields: `OutValue`, `Signature`, `PreviousInValue`, etc.
   - Set `TuneOrderInformation = { "VICTIM_MINER_PUBKEY": int.MaxValue }`
   - Or even simpler: `TuneOrderInformation = { "ATTACKER_OWN_PUBKEY": int.MaxValue }`

2. **Submit UpdateValue transaction:**
   - Transaction passes validation (UpdateValueValidationProvider doesn't check TuneOrderInformation)
   - `ProcessUpdateValue` executes, setting `FinalOrderOfNextRound = int.MaxValue` for target miner
   - Round state persisted with corrupted value

3. **Round attempts to transition to N+1:**
   - Next miner tries to create NextRound block
   - Calls `GenerateNextRoundInformation` [9](#0-8) 
   
   - Generated round has miner with `Order = int.MaxValue`, `ExpectedMiningTime` ~272 years ahead
   - NextRound transaction submitted

4. **Validation fails:**
   - `ValidateBeforeExecution` calls `TimeSlotValidationProvider`
   - Calls `CheckRoundTimeSlots()` for new round
   - Time interval check at line 53 fails: `Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval`
   - Transaction rejected

5. **Consensus halt:**
   - All subsequent miners generate identical invalid next round (deterministic from same state)
   - All NextRound attempts fail with same validation error
   - **Network stuck at round N forever**

**Expected result:** Transaction rejected or state remains valid
**Actual result:** State corrupted, consensus permanently halted

**Success condition:** Blockchain cannot progress past round N; all NextRound transactions fail validation with "Time slots are so different" error.

### Notes

The vulnerability demonstrates a critical gap in consensus state validation where miner-provided tuning data is trusted without bounds checking. The `TuneOrderInformation` mechanism appears designed for legitimate order conflict resolution (as generated by `ExtractInformationToUpdateConsensus`), but lacks defensive validation when miners provide arbitrary malicious inputs. The deterministic nature of round generation from shared state means a single corrupted value propagates to all miners' NextRound attempts, amplifying the attack's effectiveness.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

```
