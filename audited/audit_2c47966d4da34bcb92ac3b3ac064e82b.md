### Title
Unbounded TuneOrderInformation Allows Consensus DoS via Integer Overflow in Round Generation

### Summary
A malicious miner can exploit the unvalidated `TuneOrderInformation` field in `UpdateValue` to set arbitrary `FinalOrderOfNextRound` values (e.g., int.MaxValue) for any miner. When the next round is generated, this corrupted order value causes an integer overflow exception during mining time calculation, permanently blocking round progression and halting consensus.

### Finding Description

The vulnerability exists in the consensus round update flow across multiple files: [1](#0-0) 

In `ProcessUpdateValue`, the `TuneOrderInformation` map is directly applied to update miners' `FinalOrderOfNextRound` values without any bounds validation. The field accepts arbitrary int32 values from the caller. [2](#0-1) 

When the next round is generated, this corrupted `FinalOrderOfNextRound` becomes the `Order` field: [3](#0-2) 

The `Order` value (now int.MaxValue) is multiplied by `miningInterval` to calculate `ExpectedMiningTime`. Since AElf uses checked arithmetic via SafeMath: [4](#0-3) 

This multiplication throws `OverflowException`, causing the entire `NextRound` transaction to fail.

**Validation Gaps:**

The `UpdateValueValidationProvider` only validates OutValue, Signature, and PreviousInValue - it does NOT validate TuneOrderInformation bounds: [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` only checks count equality, not whether orders are within valid range [1, minersCount]: [6](#0-5) 

### Impact Explanation

**Consensus Halt (Critical)**: Once a miner corrupts another miner's order to int.MaxValue, every subsequent `NextRound` attempt will fail with `OverflowException`. The blockchain cannot progress to the next round, causing a permanent consensus deadlock.

**Affected Parties**: All network participants - validators cannot produce blocks, transactions cannot be processed, and the entire chain is frozen until manual intervention (contract upgrade or state rollback).

**Severity Justification**: This is a consensus-layer DoS with permanent impact. Unlike temporary DoS attacks, this corruption persists in state and prevents any normal recovery mechanism. The attack requires only miner privileges (which all consensus validators have) and causes complete blockchain halt.

### Likelihood Explanation

**Attacker Capabilities**: Any current miner (consensus validator) can execute this attack. The attacker must pass `PreCheck` which verifies they are in the current or previous round's miner list: [7](#0-6) 

**Attack Complexity**: Very low - requires only one `UpdateValue` transaction with malicious `TuneOrderInformation` parameter. No complex state manipulation or timing requirements.

**Feasibility Conditions**: The attack is practical in normal operation. Miners regularly call `UpdateValue` as part of consensus, so this transaction type is expected and won't raise suspicion until the overflow occurs in the subsequent `NextRound`.

**Detection/Operational Constraints**: The corruption happens during UpdateValue but manifests later during NextRound, making it difficult to detect and attribute. By the time the overflow occurs, the state corruption is already persisted.

**Probability**: High - The attack vector is straightforward, requires minimal resources (only transaction fees), and any malicious/compromised miner node can execute it.

### Recommendation

**Immediate Fix**: Add bounds validation for `TuneOrderInformation` values in `ProcessUpdateValue`:

```csharp
// In ProcessUpdateValue, after line 258:
var minersCount = currentRound.RealTimeMinersInformation.Count;
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    Assert(tuneOrder.Value >= 1 && tuneOrder.Value <= minersCount, 
           $"Invalid order value: {tuneOrder.Value}. Must be between 1 and {minersCount}");
    Assert(currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key),
           "Invalid pubkey in TuneOrderInformation");
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Additional Validation**: Enhance `NextRoundMiningOrderValidationProvider` to validate order bounds:

```csharp
// Add after line 21:
var minersCount = providedRound.RealTimeMinersInformation.Count;
foreach (var miner in providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0))
{
    if (miner.FinalOrderOfNextRound < 1 || miner.FinalOrderOfNextRound > minersCount)
    {
        validationResult.Message = $"FinalOrderOfNextRound out of bounds: {miner.FinalOrderOfNextRound}";
        return validationResult;
    }
}
```

**Test Cases**:
1. Test UpdateValue with TuneOrderInformation containing out-of-bounds values (0, negative, > minersCount, int.MaxValue)
2. Test that NextRound generation correctly handles all valid order values [1, minersCount]
3. Test that overflow protection prevents invalid mining time calculations

### Proof of Concept

**Initial State**: 
- 3 active miners in current round (Alice, Bob, Charlie)
- Alice is the attacker
- miningInterval = 4000 ms

**Attack Sequence**:

1. Alice calls `UpdateValue` with legitimate consensus data plus malicious `TuneOrderInformation`:
   ```
   TuneOrderInformation = { "Bob's_pubkey": 2147483647 }  // int.MaxValue
   ```

2. `ProcessUpdateValue` executes successfully and persists the corrupted state:
   - Bob's `FinalOrderOfNextRound` is set to 2147483647
   - Transaction succeeds, state is saved

3. Charlie (or any miner) attempts to call `NextRound`:
   - `GenerateNextRoundInformation` processes miners who mined in current round
   - When processing Bob: `order = 2147483647`
   - Line 33 calculates: `currentBlockTimestamp.AddMilliseconds(4000.Mul(2147483647))`
   - `Mul(2147483647)` throws `OverflowException` (checked arithmetic)
   - Transaction fails, round cannot advance

**Expected Result**: NextRound succeeds, blockchain progresses normally

**Actual Result**: NextRound permanently fails with OverflowException, consensus is halted

**Success Condition**: The attack succeeds when any subsequent NextRound call fails due to the overflow, and the blockchain cannot progress to the next round without manual state intervention.

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

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
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
