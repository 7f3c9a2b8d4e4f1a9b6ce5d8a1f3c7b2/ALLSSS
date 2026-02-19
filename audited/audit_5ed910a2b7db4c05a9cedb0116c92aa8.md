### Title
Missing Key Validation in ProcessUpdateValue Allows Exception-Based Consensus Disruption

### Summary
The `ProcessUpdateValue` function lacks validation to ensure keys in `TuneOrderInformation` exist in `currentRound.RealTimeMinersInformation` before accessing them. A malicious miner can craft an `UpdateValueInput` with invalid miner keys, causing a `KeyNotFoundException` that fails block production and disrupts consensus timing.

### Finding Description
**Location**: [1](#0-0) 

**Root Cause**: The code directly accesses `currentRound.RealTimeMinersInformation[tuneOrder.Key]` without verifying the key exists. While the normal flow generates `TuneOrderInformation` from the current round's miner list [2](#0-1) , miners can submit crafted transactions directly.

**Why Protections Fail**: The `PreCheck()` function only validates the sender is a current or previous miner [3](#0-2) , but does not validate the contents of `TuneOrderInformation`. The `UpdateValue` method is publicly accessible [4](#0-3) , allowing direct calls with arbitrary input.

**Execution Path**: 
1. Miner calls `UpdateValue` with crafted `UpdateValueInput` containing invalid keys in `TuneOrderInformation`
2. `ProcessConsensusInformation` passes `PreCheck()` (sender is valid miner)
3. `ProcessUpdateValue` is called
4. Line 260 attempts dictionary access with non-existent key
5. `KeyNotFoundException` thrown, transaction fails

### Impact Explanation
**Consensus Disruption**: When the exception is thrown, block production fails entirely. The `ConsensusRequestMiningEventHandler` catches exceptions and re-triggers consensus [5](#0-4) , causing:
- Wasted block production attempts
- Timing delays in consensus progression
- Potential missed time slots for the malicious miner

**Operational Impact**: Repeated failures could trigger "evil miner" detection mechanisms, but also create temporary consensus instability. While primarily self-inflicted damage, this can be weaponized for timing attacks or to cause confusion during critical consensus transitions.

**Severity**: Medium - Limited to causing transaction failures and consensus retries rather than direct fund theft or state corruption, but disrupts consensus reliability.

### Likelihood Explanation
**Attacker Capabilities**: Requires miner privileges and ability to submit consensus transactions directly (either through modified node software or direct contract calls).

**Attack Complexity**: Low - Simply craft an `UpdateValueInput` with `TuneOrderInformation` containing arbitrary string keys (e.g., random hex strings, non-existent miner public keys).

**Feasibility**: High - No cryptographic or economic barriers beyond being a miner. The `UpdateValue` method accepts user-provided input without content validation.

**Economic Rationality**: Low for direct exploitation (causes self-harm by missing blocks), but could be used strategically during specific consensus events or combined with other attacks.

**Detection**: Failed transactions and consensus retries would be logged, but might be attributed to normal network issues initially.

### Recommendation
Add key validation before accessing the dictionary:

```csharp
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
{
    if (!currentRound.RealTimeMinersInformation.ContainsKey(tuneOrder.Key))
    {
        Context.LogWarning($"Invalid tune order key: {tuneOrder.Key}");
        continue; // or Assert(false, "Invalid miner key in tune order information")
    }
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
}
```

**Alternatively**, validate during transaction generation that `TuneOrderInformation` only contains keys from the current round's miner list, similar to the pattern used in `RecoverFromUpdateValue` [6](#0-5) .

**Test Cases**: Add unit tests verifying:
1. UpdateValue with non-existent miner keys in TuneOrderInformation is rejected or handled gracefully
2. UpdateValue with valid keys processes correctly
3. UpdateValue with empty TuneOrderInformation processes correctly

### Proof of Concept
**Initial State**: Chain is running with miners [A, B, C, D, E]

**Attack Steps**:
1. Miner A modifies their node to craft malicious `UpdateValueInput`:
   - Set valid `OutValue`, `Signature`, `ActualMiningTime` 
   - Add `TuneOrderInformation` entries: `{"INVALID_KEY_1": 1, "NONEXISTENT_MINER": 2}`
2. Miner A submits transaction calling `UpdateValue` with crafted input
3. `PreCheck()` passes (Miner A is valid)
4. `ProcessUpdateValue` executes lines 243-258 successfully
5. Line 259-260 iteration encounters "INVALID_KEY_1"
6. `currentRound.RealTimeMinersInformation["INVALID_KEY_1"]` throws `KeyNotFoundException`

**Expected Result**: Transaction completes successfully, only updating orders for valid miners

**Actual Result**: `KeyNotFoundException` thrown, transaction fails, block production fails, consensus retry triggered

**Success Condition**: Transaction failure logged, consensus must re-attempt block production for that time slot

### Notes
A similar vulnerability exists in `RecoverFromUpdateValue` where it iterates through `providedRound.RealTimeMinersInformation` without validating all keys exist in the base round [7](#0-6) , though this only checks the sender's key at the function entry. The duplicate keys scenario mentioned in the question is not possible since `TuneOrderInformation` is defined as `map<string, int32>` in protobuf [8](#0-7) , which enforces unique keys in the dictionary.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-100)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
```

**File:** src/AElf.Kernel/ConsensusRequestMiningEventHandler.cs (L82-86)
```csharp
            catch (Exception)
            {
                await TriggerConsensusEventAsync(chain.BestChainHash, chain.BestChainHeight);
                throw;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

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

**File:** protobuf/aedpos_contract.proto (L208-208)
```text
    map<string, int32> tune_order_information = 7;
```
