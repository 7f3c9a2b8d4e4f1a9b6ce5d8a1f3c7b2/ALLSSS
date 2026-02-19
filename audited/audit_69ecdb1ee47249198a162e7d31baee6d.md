### Title
Race Condition in Mining Order Assignment Allows Duplicate FinalOrderOfNextRound Values

### Summary
The `ApplyNormalConsensusData()` function performs conflict detection during block generation on local copies of round state, but when multiple miners independently calculate the same `supposedOrderOfNextRound`, they both see no conflicts in their local copies. During subsequent transaction execution in `ProcessUpdateValue()`, both miners' orders are committed without re-validation, resulting in duplicate `FinalOrderOfNextRound` values that break consensus round integrity.

### Finding Description

The vulnerability exists across two execution phases with insufficient synchronization:

**Phase 1 - Block Generation (Off-chain):**
When a miner generates a block, `GetConsensusExtraDataToPublishOutValue()` calls `ApplyNormalConsensusData()` on a local copy of the current round state. [1](#0-0) 

The conflict detection logic checks for existing miners with the same `FinalOrderOfNextRound` and reassigns them. [2](#0-1) 

However, this check operates on the miner's local copy. If two miners generate blocks concurrently (reading the same initial state before either's transaction executes), both will see no conflicts and both will claim the same order. [3](#0-2) 

The resulting `UpdateValueInput` is created with `TuneOrderInformation` populated only from detected conflicts. [4](#0-3) 

**Phase 2 - Transaction Execution (On-chain):**
When `ProcessUpdateValue()` executes, it directly assigns the order from the input without re-validating uniqueness. [5](#0-4) 

It then applies `TuneOrderInformation`, but if both miners detected no conflicts, both have empty tuning maps, so no adjustments occur. [6](#0-5) 

**Why Existing Protections Fail:**

1. The `UpdateValueValidationProvider` only validates OutValue/Signature correctness and PreviousInValue, not order uniqueness. [7](#0-6) 

2. The `NextRoundMiningOrderValidationProvider` contains a bug - it calls `.Distinct()` on `MinerInRound` objects rather than on the `FinalOrderOfNextRound` integers, making it ineffective at detecting duplicates. [8](#0-7) 

3. Moreover, this validator is only registered for `NextRound` behavior, not `UpdateValue` behavior. [9](#0-8) 

4. `EnsureTransactionOnlyExecutedOnceInOneBlock()` only prevents duplicate execution of the same transaction within one block, not concurrent execution of different miners' transactions. [10](#0-9) 

### Impact Explanation

**Direct Consensus Integrity Violation:**
When two miners have the same `FinalOrderOfNextRound` value, the next round generation logic will assign them to the same time slot, causing:
- Undefined behavior in round scheduling
- Potential block production conflicts
- Inability to properly transition to the next round
- Broken miner rotation mechanism

**Likelihood of Natural Occurrence:**
The order calculation uses `GetAbsModulus(signature.ToInt64(), minersCount) + 1`, which distributes orders across N positions. [11](#0-10) 

With 17 miners (typical AEDPoS configuration), any two miners have approximately 1/17 (~6%) chance of collision per round. Over multiple rounds, collisions become highly probable.

**Severity Justification:**
This breaks a critical consensus invariant: each miner must have a unique mining order in the next round. The consensus mechanism's integrity depends on this invariant, making this a CRITICAL severity issue.

### Likelihood Explanation

**No Attacker Required:**
This vulnerability triggers naturally during normal consensus operation - no malicious actor is needed. Any time two miners' signatures happen to hash to the same modulo value, the race condition can occur.

**Attack Complexity:**
Minimal - the vulnerability is triggered by:
1. Two miners calculating the same `supposedOrderOfNextRound` (probabilistic, ~1/N chance)
2. Both generating their blocks before seeing each other's committed state (timing window exists in any distributed system)

**Feasibility Conditions:**
- Occurs naturally in multi-miner environments
- More likely with more miners due to birthday paradox
- Probability increases with block production rate and network latency

**Detection Constraints:**
The duplicate orders may not be immediately obvious until next round generation attempts to use them, potentially causing delayed failures or undefined behavior in round transitions.

**Probability Reasoning:**
With N miners and sequential block production, the cumulative probability of at least one collision across M blocks approaches: 1 - (1 - 1/N)^(M×(M-1)/2), which grows rapidly. For 17 miners over 100 blocks, collision probability exceeds 95%.

### Recommendation

**1. Add State-Based Conflict Detection in ProcessUpdateValue:**

Before assigning `FinalOrderOfNextRound`, check if any other miner already has that order in the current round state:

```csharp
// In ProcessUpdateValue, before line 247
if (currentRound.RealTimeMinersInformation.Values
    .Any(m => m.Pubkey != _processingBlockMinerPubkey && 
              m.FinalOrderOfNextRound == updateValueInput.SupposedOrderOfNextRound))
{
    // Reassign conflicting miner to next available order
    var availableOrder = FindNextAvailableOrder(currentRound, 
                                                updateValueInput.SupposedOrderOfNextRound);
    minerInRound.FinalOrderOfNextRound = availableOrder;
}
else
{
    minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
}
```

**2. Fix NextRoundMiningOrderValidationProvider:**

Correct the Distinct() call to operate on integer values:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Add this line
    .Distinct().Count();
```

**3. Add Uniqueness Validator for UpdateValue:**

Create a new validation provider to check FinalOrderOfNextRound uniqueness for UpdateValue transactions and register it in the validation pipeline.

**4. Add Invariant Assertion:**

Before committing round state in `TryToUpdateRoundInformation()`, assert that all `FinalOrderOfNextRound` values are unique among miners who have produced blocks.

**Test Cases:**
- Test scenario where two miners calculate identical `supposedOrderOfNextRound`
- Verify conflict resolution during state update
- Test with varying numbers of miners (3, 7, 17, 23)
- Verify uniqueness across multiple sequential UpdateValue transactions

### Proof of Concept

**Initial State:**
- Round N with 17 miners
- No miners have yet set their `FinalOrderOfNextRound` for round N+1
- Miners A and B both calculate signatures that hash to order 5: `GetAbsModulus(sigA, 17) = GetAbsModulus(sigB, 17) = 4`, thus `supposedOrderOfNextRound = 5`

**Step 1 - Miner A Generates Block N:**
1. Fetches `currentRound` from state (all FinalOrderOfNextRound = 0)
2. Calls `ApplyNormalConsensusData(pubkeyA, ...)`
3. Line 25-26 finds no conflicts (no one has order 5 yet)
4. Line 44 sets A's FinalOrderOfNextRound = 5 in local copy
5. `ExtractInformationToUpdateConsensus` creates input with TuneOrderInformation = {}
6. Block N is produced with A's UpdateValue transaction

**Step 2 - Miner B Generates Block N+1 (Before Block N Executes):**
1. Fetches `currentRound` from state (still all FinalOrderOfNextRound = 0, A's tx not executed yet)
2. Calls `ApplyNormalConsensusData(pubkeyB, ...)`
3. Line 25-26 finds no conflicts (A's change is in A's local copy only)
4. Line 44 sets B's FinalOrderOfNextRound = 5 in B's local copy
5. `ExtractInformationToUpdateConsensus` creates input with TuneOrderInformation = {}
6. Block N+1 is produced with B's UpdateValue transaction

**Step 3 - Transaction Execution:**
1. Block N processes: A's UpdateValue executes
   - Line 247 sets state: `currentRound.RealTimeMinersInformation[A].FinalOrderOfNextRound = 5`
   - State committed
2. Block N+1 processes: B's UpdateValue executes
   - Line 247 sets state: `currentRound.RealTimeMinersInformation[B].FinalOrderOfNextRound = 5`
   - State committed

**Expected Result:**
Only one miner should have FinalOrderOfNextRound = 5, with conflicts resolved automatically.

**Actual Result:**
Both Miner A and Miner B have `FinalOrderOfNextRound = 5` in the committed state, creating a duplicate mining order that breaks the consensus round integrity.

**Success Condition:**
Query the round state after both transactions execute: both miners will show `FinalOrderOfNextRound = 5`, violating the uniqueness invariant required for proper consensus operation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L25-40)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-87)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```
