# Audit Report

## Title
Missing Dictionary Key Validation in RecoverFromUpdateValue Causes DOS Through Block Rejection During Miner Replacements

## Summary
The `RecoverFromUpdateValue` method in the AEDPoS consensus contract accesses dictionary entries without validating key existence, causing `KeyNotFoundException` exceptions when miner lists change mid-round via `RecordCandidateReplacement`. This results in block rejection for honest miners during legitimate miner replacement operations, causing temporary consensus stalls.

## Finding Description

The vulnerability exists in the consensus validation flow where round information recovery fails due to missing dictionary key validation.

In `RecoverFromUpdateValue`, the foreach loop iterates through `providedRound.RealTimeMinersInformation` and directly accesses `baseRound.RealTimeMinersInformation[information.Key]` without checking if the key exists: [1](#0-0) 

While lines 10-12 validate that the sender's pubkey exists in both rounds, no such check exists for OTHER miners in the round: [2](#0-1) 

This method is invoked during validation when processing UpdateValue behavior: [3](#0-2) 

The root cause is that miner lists can change mid-round via `RecordCandidateReplacement`, which removes old miners and adds new ones to `RealTimeMinersInformation`: [4](#0-3) 

This method is called by the Election Contract during legitimate candidate replacements: [5](#0-4) 

When an exception occurs during validation, the Executive catches it and sets the trace status to SystemError: [6](#0-5) 

The read-only method stub returns null/default when the trace is not successful: [7](#0-6) 

This causes the consensus service to return false for validation: [8](#0-7) 

Finally, the block is rejected by the validation provider: [9](#0-8) 

## Impact Explanation

**Operational Impact - Consensus DOS:**

When `RecordCandidateReplacement` executes during a legitimate miner replacement operation, a timing window opens where:

1. Honest miners who created blocks before the replacement have those blocks rejected during validation
2. Blocks contain `providedRound` with the old miner list (e.g., miners [A,B,C])
3. Validation reads `baseRound` from state with the updated miner list (e.g., miners [A,B,D] after C was replaced by D)
4. `RecoverFromUpdateValue` throws `KeyNotFoundException` when trying to access the removed miner's data in the dictionary
5. Block is rejected as if it were invalid, even though it was created by an honest miner before the replacement

**Severity: Medium**
- Affects honest miners during legitimate miner replacements
- Can cause temporary consensus slowdown if multiple miners' blocks are rejected
- Does not result in permanent DOS as miners will eventually create new blocks with updated state
- No fund loss, but chain availability/liveness is temporarily impacted
- System self-recovers once miners sync to the new miner list

## Likelihood Explanation

**Likelihood: Medium**

**Trigger Requirements:**
- Miner replacement operation via `RecordCandidateReplacement` (legitimate protocol operation)
- Requires only candidate admin privileges, which is by design
- No attacker required - triggered by normal protocol operations

**Preconditions:**
1. Miner replacement occurs via `ReplaceCandidatePubkey` → `RecordCandidateReplacement`
2. Honest miner creates UpdateValue block before replacement executes
3. Block propagates through network and arrives for validation after replacement has executed
4. Timing window exists between block creation and block validation

**Execution Practicality:**
- Miner replacements are legitimate and expected protocol operations
- The timing window exists during every miner replacement event
- Multiple miners may be affected simultaneously if they created blocks before the replacement
- More likely during periods of miner turnover or when addressing misbehaving miners
- Network latency and block propagation delays increase probability

**Operational Constraints:**
- Temporary impact - system recovers automatically
- Detection is straightforward via `SystemError` status in transaction traces
- Does not require any malicious actor

## Recommendation

Add key existence validation before accessing the dictionary in the foreach loop. The fix should check if each key from `providedRound` exists in `baseRound` before attempting dictionary access:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    // Add key existence check
    if (!RealTimeMinersInformation.ContainsKey(information.Key))
        continue; // Skip miners that don't exist in base round
        
    RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
        information.Value.SupposedOrderOfNextRound;
    RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
        information.Value.FinalOrderOfNextRound;
    RealTimeMinersInformation[information.Key].PreviousInValue =
        information.Value.PreviousInValue;
}
```

Alternatively, handle miner replacements more gracefully by tracking replacement events and allowing blocks created with the pre-replacement miner list to validate successfully within a grace period.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Initialize a round with miners [A, B, C]
2. Miner A creates an UpdateValue block containing round information with miners [A, B, C]
3. Execute `ReplaceCandidatePubkey` to replace miner C with miner D
4. Attempt to validate the block created in step 2
5. Observe that `ValidateConsensusBeforeExecution` returns false/null due to `KeyNotFoundException`
6. Block is rejected despite being created by honest miner A

The test would verify:
- `RecordCandidateReplacement` successfully modifies the miner list in state
- `RecoverFromUpdateValue` throws exception when accessing removed miner key
- Block validation fails and returns false
- Honest miner's block is rejected

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L140-143)
```csharp
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** src/AElf.Runtime.CSharp/Executive.cs (L148-152)
```csharp
        catch (Exception ex)
        {
            CurrentTransactionContext.Trace.ExecutionStatus = ExecutionStatus.SystemError;
            CurrentTransactionContext.Trace.Error += ex + "\n";
        }
```

**File:** src/AElf.Kernel.SmartContract/Application/ReadOnlyMethodStubFactory.cs (L50-52)
```csharp
            return trace.IsSuccessful()
                ? method.ResponseMarshaller.Deserializer(trace.ReturnValue.ToByteArray())
                : default;
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L132-136)
```csharp
        if (validationResult == null)
        {
            Logger.LogDebug("Validation of consensus failed before execution.");
            return false;
        }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L70-75)
```csharp
        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
        if (!isValid) return false;
```
