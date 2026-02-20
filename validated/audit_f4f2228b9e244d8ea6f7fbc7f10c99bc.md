# Audit Report

## Title
Dictionary Key Mismatch in RecoverFromUpdateValue Causes Consensus Validation DoS During Miner Replacement

## Summary
The `RecoverFromUpdateValue` function in the AEDPoS consensus contract contains a critical bug where it iterates over all miners in the provided round and directly accesses the current round's `RealTimeMinersInformation` dictionary without checking if keys exist. This causes a `KeyNotFoundException` during miner replacement scenarios, resulting in consensus validation failure before the system's designed miner replacement validation logic can execute.

## Finding Description

The vulnerability exists in the `RecoverFromUpdateValue` method where unsafe dictionary access occurs. The function checks if the sender's pubkey exists in both rounds [1](#0-0) , but then iterates over ALL miners in the provided round and directly accesses `RealTimeMinersInformation[information.Key]` without verifying each key exists [2](#0-1) .

**Root Cause:** This violates C# dictionary safety and throws `KeyNotFoundException` when a key from the provided round doesn't exist in the current round.

**Why This Occurs:** During miner replacement via `RecordCandidateReplacement`, the current round's miner list is modified by removing the old pubkey and adding a new one [3](#0-2) . When a block produced before the replacement (containing the old miner list) is validated after the replacement, the provided round contains miners not in the current round.

**Validation Call Paths:**

The method is invoked during before-execution validation [4](#0-3)  and after-execution validation [5](#0-4) .

**Unreachable Protection:** The system has miner replacement validation logic designed to handle this scenario [6](#0-5) , but it's unreachable because the exception is thrown before this validation can execute.

**Pattern Inconsistency:** The codebase consistently uses `ContainsKey` checks before accessing `RealTimeMinersInformation` [7](#0-6)  and [8](#0-7) . The missing check in `RecoverFromUpdateValue` breaks this defensive pattern.

## Impact Explanation

**High Severity Consensus DoS:**
- Blocks containing consensus data from before miner replacement fail validation with unhandled exceptions rather than being properly validated or gracefully rejected
- Consensus validation becomes unreliable during miner replacement transitions as nodes with different timing see different round states
- The designed miner replacement validation mechanism that would properly handle these cases never executes
- Network disruption during normal protocol operations (miner replacement is a legitimate feature)

**Affected Operations:**
- Block validation during miner replacement events executed via `ReplaceCandidatePubkey` [9](#0-8) 
- All nodes attempting to validate blocks during these state transitions

**Security Guarantees Broken:**
- Consensus validation should handle legitimate state transitions gracefully
- Blocks following protocol rules should be validated correctly or rejected with proper error handling
- Miner replacement should not cause validation failures via exceptions

## Likelihood Explanation

**High Likelihood - Normal Operations:**

Miner replacement is a standard protocol feature executed when candidate admins update public keys. The vulnerability triggers during legitimate operations without malicious intent.

**Triggering Scenario:**
1. At time T1, miner M1 is active with miner list [M1, M2, M3]
2. Candidate admin calls `ReplaceCandidatePubkey` to replace M1 with M4
3. Node A produced a block at T1 with consensus data containing [M1, M2, M3]
4. Node B processes the replacement, updating its current round to [M4, M2, M3] [10](#0-9) 
5. Node B receives Node A's block and validates it
6. `RecoverFromUpdateValue` iterates over [M1, M2, M3] from the block
7. Dictionary access for M1 fails because M1 was removed from the current round
8. `KeyNotFoundException` thrown, validation fails

**Preconditions:** Only normal protocol operations - miner replacement and block propagation timing differences inherent in distributed systems.

## Recommendation

Add `ContainsKey` checks before accessing the dictionary in the loop. The fixed code should follow the defensive pattern used elsewhere in the codebase:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    if (!RealTimeMinersInformation.ContainsKey(information.Key))
        continue;
        
    RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
        information.Value.SupposedOrderOfNextRound;
    RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
        information.Value.FinalOrderOfNextRound;
    RealTimeMinersInformation[information.Key].PreviousInValue =
        information.Value.PreviousInValue;
}
```

This allows the method to gracefully skip miners that don't exist in the current round, allowing the proper miner replacement validation logic to execute afterward.

## Proof of Concept

A valid test would need to:
1. Set up a consensus round with miners [M1, M2, M3]
2. Call `RecordCandidateReplacement` to replace M1 with M4
3. Create a block with consensus data containing the old miner list [M1, M2, M3]
4. Call `ValidateConsensusBeforeExecution` or `ValidateConsensusAfterExecution` with this block
5. Observe the `KeyNotFoundException` when `RecoverFromUpdateValue` attempts to access `RealTimeMinersInformation[M1]`

The test would demonstrate that legitimate blocks fail validation during normal miner replacement operations due to this unsafe dictionary access pattern.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L136-146)
```csharp
        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-92)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L103-123)
```csharp
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L86-87)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L159-161)
```csharp
        return RealTimeMinersInformation.ContainsKey(publicKey)
            ? RealTimeMinersInformation[publicKey].ExpectedMiningTime
            : new Timestamp { Seconds = long.MaxValue };
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```
