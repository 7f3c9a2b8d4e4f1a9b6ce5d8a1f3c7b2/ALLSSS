# Audit Report

## Title
Secret Sharing Mechanism Completely Broken in NextRound Transitions - Revealed InValues Lost

## Summary
During NextRound consensus transitions, the `RevealSharedInValues()` function computes revealed InValues for miners who missed blocks using secret sharing reconstruction. However, these critical values are written to `currentRound` which is immediately discarded, while `nextRound` (which lacks these values) is persisted to state. This completely breaks the secret sharing mechanism's purpose of maintaining consensus integrity when miners fail to produce blocks.

## Finding Description

The vulnerability exists in the `GetConsensusExtraDataForNextRound()` method. The function first generates `nextRound` from `currentRound`, then calls `RevealSharedInValues(currentRound, pubkey)` to reconstruct missing InValues through secret sharing. [1](#0-0) 

The `RevealSharedInValues` function writes reconstructed InValues to `currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue`. [2](#0-1) 

However, the function returns `nextRound`, not `currentRound`, so these modifications are never persisted. [3](#0-2) 

When `ProcessNextRound` is called, only `nextRound` is persisted to state via `AddRoundInformation(nextRound)`. [4](#0-3) 

The root cause is that `GenerateNextRoundInformation` only copies `Pubkey`, `Order`, `ExpectedMiningTime`, `ProducedBlocks`, and `MissedTimeSlots` from currentRound to nextRound. The `PreviousInValue` field is completely omitted. [5](#0-4) 

This breaks the documented security guarantee. When a miner who missed blocks tries to produce blocks, the system attempts to retrieve their reconstructed InValue from `currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue`. The comment explicitly states this field contains "previous in value recovered by other miners". [6](#0-5) 

In contrast, the UpdateValue flow works correctly because revealed InValues are passed via `triggerInformation.RevealedInValues` and written to the persisted `updatedRound`. [7](#0-6) 

NextRound triggers do not populate this field - they only include basic information without RevealedInValues. [8](#0-7) 

## Impact Explanation

**Consensus Integrity Breakdown**: The secret sharing mechanism is designed to allow consensus to continue even when miners miss their time slots. By sharing encrypted pieces of their InValues, other miners can reconstruct these values and maintain the consensus randomness chain.

Without properly persisted PreviousInValues:
1. Miners who missed blocks in round N have no reconstructed InValue in round N+1
2. When they attempt to produce blocks, they cannot retrieve the expected PreviousInValue
3. The system falls back to using fake/computed InValues, breaking the consensus randomness chain
4. The entire secret sharing security mechanism is rendered useless for NextRound transitions

**Affected Parties**: All miners who fail to produce blocks in any round are unable to properly participate in subsequent consensus operations during NextRound transitions, undermining consensus unpredictability and fairness.

**Severity**: HIGH - Complete failure of a critical consensus security mechanism affecting all miners during normal round transitions.

## Likelihood Explanation

**Occurrence**: This bug triggers automatically during every NextRound transition when secret sharing is enabled. It is not an exploit requiring attacker action, but a design flaw in the normal protocol operation.

**Preconditions**:
- Secret sharing enabled (checked via `IsSecretSharingEnabled()`)
- NextRound transition occurs (happens regularly during normal operation when rounds terminate)
- At least one miner failed to produce blocks in the previous round

**Frequency**: CERTAIN - NextRound transitions occur automatically during normal consensus operation whenever time slots pass and the round needs to transition (excluding term changes). This is standard operation for AEDPoS consensus.

The issue is completely masked in UpdateValue flows (which use a different code path with `triggerInformation.RevealedInValues`), but NextRound transitions have no such mechanism, causing guaranteed data loss every time.

## Recommendation

**Fix 1: Copy PreviousInValue in GenerateNextRoundInformation**

Modify the `GenerateNextRoundInformation` method to copy the `PreviousInValue` field when creating miner information for the next round. In `Round_Generation.cs`, update the miner creation logic to include:

```csharp
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    PreviousInValue = minerInRound.PreviousInValue  // ADD THIS LINE
};
```

**Fix 2: Alternative - Call RevealSharedInValues on nextRound**

Alternatively, change the call order in `GetConsensusExtraDataForNextRound` to call `RevealSharedInValues(nextRound, pubkey)` instead of `RevealSharedInValues(currentRound, pubkey)` so the revealed values are written to the object that will be persisted.

**Fix 3: Most Robust - Populate RevealedInValues in NextRound Trigger**

The most robust solution would be to populate `RevealedInValues` in the trigger information for NextRound behaviour (similar to UpdateValue), and then write these values to `nextRound` before returning it. This would align NextRound with the UpdateValue flow and ensure consistency across consensus behaviours.

## Proof of Concept

Due to the complexity of the AEDPoS consensus system requiring a full blockchain context with multiple miners, secret sharing setup, and round transitions, a complete PoC would require extensive test infrastructure. However, the vulnerability can be demonstrated by:

1. Enable secret sharing in configuration
2. Configure multiple miners in a consensus round
3. Have one or more miners miss their blocks (fail to produce during their time slot)
4. Trigger a NextRound transition
5. Observe that `RevealSharedInValues` writes to `currentRound.RealTimeMinersInformation[miner].PreviousInValue`
6. Observe that `nextRound` (generated before the call) does not have these values
7. Verify that only `nextRound` is persisted via `AddRoundInformation`
8. Confirm that miners who missed blocks cannot retrieve their reconstructed InValue in the next round

The vulnerability is evident from static code analysis: the call to `RevealSharedInValues(currentRound, pubkey)` occurs AFTER `nextRound` generation, modifies `currentRound`, but `nextRound` is what gets returned and persisted.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L176-189)
```csharp
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L198-203)
```csharp
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-53)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-200)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
                }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L119-124)
```csharp
        return new AElfConsensusTriggerInformation
        {
            Pubkey = Pubkey,
            Behaviour = hint.Behaviour,
            RandomNumber = ByteString.CopyFrom(randomProof)
        }.ToBytesValue();
```
