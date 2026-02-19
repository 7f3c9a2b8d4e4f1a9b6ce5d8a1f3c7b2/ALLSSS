# Audit Report

## Title
Replaced Miner Can Skip Secret Revelation While Producing Next-Round Trigger Block

## Summary
A miner being replaced in the next round can produce the extra block to trigger round transition but skip the `RevealSharedInValues()` call due to an early return condition. This breaks the secret sharing security mechanism designed to reconstruct InValues through Shamir's Secret Sharing, forcing affected miners to fall back on deterministic, predictable values that compromise consensus randomness.

## Finding Description

The vulnerability exists in the `GetConsensusExtraDataForNextRound()` method where an early return condition prevents secret revelation for replaced miners. [1](#0-0) 

**How the vulnerability manifests:**

1. **Replaced miners can still produce next-round blocks**: The `PreCheck()` validation only verifies the miner is in the current OR previous round, not the next round. [2](#0-1) 

2. **Secret revelation is bypassed**: When a miner is not in `nextRound.RealTimeMinersInformation.Keys`, the function returns early without calling `RevealSharedInValues()` at line 189. This function is responsible for reconstructing miners' InValues using Shamir's Secret Sharing. [3](#0-2) 

3. **Deterministic fallback values compromise randomness**: When miners produce blocks without their `PreviousInValue` properly set, they fall back to a predictable fake value computed as `HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()))`. [4](#0-3) 

4. **Miner replacement can occur mid-term**: The system supports dynamic miner replacement when evil miners are detected, where they are removed from the miner list and replaced with alternative candidates. [5](#0-4) 

The secret sharing mechanism is a critical security feature designed to ensure that InValues remain reconstructable even when individual miners go offline or refuse to cooperate. By skipping this reconstruction, the protocol falls back on weaker security guarantees.

## Impact Explanation

**Consensus Security Degradation**: The AEDPoS secret sharing mechanism ensures miners' InValues can be reconstructed via Shamir's Secret Sharing threshold cryptography. By skipping `RevealSharedInValues()`, this security guarantee is broken for the transition into the next round.

**Randomness Compromise**: The signature calculation used for miner ordering depends on `PreviousInValue`. [6](#0-5)  When these values become predictable (based only on public key and block height), an attacker can predict or potentially influence miner ordering in subsequent rounds.

**Protocol Invariant Violation**: The system design assumes InValues are either explicitly revealed or reconstructable through secret sharing. The deterministic fallback breaks this assumption and weakens the overall security model.

**Affected Parties**:
- Miners who participated in Round N but didn't explicitly reveal their InValue
- The consensus mechanism's randomness guarantees
- Future round scheduling and miner order determination

## Likelihood Explanation

**Attacker Capabilities**: The attacker must be:
- A current miner in Round N
- The designated extra block producer for that round  
- Scheduled for replacement in Round N+1 (due to poor performance, governance decision, or being marked as evil)

**Attack Complexity**: Low to Medium
- Miner replacement occurs naturally through governance and performance monitoring
- No complex transaction crafting required - the vulnerability triggers through normal block production
- If a replaced miner is the extra block producer, the opportunity exists automatically

**Feasibility Conditions**:
- Secret sharing must be enabled in the configuration
- The replaced miner must be assigned as the extra block producer
- At least some miners need InValue reconstruction (common when miners experience network issues)

**Probability**: Medium - In active networks with regular miner list changes, a replaced miner being the extra block producer will occur periodically. The replaced miner could exploit this as a griefing attack or it could happen unintentionally.

## Recommendation

Modify `GetConsensusExtraDataForNextRound()` to call `RevealSharedInValues()` even when the current miner is not included in the next round's miner list. The revelation process should depend on whether the miner is in the CURRENT round (which they are, since they passed PreCheck), not whether they will be in the NEXT round.

```csharp
private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
    string pubkey, AElfConsensusTriggerInformation triggerInformation)
{
    GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
    
    nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
    
    // Always reveal shared InValues if the miner is in current round
    // This ensures proper secret reconstruction regardless of next round membership
    RevealSharedInValues(currentRound, pubkey);
    
    if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
    {
        // This miner was replaced by another miner in next round.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
    
    nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
    Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
    nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
    nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
        .Add(Context.CurrentBlockTime);
    
    return new AElfConsensusHeaderInformation
    {
        SenderPubkey = ByteStringHelper.FromHexString(pubkey),
        Round = nextRound,
        Behaviour = triggerInformation.Behaviour
    };
}
```

## Proof of Concept

A test demonstrating the vulnerability would involve:
1. Setting up a network with multiple miners and secret sharing enabled
2. Marking one miner as "evil" to trigger replacement
3. Ensuring that evil miner is the extra block producer
4. Monitoring the extra block production to confirm `RevealSharedInValues()` is skipped
5. Verifying that subsequent blocks use deterministic fallback InValues instead of properly reconstructed values

The test would validate that miners in the next round have `PreviousInValue` set to the predictable `HashHelper.ComputeFrom(pubkey.Append(blockHeight))` pattern rather than properly revealed values from secret sharing reconstruction.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L94-108)
```csharp
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L180-187)
```csharp
        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-54)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-342)
```csharp
            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```
