### Title
Secret Revelation Bypass When Extra Block Producer is Removed from Next Round

### Summary
The `RevealSharedInValues` function at line 189 can be completely bypassed when the extra block producer triggering the NextRound transition is not included in the next round's miner list. This occurs when a miner is marked as banned/evil before producing the NextRound block, causing an early return that skips critical secret sharing revelation, compromising consensus security and random number unpredictability.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** In `GetConsensusExtraDataForNextRound`, there is a conditional check at line 180 that returns early if the current block producer (`pubkey`) is not present in the `nextRound` miner list. When this condition is true, the function returns immediately without calling `RevealSharedInValues(currentRound, pubkey)` at line 189.

**Exploitation Path:**

1. During `GenerateNextRoundInformation` (called at line 176), the Election contract is queried to identify banned miners via `GetMinerReplacementInformation`: [2](#0-1) 

2. This function checks `State.BannedPubkeyMap[pubkey]` for each current miner: [3](#0-2) 

3. Banned miners are removed from the local `currentRound` copy and replaced with alternatives: [4](#0-3) 

4. A miner can be marked as banned through:
   - Automatic detection during `ProcessNextRound` when they miss too many time slots: [5](#0-4) 
   - Manual governance action via `RemoveEvilNode`: [6](#0-5) 
   - Both set `State.BannedPubkeyMap[pubkey] = true`: [7](#0-6) 

5. The critical issue: The `RevealSharedInValues` function is responsible for reconstructing other miners' InValues using Shamir's Secret Sharing: [8](#0-7) 

6. Unlike the `UpdateValue` behavior which uses `UpdateLatestSecretPieces` to process application-layer revealed values: [9](#0-8) 

7. The `NextRound` behavior has NO fallback mechanism to apply revealed values from the application layer when `RevealSharedInValues` is skipped.

### Impact Explanation

**Consensus Security Compromise:**
- Miners' `PreviousInValue` fields remain unset (Hash.Empty or null) for the round when the bypass occurs
- These values are critical for generating unpredictable random hashes via the random number generation mechanism: [10](#0-9) 
- Without proper secret revelation, the consensus randomness becomes predictable or compromised
- Affects extra block producer selection for subsequent rounds, which relies on signatures derived from these values

**Affected Parties:**
- All network participants relying on consensus integrity
- Miners whose secrets should have been revealed but weren't
- Applications depending on verifiable randomness from the consensus layer

**Severity Justification:** HIGH
- Directly undermines a core security mechanism (secret sharing) in the consensus protocol
- Compromises random number generation unpredictability
- Can be triggered during normal operations (evil miner detection) or governance actions
- No automatic recovery - the secrets for that round are permanently lost

### Likelihood Explanation

**Attacker Capabilities:**
- Does not require attacker control - can occur naturally when the system functions as designed
- Governance with `EmergencyResponseOrganizationAddress` authority can trigger via `RemoveEvilNode`
- Automatic detection via `TryToDetectEvilMiners` when a miner misses `≥ TolerableMissedTimeSlotsCount` slots: [11](#0-10) 

**Attack Complexity:** LOW
- Timing window exists: a miner must be marked as banned after being designated as extra block producer but before the round transition completes
- Evil miner detection happens at round transitions, creating a natural window
- No special permissions required beyond normal consensus operations

**Feasibility Conditions:**
1. A miner is designated as extra block producer for the current round
2. The miner is marked as banned (either automatically or manually) before producing the NextRound block
3. The Consensus contract's current round state hasn't yet been updated to remove them
4. They produce the NextRound block while still in the current round's miner list

**Detection Constraints:**
- The bypass leaves no obvious on-chain evidence
- Missing `PreviousInValue` fields might be attributed to normal missed blocks
- Difficult to distinguish from legitimate scenarios

**Probability:** MEDIUM-HIGH
- Can occur during routine evil miner detection
- More likely during periods of network instability or when miners are missing slots
- Governance-triggered banning creates an intentional path

### Recommendation

**Immediate Fix:**
Remove the early return optimization at lines 180-187 and always call `RevealSharedInValues`, or modify the logic to apply revealed values from trigger information:

```csharp
private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
    string pubkey, AElfConsensusTriggerInformation triggerInformation)
{
    GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);
    
    nextRound.ExtraBlockProducerOfPreviousRound = pubkey;
    
    // ALWAYS reveal secrets regardless of miner status in next round
    RevealSharedInValues(currentRound, pubkey);
    
    // Apply application-layer revealed values as fallback
    if (triggerInformation.RevealedInValues.Any())
    {
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
        {
            if (currentRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (currentRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 currentRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
            {
                currentRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
            }
        }
    }
    
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
    // ... rest of the function
}
```

**Invariant Check to Add:**
- Assert that all active miners from the previous round have their `PreviousInValue` set (non-empty) in the new round data
- Add validation in `ProcessNextRound` to verify secret revelation occurred

**Test Cases:**
1. Test NextRound transition when extra block producer is marked as evil/banned before producing the block
2. Verify `PreviousInValue` fields are properly set even when miner is removed from next round
3. Test that application-layer `RevealedInValues` are applied as fallback
4. Regression test for normal NextRound flow with and without miner replacements

### Proof of Concept

**Initial State:**
- Round N with miners [A, B, C, D, E]
- Miner A is designated as extra block producer for Round N
- During Round N, Miner A misses time slots or governance marks them as evil

**Attack Steps:**
1. At Round N-1 to N transition, or during Round N, call `UpdateCandidateInformation` with `IsEvilNode = true` for Miner A (either automatically via `ProcessNextRound` or manually via `RemoveEvilNode`)
2. This sets `State.BannedPubkeyMap[A] = true` in the Election contract
3. Round N proceeds with A still in the Consensus contract's current round state as extra block producer
4. At end of Round N, Miner A produces the NextRound block
5. During block generation, `GetConsensusExtraDataForNextRound` is called
6. `GenerateNextRoundInformation` calls `GetMinerReplacementInformation` which identifies A as banned
7. A is removed from the local `currentRound` and replacement F is added
8. Check at line 180: `!nextRound.RealTimeMinersInformation.Keys.Contains(A)` evaluates to true
9. Early return occurs, `RevealSharedInValues` is never called

**Expected vs Actual Result:**
- **Expected:** All miners' secrets from Round N are revealed and `PreviousInValue` fields are set in the round data
- **Actual:** `RevealSharedInValues` is skipped, secrets are not revealed, `PreviousInValue` fields remain empty for miners in Round N

**Success Condition:**
Inspect the saved Round N+1 information and verify that miners' `PreviousInValue` fields are Hash.Empty or null, indicating the secret revelation was bypassed.

### Notes

The vulnerability is particularly concerning because:
1. It can occur without malicious intent during normal evil miner detection
2. The application layer's `SecretSharingService` computes revealed values correctly but they are ignored for NextRound behavior
3. There is an asymmetry between `UpdateValue` and `NextRound` behaviors in how they handle secret revelation
4. The comment "This miner was replaced by another miner in next round" suggests this was considered a normal case, but the security implications of skipping secret revelation were not addressed

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-306)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L337-338)
```csharp
                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-350)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```
