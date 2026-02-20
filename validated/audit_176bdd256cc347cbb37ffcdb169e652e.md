# Audit Report

## Title
Threshold Mismatch in Secret Sharing Reconstruction on Side Chains Leads to Consensus State Corruption

## Summary
The `RevealSharedInValues` function in the AEDPoS consensus contract incorrectly calculates the Shamir secret sharing threshold using the current round's miner count instead of the previous round's miner count. When side chains update their miner list from the main chain, this causes a threshold mismatch between secret encoding and decoding, resulting in incorrect secret reconstruction and corrupted consensus state.

## Finding Description

The vulnerability exists in the on-chain secret reconstruction logic that uses an inconsistent threshold compared to the encoding phase. [1](#0-0) 

The function retrieves both `currentRound` and `previousRound`, but uses the **current round's miner count** to calculate the decoding threshold while iterating through and decoding secrets from the **previous round**. [2](#0-1) 

This contrasts with the off-chain implementation, which correctly uses the **same round's miner count** for decoding secrets from that round. [3](#0-2) 

When miners encode their secrets for a given round, they use the **previous round's miner count** as the threshold. [4](#0-3) 

**Exploitation Path:**

Side chains receive miner list updates from the main chain through the cross-chain consensus mechanism. [5](#0-4) 

When the main chain's miner list changes, the side chain's round generation logic detects this and creates a new round with the updated miner count. [6](#0-5) 

During the next round transition, `RevealSharedInValues` is called unconditionally as part of extra block generation. [7](#0-6) 

**Concrete Scenario:**
1. Side chain rounds K-2, K-1, K all operate with 7 miners (threshold = 4)
2. Main chain updates its miner list to 10 miners
3. Side chain syncs via `UpdateInformationFromCrossChain`
4. Round K+1 is generated with 10 miners (threshold = 6)
5. `RevealSharedInValues(round K, pubkey)` is called
6. Function attempts to decode secrets from round K-1 using threshold = 6
7. But secrets in round K-1 were encoded with threshold = 4
8. **Result**: Wrong secret reconstructed due to threshold mismatch

## Impact Explanation

**Consensus State Corruption:**

Shamir's secret sharing relies on Lagrange interpolation, which requires the same threshold for both encoding and decoding. [8](#0-7) 

When the threshold parameter differs between encoding and decoding, the Lagrange interpolation formula reconstructs an entirely different polynomial, yielding an incorrect secret value. This incorrectly reconstructed value is then stored directly in the consensus state as `PreviousInValue`. [9](#0-8) 

The corrupted `PreviousInValue` is subsequently used in signature calculations that form the basis of consensus randomness. [10](#0-9) 

This breaks the fundamental consensus invariant that revealed in-values must correspond to the actual commitments made by miners in previous rounds. The secret sharing mechanism, which is critical for recovering missed blocks and maintaining consensus integrity, becomes compromised.

**Affected Parties:**

All side chains in the AElf ecosystem are vulnerable during and after main chain miner list updates, which are regular occurrences in the protocol's governance and consensus operations.

## Likelihood Explanation

**High Likelihood - Automatic Trigger:**

This vulnerability triggers automatically during normal consensus operations without any attacker involvement:

1. **Reachable Entry Point**: The vulnerable code path is part of the standard consensus flow during extra block production, which is a regular occurrence.

2. **Feasible Preconditions**: 
   - Side chain must be operational (standard configuration)
   - Main chain undergoes a miner list update (regular governance event)
   - Side chain syncs the update via cross-chain indexing (automatic process)

3. **No Protection**: Unlike the off-chain implementation which skips secret sharing when the miner list changes [11](#0-10) , the on-chain `RevealSharedInValues` has no such check and executes unconditionally.

The vulnerability manifests during the first round transition after a side chain adopts a new miner count from the main chain, requiring no special conditions or malicious actors.

## Recommendation

Add a check to skip secret revelation when the miner list has changed, matching the off-chain behavior:

```csharp
private void RevealSharedInValues(Round currentRound, string publicKey)
{
    Context.LogDebug(() => "About to reveal shared in values.");

    if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;
    
    // Skip revelation if miner list just changed
    if (currentRound.IsMinerListJustChanged) return;

    if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

    var minersCount = previousRound.RealTimeMinersInformation.Count;  // Use previousRound count
    var minimumCount = minersCount.Mul(2).Div(3);
    minimumCount = minimumCount == 0 ? 1 : minimumCount;

    foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
    {
        // ... rest of the logic
    }
}
```

Alternatively, use the previous round's miner count for the threshold calculation to match the encoding threshold, though skipping revelation during miner list changes is the safer approach that mirrors the off-chain implementation.

## Proof of Concept

The proof of concept would demonstrate:
1. A side chain with initial miner count N
2. Main chain updating to miner count M (where M ≠ N)
3. Side chain syncing the update
4. Next round generation triggering `RevealSharedInValues`
5. Verification that the decoded secret differs from the original encoded value due to threshold mismatch
6. Corrupted `PreviousInValue` stored in consensus state

The vulnerability is structural and evident from the code analysis above, where the threshold calculation source (`currentRound`) and the secret source (`previousRound`) are mismatched, violating the fundamental requirement of Shamir's secret sharing scheme.

---

**Notes:**
- The vulnerability is specifically triggered when miner list sizes change between rounds, which occurs regularly during main chain governance events
- The off-chain code correctly avoids this issue by using consistent round counts and skipping secret sharing during miner list changes
- The impact extends to all operations that depend on consensus randomness integrity
- No cryptographic primitives are broken - this is a logic error in threshold parameter selection

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L19-52)
```csharp
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
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L146-176)
```csharp
        var round = secretSharingInformation.PreviousRound;
        var minersCount = round.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

        var revealedInValues = new Dictionary<string, Hash>();

        foreach (var pair in round.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == selfPubkey) continue;

            var pubkey = pair.Key;
            var minerInRound = pair.Value;

            if (minerInRound.EncryptedPieces.Count < minimumCount) continue;
            if (minerInRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = minerInRound.DecryptedPieces.Select((t, i) =>
                    round.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    minerInRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = minerInRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-63)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-294)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L72-92)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
            if (triggerInformation.PreviousInValue != null &&
                triggerInformation.PreviousInValue != Hash.Empty)
            {
                Context.LogDebug(
                    () => $"Previous in value in trigger information: {triggerInformation.PreviousInValue}");
                // Self check.
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-203)
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
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-65)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
                var denominator = BigInteger.One;
                for (var j = 0; j < threshold; j++)
                {
                    if (i == j) continue;

                    (numerator, denominator) =
                        MultiplyRational(numerator, denominator, orders[j], orders[j] - orders[i]);
                }

                result += RationalToWhole(numerator, denominator);
                result %= SecretSharingConsts.FieldPrime;
            }

            return result.ToBytesArray();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```
