# Audit Report

## Title
Threshold Mismatch in Secret Sharing Causes Incorrect InValue Revelation When Miner List Decreases

## Summary
The on-chain `RevealSharedInValues()` function incorrectly uses the current round's miner count to calculate the Shamir's Secret Sharing decoding threshold, while secrets were encoded using the previous round's miner count. When the miner list decreases between rounds, this causes mathematically incorrect InValue reconstruction that compromises consensus randomness.

## Finding Description

The vulnerability stems from a threshold calculation mismatch between the off-chain secret encoding and on-chain secret decoding phases.

**Encoding Phase (Off-chain):**
When secrets are created off-chain, the threshold is correctly calculated from the previous round's miner count. [1](#0-0) 

This encodes secrets using Shamir's Secret Sharing with a polynomial of degree `threshold - 1`. [2](#0-1) 

**Decoding Phase (On-chain - INCORRECT):**
The on-chain `RevealSharedInValues` function retrieves the previous round but calculates the threshold using the **current** round's miner count instead. [3](#0-2) 

The function then uses this incorrect threshold to decode secrets from the previous round. [4](#0-3) 

**Comparison with Correct Off-chain Implementation:**
The off-chain equivalent correctly uses the previous round's miner count for threshold calculation. [5](#0-4) 

**Call Site:**
The function is called unconditionally during next round transitions without checking if the miner list changed. [6](#0-5) 

**Why Existing Protections Fail:**
The system skips creating NEW secrets when the miner list changes. [7](#0-6) 

However, this mitigation does NOT prevent revealing OLD secrets with an incorrect threshold. The validation checks only verify sufficient pieces exist but use the wrong miner count for comparison. [8](#0-7) 

**Trigger Scenarios:**
For side chains, when the main chain miner list changes, a new round is generated with a different number of miners. [9](#0-8) 

The maximum miners count can also be adjusted via governance, causing miner count decreases. [10](#0-9) 

## Impact Explanation

**Mathematical Incorrectness:**
Shamir's Secret Sharing requires exactly `threshold` points to reconstruct a polynomial of degree `threshold - 1`. The DecodeSecret function uses only the first `threshold` points from the provided list. [11](#0-10) 

When the threshold is too low (e.g., using 2 points to reconstruct a degree-5 polynomial originally requiring 6 points), the reconstructed secret is mathematically incorrect - producing an entirely different value rather than the original secret.

**Consensus Security Impact:**
InValues are fundamental to AEDPoS consensus security. They are used to generate signatures that chain rounds together, determine miner ordering, and produce verifiable randomness. Incorrect InValue revelation breaks these cryptographic guarantees, potentially causing:
- Consensus validation failures when subsequent blocks reference incorrect PreviousInValue fields
- Broken miner order calculations for future rounds
- Compromised consensus randomness affecting block producer selection
- Chain synchronization failures or forks when nodes compute different InValues

**Severity:** HIGH - This directly compromises a critical consensus security invariant that protects against manipulation of the block production process.

## Likelihood Explanation

**Automatic Trigger:**
This vulnerability triggers automatically during normal consensus operations without requiring any attacker action. When:
1. Round N-1 has M miners (secrets encoded with threshold M * 2/3)
2. Round N has M' < M miners (due to legitimate protocol operations)
3. Round N+1 transition occurs

The code will deterministically decode Round N-1's secrets using threshold M' * 2/3 instead of M * 2/3.

**Realistic Trigger Conditions:**
- **Side chains:** Main chain miner list updates are synchronized to side chains automatically
- **Governance changes:** MaximumMinersCount can be reduced via parliament proposals
- **Term transitions:** Miner counts can decrease between terms based on election results

**Probability:** CERTAIN - The bug executes whenever the miner count decreases between consecutive rounds, which is a supported and expected protocol operation.

## Recommendation

Fix the threshold calculation in `RevealSharedInValues` to use the previous round's miner count, matching the off-chain implementation:

```csharp
private void RevealSharedInValues(Round currentRound, string publicKey)
{
    Context.LogDebug(() => "About to reveal shared in values.");

    if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

    if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

    // FIX: Use previousRound's miner count instead of currentRound's
    var minersCount = previousRound.RealTimeMinersInformation.Count;
    var minimumCount = minersCount.Mul(2).Div(3);
    minimumCount = minimumCount == 0 ? 1 : minimumCount;

    foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
    {
        // ... rest of the function remains the same
    }
}
```

This ensures the decoding threshold matches the encoding threshold, preserving the mathematical correctness of Shamir's Secret Sharing reconstruction.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up Round N with 9 miners
2. Trigger secret sharing creation (threshold = 6)
3. Transition to Round N+1 with 3 miners (e.g., via side chain main list update)
4. Call GetConsensusExtraDataForNextRound to trigger RevealSharedInValues
5. Verify that DecodeSecret is called with threshold = 2 instead of 6
6. Show that the reconstructed InValue differs from the original encoded value

The test would need to mock the consensus contract state and simulate a miner list decrease scenario, then verify the incorrect threshold usage leads to wrong InValue computation.

### Citations

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L101-104)
```csharp
        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L146-148)
```csharp
        var round = secretSharingInformation.PreviousRound;
        var minersCount = round.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L14-25)
```csharp
        public static List<byte[]> EncodeSecret(byte[] secretMessage, int threshold, int totalParts)
        {
            // Polynomial construction.
            var coefficients = new BigInteger[threshold];
            // Set p(0) = secret message.
            coefficients[0] = secretMessage.ToBigInteger();
            for (var i = 1; i < threshold; i++)
            {
                var foo = new byte[32];
                Array.Copy(HashHelper.ComputeFrom(Guid.NewGuid().ToByteArray()).ToArray(), foo, 32);
                coefficients[i] = BigInteger.Abs(new BigInteger(foo));
            }
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-48)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L19-23)
```csharp
        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-36)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L386-390)
```csharp
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
```
