# Audit Report

## Title
Secret Sharing Manipulation Through Selective Decrypted Piece Withholding

## Summary
The AEDPoS consensus contract contains a critical threshold mismatch in its secret sharing implementation. The `RevealSharedInValues()` function requires all miners (100%) to provide decrypted pieces before revealing InValues, despite Shamir's Secret Sharing only needing a 2/3 threshold. A malicious miner can exploit this by selectively withholding decrypted pieces to force targeted miners into using predictable fake values, thereby manipulating consensus randomness and mining order for subsequent rounds.

## Finding Description

The vulnerability exists in the secret sharing revelation logic where a threshold mismatch allows consensus manipulation.

The `RevealSharedInValues()` function enforces a 100% participation requirement before attempting InValue reconstruction: [1](#0-0) 

However, the cryptographic scheme only requires a 2/3 threshold (`minimumCount`) for successful secret reconstruction: [2](#0-1) [3](#0-2) 

During the `UpdateValue` consensus behavior, miners provide their decrypted pieces through `UpdateValueInput`. The `PerformSecretSharing` function processes these pieces without any validation: [4](#0-3) 

No validation mechanism exists to ensure miners provide all decrypted pieces they possess. A malicious miner can simply omit certain pubkeys from their `DecryptedPieces` map.

When InValue revelation fails due to insufficient decrypted pieces, miners without a valid `PreviousInValue` must use a deterministic fake value: [5](#0-4) 

This fake value is then used in signature calculation, which determines the next round's mining order: [6](#0-5) [7](#0-6) 

The mining order is calculated using: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`, creating a direct path from manipulated signatures to manipulated mining positions.

## Impact Explanation

**Consensus Randomness Manipulation**: An attacker can selectively prevent specific miners' InValue revelation, forcing them to use predictable fake values instead of their actual InValues. Since the signature is computed by XORing the InValue with all previous round signatures, and mining order is calculated from this signature, the attacker can influence which miners receive favorable or unfavorable mining positions.

**Concrete Attack Scenario**:
1. Attacker decrypts all other miners' encrypted pieces off-chain (possible since pieces are public on-chain)
2. For each target miner, attacker calculates resulting mining orders under two scenarios:
   - Scenario A: Provide the decrypted piece (allowing InValue revelation)
   - Scenario B: Withhold the decrypted piece (forcing fake value usage)
3. Attacker selectively withholds pieces where scenario B produces more favorable mining order
4. This manipulation increases attacker's mining frequency, enables consecutive block production, or disadvantages competing miners

**Severity Justification**: The cryptographic protocol is designed for 2/3 Byzantine fault tolerance, but the implementation requires 100% honest participation. This allows any single malicious miner to manipulate consensus without detection or penalty. Mining order directly affects block rewards and transaction fee capture, creating economic incentives for exploitation.

## Likelihood Explanation

**Attacker Capabilities**: A single malicious miner in the active miner set can execute this attack. The attacker only needs to:
1. Run standard consensus node software
2. Selectively omit certain pubkeys from their `DecryptedPieces` map when calling `UpdateValue`

**Attack Complexity**: Trivial. The encrypted pieces are stored on-chain in the round information, allowing any miner to decrypt them. The attacker simply filters which decrypted pieces to include in their `UpdateValueInput` before submitting the transaction.

**Detection/Penalties**: None. The validation provider explicitly allows `Hash.Empty` as a valid `PreviousInValue`: [8](#0-7) 

The system cannot distinguish between an honest miner who failed to decrypt due to technical issues versus a malicious miner intentionally withholding decryptions.

**Economic Rationality**: Mining order determines when miners produce blocks within a round. Earlier positions typically capture more transactions and fees. The attack cost is zero (just omitting data), while the benefit is improved mining position and increased rewards.

## Recommendation

Modify `RevealSharedInValues()` to use the cryptographic threshold (`minimumCount`) instead of requiring all miners:

```csharp
// Change line 36 from:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

// To:
if (anotherMinerInPreviousRound.DecryptedPieces.Count < minimumCount) continue;
```

This aligns the implementation with the underlying Shamir's Secret Sharing scheme's 2/3 threshold, preventing a single miner from blocking InValue revelation.

Additionally, consider implementing:
1. Penalty mechanism for miners who consistently fail to provide decrypted pieces
2. Reputation tracking for decrypted piece provision
3. Alternative randomness source that doesn't depend on complete participation

## Proof of Concept

```csharp
[Fact]
public async Task SelectiveDecryptedPieceWithholding_ManipulatesMiningOrder()
{
    // Setup: Initialize consensus with 7 miners
    var miners = GenerateMinerList(7); // 2/3 threshold = 5 miners
    await InitializeConsensus(miners);
    
    // Round 1: All miners produce blocks normally
    await CompleteRound(miners);
    
    // Round 2: Malicious miner (miners[0]) withholds decrypted pieces for target (miners[1])
    var maliciousMiner = miners[0];
    var targetMiner = miners[1];
    
    // Attacker provides decrypted pieces for all EXCEPT target
    var selectiveDecryptedPieces = new Dictionary<string, ByteString>();
    foreach (var miner in miners)
    {
        if (miner != targetMiner) // Intentionally omit target
        {
            selectiveDecryptedPieces[miner] = DecryptPiece(maliciousMiner, miner);
        }
    }
    
    // Submit UpdateValue with selective pieces
    await UpdateValueWithSelectivePieces(maliciousMiner, selectiveDecryptedPieces);
    
    // Complete round with other miners providing pieces normally
    for (int i = 1; i < miners.Count; i++)
    {
        await UpdateValueNormally(miners[i]);
    }
    
    // Round 3: Verify target miner uses fake value
    await ProduceBlock(targetMiner);
    var targetMinerInfo = await GetMinerInformation(targetMiner);
    
    // Assert: Target miner's PreviousInValue is Hash.Empty or predictable fake
    Assert.True(
        targetMinerInfo.PreviousInValue == Hash.Empty ||
        targetMinerInfo.PreviousInValue == HashHelper.ComputeFrom(targetMiner)
    );
    
    // Assert: Target miner's signature is predictable (not random)
    var predictedSignature = CalculateFakeSignature(targetMiner);
    Assert.Equal(predictedSignature, targetMinerInfo.Signature);
    
    // Assert: Mining order is manipulated based on fake signature
    var miningOrder = GetAbsModulus(predictedSignature.ToInt64(), miners.Count) + 1;
    Assert.Equal(miningOrder, targetMinerInfo.SupposedOrderOfNextRound);
    
    // Demonstrate impact: Attacker benefits from changed mining order
    var attackerExpectedOrder = await GetExpectedMiningOrder(maliciousMiner);
    Assert.True(attackerExpectedOrder < 3); // Attacker gets favorable early position
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L22-23)
```csharp
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L36-36)
```csharp
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-50)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-297)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);

        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```
