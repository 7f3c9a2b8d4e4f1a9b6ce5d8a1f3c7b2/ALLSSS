# Audit Report

## Title
Unvalidated Secret Reconstruction in RevealSharedInValues Allows Consensus State Corruption

## Summary
The `RevealSharedInValues` function reconstructs miners' InValues from DecryptedPieces without validating that the reconstructed secret matches the original OutValue hash. A malicious miner can submit corrupted DecryptedPieces via UpdateValue transactions, causing incorrect PreviousInValue storage that propagates to signature calculations and corrupts consensus state.

## Finding Description

The vulnerability exists in the AEDPoS consensus secret sharing mechanism across multiple components:

**Missing Validation in Secret Reconstruction**: The `RevealSharedInValues` function collects DecryptedPieces from miners and performs Lagrange interpolation reconstruction via `SecretSharingHelper.DecodeSecret`. [1](#0-0)  The reconstructed InValue is directly stored as `PreviousInValue` without verifying that `Hash(revealedInValue)` equals the original `OutValue` stored in the previous round.

**Unvalidated DecryptedPieces Acceptance**: When miners submit UpdateValue transactions, `PerformSecretSharing` accepts and stores their DecryptedPieces without any correctness validation. [2](#0-1) 

**Validation Gap**: The existing validation in `UpdateValueValidationProvider` only checks the sender's own PreviousInValue against their previous OutValue, not the revealed PreviousInValues reconstructed for other miners through secret sharing. [3](#0-2) 

**Corrupted Value Usage**: When miners fail to produce blocks, `SupplyCurrentRoundInformation` retrieves the potentially corrupted `PreviousInValue` and uses it to calculate signatures via `CalculateSignature`. [4](#0-3) 

**Impact on Consensus**: The signature calculation XORs the inValue with all miners' signatures, so one corrupted signature affects the collective result used for mining order determination. [5](#0-4)  Mining order is calculated from signatures using modulo arithmetic. [6](#0-5) 

**Attack Vector**: A malicious miner submits UpdateValue with corrupted DecryptedPieces. Since Shamir's Secret Sharing has no error correction, even one corrupted share among the 2/3 threshold produces a completely incorrect reconstruction. The reconstruction via Lagrange interpolation always succeeds regardless of input validity. [7](#0-6) 

## Impact Explanation

**Critical Consensus Integrity Violation**: This vulnerability breaks the core security guarantee of the AEDPoS consensus mechanism - correct round transitions and verifiable randomness. When corrupted DecryptedPieces cause incorrect PreviousInValue reconstruction, subsequent signature calculations become wrong, directly affecting:

1. **Consensus Randomness**: Signatures are combined via XOR to generate randomness for mining order selection. One corrupted signature pollutes the entire result.

2. **Mining Schedule Integrity**: The corrupted signature produces incorrect mining order calculations, potentially allowing attackers to manipulate block production scheduling.

3. **Cryptographic Chain Break**: The InValue→OutValue→Signature chain that ensures consensus unpredictability is broken for affected miners, compromising the Byzantine fault tolerance properties.

All miners and the consensus mechanism are affected because miners who fail to produce blocks have their signatures filled using the corrupted PreviousInValue, propagating the corruption through subsequent rounds.

## Likelihood Explanation

**High Likelihood - Low Complexity Attack**:

**Attacker Requirements**: Any miner in the consensus set can execute this attack, requiring only:
- Miner status (normal operational requirement)
- Ability to submit UpdateValue transactions (standard consensus participation)

**Attack Execution**: The attacker simply provides corrupted byte arrays as DecryptedPieces values when submitting UpdateValue. [8](#0-7)  The attack succeeds because:
- No validation checks DecryptedPieces correctness before storage
- Shamir's Secret Sharing inherently fails completely with any corrupted share
- If the attacker's piece is among the first 2/3 used for reconstruction, the result is guaranteed wrong
- The corruption is silent - no errors are thrown, wrong values are stored normally

**Detection Difficulty**: The attack is difficult to detect because the incorrect PreviousInValue is stored without errors, and corruption only manifests when signatures don't match expected values in subsequent consensus rounds, which could be attributed to other factors.

## Recommendation

Add validation in `RevealSharedInValues` to verify that reconstructed InValues match the stored OutValues:

```csharp
var revealedInValue = HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// Validate reconstructed value matches original OutValue
if (HashHelper.ComputeFrom(revealedInValue) != anotherMinerInPreviousRound.OutValue)
{
    Context.LogDebug(() => $"Invalid secret reconstruction for {publicKeyOfAnotherMiner}");
    continue; // Skip invalid reconstruction
}

currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

This ensures that only correctly reconstructed secrets are stored as PreviousInValue, maintaining consensus integrity.

## Proof of Concept

A test would demonstrate:
1. Setup a consensus round with multiple miners
2. Miner A submits UpdateValue with corrupted DecryptedPieces for Miner B
3. When RevealSharedInValues is called, it reconstructs Miner B's PreviousInValue using the corrupted pieces
4. The reconstructed value does not match Hash(PreviousInValue) == OutValue from previous round
5. When Miner B fails to produce a block, SupplyCurrentRoundInformation uses the corrupted PreviousInValue
6. CalculateSignature produces a wrong signature for Miner B
7. The wrong signature affects the mining order calculation via modulo arithmetic
8. Demonstrate that Hash(reconstructedInValue) ≠ originalOutValue, proving the validation gap

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-52)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-257)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L287-293)
```csharp
    private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
        string publicKey)
    {
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L44-48)
```csharp
        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L191-199)
```csharp
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
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
