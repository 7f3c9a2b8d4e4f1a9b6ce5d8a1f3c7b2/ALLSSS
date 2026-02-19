# Audit Report

## Title
Unvalidated Encrypted Secret Pieces Allow Injection of Fake Shares in Consensus Secret Sharing Mechanism

## Summary
The AEDPoS consensus secret sharing mechanism accepts encrypted pieces and reconstructed `PreviousInValue` data from miners without validating that these values correspond to the correct InValue that hashes to the miner's published OutValue. This allows a malicious miner to inject fake secret shares, causing honest miners to reconstruct and propagate incorrect PreviousInValue data that affects signature calculations and mining order, breaking the verifiable random function property of the consensus.

## Finding Description

The AEDPoS consensus implements a secret sharing scheme where miners split their InValue into encrypted pieces for other miners to reconstruct. However, there are critical missing validation points:

**1. Acceptance of Arbitrary Encrypted Pieces**

When a miner submits `UpdateValueInput`, the `PerformSecretSharing` function directly adds encrypted pieces to state without validation: [1](#0-0) 

There is no check that these encrypted pieces actually encode shares of the InValue that hashes to the miner's OutValue.

**2. Unvalidated PreviousInValue Propagation**

The same function directly sets `PreviousInValue` for other miners from `MinersPreviousInValues` without validation: [2](#0-1) 

Similarly, `UpdateLatestSecretPieces` sets PreviousInValue from trigger information's `RevealedInValues` without validation: [3](#0-2) 

**3. Insufficient Validation Scope**

The existing `UpdateValueValidationProvider` only validates the sender's own PreviousInValue: [4](#0-3) 

It checks `validationContext.SenderPubkey` but not the PreviousInValue values being set for OTHER miners.

**4. Off-Chain Reconstruction Without Validation**

The off-chain `SecretSharingService` reconstructs InValues using Shamir's Secret Sharing from decrypted pieces without validating the result: [5](#0-4) 

**Attack Execution Path:**

1. **Round N**: Malicious miner submits `UpdateValueInput` with fake `encrypted_pieces` (random data or shares of a wrong secret)
2. **Round N+1**: Honest miners decrypt these fake pieces off-chain [6](#0-5) 
3. Honest miners reconstruct a wrong InValue using the fake decrypted pieces
4. The wrong value is added to `RevealedInValues` and included in trigger information [7](#0-6) 
5. The wrong PreviousInValue is set on-chain without validation
6. When the malicious miner doesn't produce a block, `SupplyCurrentRoundInformation` retrieves this wrong PreviousInValue and uses it to calculate signature: [8](#0-7) 
7. The wrong signature affects mining order calculation: [9](#0-8) 

## Impact Explanation

**Consensus Integrity Violation:**

The attack breaks fundamental security properties of the AEDPoS consensus:

1. **Verifiable Random Function Property Broken**: The commitment-reveal scheme is bypassed since fake encrypted pieces are accepted without proving they correspond to the committed OutValue.

2. **Mining Order Manipulation**: Wrong signatures directly affect mining order through `GetAbsModulus(sigNum, minersCount) + 1`, potentially giving the attacker favorable block production positions.

3. **Randomness Compromise**: Signatures are XOR-combined to generate random values used throughout the consensus. Wrong signatures poison this randomness generation.

4. **Fairness Violation**: Honest miners' relative positions in the mining schedule can be unfairly altered, affecting reward distribution over time.

**Medium Severity Justification**: While this doesn't directly steal funds, it undermines core consensus properties (fairness, randomness, verifiability) that are critical to blockchain security. A malicious miner could gain systematic mining advantages, indirectly affecting economic outcomes and network integrity.

## Likelihood Explanation

**High Likelihood of Exploitation:**

1. **Attacker Requirements**: Only needs to be an active miner (realistic in a public blockchain)
2. **Attack Complexity**: Low - simply provide arbitrary bytes as `encrypted_pieces` instead of legitimate Shamir shares
3. **No Timing Constraints**: Attacker can execute at any time secret sharing is enabled
4. **Deterministic Success**: Once fake pieces are accepted on-chain, the attack proceeds automatically as honest miners decrypt and reconstruct
5. **Limited Detection**: No on-chain mechanism exists to detect fake encrypted pieces before they affect consensus

**Feasibility Conditions:**
- Secret sharing feature must be enabled (configuration-dependent)
- Attacker should avoid mining in subsequent rounds to prevent self-revealing the correct value

The attack requires no special privileges beyond normal miner status and exploits a clear validation gap in production code.

## Recommendation

Implement comprehensive validation of reconstructed PreviousInValue data:

1. **Add OutValue Verification**: When setting PreviousInValue for any miner (not just the sender), validate that `HashHelper.ComputeFrom(previousInValue) == previousRound.OutValue`:

```csharp
// In PerformSecretSharing
foreach (var previousInValue in input.MinersPreviousInValues)
{
    var targetMiner = previousInValue.Key;
    if (previousRound.RealTimeMinersInformation.ContainsKey(targetMiner))
    {
        var expectedOutValue = previousRound.RealTimeMinersInformation[targetMiner].OutValue;
        if (HashHelper.ComputeFrom(previousInValue.Value) != expectedOutValue)
        {
            Context.LogDebug(() => $"Invalid PreviousInValue for {targetMiner}");
            continue; // Skip invalid entries
        }
    }
    round.RealTimeMinersInformation[targetMiner].PreviousInValue = previousInValue.Value;
}
```

2. **Validate in UpdateLatestSecretPieces**: Apply the same validation when setting PreviousInValue from `RevealedInValues`.

3. **Add Validation Provider**: Create a new validation provider that checks all PreviousInValue entries in `MinersPreviousInValues` dictionary, not just the sender's own value.

4. **Consider Zero-Knowledge Proofs**: For stronger security, require miners to provide zero-knowledge proofs that encrypted pieces correspond to shares of the correct InValue without revealing the value itself.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Deploy the consensus contract with secret sharing enabled
2. Set up multiple miners in a round with valid OutValues
3. Have a malicious miner submit `UpdateValueInput` with fake `encrypted_pieces` (random bytes)
4. Simulate honest miners decrypting and reconstructing the wrong InValue
5. Have honest miners submit the wrong reconstructed value via `MinersPreviousInValues`
6. Verify the contract accepts it without validation
7. Show that `SupplyCurrentRoundInformation` uses this wrong value to calculate signature
8. Demonstrate that mining order is affected by comparing with the correct scenario

The test would confirm that:
- Fake encrypted pieces are accepted without validation
- Wrong reconstructed PreviousInValue is set without checking against OutValue
- Signature calculation uses the wrong value
- Mining order calculation produces different results than with correct values

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-290)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L148-152)
```csharp
        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L133-134)
```csharp
            var decryptedPiece =
                await _accountService.DecryptMessageAsync(senderPublicKey, interestingMessage.ToByteArray());
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L175-176)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L112-114)
```csharp
            var revealedInValues = _secretSharingService.GetRevealedInValues(hint.RoundId);
            foreach (var revealedInValue in revealedInValues)
                trigger.RevealedInValues.Add(revealedInValue.Key, revealedInValue.Value);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```
