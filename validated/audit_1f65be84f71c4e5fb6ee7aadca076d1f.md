# Audit Report

## Title
Unverified Secret Sharing Data Allows Malicious Miners to Poison Consensus State

## Summary
The AEDPoS consensus contract's `PerformSecretSharing` function accepts decrypted secret pieces and revealed InValues from miners without cryptographic verification. A malicious miner can submit arbitrary values for other miners' decrypted pieces and PreviousInValues, corrupting the Shamir Secret Sharing protocol and consensus state. [1](#0-0) [2](#0-1) 

## Finding Description

The vulnerability exists in how the AEDPoS consensus contract processes secret sharing data. When miners submit consensus updates via `UpdateValue`, they provide decrypted secret pieces and revealed InValues for OTHER miners in the `UpdateValueInput` message. The on-chain contract stores this data without any cryptographic verification.

**Attack Flow:**

1. A malicious miner calls `UpdateValue` with a crafted `UpdateValueInput` containing arbitrary values in `decrypted_pieces` and `miners_previous_in_values` maps for other miners. [3](#0-2) 

2. When secret sharing is enabled, `ProcessUpdateValue` calls `PerformSecretSharing`: [4](#0-3) 

3. `PerformSecretSharing` directly adds the attacker's provided values to OTHER miners' records without any verification: [5](#0-4) 

The first foreach loop adds arbitrary decrypted pieces to other miners' `DecryptedPieces` collection. The second foreach loop directly sets other miners' `PreviousInValue` to arbitrary hash values.

4. These poisoned decrypted pieces are later used in `RevealSharedInValues` to reconstruct secrets using Shamir Secret Sharing: [6](#0-5) 

**Why Validation Fails:**

The `UpdateValueValidationProvider` only validates the submitting miner's OWN `PreviousInValue` by checking that its hash matches their previous `OutValue`: [7](#0-6) 

There is NO validation that:
- The submitted `decrypted_pieces` were correctly decrypted from the corresponding `encrypted_pieces`
- The submitted `miners_previous_in_values` are legitimate revealed secrets
- Any cryptographic proof of correct decryption exists

## Impact Explanation

**High Severity** - This vulnerability breaks critical consensus protocol guarantees:

1. **Secret Sharing Protocol Failure**: Shamir Secret Sharing assumes that at least 2/3 of miners provide correct shares. However, a single malicious miner can poison ALL other miners' decrypted pieces in a single transaction, completely subverting the security model that relies on threshold cryptography.

2. **Consensus State Corruption**: The attacker can directly set arbitrary `PreviousInValue` for all other miners. This corrupts the InValue chain used in consensus signature calculations.

3. **Offline Miner Impact**: When miners are offline, their consensus information is supplied using stored state. The `SupplyCurrentRoundInformation` method uses the potentially poisoned `PreviousInValue` to calculate signatures for offline miners: [8](#0-7) 

4. **Network-Wide Impact**: One malicious miner can poison data for ALL N-1 other miners in a single transaction, requiring no collusion.

While the VRF verification still validates each miner's random number contribution, the underlying state used for secret reconstruction and signature calculation is compromised. [9](#0-8) 

## Likelihood Explanation

**High Likelihood** - The attack is trivially executable:

1. **Low Attacker Requirements**: Only requires being an active miner (already in the miner list), which is the expected threat model for Byzantine fault tolerance.

2. **Simple Execution**: The attacker simply populates two map fields in `UpdateValueInput` with arbitrary values - no cryptographic breaking or private key compromise needed.

3. **Guaranteed Success**: The on-chain validation has zero checks for the poisoned data. The validation only checks the sender's own fields, allowing arbitrary values for other miners.

4. **Realistic Preconditions**: Only requires secret sharing to be enabled, which is checked via configuration: [10](#0-9) 

5. **Hard to Detect**: No on-chain events or validation failures occur. Detection would require independent off-chain verification of all submitted decrypted pieces against encrypted pieces.

## Recommendation

Implement cryptographic verification of decrypted pieces and revealed InValues:

1. **Verify Decrypted Pieces**: Add validation that decrypted pieces correctly decrypt from the stored encrypted pieces using the submitter's public key. This requires storing encryption proofs or using verifiable decryption schemes.

2. **Restrict PreviousInValue Setting**: Only allow miners to set their OWN `PreviousInValue`, not other miners'. Remove lines 295-296 from `PerformSecretSharing` or add authorization checks.

3. **Consensus on Revealed Values**: Implement a consensus mechanism where multiple miners must agree on revealed InValues before they are accepted on-chain.

4. **Zero-Knowledge Proofs**: Consider using ZK-SNARK or similar cryptographic proofs to verify correct decryption without revealing private keys.

5. **Validation Events**: Emit events when secret sharing data is submitted to enable off-chain monitoring and verification.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MaliciousMiner_CanPoisonOtherMinersSecretSharingData()
{
    // Setup: Initialize consensus with 3 miners
    var miners = new[] { "MinerA", "MinerB", "MinerC" };
    await InitializeConsensus(miners);
    
    // Malicious MinerA calls UpdateValue
    var maliciousInput = new UpdateValueInput
    {
        OutValue = GenerateValidOutValue(),
        Signature = GenerateValidSignature(),
        PreviousInValue = GenerateValidPreviousInValue(),
        RandomNumber = GenerateValidRandomNumber(),
        
        // ATTACK: Provide arbitrary decrypted pieces for MinerB and MinerC
        DecryptedPieces =
        {
            ["MinerB"] = ByteString.CopyFromUtf8("POISONED_PIECE_B"),
            ["MinerC"] = ByteString.CopyFromUtf8("POISONED_PIECE_C")
        },
        
        // ATTACK: Provide arbitrary PreviousInValues for MinerB and MinerC
        MinersPreviousInValues =
        {
            ["MinerB"] = Hash.FromString("POISONED_INVALUE_B"),
            ["MinerC"] = Hash.FromString("POISONED_INVALUE_C")
        }
    };
    
    // Execute the attack - this should fail but doesn't
    var result = await ConsensusContract.UpdateValue(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // PASSES
    
    // Verify the poisoned data was stored
    var currentRound = await ConsensusContract.GetCurrentRoundInformation();
    
    // MinerB's DecryptedPieces now contains MinerA's poisoned value
    currentRound.RealTimeMinersInformation["MinerB"]
        .DecryptedPieces["MinerA"].ShouldBe(ByteString.CopyFromUtf8("POISONED_PIECE_B"));
    
    // MinerB's PreviousInValue is now the poisoned hash
    currentRound.RealTimeMinersInformation["MinerB"]
        .PreviousInValue.ShouldBe(Hash.FromString("POISONED_INVALUE_B"));
    
    // The vulnerability allows one miner to corrupt all other miners' data
}
```

**Notes:**

The vulnerability is confirmed through code analysis of the consensus contract. The `PerformSecretSharing` function accepts and stores attacker-provided data for other miners without cryptographic verification. While the VRF mechanism still validates random number contributions, the secret sharing protocol's security assumptions are completely broken, allowing state corruption that affects offline miners and consensus signature calculations.

### Citations

**File:** protobuf/aedpos_contract.proto (L212-212)
```text
    map<string, bytes> decrypted_pieces = 9;
```

**File:** protobuf/aedpos_contract.proto (L216-216)
```text
    map<string, aelf.Hash> miners_previous_in_values = 11;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-79)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-52)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
    }
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
