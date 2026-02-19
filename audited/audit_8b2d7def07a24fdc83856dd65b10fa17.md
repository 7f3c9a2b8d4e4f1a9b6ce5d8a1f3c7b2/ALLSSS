# Audit Report

## Title
Unverified Secret Sharing Data Allows Malicious Miners to Poison Consensus Random Number Generation

## Summary
The AEDPoS consensus contract's `PerformSecretSharing` function accepts decrypted secret pieces and revealed InValues from miners without cryptographic verification. A malicious miner can submit arbitrary values for other miners' decrypted pieces and PreviousInValues, directly corrupting the consensus random number generation chain and breaking the security guarantees of the Shamir Secret Sharing protocol.

## Finding Description

The vulnerability exists in the secret sharing mechanism used by the AEDPoS consensus protocol. When miners submit consensus updates via the `UpdateValue` method, they provide decrypted secret pieces and revealed InValues for other miners. The on-chain contract blindly trusts this data without any cryptographic verification.

**Attack Flow:**

1. A malicious miner calls `UpdateValue` with a crafted `UpdateValueInput` containing:
   - Arbitrary values in `decrypted_pieces` (map of miner pubkey → decrypted piece)
   - Arbitrary values in `miners_previous_in_values` (map of miner pubkey → InValue) [1](#0-0) 

2. The `ProcessUpdateValue` function calls `PerformSecretSharing` when secret sharing is enabled: [2](#0-1) 

3. `PerformSecretSharing` directly adds the attacker's provided decrypted pieces to OTHER miners' records without verification: [3](#0-2) 

4. These poisoned decrypted pieces are later used in `RevealSharedInValues` to reconstruct secrets using Shamir Secret Sharing: [4](#0-3) 

**Why Validation Fails:**

The `UpdateValueValidationProvider` only validates the submitting miner's own `PreviousInValue` through hash verification: [5](#0-4) 

There is NO validation that:
- The submitted `decrypted_pieces` were correctly decrypted from the corresponding `encrypted_pieces`
- The submitted `miners_previous_in_values` are legitimate revealed secrets
- Any cryptographic proof of correct decryption exists

**Contrast with Off-Chain Security:**

The off-chain `SecretSharingService` properly performs cryptographic encryption and decryption: [6](#0-5) 

However, the on-chain contract has no mechanism to verify that submitted data matches the cryptographically computed values.

## Impact Explanation

**High Severity** - This vulnerability breaks critical consensus security guarantees:

1. **Consensus Random Number Corruption**: The consensus protocol relies on InValues for random number generation. While VRF verification exists for the submitted random number itself, the underlying InValue chain that feeds into future rounds can be poisoned: [7](#0-6) 

2. **Secret Sharing Protocol Failure**: Shamir Secret Sharing assumes that at least 2/3 of miners provide correct shares. However, a single malicious miner can poison ALL other miners' decrypted pieces, completely subverting the security model.

3. **Signature Chain Integrity**: Consensus signatures are calculated based on `PreviousInValue`. The poisoned values propagate through subsequent rounds, affecting signature calculations: [8](#0-7) 

4. **Network-Wide Impact**: One malicious miner can poison data for ALL N-1 other miners in a single transaction, requiring no collusion.

## Likelihood Explanation

**High Likelihood** - The attack is trivially executable:

1. **Low Attacker Requirements**: Only requires being an active miner (already in the miner list), which is the expected threat model for Byzantine fault tolerance.

2. **Simple Execution**: The attacker simply modifies two fields in `UpdateValueInput` to arbitrary values - no cryptographic breaking or private key compromise needed.

3. **Guaranteed Success**: The on-chain validation has zero checks for the poisoned data, ensuring the attack succeeds.

4. **Realistic Preconditions**: Only requires secret sharing to be enabled: [9](#0-8) 

5. **Hard to Detect**: No on-chain events or validation failures occur. Detection would require independent off-chain verification of all submitted decrypted pieces against encrypted pieces.

## Recommendation

Implement on-chain cryptographic verification of decrypted pieces. Options include:

1. **Zero-Knowledge Proofs**: Require miners to submit ZK proofs that decrypted pieces were correctly decrypted from encrypted pieces.

2. **Commitment Scheme**: Use a commitment-reveal scheme where miners commit to decrypted pieces with cryptographic proofs.

3. **Multi-Sig Verification**: Require multiple miners to independently verify and co-sign decrypted pieces before acceptance.

4. **Remove Unverifiable Data**: Remove the ability for miners to submit decrypted pieces for OTHER miners entirely. Only allow self-reported data that can be independently verified through the encrypted pieces already on-chain.

Example conceptual fix for option 4:
```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round, string publicKey)
{
    // Only accept encrypted pieces from the submitting miner
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    
    // REMOVED: Accepting decrypted pieces for other miners
    // Each miner must decrypt pieces themselves off-chain and submit their own PreviousInValue
    
    // Only allow setting own PreviousInValue (already validated by UpdateValueValidationProvider)
    if (input.PreviousInValue != Hash.Empty)
        minerInRound.PreviousInValue = input.PreviousInValue;
}
```

## Proof of Concept

```csharp
// POC: Malicious miner poisons other miners' decrypted pieces
[Test]
public async Task MaliciousMinerCanPoisonSecretSharing()
{
    // Setup: Initialize consensus with secret sharing enabled
    var miners = await InitializeConsensusWithSecretSharing();
    var maliciousMiner = miners[0];
    var victimMiner = miners[1];
    
    // Malicious miner crafts poisoned UpdateValueInput
    var poisonedInput = new UpdateValueInput
    {
        OutValue = GenerateValidOutValue(),
        Signature = GenerateValidSignature(),
        PreviousInValue = GenerateValidPreviousInValue(), // Valid for self
        RoundId = CurrentRoundId,
        ActualMiningTime = Timestamp.Now,
        
        // ATTACK: Submit arbitrary decrypted pieces for victim miner
        DecryptedPieces = 
        {
            { victimMiner.Pubkey, ByteString.CopyFromUtf8("POISONED_DATA") }
        },
        
        // ATTACK: Submit arbitrary PreviousInValue for victim miner  
        MinersPreviousInValues =
        {
            { victimMiner.Pubkey, Hash.FromString("FAKE_INVALUE") }
        },
        
        RandomNumber = GenerateValidVRFRandomNumber()
    };
    
    // Execute attack
    await ConsensusContract.UpdateValue(poisonedInput);
    
    // Verify: Victim miner's data has been poisoned
    var currentRound = await GetCurrentRoundInformation();
    var victimData = currentRound.RealTimeMinersInformation[victimMiner.Pubkey];
    
    Assert.Contains(maliciousMiner.Pubkey, victimData.DecryptedPieces.Keys);
    Assert.Equal("POISONED_DATA", victimData.DecryptedPieces[maliciousMiner.Pubkey].ToStringUtf8());
    Assert.Equal(Hash.FromString("FAKE_INVALUE"), victimData.PreviousInValue);
    
    // Impact: Poisoned data will be used in RevealSharedInValues to reconstruct secrets
    // This breaks the integrity of the secret sharing protocol and consensus randomness
}
```

### Citations

**File:** protobuf/aedpos_contract.proto (L211-216)
```text
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 9;
    // The amount of produced blocks.
    int64 produced_blocks = 10;
    // The InValue in the previous round, miner public key -> InValue.
    map<string, aelf.Hash> miners_previous_in_values = 11;
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L114-134)
```csharp
            var encryptedPiece = await _accountService.EncryptMessageAsync(receiverPublicKey, plainMessage);
            encryptedPieces[pubkey] = encryptedPiece;
            if (secretSharingInformation.PreviousRound.RealTimeMinersInformation.ContainsKey(selfPubkey) &&
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[selfPubkey].EncryptedPieces
                    .ContainsKey(pubkey))
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[selfPubkey]
                        .EncryptedPieces[pubkey]
                    = ByteString.CopyFrom(encryptedPiece);
            else
                continue;

            if (!secretSharingInformation.PreviousRound.RealTimeMinersInformation.ContainsKey(pubkey)) continue;

            var encryptedShares =
                secretSharingInformation.PreviousRound.RealTimeMinersInformation[pubkey].EncryptedPieces;
            if (!encryptedShares.Any() || !encryptedShares.ContainsKey(selfPubkey)) continue;
            var interestingMessage = encryptedShares[selfPubkey];
            var senderPublicKey = ByteArrayHelper.HexStringToByteArray(pubkey);

            var decryptedPiece =
                await _accountService.DecryptMessageAsync(senderPublicKey, interestingMessage.ToByteArray());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-210)
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
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }
```
