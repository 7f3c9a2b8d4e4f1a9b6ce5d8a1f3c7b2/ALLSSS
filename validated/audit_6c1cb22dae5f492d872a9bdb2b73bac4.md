# Audit Report

## Title
Missing Authorization Check in Secret Sharing Allows Malicious Miners to Corrupt Consensus InValue Reconstruction

## Summary
The `PerformSecretSharing` function in the AEDPoS consensus contract does not validate whether a miner is authorized to decrypt secret pieces from other miners before accepting their `DecryptedPieces` input. This allows any malicious miner to inject arbitrary decrypted values, corrupting the Shamir's Secret Sharing reconstruction protocol and compromising consensus integrity.

## Finding Description

The vulnerability exists in the `PerformSecretSharing` function where it unconditionally accepts any entries provided in `input.DecryptedPieces` without verifying that the submitting miner was authorized to decrypt those specific pieces. [1](#0-0) 

The function iterates through all provided `DecryptedPieces` entries and stores them directly into the target miner's state without checking whether that target miner actually encrypted a piece for the current miner in the previous round. The expected validation would verify `previousRound.RealTimeMinersInformation[targetMinerKey].EncryptedPieces.ContainsKey(publicKey)` before accepting any decrypted piece.

**Why Existing Protections Fail:**

The `PreCheck` function only validates that the transaction sender is in the current or previous miner list, not whether they are authorized to perform specific decryption operations. [2](#0-1) 

The off-chain `SecretSharingService` correctly implements authorization checks when generating legitimate decrypted pieces by verifying `EncryptedPieces.ContainsKey(selfPubkey)` before attempting decryption. [3](#0-2) 

However, the on-chain contract does not enforce this validation, allowing malicious miners to bypass the off-chain checks by crafting custom `UpdateValueInput` transactions directly.

**Execution Path:**

1. In Round N, honest miners encrypt secret shares and store them in their `EncryptedPieces` maps
2. In Round N+1, a malicious miner calls the public `UpdateValue` method [4](#0-3)  with fabricated `DecryptedPieces` entries for any victim miner
3. The contract stores these malicious values without validation via `PerformSecretSharing` 
4. During round transitions, `RevealSharedInValues` uses all accumulated `DecryptedPieces` (including the malicious ones) to reconstruct InValues via Shamir's Secret Sharing [5](#0-4) 
5. The Shamir's Secret Sharing reconstruction (`SecretSharingHelper.DecodeSecret`) produces incorrect results when corrupted pieces are included
6. The reconstructed InValue is stored in state and may fail validation against the victim's previous OutValue [6](#0-5) 

## Impact Explanation

**HIGH Severity** - This vulnerability breaks critical consensus security guarantees:

**Consensus Integrity Violation**: A malicious miner can inject false decrypted pieces for any victim miner, causing the Shamir's Secret Sharing reconstruction to produce an incorrect InValue. This corrupts the secret sharing protocol that underpins consensus security.

**Concrete Harm:**
- **Randomness Corruption**: InValues feed into random number generation for consensus. Corrupted reconstructed values compromise the randomness source used for miner scheduling and other consensus operations.
- **State Pollution**: Incorrect reconstructed InValues are stored permanently in contract state, potentially affecting subsequent rounds and consensus operations.
- **Protocol Assumption Violation**: The secret sharing protocol assumes only authorized parties (those who received encrypted pieces) can provide decrypted values. This assumption is violated, breaking the cryptographic security model.
- **Potential Evil Node Marking**: If corrupted values cause validation failures, the detection mechanism may incorrectly identify honest miners as malicious [7](#0-6) 

**Who Is Affected**: All miners in the consensus set are potential victims. The protocol's consensus integrity and randomness guarantees are fundamentally compromised.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood** - The attack is straightforward to execute:

**Attacker Capabilities**: Any miner in the consensus set can execute this attack. No special privileges beyond being an active miner are required.

**Attack Complexity**: LOW
- Attacker crafts an `UpdateValueInput` message with arbitrary `DecryptedPieces` entries
- Submits via the public `UpdateValue` method that all miners routinely use
- No complex state manipulation or precise timing requirements
- The attack is undetectable at transaction submission time since the contract accepts any values

**Feasibility Conditions:**
- Attacker must be a valid miner (passes `PreCheck`)
- Secret sharing must be enabled via configuration [8](#0-7) 
- Attack is repeatable every round against any target miner

**Detection Constraints**: The malicious submission appears identical to legitimate consensus updates at submission time. The corruption only becomes apparent during InValue reconstruction, by which point the malicious data has been committed to state.

**Economic Rationality**: The attack costs only standard transaction fees. The attacker gains the ability to corrupt consensus randomness and disrupt the secret sharing protocol at minimal cost.

## Recommendation

Add authorization validation in the `PerformSecretSharing` function before accepting any `DecryptedPieces` entry:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    
    // Get previous round to validate authorization
    if (!TryToGetPreviousRoundInformation(out var previousRound))
        return;
    
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
    {
        // AUTHORIZATION CHECK: Verify that the target miner encrypted a piece for the current miner
        if (!previousRound.RealTimeMinersInformation.ContainsKey(decryptedPreviousInValue.Key))
            continue;
            
        if (!previousRound.RealTimeMinersInformation[decryptedPreviousInValue.Key]
            .EncryptedPieces.ContainsKey(publicKey))
            continue; // Skip unauthorized decryption attempts
            
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);
    }

    foreach (var previousInValue in input.MinersPreviousInValues)
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
}
```

This mirrors the authorization logic already implemented in the off-chain `SecretSharingService` and ensures consistency between off-chain validation and on-chain enforcement.

## Proof of Concept

A malicious miner can execute the following attack:

1. Wait for Round N where target miner produces a block with `OutValue_N`
2. In Round N+1, craft a malicious `UpdateValueInput`:
   - Set `DecryptedPieces[targetMiner.pubkey] = malicious_bytes`
   - Include other legitimate consensus data
3. Call `UpdateValue(maliciousInput)` 
4. Transaction succeeds - `PreCheck` only validates miner list membership
5. `PerformSecretSharing` stores the malicious piece without authorization check
6. During `NextRound`, `RevealSharedInValues` reconstructs targetMiner's InValue using the corrupted piece
7. Reconstruction produces `incorrect_InValue ≠ Hash^-1(OutValue_N)`
8. The corrupted InValue is stored in state, breaking the secret sharing protocol

The vulnerability is confirmed by the absence of any `EncryptedPieces.ContainsKey` validation in the on-chain contract code, despite its presence in the off-chain service.

**Notes**

This is a critical security vulnerability that violates the fundamental assumptions of the Shamir's Secret Sharing protocol used in AEDPoS consensus. The discrepancy between off-chain authorization checks and on-chain validation creates an exploitable gap that allows any miner to corrupt the consensus randomness source. The fix requires adding the same authorization check that exists off-chain to the on-chain contract to enforce the protocol's security model consistently.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-254)
```csharp
        if (IsSecretSharingEnabled())
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L116-138)
```csharp
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
            decryptedPieces[pubkey] = decryptedPiece;
            secretSharingInformation.PreviousRound.RealTimeMinersInformation[pubkey].DecryptedPieces[selfPubkey]
                = ByteString.CopyFrom(decryptedPiece);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L48-48)
```csharp
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```
