# Audit Report

## Title
Missing Authorization Check in Secret Sharing Allows Malicious Miners to Corrupt Consensus InValue Reconstruction

## Summary
The `PerformSecretSharing` function does not validate whether a miner was authorized to decrypt secret pieces from other miners before accepting their `DecryptedPieces` input. A malicious miner can inject arbitrary decrypted values for any miner, corrupting the Shamir's Secret Sharing reconstruction and causing consensus validation failures that falsely implicate honest miners.

## Finding Description

The vulnerability exists in the `PerformSecretSharing` function where it blindly accepts any entries in `input.DecryptedPieces` without verifying authorization. [1](#0-0) 

The function iterates through all provided `DecryptedPieces` and stores them in the target miner's state without checking if that target miner actually encrypted a piece for the current miner in the previous round. The expected validation would verify `previousRound.RealTimeMinersInformation[targetMinerKey].EncryptedPieces.ContainsKey(publicKey)` before accepting the decrypted piece.

**Why Existing Protections Fail:**

The `PreCheck` function only validates that the sender is in the current or previous miner list, not whether specific decryption operations are authorized. [2](#0-1) 

The off-chain `SecretSharingService` correctly implements authorization checks when generating legitimate decrypted pieces. [3](#0-2) 

However, the on-chain contract does not enforce this validation, allowing malicious miners to bypass off-chain checks by crafting custom `UpdateValueInput` transactions directly.

**Execution Path:**

1. In Round N, honest miners encrypt secret shares and store them in `EncryptedPieces`
2. In Round N+1, a malicious miner calls the public `UpdateValue` method with fabricated `DecryptedPieces` entries [4](#0-3) 
3. The contract stores these without validation via `PerformSecretSharing`
4. Later, `RevealSharedInValues` uses all accumulated `DecryptedPieces` (including the malicious ones) to reconstruct InValues via Shamir's Secret Sharing [5](#0-4) 
5. The Shamir's Secret Sharing reconstruction produces incorrect results when bogus pieces are included in the computation
6. The incorrect InValue fails validation against the victim's previous OutValue during consensus validation [6](#0-5) 

## Impact Explanation

**HIGH Severity** - This vulnerability breaks critical consensus integrity guarantees:

**Consensus Disruption**: A malicious miner can inject false decrypted pieces for any victim miner, causing the Shamir's Secret Sharing reconstruction to produce an incorrect InValue. This corrupted InValue will fail the validation check `HashHelper.ComputeFrom(previousInValue) == previousOutValue`, making the honest victim appear to have provided invalid consensus data.

**Concrete Harm:**
- **Consensus Integrity Violation**: Incorrect InValue reconstruction breaks the secret sharing protocol that ensures consensus security
- **Randomness Corruption**: Since InValues feed into random number generation for consensus, this compromises the randomness source
- **False Accusations**: Honest miners appear malicious due to validation failures, potentially triggering penalties or evil node marking through the election contract update mechanism [7](#0-6) 
- **Operational DoS**: Systematic attacks across multiple rounds could prevent consensus progress by causing repeated validation failures

**Who Is Affected**: All honest miners in the consensus set can become victims. The protocol's consensus integrity and randomness guarantees are fundamentally compromised.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood** - The attack is straightforward to execute:

**Attacker Capabilities**: Any miner in the consensus set can execute this attack. No special privileges beyond being an active miner are required.

**Attack Complexity**: LOW
- Attacker crafts an `UpdateValueInput` message with arbitrary `DecryptedPieces` entries
- Submits via the public `UpdateValue` method that all miners use
- No complex state manipulation or precise timing requirements needed
- The attack is undetectable at submission time since the contract accepts any values

**Feasibility Conditions:**
- Attacker must be a valid miner (passes `PreCheck`)
- Secret sharing must be enabled (configuration check at line 254) [8](#0-7) 
- Attack is repeatable every round against any target miner

**Detection Constraints**: The malicious submission appears identical to legitimate consensus updates at transaction submission time. The corruption only becomes apparent later during InValue reconstruction and validation, by which point the malicious data has been committed to state.

**Economic Rationality**: The attack costs no more than a normal `UpdateValue` transaction (standard gas fees). The attacker gains the ability to disrupt consensus and harm competitors' reputations at minimal cost.

## Recommendation

Add authorization validation in the `PerformSecretSharing` function to verify that each decrypted piece corresponds to an encrypted piece that was actually provided for the current miner:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    
    // Get previous round to validate authorization
    if (!TryToGetPreviousRoundInformation(out var previousRound)) return;
    
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
    {
        // SECURITY FIX: Verify that the target miner actually encrypted a piece for the current miner
        if (!previousRound.RealTimeMinersInformation.ContainsKey(decryptedPreviousInValue.Key)) continue;
        if (!previousRound.RealTimeMinersInformation[decryptedPreviousInValue.Key].EncryptedPieces
            .ContainsKey(publicKey)) continue;
            
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);
    }

    foreach (var previousInValue in input.MinersPreviousInValues)
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
}
```

This ensures that miners can only provide decrypted pieces for miners who explicitly encrypted pieces for them in the previous round, matching the authorization logic already implemented in the off-chain `SecretSharingService`.

## Proof of Concept

A test demonstrating the vulnerability would:

1. Initialize a consensus round with multiple miners (M1, V1, V2, V3, V4)
2. Have victim V1 encrypt secret shares for miners V2, V3, V4 (but NOT for M1)
3. Have malicious miner M1 submit `UpdateValue` with fake `DecryptedPieces[V1] = FakeShare`
4. Observe that the contract accepts this without validation
5. Later trigger `RevealSharedInValues` which uses the fake share
6. Verify that the reconstructed InValue for V1 is incorrect
7. Show that validation fails: `Hash(reconstructedInValue) != V1.previousOutValue`

The test would prove that the contract accepts unauthorized decrypted pieces and uses them in consensus-critical reconstruction, violating the protocol's security guarantees.

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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L129-135)
```csharp
            if (!encryptedShares.Any() || !encryptedShares.ContainsKey(selfPubkey)) continue;
            var interestingMessage = encryptedShares[selfPubkey];
            var senderPublicKey = ByteArrayHelper.HexStringToByteArray(pubkey);

            var decryptedPiece =
                await _accountService.DecryptMessageAsync(senderPublicKey, interestingMessage.ToByteArray());
            decryptedPieces[pubkey] = decryptedPiece;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-53)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L48-48)
```csharp
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```
