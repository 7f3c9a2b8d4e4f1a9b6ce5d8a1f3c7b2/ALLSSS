### Title
Authorization Bypass: Any Miner Can Arbitrarily Set Other Miners' PreviousInValue Without Secret Sharing Validation

### Summary
The `PerformSecretSharing` function in the AEDPoS consensus contract allows any miner to set arbitrary `PreviousInValue` for other miners without validating that these values were correctly reconstructed through the secret sharing mechanism. This bypasses the threshold-based reveal mechanism and allows unauthorized modification of other miners' consensus state, corrupting the blockchain's secret sharing integrity.

### Finding Description

The vulnerability exists in the `PerformSecretSharing` method which is called during `UpdateValue` transaction execution: [1](#0-0) 

Specifically, line 296 unconditionally sets `PreviousInValue` for any miner specified in the input's `MinersPreviousInValues` map without any authorization check: [2](#0-1) 

The `UpdateValueInput` protobuf message structure includes a `miners_previous_in_values` field that maps miner public keys to hash values: [3](#0-2) 

The `UpdateValue` method is a public entry point accessible to any miner: [4](#0-3) 

The `PreCheck` function only validates that the sender is in the miner list, but does NOT validate the contents of `MinersPreviousInValues`: [5](#0-4) 

The `UpdateValueValidationProvider` only validates the sender's OWN `PreviousInValue`, not when the sender attempts to set values for OTHER miners: [6](#0-5) 

**Contrast with Correct Implementation**: The `RevealSharedInValues` function demonstrates the INTENDED approach, requiring threshold validation and using `SecretSharingHelper.DecodeSecret`: [7](#0-6) 

Note: The question mentioned `UpdateLatestSecretPieces()` function, which is a view function that modifies in-memory Round objects: [8](#0-7) 

However, the actual vulnerability is in the state-modifying `PerformSecretSharing` function, not the view function. The view function has a protective check (lines 150-151) that only sets values if they're Empty or null, but the state-modifying function has no such protection.

### Impact Explanation

**Consensus Integrity Breach**: The secret sharing mechanism is designed to prevent miners from withholding their InValues to manipulate consensus randomness. By allowing arbitrary `PreviousInValue` setting, this mechanism is completely bypassed.

**State Corruption**: Malicious values written to blockchain state are persisted via `TryToUpdateRoundInformation`: [9](#0-8) 

**Propagation of Corruption**: The corrupted values are subsequently extracted by `ExtractInformationToUpdateConsensus` and can be propagated by honest miners in future rounds: [10](#0-9) 

**Affected Parties**: All miners in the consensus round can have their `PreviousInValue` arbitrarily modified, affecting the integrity of the commit-reveal scheme that underpins the secret sharing randomness mechanism.

### Likelihood Explanation

**Attacker Capabilities**: Attacker must be an elected miner, which is feasible for any malicious validator or compromised miner node. This does not require exceptional privilege beyond normal miner status.

**Attack Complexity**: Low - attacker simply crafts an `UpdateValueInput` with malicious entries in the `MinersPreviousInValues` map and calls the public `UpdateValue` method.

**Execution Practicality**: The attack is straightforward and executable in every round where the attacker produces blocks. The `UpdateValue` method is called as part of normal consensus operation: [11](#0-10) 

**Detection Constraints**: No validation or event logging exists to detect when a miner sets another miner's `PreviousInValue`. The attack is silent and can persist across multiple rounds.

**Economic Rationality**: Attack cost is negligible (only transaction fees for normal UpdateValue calls), while the ability to manipulate consensus state could provide strategic advantages in block production ordering or committee selection.

### Recommendation

**Immediate Fix**: Add authorization validation in `PerformSecretSharing` to prevent setting `PreviousInValue` for other miners:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    // REMOVE or RESTRICT this logic:
    // foreach (var previousInValue in input.MinersPreviousInValues)
    //     round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    
    // Only allow miners to set their OWN PreviousInValue:
    if (input.MinersPreviousInValues.ContainsKey(publicKey))
        minerInRound.PreviousInValue = input.MinersPreviousInValues[publicKey];
}
```

**Alternative Approach**: Remove the `MinersPreviousInValues` processing from `PerformSecretSharing` entirely and rely solely on `RevealSharedInValues` (called during NextRound) to properly reconstruct and set `PreviousInValue` using threshold-based validation.

**Additional Validation**: If miners need to reveal other miners' InValues, add explicit checks:
1. Verify minimum threshold of decrypted pieces exists
2. Recompute the InValue using `SecretSharingHelper.DecodeSecret`
3. Validate the computed hash matches the expected value

**Test Cases**: Add regression tests that:
1. Verify a miner cannot set another miner's `PreviousInValue` through `UpdateValue`
2. Confirm `PreviousInValue` can only be set through proper secret sharing reconstruction
3. Validate that unauthorized modifications are rejected with appropriate error messages

### Proof of Concept

**Initial State**:
- Miner A (malicious) and Miner B (victim) are both in the current round's miner list
- Miner B has not yet revealed their PreviousInValue for the current round

**Attack Steps**:

1. Miner A crafts a malicious `UpdateValueInput`:
   - Populate normal fields (OutValue, Signature, etc.) with valid data for Miner A
   - Set `MinersPreviousInValues` map with entry: `{MinerB_Pubkey: arbitrary_malicious_hash}`

2. Miner A calls `UpdateValue(malicious_input)` transaction

3. Contract execution flow:
   - `ProcessConsensusInformation` calls `PreCheck()` - PASSES (Miner A is valid)
   - `ProcessUpdateValue` calls `PerformSecretSharing` at line 256
   - Line 296 executes: `round.RealTimeMinersInformation[MinerB_Pubkey].PreviousInValue = arbitrary_malicious_hash`
   - Line 284: `TryToUpdateRoundInformation(currentRound)` persists corrupted state

**Expected vs Actual Result**:
- **Expected**: Transaction should FAIL with "Unauthorized to set other miner's PreviousInValue" or similar error
- **Actual**: Transaction SUCCEEDS, Miner B's `PreviousInValue` is set to the arbitrary malicious hash in blockchain state

**Success Condition**: Query the Round state after the transaction and observe that Miner B's `PreviousInValue` was modified to the malicious value without proper secret sharing validation, and this corrupted value persists in subsequent rounds.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L284-284)
```csharp
        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
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

**File:** protobuf/aedpos_contract.proto (L215-216)
```text
    // The InValue in the previous round, miner public key -> InValue.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-52)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L136-153)
```csharp
    private void UpdateLatestSecretPieces(Round updatedRound, string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);

        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;

        foreach (var revealedInValue in triggerInformation.RevealedInValues)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(revealedInValue.Key) &&
                (updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == Hash.Empty ||
                 updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue == null))
                updatedRound.RealTimeMinersInformation[revealedInValue.Key].PreviousInValue = revealedInValue.Value;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L144-146)
```csharp
                        GenerateTransaction(nameof(UpdateValue),
                            round.ExtractInformationToUpdateConsensus(pubkey.ToHex(), randomNumber))
                    }
```
