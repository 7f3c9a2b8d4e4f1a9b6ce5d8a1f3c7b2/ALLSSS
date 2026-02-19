### Title
Secret Sharing Information Persists in Contract State Despite Deletion Attempt

### Summary
The `DeleteSecretSharingInformation()` function only clears secret sharing data from the Round object copy used in block headers, but fails to remove it from persistent contract state storage. This allows anyone to recover sensitive EncryptedPieces and DecryptedPieces through public view methods, completely defeating the intended security mechanism of ephemeral secret sharing data.

### Finding Description

The vulnerability exists in the AEDPoS consensus contract's handling of secret sharing information: [1](#0-0) 

The `DeleteSecretSharingInformation()` method clears EncryptedPieces and DecryptedPieces from a Round object. However, this method is only invoked when generating consensus block extra data: [2](#0-1) 

This deletion occurs on an in-memory copy prepared for the block header, NOT on the persistent state. The root cause is that secret sharing data was already written to permanent storage earlier in the flow: [3](#0-2) 

When `ProcessUpdateValue` calls `PerformSecretSharing`, it adds the secrets to the Round object: [4](#0-3) 

This Round object (with secrets) is then persisted to state: [5](#0-4) [6](#0-5) 

The persistent state in `State.Rounds[round.RoundNumber]` is NEVER updated to remove the secrets. Public view methods directly return this state with all secret sharing information intact: [7](#0-6) 

The MinerInRound protobuf structure contains these sensitive fields: [8](#0-7) 

### Impact Explanation

This vulnerability compromises consensus integrity by exposing cryptographic materials that should remain ephemeral. The encrypted_pieces contain encrypted shares of miners' InValues, and decrypted_pieces contain decrypted shares recovered from other miners. These are part of the secret sharing protocol used for consensus randomness generation.

An attacker with access to these values could:
1. Reconstruct miners' InValues before they're supposed to be revealed
2. Predict future random values used in consensus
3. Potentially manipulate consensus outcomes by knowing future randomness

The severity is HIGH because consensus randomness is a critical security property, and the vulnerability completely defeats the intended protection mechanism. All consensus participants are affected, as their secret sharing information becomes publicly queryable indefinitely.

### Likelihood Explanation

The likelihood is 100% - this is not a timing-dependent or race condition vulnerability, but a fundamental architectural flaw.

**Attacker capabilities required:** None beyond calling a public view method.

**Attack complexity:** Trivial - a single view call to `GetCurrentRoundInformation()` or `GetRoundInformation(roundNumber)` exposes the data.

**Feasibility conditions:** Always exploitable whenever secret sharing is enabled and miners execute UpdateValue transactions.

**Detection constraints:** The attack requires no transactions and leaves no traces, as it only involves reading public state.

The vulnerability contradicts the entire purpose of `DeleteSecretSharingInformation()`, which exists specifically to prevent persistent storage of these sensitive cryptographic materials.

### Recommendation

**Immediate fix:** Clear secret sharing information BEFORE persisting to state. Modify the flow in `ProcessUpdateValue`:

1. After calling `PerformSecretSharing`, immediately call `DeleteSecretSharingInformation()` on the Round object before `TryToUpdateRoundInformation()`
2. Alternatively, implement a cleanup mechanism that removes secrets from `State.Rounds` after the round completes

**Code-level mitigation:** In `AEDPoSContract_ProcessConsensusInformation.cs`, add after line 256:
```csharp
if (IsSecretSharingEnabled())
{
    PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
    currentRound.DeleteSecretSharingInformation(); // Clear before persisting
}
```

**Invariant check:** Add assertion in `GetCurrentRoundInformation()` that returned Round objects have empty EncryptedPieces/DecryptedPieces maps.

**Test case:** Add unit test verifying that calling `GetCurrentRoundInformation()` after `UpdateValue` with secret sharing returns a Round with no secret sharing data.

### Proof of Concept

**Initial state:** AEDPoS consensus contract initialized with secret sharing enabled.

**Attack sequence:**
1. Wait for any miner to execute `UpdateValue` transaction with secret sharing data (EncryptedPieces/DecryptedPieces in UpdateValueInput)
2. Transaction executes: ProcessUpdateValue → PerformSecretSharing → TryToUpdateRoundInformation
3. Attacker calls public view method: `GetCurrentRoundInformation()`
4. Observe returned Round object's `RealTimeMinersInformation` contains miners with populated `encrypted_pieces` and `decrypted_pieces` maps

**Expected result:** Round objects should have empty EncryptedPieces/DecryptedPieces after DeleteSecretSharingInformation is called.

**Actual result:** Secret sharing information remains fully accessible in state and is returned by view methods, defeating the purpose of deletion.

**Success condition:** Attacker successfully retrieves secret sharing cryptographic materials that were supposed to be deleted, with zero cost and no special permissions required.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLighterRound.cs (L7-14)
```csharp
    public void DeleteSecretSharingInformation()
    {
        var encryptedPieces = RealTimeMinersInformation.Values.Select(i => i.EncryptedPieces);
        foreach (var encryptedPiece in encryptedPieces) encryptedPiece.Clear();

        var decryptedPieces = RealTimeMinersInformation.Values.Select(i => i.DecryptedPieces);
        foreach (var decryptedPiece in decryptedPieces) decryptedPiece.Clear();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L50-50)
```csharp
        if (!isGeneratingTransactions) information.Round.DeleteSecretSharingInformation();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L126-132)
```csharp
    private bool TryToUpdateRoundInformation(Round round)
    {
        var ri = State.Rounds[round.RoundNumber];
        if (ri == null) return false;
        State.Rounds[round.RoundNumber] = round;
        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L21-24)
```csharp
    public override Round GetCurrentRoundInformation(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var currentRound) ? currentRound : new Round();
    }
```

**File:** protobuf/aedpos_contract.proto (L293-296)
```text
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
```
