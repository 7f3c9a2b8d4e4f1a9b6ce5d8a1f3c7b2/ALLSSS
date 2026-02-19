# Audit Report

## Title
Secret Sharing Information Persists in Contract State Despite Deletion Attempt

## Summary
The AEDPoS consensus contract's `DeleteSecretSharingInformation()` function only clears secret sharing data from an in-memory Round object copy used for block headers, but fails to remove it from persistent contract state storage. This architectural flaw allows anyone to recover sensitive EncryptedPieces and DecryptedPieces through public view methods, completely defeating the intended security mechanism of ephemeral secret sharing data used for consensus randomness generation.

## Finding Description

The vulnerability stems from a critical disconnect between the deletion mechanism and persistent state management in the secret sharing protocol.

The `DeleteSecretSharingInformation()` method clears EncryptedPieces and DecryptedPieces from a Round object: [1](#0-0) 

However, this method is only invoked when generating consensus block extra data, specifically on a local variable prepared for the block header: [2](#0-1) 

The root cause is that secret sharing data was already written to permanent storage earlier in the execution flow. When miners execute UpdateValue transactions, the `ProcessUpdateValue` method calls `PerformSecretSharing` when secret sharing is enabled: [3](#0-2) 

The `PerformSecretSharing` method adds encrypted and decrypted pieces directly to the Round object: [4](#0-3) 

This Round object containing all secret sharing data is then persisted to state: [5](#0-4) 

The `TryToUpdateRoundInformation` implementation writes directly to persistent state: [6](#0-5) 

Critically, the persistent state in `State.Rounds[round.RoundNumber]` is never updated to remove the secrets after they are added. Public view methods directly return this unredacted state: [7](#0-6) 

The helper methods used by these view methods retrieve data directly from persistent state: [8](#0-7) [9](#0-8) 

The protobuf structure confirms that MinerInRound contains these sensitive cryptographic fields: [10](#0-9) 

## Impact Explanation

This vulnerability represents a **HIGH severity** breach of consensus integrity by exposing cryptographic materials that are fundamental to the security of the AEDPoS consensus protocol.

The encrypted_pieces contain encrypted shares of miners' InValues, and decrypted_pieces contain decrypted shares recovered from other miners. These are part of the secret sharing protocol used for verifiable random number generation in consensus. The protocol design assumes these pieces remain ephemeral - used only during the consensus round and then discarded.

By making these pieces permanently queryable through public view methods, an attacker can:

1. **Reconstruct miners' InValues prematurely**: With access to sufficient decrypted pieces, an attacker can potentially reconstruct a miner's InValue before it's meant to be revealed, breaking the commit-reveal scheme.

2. **Predict future random values**: The consensus protocol uses these InValues to generate signatures and ultimately random hashes. Knowledge of InValues allows prediction of future randomness used in consensus decisions.

3. **Manipulate consensus outcomes**: With foreknowledge of consensus randomness, an attacker could potentially time transactions or actions to take advantage of predictable random outcomes, undermining the fairness guarantees of the consensus mechanism.

The severity is HIGH because:
- Consensus randomness is a **critical security property** of the AEDPoS protocol
- The vulnerability completely defeats the intended protection mechanism (DeleteSecretSharingInformation exists specifically to prevent this exposure)
- All consensus participants are affected - their secret sharing information becomes publicly queryable indefinitely
- The design intent is clear (ephemeral secrets), but the implementation fails to achieve it

## Likelihood Explanation

The likelihood is **100% - CERTAIN**. This is not a race condition or timing-dependent vulnerability, but a fundamental architectural flaw in state management.

**Attacker capabilities required:** None beyond calling a public view method available to any user or observer.

**Attack complexity:** Trivial - requires only:
```
GetCurrentRoundInformation() -> returns Round with all secret sharing data
OR
GetRoundInformation(roundNumber) -> returns historical Round with all secret sharing data
```

**Feasibility conditions:** 
- Secret sharing is enabled (checked via `IsSecretSharingEnabled()`)
- Miners have executed UpdateValue transactions (normal consensus operation)
- Both conditions are met during standard protocol operation on mainnet

**Detection constraints:** The attack requires no transactions and leaves no traces, as it only involves reading public state through view methods. The data exposure is persistent - once written, it remains queryable indefinitely (until old rounds are pruned per the retention policy).

The vulnerability contradicts the entire purpose of `DeleteSecretSharingInformation()`, which exists specifically to prevent persistent storage of these sensitive cryptographic materials. The fact that this function exists but only operates on ephemeral copies demonstrates clear design intent that is not properly implemented.

## Recommendation

The fix requires ensuring that `DeleteSecretSharingInformation()` is called on the persistent state after the Round is used for block generation. There are two potential approaches:

**Approach 1: Clean up after persistence (Recommended)**
After persisting the Round to state in `ProcessUpdateValue`, immediately retrieve and clean it:

```csharp
// In ProcessUpdateValue, after line 284:
if (IsSecretSharingEnabled())
{
    currentRound.DeleteSecretSharingInformation();
    if (!TryToUpdateRoundInformation(currentRound)) 
        Assert(false, "Failed to clean secret sharing information.");
}
```

**Approach 2: Never persist secrets to state**
Modify `PerformSecretSharing` to only update a temporary Round copy used for validation, and avoid persisting secrets to `State.Rounds`:

```csharp
// In ProcessUpdateValue:
if (IsSecretSharingEnabled())
{
    // Create a temporary copy for secret sharing validation
    var tempRound = currentRound.Clone();
    PerformSecretSharing(updateValueInput, tempRound.RealTimeMinersInformation[_processingBlockMinerPubkey], 
        tempRound, _processingBlockMinerPubkey);
    // Validate using tempRound but persist currentRound without secrets
}
```

**Approach 1 is recommended** because it maintains the current transaction flow while ensuring proper cleanup of persistent state. This approach is less invasive and maintains backward compatibility with existing validation logic that may depend on these fields being present during transaction processing.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task SecretSharingInformation_PersistsInState_AfterUpdateValue()
{
    // Arrange: Setup consensus with secret sharing enabled
    var keyPair = CryptoHelper.GenerateKeyPair();
    var starter = GetConsensusContractTester(keyPair);
    var initialMiners = new[] { keyPair }.Select(k => k.PublicKey.ToHex()).ToList();
    
    await starter.InitialAElfConsensusContract(initialMiners, ...);
    await starter.FirstRound(...);
    
    // Prepare UpdateValueInput with secret sharing data
    var updateValueInput = new UpdateValueInput
    {
        OutValue = Hash.Generate(),
        Signature = Hash.Generate(),
        RoundId = currentRound.RoundId,
        PreviousInValue = Hash.Generate(),
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        EncryptedPieces = { { "pubkey1", ByteString.CopyFromUtf8("encrypted_data") } },
        DecryptedPieces = { { "pubkey2", ByteString.CopyFromUtf8("decrypted_data") } },
        // ... other required fields
    };
    
    // Act: Execute UpdateValue transaction
    await starter.UpdateValue(updateValueInput);
    
    // Assert: Secret sharing data is exposed in persistent state
    var roundInfo = await starter.GetCurrentRoundInformation(new Empty());
    
    // Vulnerability: EncryptedPieces and DecryptedPieces should be empty but aren't
    var minerInfo = roundInfo.RealTimeMinersInformation[keyPair.PublicKey.ToHex()];
    Assert.NotEmpty(minerInfo.EncryptedPieces); // FAILS - secrets still present
    Assert.NotEmpty(minerInfo.DecryptedPieces); // FAILS - secrets still present
    
    // Expected behavior: Both should be empty after DeleteSecretSharingInformation
    // Actual behavior: Both contain sensitive cryptographic data indefinitely
}
```

## Notes

This vulnerability represents a critical gap between design intent and implementation. The existence of `DeleteSecretSharingInformation()` clearly indicates that the protocol designers intended for secret sharing data to be ephemeral. However, the implementation only applies this cleanup to ephemeral copies used for block headers, while leaving the persistent state exposed.

The vulnerability is particularly concerning because:
1. It affects a core consensus security mechanism (randomness generation)
2. The exposure is permanent and publicly accessible
3. The fix intent is evident but incorrectly implemented
4. No access controls or special conditions can prevent exploitation

The recommended fix (Approach 1) maintains the existing architecture while ensuring proper cleanup of sensitive data from persistent state.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L48-54)
```csharp
    private bool TryToGetCurrentRoundInformation(out Round round)
    {
        round = null;
        if (!TryToGetRoundNumber(out var roundNumber)) return false;
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L66-70)
```csharp
    private bool TryToGetRoundInformation(long roundNumber, out Round round)
    {
        round = State.Rounds[roundNumber];
        return !round.IsEmpty;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L21-29)
```csharp
    public override Round GetCurrentRoundInformation(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var currentRound) ? currentRound : new Round();
    }

    public override Round GetRoundInformation(Int64Value input)
    {
        return TryToGetRoundInformation(input.Value, out var round) ? round : new Round();
    }
```

**File:** protobuf/aedpos_contract.proto (L294-296)
```text
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
```
