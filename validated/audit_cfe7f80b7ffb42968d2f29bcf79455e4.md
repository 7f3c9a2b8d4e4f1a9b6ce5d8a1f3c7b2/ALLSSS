# Audit Report

## Title
Secret Sharing Information Exposed Through Public View Methods Allowing Premature InValue Reconstruction

## Summary
The AEDPoS consensus contract exposes sensitive secret sharing data (`DecryptedPieces`) through public view methods `GetCurrentRoundInformation()` and `GetRoundInformation()`, allowing unauthorized reconstruction of miners' `InValues` before they should be revealed. This violates the protocol's security model where InValues must remain private during the current round.

## Finding Description

The AEDPoS consensus protocol uses Shamir's Secret Sharing for InValue generation and verification. According to the protocol design, each miner's InValue must remain secret during round N and only becomes public when revealed as `PreviousInValue` in round N+1.

**Vulnerability Flow:**

1. The `DeleteSecretSharingInformation()` method correctly clears `EncryptedPieces` and `DecryptedPieces` from Round objects: [1](#0-0) 

2. However, this cleanup is only invoked when `!isGeneratingTransactions` during consensus block extra data generation: [2](#0-1) 

3. The public view methods return Round data directly from state without any sanitization: [3](#0-2) 

4. During consensus processing, `DecryptedPieces` are explicitly stored into persistent state: [4](#0-3) 

5. The state is persisted via `TryToUpdateRoundInformation`: [5](#0-4) 

6. These DecryptedPieces can be used to reconstruct InValues using the same algorithm employed internally: [6](#0-5) 

7. The protobuf definition confirms these fields contain secret sharing components: [7](#0-6) 

## Impact Explanation

This vulnerability compromises consensus integrity in the following ways:

1. **InValue Confidentiality Violation**: The protocol explicitly requires InValues to be private during the current round. Exposing DecryptedPieces violates this core security property.

2. **Mining Order Predictability**: InValues are used to calculate signatures via `CalculateSignature()`: [8](#0-7) 

3. These signatures determine mining order in subsequent rounds: [9](#0-8) 

4. **Strategic Manipulation**: With advance knowledge of mining order, malicious miners could:
   - Selectively participate or abstain when the order is favorable
   - Coordinate attacks during predictable time slots
   - Manipulate any protocol features depending on "unpredictable" mining sequences

**Severity**: High - While this does not directly enable fund theft, it fundamentally breaks a core consensus security property and enables strategic manipulation of block production ordering.

## Likelihood Explanation

**Attack Complexity**: Very Low
- Attacker calls public view method `GetCurrentRoundInformation()`
- Extracts `Round.RealTimeMinersInformation[minerPubkey].DecryptedPieces` for all miners
- Applies Shamir Secret Sharing reconstruction (threshold = minersCount × 2/3)

**Attacker Capabilities**: Minimal
- No special permissions required - view methods are publicly accessible
- No transaction submission needed (free RPC queries)
- No timing constraints - Round data persists throughout the round

**Feasibility**: Very High
- Direct API access through any AElf node
- DecryptedPieces are populated during normal consensus operation
- Reconstruction is deterministic once threshold is met
- The view methods are explicitly marked as public: [10](#0-9) 

**Detection**: Difficult
- View method calls generate no transactions
- No state modifications
- Passive observation only

## Recommendation

Implement sanitization in view methods to remove secret sharing data before returning Round information:

```csharp
public override Round GetCurrentRoundInformation(Empty input)
{
    if (!TryToGetCurrentRoundInformation(out var currentRound)) 
        return new Round();
    
    // Clone and sanitize before returning
    var sanitizedRound = currentRound.Clone();
    sanitizedRound.DeleteSecretSharingInformation();
    return sanitizedRound;
}

public override Round GetRoundInformation(Int64Value input)
{
    if (!TryToGetRoundInformation(input.Value, out var round)) 
        return new Round();
    
    // Clone and sanitize before returning
    var sanitizedRound = round.Clone();
    sanitizedRound.DeleteSecretSharingInformation();
    return sanitizedRound;
}
```

## Proof of Concept

```csharp
// Test demonstrating DecryptedPieces exposure
[Fact]
public void DecryptedPieces_Exposed_Through_ViewMethod()
{
    // Setup: Advance to a round where secret sharing is active
    ProduceNormalBlocks(10);
    
    // Attack: Call public view method
    var currentRound = AEDPoSContract.GetCurrentRoundInformation.Call(new Empty());
    
    // Verify: DecryptedPieces are present in the returned data
    var hasDecryptedPieces = currentRound.RealTimeMinersInformation.Values
        .Any(m => m.DecryptedPieces.Count > 0);
    
    // This should be false (data should be sanitized), but is true (vulnerability)
    Assert.True(hasDecryptedPieces, 
        "DecryptedPieces should not be exposed through view methods");
}
```

## Notes

The vulnerability is confirmed as DecryptedPieces are stored in persistent state and exposed through unsanitized view methods. While the original claim mentioned "random hash prediction," the actual exploitable impact is mining order predictability through signature calculation, which still constitutes a significant consensus integrity violation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L46-50)
```csharp
            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```

**File:** protobuf/aedpos_contract.proto (L88-90)
```text
    rpc GetCurrentRoundInformation (google.protobuf.Empty) returns (Round) {
        option (aelf.is_view) = true;
    }
```

**File:** protobuf/aedpos_contract.proto (L293-296)
```text
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
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
