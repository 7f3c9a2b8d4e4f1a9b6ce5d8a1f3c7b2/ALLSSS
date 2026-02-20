# Audit Report

## Title
Case-Sensitive Pubkey Comparison Causes Valid Miner Rejection After Candidate Replacement

## Summary
When a candidate's public key is replaced through `ReplaceCandidatePubkey`, if the new pubkey string contains uppercase hex characters, it creates a case mismatch that prevents the miner from producing blocks. The root cause is that normal round generation uses lowercase hex via `ToHex()`, but the replacement flow stores the input string without case normalization, while all validation and block production logic expects lowercase keys.

## Finding Description

The vulnerability stems from inconsistent case handling across the candidate replacement and consensus flows:

**Normal Flow:** When rounds are generated, miner pubkeys are converted to lowercase hex strings using `.ToHex()` and stored as dictionary keys in `RealTimeMinersInformation`. [1](#0-0)  The `ToHex()` implementation uses the formula `b + 0x37 + 0x20` for values 10-15, which produces lowercase 'a'-'f' characters (ASCII 97-102). [2](#0-1) 

**Replacement Flow:** When `ReplaceCandidatePubkey` is called, the input hex strings are validated by `ByteArrayHelper.HexStringToByteArray`, which accepts both uppercase and lowercase hex characters via `Convert.ToByte(hex.Substring(i, 2), 16)`. [3](#0-2)  The method passes these strings directly to the consensus contract without normalization. [4](#0-3) 

**Consensus Update:** The `RecordCandidateReplacement` method uses the input strings AS-IS as dictionary keys. [5](#0-4)  If `NewPubkey` contains uppercase characters, the dictionary key will be stored with that casing.

**Block Production Failure:** When the miner attempts to produce a block, `GetConsensusBlockExtraData` converts their pubkey to lowercase via `ToHex()`. [6](#0-5)  This lowercase key is then used to access `RealTimeMinersInformation`, which fails if the stored key has uppercase characters.

**Validation Failure:** The `MiningPermissionValidationProvider` performs case-sensitive `Contains()` checking on the dictionary keys. [7](#0-6)  The `SenderPubkey` property always produces lowercase via `ToHex()`. [8](#0-7) 

## Impact Explanation

**Severity: Low**

The impact is a consensus availability issue where a valid miner becomes unable to produce blocks. This directly affects network operation as the affected miner cannot fulfill their consensus duties. However, severity is assessed as Low because:

- Requires candidate admin role (semi-trusted position, not arbitrary attacker)
- Only affects one miner at a time (not systemic)
- Immediately detectable (miner fails to produce blocks)
- Easily recoverable (admin can call `ReplaceCandidatePubkey` again with lowercase hex)
- No fund loss or permanent state corruption
- More likely to occur accidentally than maliciously

## Likelihood Explanation

**Likelihood: Low**

While the vulnerability is technically exploitable, the probability is low because:

- Standard SDK tooling generates lowercase hex via `ToHex()`
- Requires admin to manually input or construct uppercase hex strings
- Needs intentional deviation from normal tooling or direct API calls
- Most development workflows would not produce uppercase hex

However, it can occur in scenarios like:
- Manual administrative operations during emergency procedures
- Custom integration tools that don't use standard SDK methods
- Copy-paste errors with hex strings from external sources

## Recommendation

Add case normalization in the Election contract before passing pubkey strings to the consensus contract. Modify the `ReplaceCandidatePubkey` method:

```csharp
public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
{
    // Normalize to lowercase
    var oldPubkey = input.OldPubkey.ToLower();
    var newPubkey = input.NewPubkey.ToLower();
    
    Assert(IsCurrentCandidateOrInitialMiner(oldPubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(oldPubkey) && !IsPubkeyBanned(newPubkey),
        "Pubkey is in already banned.");
    
    // Permission check.
    Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = oldPubkey }), "No permission.");
    
    // Record the replacement with normalized keys
    PerformReplacement(oldPubkey, newPubkey);
    // ... rest of implementation
}
```

Alternatively, normalize in the `RecordCandidateReplacement` method:

```csharp
public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
{
    Assert(Context.Sender == State.ElectionContract.Value,
        "Only Election Contract can record candidate replacement information.");
    
    // Normalize to lowercase
    var oldPubkey = input.OldPubkey.ToLower();
    var newPubkey = input.NewPubkey.ToLower();
    
    if (!TryToGetCurrentRoundInformation(out var currentRound) ||
        !currentRound.RealTimeMinersInformation.ContainsKey(oldPubkey)) return new Empty();
    
    var realTimeMinerInformation = currentRound.RealTimeMinersInformation[oldPubkey];
    realTimeMinerInformation.Pubkey = newPubkey;
    currentRound.RealTimeMinersInformation.Remove(oldPubkey);
    currentRound.RealTimeMinersInformation.Add(newPubkey, realTimeMinerInformation);
    // ... rest of implementation
}
```

## Proof of Concept

The PoC would demonstrate calling `ReplaceCandidatePubkey` with an uppercase hex string in `NewPubkey`, then attempting block production which would fail due to the case mismatch in dictionary lookup during validation. A test implementation would need to:

1. Set up a candidate admin and announce election
2. Call `ReplaceCandidatePubkey` with uppercase hex in `NewPubkey` 
3. Trigger block production for the replaced miner
4. Verify that `MiningPermissionValidationProvider` rejects the block due to case mismatch

## Notes

This is a code robustness issue with real consensus availability impact. While the likelihood is low due to standard tooling using lowercase hex, the lack of input normalization creates an operational risk during manual administration or when using non-standard integration tools. The fix is straightforward: normalize all pubkey strings to lowercase before storing them as dictionary keys.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L16-17)
```csharp
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
```

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L25-25)
```csharp
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
```

**File:** src/AElf.Types/Helper/ByteArrayHelper.cs (L16-16)
```csharp
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L298-302)
```csharp
        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L143-143)
```csharp
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L23-23)
```csharp
        var pubkey = publicKeyBytes.ToHex();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-17)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L17-17)
```csharp
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();
```
