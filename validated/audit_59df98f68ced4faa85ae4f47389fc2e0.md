# Audit Report

## Title
Missing Size Validation on Encrypted Pieces Allows State Bloat Attack

## Summary
The AEDPoS consensus contract lacks size validation on encrypted secret sharing pieces submitted through the `UpdateValue()` method. A malicious miner can exploit this to inject up to 4.5MB of bloated data per transaction, which persists in state for 40,960 rounds, causing cumulative state bloat and network-wide DoS.

## Finding Description

The vulnerability exists in the secret sharing mechanism where miners submit encrypted pieces without any size constraints. The public `UpdateValue()` method accepts an `UpdateValueInput` parameter containing an `encrypted_pieces` map defined as `map<string, bytes>` with no size limits in the protobuf schema. [1](#0-0) 

When `UpdateValue()` is called, it invokes `ProcessConsensusInformation()` which routes to `ProcessUpdateValue()`. [2](#0-1) 

If secret sharing is enabled, `ProcessUpdateValue()` calls `PerformSecretSharing()` at line 256. [3](#0-2) 

The critical vulnerability occurs in `PerformSecretSharing()` where encrypted pieces are blindly added to state without validation: `minerInRound.EncryptedPieces.Add(input.EncryptedPieces);` [4](#0-3) 

Similarly, `UpdateLatestSecretPieces()` adds encrypted pieces from trigger information without size checks. [5](#0-4) 

The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are non-null and that `PreviousInValue` hashes correctly - it performs no size validation on encrypted pieces. [6](#0-5) 

The only protection is the transaction size limit of 5MB. [7](#0-6) 

However, this is insufficient because bloated rounds persist in state. The system retains 40,960 rounds as defined by `KeepRounds`. [8](#0-7) 

Round cleanup only removes rounds older than `KeepRounds`, allowing bloated data to persist for extended periods. [9](#0-8) 

The attacker must be a valid miner as verified by `PreCheck()`, which only checks miner membership without any size validation. [10](#0-9) 

## Impact Explanation

**State Bloat Severity:** Normal encrypted pieces for legitimate secret sharing among ~17 miners total approximately 3KB per `UpdateValue` transaction. A malicious miner can inflate this to approximately 4.5MB (leaving room for other required fields within the 5MB transaction limit), achieving a 1500x bloat factor.

**Cumulative Damage:** With 40,960 rounds retained in state, if an attacker bloats even 100 rounds before detection, this results in 450MB of unnecessary state. A sustained attack across multiple mining terms could bloat hundreds or thousands of rounds, potentially reaching gigabytes of bloated state.

**Operational Impact:**
- All full nodes must store and synchronize the bloated state data
- New nodes face significantly longer synchronization times
- State queries and consensus operations degrade in performance
- Storage infrastructure costs increase for all network participants
- Potential chain halt if state size becomes unmanageable

**Affected Parties:** All network participants including full nodes, validators, and end users suffer from degraded performance and increased resource requirements. This is a network-wide availability impact.

## Likelihood Explanation

**Attacker Capabilities:** The attacker must be a valid miner in the current or previous round. While this requires winning election, it is achievable through the standard election process without requiring any privileged keys or consensus breaks.

**Attack Complexity:** Low. The attacker only needs to modify their node software to generate oversized `encrypted_pieces` when calling `UpdateValue()`. No complex cryptographic bypasses or precise timing attacks are required.

**Feasibility Conditions:**
- Miner status is required but achievable through the public election process
- No additional economic barriers beyond maintaining miner status
- Attack is immediately executable upon becoming a miner
- Can be repeated across multiple rounds/blocks during the miner's entire tenure

**Detection and Response:** The attack would eventually be detected through monitoring of unusual transaction sizes and state growth. However, damage accumulates before remediation can occur. Network governance would need to vote to exclude the malicious miner, during which time additional bloat continues to accumulate.

**Economic Rationality:** A malicious actor willing to sacrifice their reputation and future mining rewards could execute this attack as a form of griefing, competitive attack against the network, or to cause operational disruption.

## Recommendation

Implement size validation for `encrypted_pieces` and `decrypted_pieces` fields:

1. **Add field size limits in validation:**
   - Define maximum bytes per encrypted piece (e.g., 512 bytes per piece)
   - Define maximum number of pieces per miner (should equal number of miners)
   - Validate in `UpdateValueValidationProvider` or add a new validation provider

2. **Add runtime checks in `PerformSecretSharing()`:**
   ```csharp
   private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round, string publicKey)
   {
       // Validate total size of encrypted pieces
       var totalEncryptedSize = input.EncryptedPieces.Values.Sum(p => p.Length);
       Assert(totalEncryptedSize <= MaxEncryptedPiecesSize, "Encrypted pieces size exceeded.");
       Assert(input.EncryptedPieces.Count <= round.RealTimeMinersInformation.Count, "Too many encrypted pieces.");
       
       minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
       // ... rest of method
   }
   ```

3. **Add similar validation in `UpdateLatestSecretPieces()`**

4. **Define constants for limits:**
   ```csharp
   public const int MaxEncryptedPieceSize = 512; // bytes per piece
   public const int MaxEncryptedPiecesSize = 10240; // 10KB total
   ```

## Proof of Concept

A malicious miner can execute this attack by:

1. Becoming an elected miner through the standard election process
2. Modifying their consensus node to generate a `UpdateValueInput` with bloated `encrypted_pieces`:
   - Create a map with entries for each miner public key
   - Fill each entry with 200KB-300KB of arbitrary bytes
   - Total encrypted_pieces size: ~4.5MB
3. Submit `UpdateValue()` transaction during their mining slot
4. Transaction passes validation (only 5MB limit checked)
5. Bloated data is stored in round state
6. Repeat for each block they mine during their tenure
7. Data persists for 40,960 rounds (~several days to weeks depending on round duration)

The attack requires only standard miner capabilities and causes persistent state bloat affecting all network participants.

## Notes

This vulnerability represents a fundamental input validation failure in consensus state management. The 5MB transaction limit is insufficient protection because it allows individual transactions to bloat state with megabytes of data that persists for tens of thousands of rounds. The lack of per-field validation on critical consensus data structures creates a griefing vector where a single malicious miner can cause network-wide performance degradation and availability issues.

### Citations

**File:** protobuf/aedpos_contract.proto (L210-210)
```text
    map<string, bytes> encrypted_pieces = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L10-10)
```csharp
    public const int KeepRounds = 40960;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L118-123)
```csharp
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
```
