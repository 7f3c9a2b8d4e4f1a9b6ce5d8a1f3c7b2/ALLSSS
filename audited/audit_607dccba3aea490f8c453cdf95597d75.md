### Title
Information Leakage of Secret Sharing Data Through Consensus Validation Error Messages

### Summary
The AEDPoS consensus validation system exposes sensitive secret sharing information (encrypted and decrypted pieces) through error messages that are logged during validation failures. Round objects containing secret shares are directly serialized using protobuf's default ToString() method, which includes all fields in JSON format, and these error messages are logged via debug logging mechanisms accessible to node operators.

### Finding Description

**Root Cause:**
The `Round` protobuf message contains sensitive secret sharing data in `encrypted_pieces` and `decrypted_pieces` fields within `MinerInRound` submessages. [1](#0-0) 

When consensus validation fails, error messages directly embed `Round` objects using string interpolation without format specifiers (e.g., `{this}`), which invokes the protobuf base `ToString()` method that serializes ALL fields to JSON format.

**Vulnerable Code Locations:**

1. **CheckRoundTimeSlots validation errors:** [2](#0-1) [3](#0-2) 

2. **ValidateConsensusAfterExecution errors:** [4](#0-3) 

3. **Error message logging:** [5](#0-4) [6](#0-5) 

**Why Existing Protections Fail:**

The `Round` class implements `IFormattable` with a custom `ToString(string format, IFormatProvider)` method, but when string interpolation uses `{this}` without a format specifier, C# calls the parameterless `ToString()` method. [7](#0-6) 

The custom format "G" explicitly returns the base `ToString()`, and without a format specifier, the protobuf-generated `ToString()` is invoked, which serializes all fields including `encrypted_pieces` and `decrypted_pieces`.

While `GetCheckableRound()` method exists to create sanitized Round copies with secret sharing data cleared, it is ONLY used for hash computation, not for error message serialization: [8](#0-7) 

### Impact Explanation

**Sensitive Data Exposed:**
- `encrypted_pieces`: Map of miner pubkey → encrypted secret shares (bytes encoded as base64 in JSON)
- `decrypted_pieces`: Map of miner pubkey → decrypted secret shares (already decrypted, more sensitive)

These contain Shamir secret shares used in the AEDPoS consensus mechanism for generating random numbers and validating miners' previous InValues. [9](#0-8) 

**Attack Impact:**
- An attacker with access to debug logs can extract encrypted/decrypted pieces from multiple validation failures
- With sufficient decrypted pieces (2/3 threshold), an attacker can reconstruct miners' InValues
- This compromises the randomness and fairness of the consensus mechanism
- Attackers could predict or influence block production order and timing

**Affected Parties:**
- All consensus miners whose secret shares are exposed
- Network security depending on consensus randomness integrity
- Users affected by potential consensus manipulation

**Severity Justification:**
Low to Medium severity because:
- Requires debug logging to be enabled (common in development/testing environments)
- Requires attacker access to node logs (compromised node operator or misconfigured logging infrastructure)
- Encrypted pieces still require cryptographic attacks to fully exploit
- Decrypted pieces provide more direct attack surface

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Access to debug logs from consensus nodes (via compromised node, log aggregation systems, or misconfigured log exports)
2. Ability to trigger validation failures (malformed blocks, timing manipulation)

**Attack Complexity:**
- **Medium**: Triggering validation failures is straightforward (submit blocks with incorrect timing or round information)
- Log access varies by deployment: easier in test/dev environments, harder in production with proper security

**Feasibility Conditions:**
- Debug logging enabled (`Context.LogDebug()` and `Logger.LogDebug()` calls are active in debug builds)
- Validation failures occur naturally or can be induced
- Logs are retained and accessible to attacker

**Detection Constraints:**
- Legitimate debug logging makes malicious log access hard to distinguish
- Validation failures are expected during normal network operation (Byzantine miners, network delays)

**Probability Assessment:**
Moderate probability in environments with:
- Debug builds deployed to production
- Centralized log aggregation without proper access controls
- Compromised node operators
- Misconfigured cloud logging services exposing sensitive data

### Recommendation

**Immediate Mitigation:**
1. Override the parameterless `ToString()` method in the `Round` partial class to use the sanitized `GetLogs()` method by default:

```csharp
public override string ToString()
{
    return GetLogs(""); // Returns formatted output without secret sharing data
}
```

2. Alternatively, modify error messages to explicitly exclude Round serialization or use `GetCheckableRound()` for string representation:

```csharp
// In Round.cs CheckRoundTimeSlots
return new ValidationResult { 
    Message = $"Incorrect expected mining time. Round {RoundNumber}, Term {TermNumber}" 
};

// In ValidateConsensusAfterExecution
var sanitizedHeader = headerInformation.Round.Clone();
sanitizedHeader.DeleteSecretSharingInformation();
var sanitizedCurrent = currentRound.Clone();
sanitizedCurrent.DeleteSecretSharingInformation();
Message = "Current round information is different with consensus extra data.\n" +
          $"New block header consensus information:\n{sanitizedHeader}" +
          $"Stated block header consensus information:\n{sanitizedCurrent}"
```

3. Add explicit check to ensure `encrypted_pieces` and `decrypted_pieces` are cleared before any string serialization for logging purposes.

**Long-term Solution:**
- Implement `ICustomDiagnosticMessage` interface for `Round` to control diagnostic string output
- Add automated tests to verify secret sharing data is never exposed in error messages
- Use structured logging with explicit field filtering for sensitive consensus data
- Add runtime checks to detect and prevent logging of protobuf fields containing `encrypted_pieces` or `decrypted_pieces`

**Test Cases:**
- Verify Round.ToString() does not contain "encrypted_pieces" or "decrypted_pieces" keywords
- Trigger validation failures and assert log output excludes secret sharing data
- Parse ValidationResult.Message as JSON and verify sensitive fields are absent

### Proof of Concept

**Required Initial State:**
- Node running in debug mode with `Context.LogDebug()` enabled
- Multiple miners participating in consensus with secret sharing active
- Attacker has access to node debug logs

**Attack Steps:**

1. **Trigger CheckRoundTimeSlots validation failure:**
   - Submit a block with incorrect expected mining times for miners
   - Validation fails at `CheckRoundTimeSlots()` 
   - Error message includes `{this}` serialization of Round object containing encrypted/decrypted pieces

2. **Trigger ValidateConsensusAfterExecution failure:**
   - Submit a block where round information hash doesn't match state
   - Validation fails with mismatch detection
   - Error message directly serializes both `headerInformation.Round` and `currentRound` with all fields

3. **Extract from logs:**
   - Access debug logs via log aggregation system, compromised node, or misconfigured exports
   - Parse JSON output from ValidationResult.Message
   - Extract `realTimeMinersInformation[*].encryptedPieces` and `decryptedPieces` maps

4. **Exploit secret shares:**
   - Collect decrypted pieces from multiple validation failures
   - With 2/3 threshold met, reconstruct target miner's InValue using Shamir secret reconstruction
   - Predict or influence future consensus decisions

**Expected vs Actual Result:**
- **Expected**: Error messages should contain only round metadata (round number, term, miner count) without secret sharing data
- **Actual**: Error messages contain complete Round JSON serialization including base64-encoded encrypted/decrypted pieces

**Success Condition:**
Attacker successfully extracts and reconstructs at least one miner's InValue from log data, demonstrating compromise of consensus randomness.

**Notes:**
While the vulnerability is real and the information leakage occurs, the practical exploitability depends heavily on deployment configuration (debug mode, log access controls) and cryptographic strength of the secret sharing encryption. Production environments with proper security controls (release builds, restricted log access) significantly reduce the risk.

### Citations

**File:** protobuf/aedpos_contract.proto (L293-296)
```text
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L40-41)
```csharp
        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L46-47)
```csharp
        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-196)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L107-113)
```csharp
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L138-140)
```csharp
        if (!validationResult.Success)
        {
            Logger.LogDebug($"Consensus validating before execution failed: {validationResult.Message}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L100-101)
```csharp
        if (validationResult.Success == false)
            Context.LogDebug(() => $"Consensus Validation before execution failed : {validationResult.Message}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLogs.cs (L9-22)
```csharp
    public string ToString(string format, IFormatProvider formatProvider = null)
    {
        if (string.IsNullOrEmpty(format)) format = "G";

        switch (format)
        {
            case "G": return ToString();
            case "M":
                // Return formatted miner list.
                return RealTimeMinersInformation.Keys.Aggregate("\n", (key1, key2) => key1 + "\n" + key2);
        }

        return GetLogs(format);
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L95-142)
```csharp
    private async Task CollectPiecesWithSecretSharingAsync(SecretSharingInformation secretSharingInformation,
        Hash newInValue, string selfPubkey)
    {
        var encryptedPieces = new Dictionary<string, byte[]>();
        var decryptedPieces = new Dictionary<string, byte[]>();

        var minersCount = secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        var secretShares =
            SecretSharingHelper.EncodeSecret(newInValue.ToByteArray(), minimumCount, minersCount);

        foreach (var pair in secretSharingInformation.PreviousRound.RealTimeMinersInformation
                     .OrderBy(m => m.Value.Order).ToDictionary(m => m.Key, m => m.Value.Order))
        {
            var pubkey = pair.Key;
            var order = pair.Value;

            var plainMessage = secretShares[order - 1];
            var receiverPublicKey = ByteArrayHelper.HexStringToByteArray(pubkey);
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
            decryptedPieces[pubkey] = decryptedPiece;
            secretSharingInformation.PreviousRound.RealTimeMinersInformation[pubkey].DecryptedPieces[selfPubkey]
                = ByteString.CopyFrom(decryptedPiece);
        }

        _encryptedPieces[secretSharingInformation.CurrentRoundId] = encryptedPieces;
        _decryptedPieces[secretSharingInformation.CurrentRoundId] = decryptedPieces;
    }
```
