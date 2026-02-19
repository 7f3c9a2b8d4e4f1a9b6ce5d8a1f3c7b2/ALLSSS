### Title
Unvalidated Decrypted Secret Pieces Enable Secret Sharing Corruption in AEDPoS Consensus

### Summary
The `UpdateLatestSecretPieces()` function accepts and stores decrypted secret pieces from miners without any cryptographic validation, allowing any malicious miner to submit arbitrary data claiming to be decrypted pieces of other miners' secrets. When these corrupted pieces are used in `RevealSharedInValues()` for Shamir's Secret Sharing reconstruction, the wrong InValue is revealed and set as PreviousInValue, corrupting the consensus randomness mechanism and breaking the security guarantees of the threshold secret sharing scheme.

### Finding Description

The vulnerability exists in the `UpdateLatestSecretPieces()` function where decrypted pieces are stored without validation: [1](#0-0) 

**Root Cause**: The function only checks if the target miner exists in `RealTimeMinersInformation`, but performs NO validation that:
1. The submitting miner actually received an encrypted piece from the target miner
2. The decrypted piece is cryptographically valid
3. The decrypted piece corresponds to any legitimate encrypted piece

**Execution Path**:
1. During block production, miners call `GetConsensusExtraDataToPublishOutValue()` which invokes `UpdateLatestSecretPieces()`: [2](#0-1) 

2. Malicious miner submits crafted `DecryptedPieces` containing arbitrary data for other miners' secrets

3. These pieces are stored at line 145 without any validation

4. During next round transition, `RevealSharedInValues()` reconstructs secrets using ALL submitted decrypted pieces: [3](#0-2) 

5. The function uses `SecretSharingHelper.DecodeSecret()` with the corrupted pieces, producing a WRONG reconstructed InValue

6. This wrong value is set as PreviousInValue WITHOUT validation against the original OutValue

**Why Existing Protections Fail**: The only validation that exists is when a miner submits their OWN PreviousInValue: [4](#0-3) 

However, this validation does NOT apply to PreviousInValues revealed through secret sharing reconstruction in `RevealSharedInValues()`.

### Impact Explanation

**Consensus Integrity Violation**: 
- PreviousInValue is used in signature calculations for consensus randomness: [5](#0-4) 

- Corrupted PreviousInValues can manipulate the randomness beacon, affecting miner ordering and consensus fairness

**Secret Sharing Security Break**: 
- The threshold secret sharing scheme guarantees that secrets can be reconstructed if 2/3 of miners cooperate
- A single malicious miner can inject fake pieces, corrupting reconstruction for ALL target miners
- This breaks the Byzantine fault tolerance guarantee of the secret sharing mechanism

**Denial of Service**: 
- Legitimate miners' InValues cannot be properly revealed
- The consensus mechanism degrades as secret sharing becomes unreliable
- Affects all miners in the network when secret sharing is enabled

**Severity: Critical** - Breaks consensus randomness and core cryptographic security properties with low attack complexity.

### Likelihood Explanation

**Attacker Capabilities**: 
- Attacker must be a miner in the consensus set
- No special privileges required beyond normal mining rights

**Attack Complexity**: LOW
- Simply submit arbitrary data in `triggerInformation.DecryptedPieces` during block production
- No cryptographic operations needed
- No coordination with other actors required

**Feasibility Conditions**:
- Secret sharing must be enabled (checked via configuration)
- Attacker produces at least one block in the round

**Detection Difficulty**: HIGH
- No on-chain validation to detect malicious pieces
- Off-chain services decrypt pieces correctly but cannot prevent on-chain corruption
- Requires analyzing revealed InValues against original OutValues to detect

**Economic Rationality**: 
- Near-zero cost (normal block production)
- High impact (disrupts consensus for entire network)
- Risk/reward heavily favors attack

### Recommendation

**Immediate Fix**:
Add cryptographic validation in `UpdateLatestSecretPieces()` and `PerformSecretSharing()` to verify decrypted pieces:

1. **Validate against original OutValue**: After reconstruction in `RevealSharedInValues()`, add check:
```csharp
if (HashHelper.ComputeFrom(revealedInValue) != anotherMinerInPreviousRound.OutValue)
    continue; // Skip invalid reconstruction
```

2. **Store encrypted piece verification data**: When miners submit encrypted pieces, store commitment data that can later verify decrypted pieces are legitimate

3. **Limit decryption scope**: Only allow miners to submit decrypted pieces for miners who actually sent them encrypted pieces in previous rounds

**Additional Invariant Checks**:
- Assert that reconstructed InValue hashes to the published OutValue
- Verify DecryptedPieces count matches EncryptedPieces distribution
- Add threshold validation: reject if too many pieces are invalid

**Test Cases**:
- Test malicious miner submitting arbitrary decrypted pieces
- Verify reconstruction fails gracefully with invalid pieces
- Confirm OutValue validation catches corrupted revelations
- Test with various malicious piece counts (1, threshold-1, threshold, all)

### Proof of Concept

**Initial State**:
- Secret sharing enabled in network configuration
- Miner A, Miner B, and Miner C in consensus set
- Round N: Miner A publishes OutValue_A = Hash(InValue_A) and distributes encrypted pieces

**Attack Steps**:

1. **Miner B produces block in Round N**:
   - Includes legitimate EncryptedPieces for distribution
   - Submits MALICIOUS DecryptedPieces: `{"MinerA": "0xDEADBEEF..."}`
   - These fake pieces claim to be Miner A's secret but are arbitrary data

2. **Malicious pieces stored without validation** (line 145):
   - `RealTimeMinersInformation["MinerA"].DecryptedPieces["MinerB"] = "0xDEADBEEF..."`
   - No check that this corresponds to any real encrypted piece
   - No validation against cryptographic properties

3. **Next round transition occurs**:
   - `RevealSharedInValues()` called during NextRound
   - Collects DecryptedPieces including malicious "0xDEADBEEF..." from Miner B
   - Calls `SecretSharingHelper.DecodeSecret()` with corrupted data

4. **Wrong secret reconstructed**:
   - DecodeSecret returns garbage value != original InValue_A
   - `revealedInValue_corrupted = Hash(garbage_value)`
   - Sets `CurrentRound.RealTimeMinersInformation["MinerA"].PreviousInValue = revealedInValue_corrupted`

**Expected vs Actual Result**:
- **Expected**: PreviousInValue = Hash(InValue_A) matching OutValue_A from previous round
- **Actual**: PreviousInValue = corrupted value that does NOT match OutValue_A
- **Consequence**: Consensus randomness calculation uses wrong value, breaking security assumptions

**Success Condition**: 
Query `GetCurrentRoundInformation()` and verify `RealTimeMinersInformation["MinerA"].PreviousInValue != Hash(InValue_A)` despite correct OutValue_A being published in previous round.

### Notes

The vulnerability is particularly severe because:
1. It requires only a single malicious miner to corrupt the entire secret sharing mechanism
2. The attack is undetectable on-chain without post-reconstruction validation
3. It breaks a fundamental cryptographic security property (threshold secret sharing)
4. The same vulnerability exists in `PerformSecretSharing()` which processes UpdateValueInput: [6](#0-5) 

The off-chain `SecretSharingService` correctly encrypts and decrypts pieces using proper cryptography, but the on-chain contract accepts the results blindly without verification, creating a trust boundary violation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L122-125)
```csharp
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L143-146)
```csharp
        foreach (var decryptedPiece in triggerInformation.DecryptedPieces)
            if (updatedRound.RealTimeMinersInformation.ContainsKey(decryptedPiece.Key))
                updatedRound.RealTimeMinersInformation[decryptedPiece.Key].DecryptedPieces[pubkey] =
                    decryptedPiece.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```
