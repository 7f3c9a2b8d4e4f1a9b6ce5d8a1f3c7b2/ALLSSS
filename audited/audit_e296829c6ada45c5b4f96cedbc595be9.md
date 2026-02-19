### Title
Unvalidated Other Miners' PreviousInValues Allow Cryptographic Commit-Reveal Bypass in Secret Sharing

### Summary
The `PerformSecretSharing()` function accepts arbitrary `PreviousInValue` hashes for other miners without cryptographic validation against their previous round `OutValue` commitments. While the current miner's own `PreviousInValue` is validated, other miners' values in `input.MinersPreviousInValues` are directly applied to consensus state, breaking the commit-reveal scheme that underpins AEDPoS consensus security.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The `PerformSecretSharing()` function blindly sets `PreviousInValue` for all miners from the input map without validating that these values cryptographically match the `OutValue` commitments from the previous round.

**Execution Path**:
1. Malicious miner generates trigger information with arbitrary `RevealedInValues` for other miners
2. `GetConsensusExtraDataToPublishOutValue()` accepts this trigger information and calls `UpdateLatestSecretPieces()` which directly sets these values: [2](#0-1) 
3. `ExtractInformationToUpdateConsensus()` extracts all `PreviousInValue` entries into `MinersPreviousInValues`: [3](#0-2) 
4. `ValidateBeforeExecution()` only validates the **sender's** `PreviousInValue`, not others: [4](#0-3) 
5. `PerformSecretSharing()` applies all values without validation
6. `ValidateAfterExecution()` compares round hashes that include these `PreviousInValues`, but since both header and state contain the same (incorrect) values, hashes match: [5](#0-4) 

**Why Protections Fail**: The validation in `UpdateValueValidationProvider.ValidatePreviousInValue()` only checks `validationContext.SenderPubkey` (line 38), not all miners in the `MinersPreviousInValues` map. The hash comparison in `ValidateAfterExecution()` verifies consistency between header and transaction but not cryptographic correctness against previous round commitments.

### Impact Explanation

**Harm**: Breaks the fundamental cryptographic commit-reveal invariant of AEDPoS consensus: `HashHelper.ComputeFrom(PreviousInValue) == OutValue_from_previous_round`. This invariant is critical because:

1. **Consensus Integrity Violation**: The secret sharing mechanism is designed so miners commit to random values (`OutValue`) in round N, then reveal the preimage (`PreviousInValue`) in round N+1 for verification. Incorrect values bypass this verification.

2. **Signature Calculation Corruption**: `PreviousInValue` is used in `CalculateSignature()` which determines mining order for the next round: [6](#0-5) 
   The corrupted signature affects `SupposedOrderOfNextRound` calculation: [7](#0-6) 

3. **Secret Sharing Bypass**: The legitimate secret sharing recovery via `RevealSharedInValues()` using `SecretSharingHelper.DecodeSecret()` is bypassed: [8](#0-7) 

**Affected Parties**: All miners whose `PreviousInValue` is incorrectly set, potentially affecting consensus randomness and mining schedule fairness.

**Severity**: HIGH - violates critical consensus cryptographic invariants, though doesn't directly steal funds.

### Likelihood Explanation

**Attacker Capabilities**: Must be a current miner with valid block production rights.

**Attack Complexity**: LOW
- Attacker modifies the `RevealedInValues` in their `AElfConsensusTriggerInformation` when calling `GetConsensusExtraData()`
- Provides arbitrary hash values for other miners instead of cryptographically correct values
- No special cryptographic knowledge required beyond being able to generate arbitrary hashes

**Feasibility Conditions**:
- Attacker is in current miner list (verified in `PreCheck()`): [9](#0-8) 
- It's attacker's time slot to produce block
- Secret sharing is enabled: [10](#0-9) 

**Detection**: Difficult - the incorrect values appear valid in format, and validation only ensures consistency not correctness. Other miners would need to compare against their own records of the previous round's `OutValues`.

**Probability**: HIGH for motivated attacker with miner access.

### Recommendation

**Code-Level Mitigation**: Add validation loop in `PerformSecretSharing()` to verify each entry in `MinersPreviousInValues`:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey, Round previousRound)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        // ADDED: Validate against previous round's OutValue
        if (previousRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
        {
            var previousOutValue = previousRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
            if (previousOutValue != null && previousOutValue != Hash.Empty)
            {
                var computedHash = HashHelper.ComputeFrom(previousInValue.Value);
                Assert(computedHash == previousOutValue, 
                    $"Invalid PreviousInValue for miner {previousInValue.Key}");
            }
        }
        round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
    }
}
```

**Alternative**: Add validation in `UpdateLatestSecretPieces()` to verify `RevealedInValues` before they're set: [11](#0-10) 

**Test Cases**: 
- Test that providing incorrect `RevealedInValues` for other miners causes transaction rejection
- Test that only cryptographically correct `PreviousInValues` (matching previous `OutValue`) are accepted
- Test secret sharing recovery still works when legitimate values are provided

### Proof of Concept

**Initial State**:
- Chain has multiple miners (A, B, C, D)
- In Round N: Miner B committed `OutValue_B = Hash(InValue_B)` where `InValue_B = "legitimate_secret"`
- Round N+1 begins, Miner A's turn to produce block

**Attack Steps**:
1. Miner A prepares trigger information with malicious `RevealedInValues`:
   - `RevealedInValues[B] = Hash("attacker_controlled_fake_value")` (does NOT equal `InValue_B`)
2. Miner A calls `GetConsensusExtraData()` with this trigger information
3. `UpdateLatestSecretPieces()` sets Miner B's `PreviousInValue` to the fake value
4. `UpdateValue` transaction is generated with `MinersPreviousInValues[B] = fake_value`
5. `ValidateBeforeExecution()` passes (only checks Miner A's own `PreviousInValue`)
6. `PerformSecretSharing()` executes, setting `round.RealTimeMinersInformation[B].PreviousInValue = fake_value`
7. `ValidateAfterExecution()` passes (hashes match because both header and state have fake value)

**Expected Result**: Transaction should be rejected because `Hash(fake_value) != OutValue_B`

**Actual Result**: Transaction succeeds, Miner B's `PreviousInValue` is set to incorrect value, breaking commit-reveal scheme

**Success Condition**: Check that `round.RealTimeMinersInformation[B].PreviousInValue` is set to fake value, and that `HashHelper.ComputeFrom(fake_value) != previousRound.RealTimeMinersInformation[B].OutValue`

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L254-257)
```csharp
        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L295-296)
```csharp
        foreach (var previousInValue in input.MinersPreviousInValues)
            round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-101)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```
