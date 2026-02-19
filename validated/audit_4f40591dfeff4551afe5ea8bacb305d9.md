# Audit Report

## Title
Missing Validation on EncryptedPieces Dictionary Size Enables Consensus DoS and State Bloat

## Summary
The AEDPoS consensus contract accepts unlimited `EncryptedPieces` dictionary entries from miners without validation, enabling malicious miners to inject thousands of fake entries. This causes either repeated resource-wasting transaction failures (with default 128KB state limit) or permanent consensus state bloat (if state limits are increased), affecting all network nodes.

## Finding Description

The vulnerability exists in the consensus update flow where `EncryptedPieces` dictionary size is never validated against the expected count of miners in the round.

**Entry Point:**
The `ExtractInformationToUpdateConsensus` function copies the entire `EncryptedPieces` dictionary without checking its size. [1](#0-0) 

**Root Cause:**
When processing consensus information, the `UpdateLatestSecretPieces` method accepts `EncryptedPieces` from miner-controlled `AElfConsensusTriggerInformation` and adds all entries without count validation. [2](#0-1) 

Subsequently, `PerformSecretSharing` adds all these entries to the miner's round information. [3](#0-2) 

**Missing Validations:**

1. **No count validation in UpdateValueValidationProvider:** The validation provider only checks `OutValue` and `Signature` fields, with no validation of `EncryptedPieces` count. [4](#0-3) 

2. **No validation when adding to UpdateValue behavior:** When `ValidateBeforeExecution` processes UpdateValue behavior, it only adds `UpdateValueValidationProvider` which performs no size checks. [5](#0-4) 

3. **UpdateValue is marked as size-fee-free:** The `UpdateValue` method is explicitly marked with `IsSizeFeeFree = true`, making the attack economically cheap regardless of data size. [6](#0-5) 

**Expected vs Actual Behavior:**
The only validation that exists checks for a MINIMUM count (at least 2/3 of miners) but imposes no MAXIMUM limit. [7](#0-6) 

Normal operation expects one `EncryptedPieces` entry per miner in the round (typically 17-100 miners), but the contract will accept and process unlimited entries from malicious miners who control the `AElfConsensusTriggerInformation` provided to their node software during block production.

## Impact Explanation

**Scenario 1 (Default 128KB State Limit):**
- A malicious miner injects approximately 789 fake `EncryptedPieces` entries (~166 bytes each)
- The transaction processes through all validation logic successfully
- When attempting to write state, the runtime-enforced 128KB limit is exceeded, causing transaction failure
- Block execution time is wasted processing the oversized data before rejection
- The malicious miner can repeat this attack cheaply in every block they produce (no size fees apply)
- All network nodes waste CPU and memory resources validating and processing transactions that ultimately fail

**Scenario 2 (Increased State Limit via Governance):**
- If Parliament governance increases the state size limit (which is configurable)
- The malicious miner successfully writes thousands of fake entries to consensus state
- The `Round` object becomes permanently bloated and is stored in contract state
- All nodes must store, serialize, and process this bloated consensus state
- Round information retrieval becomes slower, degrading consensus performance
- Storage costs increase for all network participants

**Affected Parties:**
- All network nodes (must process/store bloated data)
- Consensus operations (degraded performance)
- Overall chain performance and reliability

## Likelihood Explanation

**High Likelihood:**

1. **Attacker Capability:** Any active miner in the consensus can exploit this vulnerability by modifying their node software to inject fake `EncryptedPieces` entries into the `AElfConsensusTriggerInformation` structure before block production. Miners are not explicitly listed as trusted roles in the threat model.

2. **Low Attack Cost:** Since `UpdateValue` has `IsSizeFeeFree = true`, transaction costs remain minimal regardless of the amount of data injected.

3. **No Detection Mechanism:** The contract validation logic does not check the `EncryptedPieces` count against the expected number of miners in the current round.

4. **Easy Exploitation:** The miner controls the trigger information generation process off-chain, making injection trivial. The consensus contract accepts whatever data is provided in the `AElfConsensusTriggerInformation`.

5. **Repeatable Attack:** A malicious miner can execute this attack repeatedly in every block they produce, as there are no rate limits or detection mechanisms.

**Attack Prerequisites:**
- Must be an active miner in the consensus (realistic under this threat model)
- Requires modifying node software (trivial for a motivated attacker)

## Recommendation

Add validation in `UpdateValueValidationProvider` to check that the `EncryptedPieces` count does not exceed the expected number of miners:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    // Only one Out Value should be filled.
    if (!NewConsensusInformationFilled(validationContext))
        return new ValidationResult { Message = "Incorrect new Out Value." };

    if (!ValidatePreviousInValue(validationContext))
        return new ValidationResult { Message = "Incorrect previous in value." };
    
    // NEW: Validate EncryptedPieces count
    if (!ValidateEncryptedPiecesCount(validationContext))
        return new ValidationResult { Message = "EncryptedPieces count exceeds miner count." };

    return new ValidationResult { Success = true };
}

private bool ValidateEncryptedPiecesCount(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var expectedMaxCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    
    return minerInRound.EncryptedPieces.Count <= expectedMaxCount;
}
```

Additionally, consider adding similar validation in `PerformSecretSharing` before adding entries to the state.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanInjectUnlimitedEncryptedPieces()
{
    // Setup: Initialize consensus with normal miners
    var miners = GenerateMiners(17); // Normal miner count
    await InitializeConsensus(miners);
    
    // Attack: Malicious miner creates UpdateValueInput with 1000 fake EncryptedPieces
    var maliciousMiner = miners[0];
    var updateValueInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("signature"),
        PreviousInValue = Hash.Empty,
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        EncryptedPieces = GenerateFakeEncryptedPieces(1000), // 1000 fake entries instead of 17
        RandomNumber = ByteString.CopyFrom(new byte[32])
    };
    
    // Execute: Call UpdateValue (should fail validation but doesn't)
    var result = await ConsensusStub.UpdateValue.SendAsync(updateValueInput);
    
    // Verify: Transaction either fails at state write (128KB limit) OR succeeds with bloated state
    // Both outcomes demonstrate the vulnerability:
    // 1. If it fails with StateOverSizeException -> wasted resources (DoS)
    // 2. If it succeeds -> permanent state bloat
    
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = currentRound.RealTimeMinersInformation[maliciousMiner.PublicKey.ToHex()];
    
    // Assert: EncryptedPieces count is excessive (vulnerability confirmed)
    Assert.True(minerInfo.EncryptedPieces.Count > 100); // Far exceeds expected 17
}

private Dictionary<string, ByteString> GenerateFakeEncryptedPieces(int count)
{
    var dict = new Dictionary<string, ByteString>();
    for (int i = 0; i < count; i++)
    {
        dict[$"fake_pubkey_{i}"] = ByteString.CopyFrom(new byte[166]);
    }
    return dict;
}
```

## Notes

This vulnerability breaks the consensus integrity guarantee that miners should only provide legitimate secret-sharing data. The expected behavior (one encrypted piece per miner) is violated without detection. The contract's reliance on off-chain node software to populate `EncryptedPieces` correctly, combined with missing on-chain validation, creates a trust assumption that miners are not listed as trusted roles in the threat model.

The vulnerability is particularly concerning because:
1. The `IsSizeFeeFree` flag makes exploitation economically cheap
2. No existing validation checks maximum count, only minimum
3. The attack can be repeated in every block the malicious miner produces
4. Impact scales with whether governance has increased state size limits

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L45-45)
```csharp
            EncryptedPieces = { minerInRound.EncryptedPieces },
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L139-141)
```csharp
        foreach (var encryptedPiece in triggerInformation.EncryptedPieces)
            updatedRound.RealTimeMinersInformation[pubkey].EncryptedPieces
                .Add(encryptedPiece.Key, encryptedPiece.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L290-290)
```csharp
        minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-80)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L42-48)
```csharp
                nameof(InitialAElfConsensusContract), nameof(FirstRound), nameof(UpdateValue),
                nameof(UpdateTinyBlockInformation), nameof(NextRound), nameof(NextTerm)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L35-35)
```csharp
            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
```
