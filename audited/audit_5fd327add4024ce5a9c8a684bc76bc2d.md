### Title
Null Reference Exception in Consensus Validation Causes Potential Consensus Halting

### Summary
The consensus validation flow lacks null checks for the `Round` field in block header extra data. A malicious miner can craft a block with null `Round` information, causing `NullReferenceException` during validation at multiple points before block execution. This can lead to consensus disruption and potential denial-of-service.

### Finding Description

**Root Cause:**
The `AElfConsensusHeaderInformation.Round` field is an optional protobuf message field that can be null, but the validation flow assumes it is always populated. [1](#0-0) 

**Entry Point:**
Block validation begins at `ValidateConsensusBeforeExecution`, which parses the consensus extra data without validating that the `Round` field is set: [2](#0-1) 

**Extraction Without Validation:**
The `AEDPoSExtraDataExtractor` only validates that `SenderPubkey` matches the block signer, but does not check if the `Round` field is null: [3](#0-2) 

**First Null Dereference (UpdateValue behavior):**
In `ValidateBeforeExecution`, when the behavior is `UpdateValue`, the code calls `RecoverFromUpdateValue` with the potentially null `extraData.Round`: [4](#0-3) 

The `RecoverFromUpdateValue` method immediately dereferences the `providedRound` parameter without null checking: [5](#0-4) 

**Second Null Dereference (TinyBlock behavior):**
Similarly, for `TinyBlock` behavior, `RecoverFromTinyBlock` is called with potentially null `extraData.Round`: [6](#0-5) [7](#0-6) 

**Third Null Dereference (LibInformationValidationProvider):**
Even if the above are bypassed, the `LibInformationValidationProvider` extracts `providedRound` from `validationContext.ProvidedRound`, which returns `ExtraData.Round`: [8](#0-7) 

The validator then dereferences `providedRound` without null checking: [9](#0-8) 

And again at a second location: [10](#0-9) 

### Impact Explanation

**Harm:**
- Block validation throws `NullReferenceException`, causing validation to fail
- Consensus validation failure can halt block processing on affected nodes
- Network-wide impact if multiple nodes receive and attempt to validate the malicious block

**Who is Affected:**
- All nodes in the network that receive and attempt to validate the malicious block
- The blockchain's consensus integrity and liveness

**Severity Justification:**
HIGH severity because:
1. **Consensus Disruption**: Can cause consensus validation failures across the network
2. **DoS Attack Vector**: A compromised or malicious miner can repeatedly exploit this during their time slots
3. **Low Attack Complexity**: Simply requires crafting a block with null `Round` field
4. **Network-Wide Impact**: Affects all nodes that receive the block

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a valid miner in the current miner list (has block signing capability)
- Must be able to produce blocks during their allocated time slot

**Attack Complexity:**
- LOW: Attacker simply needs to craft consensus extra data with:
  - Valid `SenderPubkey` (their own public key)
  - Valid `Behaviour` (UpdateValue or TinyBlock)
  - Omit the `Round` field (leave it null in protobuf serialization)

**Feasibility:**
- HIGHLY FEASIBLE: In protobuf3, message fields are optional by default. An attacker can easily serialize `AElfConsensusHeaderInformation` without setting the `Round` field
- The block will pass signature validation and initial extra data extraction
- Validation will fail with exception when attempting to process the null Round

**Detection:**
- Attack is immediately detected when validation fails
- However, the damage (validation failure) occurs before detection can prevent it
- No preventive checks exist in the extraction phase

**Probability:**
MEDIUM-HIGH: Requires attacker to be an active miner, but exploitation is trivial once in that position

### Recommendation

**Immediate Mitigation:**
1. Add null check in `ValidateBeforeExecution` before calling recovery methods:
```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
{
    if (extraData.Round == null)
        return new ValidationResult { Success = false, Message = "Round information is required for UpdateValue." };
    baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
}
```

2. Add null check in `LibInformationValidationProvider.ValidateHeaderInformation`:
```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var baseRound = validationContext.BaseRound;
    var providedRound = validationContext.ProvidedRound;
    
    if (baseRound == null || providedRound == null)
    {
        validationResult.Message = "Round information cannot be null.";
        return validationResult;
    }
    // ... rest of validation
}
```

3. Add validation in `AEDPoSExtraDataExtractor` to check Round field:
```csharp
if (headerInformation.Round == null)
    return null;
```

**Invariant to Enforce:**
- All consensus extra data must contain non-null Round information for UpdateValue, TinyBlock, NextRound, and NextTerm behaviors

**Test Cases:**
1. Test block validation with null Round field for each behavior type
2. Test that validation properly rejects blocks with missing Round information
3. Test that valid blocks with proper Round data continue to pass validation

### Proof of Concept

**Required Initial State:**
- Attacker is a valid miner in the current miner list
- It is the attacker's time slot to produce a block

**Attack Steps:**
1. Attacker creates a block header with consensus extra data:
   - Serialize `AElfConsensusHeaderInformation` with:
     - `sender_pubkey`: attacker's public key
     - `behaviour`: AElfConsensusBehaviour.UpdateValue (or TinyBlock)
     - `round`: NOT SET (null in serialization)
   
2. Sign and broadcast the block to the network

3. Network nodes receive the block and begin validation:
   - `ExtractConsensusExtraData` succeeds (only checks SenderPubkey)
   - `ValidateConsensusBeforeExecution` is called
   - `ValidateBeforeExecution` executes line 47: `baseRound.RecoverFromUpdateValue(extraData.Round, ...)`
   - `RecoverFromUpdateValue` attempts to access `providedRound.RealTimeMinersInformation`
   
**Expected Result:**
Block validation succeeds normally

**Actual Result:**
`NullReferenceException` is thrown at line 11 of `Round_Recover.cs`, causing validation failure

**Success Condition:**
Validation fails with exception, potentially causing consensus disruption or node processing issues depending on exception handling at the consensus service level.

### Citations

**File:** protobuf/aedpos_contract.proto (L303-310)
```text
message AElfConsensusHeaderInformation {
    // The sender public key.
    bytes sender_pubkey = 1;
    // The round information.
    Round round = 2;
    // The behaviour of consensus.
    AElfConsensusBehaviour behaviour = 3;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L49-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-12)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-39)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L23-27)
```csharp

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L11-17)
```csharp
        var baseRound = validationContext.BaseRound;
        var providedRound = validationContext.ProvidedRound;
        var pubkey = validationContext.SenderPubkey;
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-26)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
```
