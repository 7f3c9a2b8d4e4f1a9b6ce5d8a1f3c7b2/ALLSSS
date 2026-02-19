### Title
Unhandled Null Reference in Consensus Validation Causes Poor Error Reporting

### Summary
The `NextRoundMiningOrderValidationProvider.ValidateHeaderInformation()` method accesses `validationContext.ProvidedRound.RealTimeMinersInformation` without null checks, causing a NullReferenceException when a miner submits a block with incomplete consensus extra data. While the contract execution framework catches the exception preventing a crash, the validation fails with a generic error message instead of providing specific feedback about the malformed data.

### Finding Description
The vulnerability exists in the consensus validation flow where blocks are validated before execution: [1](#0-0) 

At line 14-15, the code retrieves `ProvidedRound` and immediately accesses its `RealTimeMinersInformation` property without checking if `ProvidedRound` is null.

The `ProvidedRound` property is defined as: [2](#0-1) 

This returns `ExtraData.Round`, which is a protobuf message field that can be null if not set in the serialized data. The validation entry point parses untrusted input: [3](#0-2) 

The protobuf parser successfully parses messages with missing fields, setting them to null. The consensus extra data extractor only validates the sender's public key, not the completeness of the Round field: [4](#0-3) 

Additionally, the same null reference issue exists in other validation providers executed before `NextRoundMiningOrderValidationProvider`: [5](#0-4) 

And in the recovery methods for UpdateValue and TinyBlock behaviors: [6](#0-5) 

### Impact Explanation
When a miner submits a block with null `Round` field in consensus extra data:

1. The NullReferenceException is thrown during contract execution
2. The contract execution framework catches it and returns null to the caller: [7](#0-6) 

3. The validation service treats null as failure with a generic message: [8](#0-7) 

The impact is:
- **Operational disruption**: Legitimate miners may waste resources debugging generic error messages when the issue is malformed data
- **Poor observability**: Administrators cannot distinguish between null reference errors and actual consensus violations
- **Potential confusion during incidents**: If a buggy miner client produces malformed blocks, the unhelpful error messaging delays diagnosis

The node does not crash, and consensus continues with other miners, so there is no permanent DoS. However, the poor error handling creates operational friction.

### Likelihood Explanation
The vulnerability is readily exploitable:

**Attacker capabilities**: Any elected miner can propose blocks. Miners are elected through the public Election contract, not limited to trusted administrators.

**Attack complexity**: Low - a miner simply needs to send a block with consensus extra data where the Round protobuf field is not set. This can occur:
- Maliciously: A compromised miner client intentionally sends malformed data
- Accidentally: A buggy miner client implementation fails to populate Round

**Execution practicality**: The validation is called during standard block validation: [9](#0-8) 

**Detection constraints**: The generic error message makes detection difficult until examining detailed execution traces.

### Recommendation
Add explicit null checks at multiple defensive layers:

1. **In validation providers** before accessing ProvidedRound properties:
```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    
    if (providedRound == null)
    {
        validationResult.Message = "ProvidedRound is null in consensus extra data.";
        return validationResult;
    }
    
    if (providedRound.RealTimeMinersInformation == null)
    {
        validationResult.Message = "RealTimeMinersInformation is null in ProvidedRound.";
        return validationResult;
    }
    
    // Existing logic...
}
```

2. **In ValidateBeforeExecution** before using ProvidedRound:
```csharp
private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
{
    if (extraData.Round == null)
        return new ValidationResult { Success = false, Message = "Round information is required in consensus extra data." };
    
    // Existing logic...
}
```

3. **Add test cases** to verify null handling:
    - Test with consensus extra data missing Round field
    - Test with Round present but RealTimeMinersInformation empty
    - Verify error messages are specific and actionable

### Proof of Concept
**Initial state**: Standard AEDPoS consensus running with elected miners

**Attack steps**:
1. Attacker controls a miner node in the elected miner list
2. During their time slot, attacker modifies miner client to construct a block with incomplete consensus extra data
3. Attacker serializes `AElfConsensusHeaderInformation` with `Behaviour = NextRound` but without setting the `Round` field
4. Attacker signs and broadcasts the malformed block

**Expected result**: Validation should fail with clear message "Round information is required in consensus extra data"

**Actual result**: 
- NullReferenceException thrown at line 15 of NextRoundMiningOrderValidationProvider (or earlier in TimeSlotValidationProvider)
- Contract execution fails
- Generic error logged: "Validation of consensus failed before execution."
- Block rejected but with unhelpful diagnostic information

**Success condition**: Block is properly rejected, but with actionable error message identifying the specific null field rather than generic failure message.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-17)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L29-32)
```csharp
        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-14)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** src/AElf.Kernel.SmartContract/Application/ReadOnlyMethodStubFactory.cs (L50-52)
```csharp
            return trace.IsSuccessful()
                ? method.ResponseMarshaller.Deserializer(trace.ReturnValue.ToByteArray())
                : default;
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L132-136)
```csharp
        if (validationResult == null)
        {
            Logger.LogDebug("Validation of consensus failed before execution.");
            return false;
        }
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L70-75)
```csharp
        var isValid = await _consensusService.ValidateConsensusBeforeExecutionAsync(new ChainContext
        {
            BlockHash = block.Header.PreviousBlockHash,
            BlockHeight = block.Header.Height - 1
        }, consensusExtraData.ToByteArray());
        if (!isValid) return false;
```
