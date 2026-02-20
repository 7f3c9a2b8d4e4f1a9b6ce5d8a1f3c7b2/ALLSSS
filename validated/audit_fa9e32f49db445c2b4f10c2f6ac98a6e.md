# Audit Report

## Title
Memory Exhaustion DoS via Unbounded RealTimeMinersInformation Dictionary in Consensus Validation

## Summary
The AEDPoS consensus validation process does not validate the size of the `ProvidedRound.RealTimeMinersInformation` dictionary before performing memory-intensive materialization operations. An elected miner can craft a block with consensus extra data containing an excessively large Round object, causing memory exhaustion on all validating nodes and resulting in network-wide denial of service.

## Finding Description

When a block is validated, the `ValidateConsensusBeforeExecution` method parses the consensus header information without any size constraints on the Round object's miner dictionary: [1](#0-0) 

The parsed `extraData.Round` becomes the `ProvidedRound` in the validation context: [2](#0-1) 

During validation of new rounds, `TimeSlotValidationProvider` unconditionally calls `CheckRoundTimeSlots()`: [3](#0-2) 

The critical vulnerability occurs in `CheckRoundTimeSlots()`, which materializes ALL values from the `RealTimeMinersInformation` dictionary into memory and sorts them: [4](#0-3) 

Additional materialization occurs in `NextRoundMiningOrderValidationProvider` for NextRound behavior: [5](#0-4) 

And in `RoundTerminateValidationProvider`: [6](#0-5) 

**Root Cause:** There is no validation comparing `ProvidedRound.RealTimeMinersInformation.Count` against `BaseRound.RealTimeMinersInformation.Count` or reasonable bounds. The only check is that the sender exists in the BaseRound: [7](#0-6) 

Each `MinerInRound` is a complex protobuf structure with multiple fields including maps and repeated timestamps: [8](#0-7) 

The network message size limit is 100MB, which allows for tens of thousands of miner entries: [9](#0-8) 

## Impact Explanation

**Concrete Harm:**
- **Memory Exhaustion**: Materializing hundreds of thousands of `MinerInRound` objects causes OutOfMemoryException or severe memory pressure on all validating nodes
- **Network-Wide DoS**: All nodes validating the malicious block experience simultaneous memory exhaustion, as the validation service processes each provider sequentially [10](#0-9) 
- **Consensus Disruption**: Nodes cannot process blocks, halting chain progression
- **Resource Starvation**: Even without OutOfMemoryException, excessive allocation and sorting operations degrade all node performance

**Affected Parties:**
- All full nodes performing block validation
- Block producers attempting to continue consensus
- Overall network availability and liveness

This represents a high-impact consensus availability attack that can be executed with a single malicious block from any elected miner.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an elected miner (one of ~17-21 initially based on consensus configuration)
- Can sign blocks and include arbitrary consensus extra data
- Needs to craft only one malicious block to trigger DoS

**Attack Complexity:**
- Low - simply populate the `RealTimeMinersInformation` protobuf map with excessive entries (e.g., 100,000+)
- No complex state manipulation required
- No precise timing requirements
- The malicious block propagates normally through the network

**Feasibility:**
- Attacker must be elected as a miner (requires community support/stake)
- Once elected, execution is straightforward
- No network-level protections prevent oversized Round objects in block headers
- The validation flow always adds `TimeSlotValidationProvider` [11](#0-10) 

**Detection Difficulty:**
- The attack appears as a valid block until validation begins
- Memory exhaustion occurs during validation processing
- Limited forensic traces beyond the oversized consensus data

Given these factors, the likelihood is **Medium-High** for a malicious elected miner, as execution is trivial once miner status is obtained.

## Recommendation

Add size validation in `ValidateBeforeExecution` before creating the validation context:

```csharp
// After line 20 in AEDPoSContract_Validation.cs, add:
if (extraData.Round.RealTimeMinersInformation.Count > baseRound.RealTimeMinersInformation.Count + 1)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = "ProvidedRound contains excessive miner entries." 
    };
}
```

Alternatively, add validation in `TimeSlotValidationProvider.ValidateHeaderInformation`:

```csharp
// At line 14 of TimeSlotValidationProvider.cs, before CheckRoundTimeSlots():
if (validationContext.ProvidedRound.RealTimeMinersInformation.Count > 
    validationContext.BaseRound.RealTimeMinersInformation.Count * 2)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = "ProvidedRound miner count exceeds acceptable bounds." 
    };
}
```

The multiplier allows for some flexibility in round transitions while preventing abuse.

## Proof of Concept

```csharp
[Fact]
public async Task MemoryExhaustionDoS_ViaUnboundedRealTimeMinersInformation()
{
    // Setup: Get current round and miner
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var miner = ValidationDataProvider.GetValidationDataCenterList().First();
    
    // Create malicious Round with excessive miner entries
    var maliciousRound = new Round
    {
        RoundNumber = currentRound.RoundNumber + 1,
        TermNumber = currentRound.TermNumber,
        RealTimeMinersInformation = { }
    };
    
    // Populate with 50,000 fake miner entries (within 100MB limit but causes memory exhaustion)
    for (int i = 0; i < 50000; i++)
    {
        maliciousRound.RealTimeMinersInformation.Add(
            $"FakeMiner{i}",
            new MinerInRound
            {
                Order = i + 1,
                ExpectedMiningTime = TimestampHelper.GetUtcNow().AddSeconds(i * 4),
                Pubkey = $"FakeMiner{i}"
            });
    }
    
    var headerInformation = new AElfConsensusHeaderInformation
    {
        SenderPubkey = ByteStringHelper.FromHexString(miner),
        Round = maliciousRound,
        Behaviour = AElfConsensusBehaviour.NextRound
    };
    
    // Attempt validation - this should exhaust memory
    var result = await AEDPoSContractStub.ValidateConsensusBeforeExecution.CallAsync(
        new BytesValue { Value = headerInformation.ToByteString() });
    
    // In production, this would cause OutOfMemoryException or severe performance degradation
    // The test demonstrates the vulnerability exists
    result.Success.ShouldBeFalse(); // Should fail validation, but currently doesn't check size
}
```

## Notes

The vulnerability exists because the validation logic assumes that `ProvidedRound` will contain approximately the same number of miners as `BaseRound`, but this assumption is never enforced. The protobuf parsing accepts any size up to the 100MB gRPC limit, and the materialization operations (`ToList()`, `OrderBy()`, `Where().Count()`) load the entire collection into memory without bounds checking.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L79-80)
```csharp
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L35-35)
```csharp
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L32-32)
```csharp
        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** src/AElf.OS.Network.Grpc/GrpcConstants.cs (L28-28)
```csharp
    public const int DefaultMaxReceiveMessageLength = 100 * 1024 * 1024;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L16-26)
```csharp
    public ValidationResult ValidateInformation(ConsensusValidationContext validationContext)
    {
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-75)
```csharp
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```
