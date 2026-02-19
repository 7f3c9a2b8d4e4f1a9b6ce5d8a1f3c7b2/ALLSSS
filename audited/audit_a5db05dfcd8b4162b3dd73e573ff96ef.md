### Title
Unbounded ActualMiningTimes in Consensus Validation Enables Memory Exhaustion DoS

### Summary
The `RecoverFromUpdateValue()` and `RecoverFromTinyBlock()` methods add all timestamps from untrusted block header consensus extra data to the `ActualMiningTimes` list without size validation. A malicious miner can craft a block containing millions of timestamps in the consensus extra data, causing memory exhaustion and DoS when honest nodes attempt validation.

### Finding Description

The vulnerability exists in the consensus validation recovery functions that process block header extra data without size limits. [1](#0-0) [2](#0-1) 

The `ActualMiningTimes` field is defined as a protobuf repeated field with no inherent size constraint: [3](#0-2) 

These recovery methods are invoked during consensus validation before and after block execution: [4](#0-3) [5](#0-4) 

The consensus extra data originates from the block header and is parsed without size validation: [6](#0-5) 

No validation provider checks the size of `ActualMiningTimes` before the recovery methods are called: [7](#0-6) 

While legitimate operation limits tiny blocks to a maximum count: [8](#0-7) 

This limit is not enforced on the consensus extra data provided by block producers. The gRPC network layer has a 100MB message limit, allowing approximately 5-6 million timestamps (~80MB) to pass through.

### Impact Explanation

A malicious miner can produce a block with consensus extra data containing millions of timestamps in the `ActualMiningTimes` field. When honest nodes validate this block:

1. **Memory Allocation**: Copying millions of timestamp objects allocates 80+ MB of memory per validation attempt
2. **GC Pressure**: Repeated allocations cause garbage collection overhead, degrading node performance
3. **Potential OOM**: On resource-constrained nodes, this can trigger out-of-memory errors
4. **Chain Halt**: All nodes attempting to validate the malicious block simultaneously experience DoS, halting consensus

The attack affects all consensus participants and can be repeated during each of the attacker's assigned mining slots. While individual node crashes may not persist, coordinated DoS during the attacker's time slots disrupts the network's ability to reach consensus and produce blocks.

**Severity**: Medium - Concrete DoS impact on consensus availability, but requires attacker to hold miner privileges.

### Likelihood Explanation

**Attacker Capabilities**: Must be a valid miner with block production privileges (public key in current miner list).

**Attack Complexity**: Low
- Craft a protobuf `Round` message with `ActualMiningTimes` containing millions of timestamps
- Include this in the block's consensus extra data
- Sign and broadcast the block normally

**Feasibility**: 
- No cryptographic barriers beyond normal block signing
- Protobuf serialization supports the required message size
- Network layer accepts messages under 100MB
- No size validation exists in the validation pipeline

**Detection**: Difficult to detect preemptively; nodes only discover the issue during validation when memory pressure occurs.

**Economic Cost**: Minimal - attacker only sacrifices one block production opportunity per attack.

### Recommendation

Add explicit size validation for `ActualMiningTimes` in the recovery methods:

```csharp
public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
{
    if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
        !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
        return this;

    var minerInRound = RealTimeMinersInformation[pubkey];
    var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
    
    // ADD: Validate ActualMiningTimes size
    Assert(providedInformation.ActualMiningTimes.Count <= AEDPoSContractConstants.MaximumTinyBlocksCount,
           "ActualMiningTimes exceeds maximum allowed size.");
    
    minerInRound.OutValue = providedInformation.OutValue;
    minerInRound.Signature = providedInformation.Signature;
    minerInRound.PreviousInValue = providedInformation.PreviousInValue;
    minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
    minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
    // ... rest of method
}
```

Apply the same validation to `RecoverFromTinyBlock()`. Add test cases that:
1. Attempt to validate blocks with oversized `ActualMiningTimes` (should fail validation)
2. Verify legitimate blocks with up to `MaximumTinyBlocksCount` entries pass validation
3. Test boundary conditions (exactly at limit, one over limit)

### Proof of Concept

**Initial State**: 
- Attacker controls a miner node with valid signing key in the current round's miner list
- Network has `MaximumTinyBlocksCount = 8` configured

**Attack Steps**:

1. **Craft Malicious Round**: Create a `MinerInRound` protobuf with `ActualMiningTimes` containing 5,000,000 timestamp entries (approximately 80MB)

2. **Create Malicious Block**: Generate a block with consensus extra data containing the crafted Round where the attacker's miner entry has the oversized `ActualMiningTimes`

3. **Broadcast Block**: Sign and broadcast the block using valid miner credentials during assigned time slot

4. **Validation Triggered**: Honest nodes receive the block and invoke consensus validation: [9](#0-8) 

5. **Memory Exhaustion**: During validation, `RecoverFromUpdateValue` copies all 5,000,000 timestamps, allocating ~80MB and causing severe GC pressure or OOM

**Expected Result**: Block validation completes normally, rejecting invalid blocks gracefully

**Actual Result**: Nodes experience memory exhaustion, performance degradation, or crash during validation, causing consensus disruption

**Success Condition**: Monitor node memory usage and validation latency when processing the malicious block. Successful attack shows memory spike of 80+ MB and validation taking orders of magnitude longer than normal, or node crash with OOM error.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L20-20)
```csharp
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L44-44)
```csharp
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);
```

**File:** protobuf/aedpos_contract.proto (L292-292)
```text
    repeated google.protobuf.Timestamp actual_mining_times = 13;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L89-97)
```csharp
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L29-29)
```csharp
        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
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
