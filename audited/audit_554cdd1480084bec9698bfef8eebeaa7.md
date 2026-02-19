### Title
Unhandled KeyNotFoundException in UpdateValueValidationProvider Enables Consensus Validation DOS

### Summary
The `NewConsensusInformationFilled()` method in `UpdateValueValidationProvider` directly accesses `ProvidedRound.RealTimeMinersInformation[SenderPubkey]` without validating key existence, allowing a malicious miner to trigger an unhandled `KeyNotFoundException` that propagates through the entire validation pipeline, potentially causing node crashes or blocking legitimate block processing.

### Finding Description

**Root Cause Location:** [1](#0-0) 

The vulnerability occurs because the code directly accesses the dictionary using the indexer operator without first checking if the key exists. This contrasts with defensive patterns used elsewhere in the codebase.

**Why Existing Protections Fail:**

1. **MiningPermissionValidationProvider checks wrong dictionary**: While `MiningPermissionValidationProvider` validates that `SenderPubkey` exists in `BaseRound.RealTimeMinersInformation`: [2](#0-1) 

2. **UpdateValueValidationProvider accesses different dictionary**: The vulnerable code accesses `ProvidedRound.RealTimeMinersInformation` (the attacker-supplied data), not `BaseRound`: [3](#0-2) 

3. **RecoverFromUpdateValue silently fails**: While `RecoverFromUpdateValue` checks for missing keys and returns early: [4](#0-3) 

This happens BEFORE validation, but validation still proceeds with the invalid `ProvidedRound`, and the exception occurs later.

4. **No exception handling in validation pipeline**: The validation service iterates through providers without try-catch: [5](#0-4) 

5. **Exception propagates uncaught**: The consensus service calls the contract without exception handling: [6](#0-5) 

6. **Block validation service has no exception handling**: [7](#0-6) 

7. **Top-level catch only handles specific exception type**: The only catch block in the execution pipeline only catches `BlockValidationException` with a specific inner exception: [8](#0-7) 

A `KeyNotFoundException` does not match this pattern and will propagate further.

**Attack Execution Path:**
1. Attacker must be a valid miner in `BaseRound.RealTimeMinersInformation`
2. Attacker crafts UpdateValue block with `ExtraData.Round` (ProvidedRound) that deliberately excludes their own `SenderPubkey` from `RealTimeMinersInformation`
3. Block passes through validation order defined at: [9](#0-8) 

4. `MiningPermissionValidationProvider` passes (checks BaseRound, not ProvidedRound)
5. `UpdateValueValidationProvider` is invoked and throws `KeyNotFoundException` at line 30
6. Exception propagates through entire call stack uncaught

### Impact Explanation

**Operational DOS Impact:**
- Nodes processing the malicious block encounter an unhandled exception during validation
- The validation pipeline is disrupted, potentially causing node crashes or blocking further block processing
- Repeated attacks can prevent legitimate blocks from being validated and processed
- Network consensus can be degraded if multiple nodes are affected simultaneously

**Affected Parties:**
- All nodes attempting to validate blocks from the malicious miner
- Network availability and block production rate
- Honest miners whose blocks may be delayed or rejected due to validation pipeline disruption

**Severity Justification:**
MEDIUM severity because:
- Requires attacker to be a valid miner (elevated privileges)
- Causes operational disruption but not direct fund loss
- Can be repeated easily to sustain DOS
- Affects core consensus validation functionality

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an authorized miner in the current round (requires staking/election process)
- Can craft arbitrary consensus extra data for their blocks
- No additional technical sophistication needed beyond normal block production

**Attack Complexity:**
- LOW complexity: Simply omit own pubkey from `ProvidedRound.RealTimeMinersInformation` in block header
- Attack is deterministic and guaranteed to trigger the exception
- Can be automated and repeated

**Feasibility Conditions:**
- Attacker already has miner privileges (realistic for malicious insider or compromised miner)
- No economic cost beyond normal block production costs
- No detection mechanism in place to identify malformed ProvidedRound before exception

**Probability Assessment:**
HIGH likelihood given that:
- Attack vector is straightforward to exploit
- Miner privileges are the only prerequisite
- No cryptographic or timing challenges
- Exception is guaranteed to occur with crafted input

### Recommendation

**Immediate Fix:**
Add defensive key existence check in `UpdateValueValidationProvider.NewConsensusInformationFilled()`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    // Add safety check before dictionary access
    if (!validationContext.ProvidedRound.RealTimeMinersInformation.ContainsKey(validationContext.SenderPubkey))
        return false;
        
    var minerInRound =
        validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}
```

**Additional Hardening:**
1. Use the same defensive pattern seen in `LibInformationValidationProvider`: [10](#0-9) 

2. Add try-catch wrapper in `HeaderInformationValidationService.ValidateInformation()` to convert unexpected exceptions into validation failures
3. Add invariant check that `ProvidedRound` structure matches expected miner list before detailed validation

**Test Cases:**
1. Test UpdateValue block where `SenderPubkey` is missing from `ProvidedRound.RealTimeMinersInformation`
2. Test UpdateValue block where `ProvidedRound.RealTimeMinersInformation` is empty
3. Test UpdateValue block where `ProvidedRound.RealTimeMinersInformation` contains different miners than `BaseRound`
4. Verify validation returns proper failure message instead of throwing exception

### Proof of Concept

**Required Initial State:**
- Attacker "MinerA" is an authorized miner in current consensus round
- `BaseRound.RealTimeMinersInformation` contains `MinerA` pubkey
- Chain is accepting UpdateValue behavior blocks

**Attack Steps:**
1. MinerA produces a block with consensus behavior = `UpdateValue`
2. In block's `AElfConsensusHeaderInformation.Round.RealTimeMinersInformation`:
   - Include all other miners from `BaseRound`
   - Deliberately EXCLUDE MinerA's own pubkey
3. Sign and broadcast the block

**Expected vs Actual Result:**
- **Expected**: Validation should fail gracefully with message "Invalid consensus information"
- **Actual**: `KeyNotFoundException` thrown at line 30 of `UpdateValueValidationProvider.cs`, exception propagates uncaught through validation pipeline, potentially crashing node or blocking validation service

**Success Condition:**
Block validation throws unhandled `KeyNotFoundException` observable in node logs, demonstrating validation pipeline disruption without graceful failure handling.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L29-30)
```csharp
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-17)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L10-12)
```csharp
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ValidationService.cs (L18-22)
```csharp
        foreach (var headerInformationValidationProvider in _headerInformationValidationProviders)
        {
            var result =
                headerInformationValidationProvider.ValidateHeaderInformation(validationContext);
            if (!result.Success) return result;
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L127-130)
```csharp
        var validationResult = await _contractReaderFactory
            .Create(contractReaderContext)
            .ValidateConsensusBeforeExecution
            .CallAsync(new BytesValue { Value = ByteString.CopyFrom(consensusExtraData) });
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationService.cs (L37-38)
```csharp
        foreach (var provider in _blockValidationProviders)
            if (!await provider.ValidateBlockBeforeExecuteAsync(block))
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockchainExecutingService.cs (L61-63)
```csharp
        catch (BlockValidationException ex)
        {
            if (!(ex.InnerException is ValidateNextTimeBlockValidationException)) throw;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-80)
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

        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-24)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
```
