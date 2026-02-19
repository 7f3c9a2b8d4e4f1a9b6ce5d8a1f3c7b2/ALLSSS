### Title
Unsafe Dictionary Access in UpdateValueValidationProvider Allows Malicious Miners to Cause Consensus Validation Failures

### Summary
The `NewConsensusInformationFilled()` and `ValidatePreviousInValue()` functions in `UpdateValueValidationProvider` directly access the user-provided `ProvidedRound.RealTimeMinersInformation` dictionary without verifying the sender's public key exists in it. A malicious miner can exploit this by submitting a block with a malformed Round object that omits their own entry, causing a `KeyNotFoundException` that crashes block validation and disrupts consensus.

### Finding Description

The vulnerability exists in the `UpdateValueValidationProvider` class used during consensus header validation. The root cause is an unsafe assumption about the structure of user-provided data. [1](#0-0) 

At this location, the function uses the C# bracket operator `[]` to access the dictionary directly, which throws `KeyNotFoundException` if the key doesn't exist. This occurs with the `ProvidedRound` object, which comes from untrusted block header data. [2](#0-1) 

The same vulnerability exists in the `ValidatePreviousInValue` method: [3](#0-2) 

Lines 42 and 45 access `extraData.Round.RealTimeMinersInformation[publicKey]` without verification.

The existing `MiningPermissionValidationProvider` only validates the sender exists in `BaseRound` (trusted state data), not in `ProvidedRound` (user-provided data): [4](#0-3) 

The validation provider chain shows `MiningPermissionValidationProvider` runs before `UpdateValueValidationProvider`: [5](#0-4) 

The `RecoverFromUpdateValue` method checks for key existence but only returns early without raising an error: [6](#0-5) 

This means a malformed Round passes through recovery but crashes during validation. In contrast, `LibInformationValidationProvider` demonstrates the correct pattern by using `ContainsKey`: [7](#0-6) 

### Impact Explanation

**Consensus Disruption**: A malicious miner can repeatedly produce blocks with malformed Round objects, causing validation failures across the network. Each invalid block triggers a `KeyNotFoundException`, preventing honest nodes from properly validating and processing blocks.

**Operational DoS**: The attack creates sustained disruption to the consensus mechanism. Nodes waste computational resources attempting to validate malformed blocks, and synchronization may be affected if multiple malicious miners coordinate attacks.

**Network-Wide Effect**: All nodes attempting to validate the malicious block will experience the same exception, potentially causing cascading failures in the block validation pipeline.

**Severity Justification**: This is HIGH severity because it directly compromises the consensus integrity invariant. The attack allows a valid miner to disrupt the entire network's ability to reach consensus on new blocks, threatening the blockchain's liveness guarantee.

### Likelihood Explanation

**Attacker Capabilities**: The attacker only needs to be a valid miner (member of the current miner list). No additional privileges or compromised roles are required.

**Attack Complexity**: Very low. The attacker simply needs to:
1. Generate a consensus block as normal
2. Modify the `Round.RealTimeMinersInformation` in the consensus extra data to omit their own public key
3. Broadcast the block

**Execution Practicality**: The attack is trivially executable. The attacker controls the block content including the consensus header information: [8](#0-7) 

The Round structure allows arbitrary content in the `real_time_miners_information` map: [9](#0-8) 

**Economic Rationality**: The attack requires no economic cost beyond normal block production. A malicious miner could execute this attack repeatedly with each of their scheduled time slots.

**Detection/Constraints**: The attack is easily detectable in logs (exception stack traces), but by the time it's detected, consensus has already been disrupted. There are no preventive measures in the current code.

### Recommendation

**Immediate Fix**: Add defensive key existence checks before all dictionary accesses to `ProvidedRound.RealTimeMinersInformation`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    // Add existence check
    if (!validationContext.ProvidedRound.RealTimeMinersInformation.ContainsKey(validationContext.SenderPubkey))
        return false;
        
    var minerInRound =
        validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    return minerInRound.OutValue != null && minerInRound.Signature != null &&
           minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
}

private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;

    // Add existence check for ProvidedRound
    if (!extraData.Round.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return false;
        
    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) 
        return true;

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (previousInValue == Hash.Empty) return true;

    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

**Invariant Enforcement**: Add validation that `ProvidedRound.RealTimeMinersInformation` must contain an entry for the sender when the behavior is `UpdateValue` or `TinyBlock`.

**Test Cases**: Add regression tests that:
1. Attempt to validate a block with missing sender entry in RealTimeMinersInformation
2. Verify validation fails gracefully with proper error message (not exception)
3. Ensure recovery methods and validation providers handle malformed Round objects consistently

### Proof of Concept

**Initial State**:
- Blockchain is running with multiple miners
- Attacker is a valid miner in the current round's miner list
- Network is accepting blocks normally

**Attack Steps**:

1. **Attacker waits for their time slot**: When it's their turn to produce a block with `UpdateValue` behavior

2. **Attacker crafts malformed consensus data**:
   - Generate normal block content
   - In the `AElfConsensusHeaderInformation`, create a `Round` object
   - Populate `RealTimeMinersInformation` with all miners EXCEPT their own public key
   - Sign and broadcast the block

3. **Validation execution path**:
   - Node receives block, extracts consensus extra data
   - `ValidateBeforeExecution` is called via `ValidateConsensusBeforeExecution`
   - `MiningPermissionValidationProvider` checks `BaseRound` → PASSES (attacker is valid miner)
   - `TimeSlotValidationProvider` checks timing → PASSES
   - `ContinuousBlocksValidationProvider` checks block production → PASSES
   - `UpdateValueValidationProvider.ValidateHeaderInformation` is called
   - `NewConsensusInformationFilled` executes line 30
   - Dictionary access with missing key → `KeyNotFoundException` thrown

**Expected Result**: Validation should fail gracefully with error message "Sender not found in provided round information"

**Actual Result**: Unhandled `KeyNotFoundException` propagates up the call stack, causing validation to fail with exception, potentially crashing validation logic or requiring exception handling at higher layers

**Success Condition**: The attack succeeds if the exception is thrown and block validation fails abnormally (with exception rather than proper validation failure result).

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-83)
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
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-12)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L23-26)
```csharp
        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
```

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
}
```

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
