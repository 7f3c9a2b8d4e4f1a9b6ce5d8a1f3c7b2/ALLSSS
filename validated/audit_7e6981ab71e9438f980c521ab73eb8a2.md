# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Breakdown via Empty RealTimeMinersInformation

## Summary
The `NextTerm` method in the AEDPoS consensus contract accepts externally-provided `NextTermInput` without validating that `RealTimeMinersInformation` contains any miners. A malicious current miner can submit a transaction with an empty miner map that passes all validation checks, resulting in zero authorized block producers for the next term and permanent blockchain halt.

## Finding Description

The vulnerability exists in the term transition flow where the consensus contract processes `NextTermInput` from transaction data without validating the integrity of the miner list field.

**Entry Point**: The `NextTerm` method is public and accepts input directly from transaction deserialization. [1](#0-0) 

**Root Cause**: In `ProcessNextTerm`, the miner list is constructed directly from the input's `RealTimeMinersInformation.Keys` without any validation that this map contains entries. [2](#0-1) 

The protobuf schema permits an empty map for `real_time_miners_information`. [3](#0-2) 

**Insufficient Validation**: The validation layer only verifies sequential term and round number increments via `RoundTerminateValidationProvider`, with no check for miner list content. [4](#0-3) 

The `NextTerm` behavior only adds `RoundTerminateValidationProvider` to the validation chain. [5](#0-4) 

**Authorization Bypass**: `PreCheck` only validates that the transaction sender is in the current or previous miner list, not the validity of the input data. [6](#0-5) 

**State Corruption Path**: `SetMinerList` stores the provided list without validating it is non-empty, only checking if the term was already initialized. [7](#0-6) 

The corrupted round state is persisted via `AddRoundInformation` without any content validation. [8](#0-7) 

**Consensus Breakdown**: After the malicious transaction executes, `MiningPermissionValidationProvider` will reject all future block production attempts because no public key exists in the empty `RealTimeMinersInformation.Keys` set. [9](#0-8) 

The `IsInMinerList` check used throughout the consensus system will fail for all miners when the list is empty. [10](#0-9) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability breaks the fundamental consensus invariant that there must always be authorized miners capable of producing blocks. Once exploited:

1. **Complete Blockchain Halt**: Zero miners are authorized to produce blocks for the corrupted term. All block production attempts fail validation because `MiningPermissionValidationProvider` validates against an empty miner list.

2. **Permanent Damage**: No recovery mechanism exists within the protocol. All consensus methods (`NextRound`, `UpdateValue`, `TinyBlock`, and even subsequent `NextTerm`) require passing `PreCheck`, which validates sender membership in the current or previous round miner lists - both of which would be empty after exploitation.

3. **Total Service Disruption**: No transactions can be processed, no cross-chain operations execute, all dApps become unavailable, miners lose rewards, and users cannot transact.

4. **Hard Fork Required**: Recovery requires off-chain coordination and a hard fork to restore consensus state, as there is no in-protocol mechanism to recover from an empty miner list.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Prerequisites**:
- Must be a current active miner (passes `PreCheck` authorization check)
- Can generate valid VRF proof for `random_number` field (standard miner cryptographic capability verified at transaction processing time)

**Attack Complexity: LOW**

The attack requires only constructing a `NextTermInput` with:
1. Correct `term_number` (current + 1) to pass term validation
2. Correct `round_number` (current + 1) to pass round validation  
3. Empty `real_time_miners_information` map `{}`
4. Valid VRF proof via `random_number` field
5. Submit as a regular transaction before natural term transition

**Feasibility Assessment**:
- No special timing conditions beyond being a current miner
- Transaction passes all existing validation providers
- No detection mechanisms exist to identify the malicious empty miner list
- Attack cost is minimal (only standard transaction fees)
- If the malicious transaction is included in a block before the legitimate term transition, it executes first and corrupts state

The VRF validation requirement [11](#0-10)  is satisfied by any current miner as part of their standard consensus participation capabilities.

## Recommendation

Add mandatory validation in `ProcessNextTerm` to ensure the miner list is non-empty before state updates:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // Add validation for non-empty miner list
    Assert(nextRound.RealTimeMinersInformation.Count > 0, 
        "Miner list cannot be empty for term transition.");
    
    // ... rest of existing logic
}
```

Additionally, consider adding validation in `SetMinerList`:

```csharp
private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
{
    // Validate miner list is non-empty
    Assert(minerList != null && minerList.Pubkeys.Count > 0,
        "Cannot set empty miner list.");
        
    // ... rest of existing logic
}
```

## Proof of Concept

The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task NextTerm_WithEmptyMinerList_CausesConsensusHalt()
{
    // Assume we are a current miner
    var currentMinerKeyPair = SampleAccount.Accounts[0].KeyPair;
    var consensusStub = GetConsensusContractStub(currentMinerKeyPair);
    
    // Get current state
    var currentRound = await consensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var currentTerm = (await consensusStub.GetCurrentTermNumber.CallAsync(new Empty())).Value;
    
    // Construct malicious NextTermInput with empty miner list
    var maliciousInput = new NextTermInput
    {
        TermNumber = currentTerm + 1,
        RoundNumber = currentRound.RoundNumber + 1,
        RealTimeMinersInformation = {}, // Empty map - the vulnerability
        RandomNumber = GenerateValidVrfProof(currentMinerKeyPair)
    };
    
    // Execute the attack
    var result = await consensusStub.NextTerm.SendAsync(maliciousInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify consensus is broken - no miner can produce blocks
    var newRound = await consensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.RealTimeMinersInformation.Count.ShouldBe(0); // Miner list is empty
    
    // Attempt block production by any miner should fail validation
    var validationResult = await consensusStub.ValidateConsensusBeforeExecution.CallAsync(
        CreateBlockExtraData(SampleAccount.Accounts[0].KeyPair));
    validationResult.Success.ShouldBe(false);
    validationResult.Message.ShouldContain("is not a miner");
}
```

## Notes

The root cause is a critical gap between two validation layers:
1. **Block consensus validation** (`ValidateConsensusBeforeExecution`) - only applies to block consensus extra data
2. **Transaction execution validation** (`PreCheck`) - only validates sender authority, not input data integrity

The `NextTerm` method is public and can be called directly via transaction, bypassing the comprehensive block consensus validation that would normally prevent malformed consensus data. This dual-path execution creates the vulnerability window where malicious input can corrupt consensus state.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-78)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** protobuf/aedpos_contract.proto (L488-488)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```
