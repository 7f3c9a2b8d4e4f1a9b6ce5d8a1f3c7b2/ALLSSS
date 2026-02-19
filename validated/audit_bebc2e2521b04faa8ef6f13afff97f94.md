# Audit Report

## Title
Insufficient Hash Length Validation Enables Consensus DoS via Cryptographic Primitive Downgrade

## Summary
The AEDPoS consensus contract lacks cryptographic length validation for `OutValue` and `Signature` hash fields during the `UpdateValue` consensus behavior. A malicious miner can submit hashes shorter than the required 32 bytes, which are blindly copied and persisted to contract state. When subsequent miners attempt block production, the `XorAndCompute` operation throws an `IndexOutOfRangeException` when accessing indices 0-31 of the short hash, completely halting consensus and block production.

## Finding Description

The vulnerability exists across three critical layers in the consensus validation and execution pipeline:

**Layer 1: Protobuf Definition Without Length Constraint**

The Hash protobuf message accepts arbitrary byte lengths without enforcing the 32-byte requirement: [1](#0-0) 

**Layer 2: Blind Copying During Validation**

During block validation, `RecoverFromUpdateValue` directly copies `OutValue` and `Signature` from provided round information without any length validation: [2](#0-1) 

This method is called during `ValidateBeforeExecution` before the block is executed: [3](#0-2) 

**Layer 3: Insufficient Validation Logic**

The `UpdateValueValidationProvider` only checks that hashes are non-null and have at least one byte (`.Any()`), but does NOT validate they are exactly 32 bytes: [4](#0-3) 

**Layer 4: Persistence Without Validation**

After validation passes, `ProcessUpdateValue` persists the unvalidated short hashes directly to contract state: [5](#0-4) 

**Layer 5: Failure Point - XOR Operation**

The system expects all hashes to be exactly 32 bytes: [6](#0-5) 

When `CalculateSignature` aggregates miner signatures during the next block production: [7](#0-6) 

It calls `XorAndCompute` which assumes 32-byte hashes and attempts to access all 32 indices: [8](#0-7) 

When the loop encounters a short hash (e.g., 16 bytes), accessing `h1.Value[16]` through `h1.Value[31]` throws `IndexOutOfRangeException`.

**Layer 6: Trigger Point**

This failure occurs when any miner prepares block extra data, specifically in `GetConsensusExtraDataToPublishOutValue`: [9](#0-8) 

**Note on Bypassed Protection:**

While `Hash.LoadFromByteArray()` does validate the 32-byte length requirement: [10](#0-9) 

This method is only used for programmatic hash construction, NOT for protobuf deserialization which directly populates the `Value` field without length checks.

## Impact Explanation

**Severity: HIGH - Complete Consensus Halt**

Once a malicious miner executes this attack:

1. **Immediate Consensus Failure**: The short hash is persisted in the current round's state. When any subsequent miner (including honest miners) attempts to produce the next block, the consensus system calls `CalculateSignature` to compute their signature from previous round data.

2. **Unrecoverable Exception**: The `XorAndCompute` method throws `IndexOutOfRangeException` when iterating over the expected 32 bytes, causing block production to fail completely.

3. **Blockchain Halt**: No new blocks can be produced until manual intervention removes or corrects the corrupted round data from contract state, requiring emergency governance action or chain restart.

4. **Network-Wide Impact**: All network participants are affected - validators cannot mine, users cannot submit transactions, and the entire network is frozen.

5. **Cryptographic Scheme Degradation**: Even if DoS is mitigated, short hashes undermine the VRF scheme's security assumptions about entropy and collision resistance.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Prerequisites:**
- Attacker must control a valid miner position in the current round
- This requires sufficient stake/votes to be elected as a validator OR compromise of an existing validator's private key
- In PoS systems, obtaining validator status is achievable with sufficient resources

**Attack Complexity: LOW**
- Once positioned as a miner, execution is trivial
- Simply construct `UpdateValueInput` with 16-byte (or any length < 32) values for `OutValue` and `Signature`
- Submit during the attacker's assigned time slot via the standard `UpdateValue` method
- No complex transaction sequences or timing requirements

**Detection: DIFFICULT**
- The malicious block appears valid during validation (passes all checks)
- Attack only manifests when the next miner attempts block production
- No proactive detection mechanism exists

The combination of achievable preconditions and trivial execution once positioned makes this a realistic attack vector despite the miner requirement.

## Recommendation

Add explicit 32-byte length validation in `UpdateValueValidationProvider.NewConsensusInformationFilled`:

```csharp
private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Existing checks
    if (minerInRound.OutValue == null || minerInRound.Signature == null)
        return false;
    if (!minerInRound.OutValue.Value.Any() || !minerInRound.Signature.Value.Any())
        return false;
    
    // Add cryptographic length validation
    if (minerInRound.OutValue.Value.Length != AElfConstants.HashByteArrayLength)
        return false;
    if (minerInRound.Signature.Value.Length != AElfConstants.HashByteArrayLength)
        return false;
    
    return true;
}
```

Additionally, consider adding similar validation in `RecoverFromUpdateValue` before copying values to provide defense-in-depth.

## Proof of Concept

```csharp
[Fact]
public async Task ConsensusDoS_ShortHashCausesIndexOutOfRange()
{
    // Setup: Initialize consensus with valid miners
    var miners = await InitializeConsensusWithMiners(3);
    var maliciousMiner = miners[0];
    
    // Attack: Malicious miner submits UpdateValue with 16-byte hash (instead of 32)
    var shortHash = new Hash { Value = ByteString.CopyFrom(new byte[16]) };
    var updateValueInput = new UpdateValueInput
    {
        OutValue = shortHash,           // 16 bytes instead of 32
        Signature = shortHash,          // 16 bytes instead of 32  
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        ImpliedIrreversibleBlockHeight = 1
    };
    
    // Malicious miner's block with short hash gets validated and executed
    var result = await maliciousMiner.UpdateValue(updateValueInput);
    result.Status.ShouldBe(TransactionResultStatus.Mined); // Passes validation!
    
    // Trigger: Next honest miner tries to produce block
    var honestMiner = miners[1];
    
    // This should throw IndexOutOfRangeException when CalculateSignature is called
    var exception = await Assert.ThrowsAsync<IndexOutOfRangeException>(async () =>
    {
        await honestMiner.GetConsensusExtraData(new BytesValue 
        { 
            Value = triggerInformation.ToByteString() 
        });
    });
    
    // Consensus is now halted - no more blocks can be produced
    exception.ShouldNotBeNull();
}
```

## Notes

This vulnerability demonstrates a critical gap between protobuf's flexible deserialization (which accepts any byte length) and the contract's cryptographic assumptions (which expect exactly 32 bytes). The validation layer fails to enforce this invariant, allowing malformed data to propagate into the consensus state and trigger an exception during subsequent operations. The attack is particularly severe because it causes a permanent consensus halt rather than a transient failure, requiring emergency intervention to restore the blockchain.

### Citations

**File:** protobuf/aelf/core.proto (L140-143)
```text
message Hash
{
    bytes value = 1;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-17)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L31-32)
```csharp
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-245)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
```

**File:** src/AElf.Types/AElfConstants.cs (L7-7)
```csharp
        public const int HashByteArrayLength = 32;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-114)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L68-69)
```csharp
            var newBytes = new byte[AElfConstants.HashByteArrayLength];
            for (var i = 0; i < newBytes.Length; i++) newBytes[i] = (byte)(h1.Value[i] ^ h2.Value[i]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** src/AElf.Types/Types/Hash.cs (L51-52)
```csharp
            if (bytes.Length != AElfConstants.HashByteArrayLength)
                throw new ArgumentException("Invalid bytes.", nameof(bytes));
```
