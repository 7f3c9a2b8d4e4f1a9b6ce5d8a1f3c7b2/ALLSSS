# Audit Report

## Title
Malicious Miner Can Overwrite Other Miners' PreviousInValue Without Cryptographic Validation

## Summary
The AEDPoS consensus contract allows any miner to overwrite other miners' `PreviousInValue` fields with arbitrary values through the `PerformSecretSharing()` function, without validating these values against the cryptographic commitments from the previous round. This breaks the fundamental commitment scheme (where `hash(PreviousInValue)` must equal the previous `OutValue`) and enables manipulation of consensus signatures used in random number generation.

## Finding Description

The vulnerability exists in the `PerformSecretSharing` method where values from `input.MinersPreviousInValues` are directly written to round state without cryptographic validation: [1](#0-0) 

This method is invoked during `ProcessUpdateValue` when secret sharing is enabled: [2](#0-1) 

The critical flaw is that `UpdateValueValidationProvider` only validates the **sender's own** `PreviousInValue`, not the values for other miners provided in `MinersPreviousInValues`: [3](#0-2) 

Notice line 38 explicitly retrieves only `SenderPubkey`, and the hash validation on line 48 only applies to the sender's own value. The malicious values for other miners in the dictionary pass through unchecked.

**Attack Path:**
1. In Round N, Miner A produces a block with `OutValue_A = hash(InValue_A)`
2. In Round N+1, Miner A misses their time slot (doesn't produce a block)
3. Malicious Miner B calls `UpdateValue` with `input.MinersPreviousInValues[A] = fake_value` where `hash(fake_value) ≠ OutValue_A`
4. The vulnerable code at line 296 writes: `round.RealTimeMinersInformation[A].PreviousInValue = fake_value`
5. This corrupted state is persisted via `TryToUpdateRoundInformation`

The corrupted `PreviousInValue` is later used when the system fills in consensus data for miners who missed their slots. The `SupplyCurrentRoundInformation` method retrieves the corrupted value from state and uses it to calculate signatures: [4](#0-3) 

The signature calculation uses the `CalculateSignature` method which XORs the `PreviousInValue` with all miners' signatures: [5](#0-4) 

The `UpdateValueInput` protobuf definition confirms that `miners_previous_in_values` is user-controlled input: [6](#0-5) 

## Impact Explanation

**Critical Consensus Invariant Violation**: The AEDPoS consensus mechanism relies on a cryptographic commitment scheme where miners commit to `OutValue = hash(InValue)` in round N, then reveal `InValue` as `PreviousInValue` in round N+1. This vulnerability allows attackers to substitute fake `PreviousInValue` values that don't hash to the committed `OutValue`, fundamentally breaking the commitment scheme.

**Signature and Random Number Manipulation**: The corrupted `PreviousInValue` is used in signature calculations that feed into random number generation. When miners miss their time slots, the system retrieves their `PreviousInValue` from state and uses it to calculate their signature via `CalculateSignature`. Since this signature contributes to consensus random numbers, an attacker can influence randomness by controlling other miners' `PreviousInValue` values.

**Persistent State Corruption**: The invalid values are permanently written to the round state and persist across consensus operations, affecting multiple rounds and potentially propagating through secret sharing reconstruction mechanisms.

**Wide Impact**: All miners in the network are vulnerable as any miner can have their legitimately revealed `PreviousInValue` overwritten by any other miner with malicious intent.

## Likelihood Explanation

**High Likelihood** due to multiple factors:

- **Direct Entry Point**: Any miner can call the public `UpdateValue` method, which only requires being in the miner list (a normal operating requirement) [7](#0-6) 

- **Minimal Privileges**: The `PreCheck` only verifies the caller is in the current or previous miner list, which every legitimate miner satisfies [8](#0-7) 

- **Low Attack Complexity**: The attacker simply includes arbitrary key-value pairs in `MinersPreviousInValues` when calling `UpdateValue`
- **No Detection**: The malicious values are written silently without validation errors or logging
- **No Cost Barrier**: Only standard transaction fees apply
- **Timing Flexibility**: Attack can be executed at any time during the round when secret sharing is enabled

The `ExtractInformationToUpdateConsensus` method shows miners are expected to extract `PreviousInValue` from state, but since this occurs off-chain, a malicious miner can modify these values before submission: [9](#0-8) 

## Recommendation

Add cryptographic validation to verify that each `PreviousInValue` in `MinersPreviousInValues` matches the corresponding miner's `OutValue` from the previous round:

```csharp
private static void PerformSecretSharing(UpdateValueInput input, MinerInRound minerInRound, Round round,
    string publicKey, Round previousRound)
{
    minerInRound.EncryptedPieces.Add(input.EncryptedPieces);
    foreach (var decryptedPreviousInValue in input.DecryptedPieces)
        round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
            .Add(publicKey, decryptedPreviousInValue.Value);

    // FIXED: Add validation before writing PreviousInValue
    foreach (var previousInValue in input.MinersPreviousInValues)
    {
        // Verify the revealed value hashes to the committed OutValue from previous round
        if (previousRound != null && 
            previousRound.RealTimeMinersInformation.ContainsKey(previousInValue.Key))
        {
            var expectedOutValue = previousRound.RealTimeMinersInformation[previousInValue.Key].OutValue;
            var actualHash = HashHelper.ComputeFrom(previousInValue.Value);
            
            // Only write if the cryptographic commitment is valid
            if (actualHash == expectedOutValue)
            {
                round.RealTimeMinersInformation[previousInValue.Key].PreviousInValue = previousInValue.Value;
            }
        }
    }
}
```

Additionally, update the method signature in `ProcessUpdateValue` to pass the `previousRound`:

```csharp
if (IsSecretSharingEnabled())
{
    if (TryToGetPreviousRoundInformation(out var previousRoundForValidation))
    {
        PerformSecretSharing(updateValueInput, minerInRound, currentRound, 
            _processingBlockMinerPubkey, previousRoundForValidation);
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMinerCanOverwriteOtherMinersPreviousInValue()
{
    // Setup: Initialize consensus with miners A and B
    var minerA = SampleECKeyPairs.KeyPairs[0];
    var minerB = SampleECKeyPairs.KeyPairs[1];
    
    // Round N: Miner A produces block with OutValue_A = hash(InValue_A)
    var inValueA = HashHelper.ComputeFrom("legitimate_secret_A");
    var outValueA = HashHelper.ComputeFrom(inValueA);
    
    // Advance to Round N+1 where Miner A misses their slot
    // Malicious Miner B calls UpdateValue with fake PreviousInValue for Miner A
    var fakeInValueForA = HashHelper.ComputeFrom("malicious_fake_value");
    // Note: hash(fakeInValueForA) ≠ outValueA (commitment scheme violated)
    
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("minerB_secret"),
        Signature = Hash.Empty,
        PreviousInValue = Hash.Empty,
        MinersPreviousInValues =
        {
            { minerA.PublicKey.ToHex(), fakeInValueForA }  // MALICIOUS: Wrong value
        }
    };
    
    // Execute attack
    await ConsensusStub.UpdateValue.SendAsync(maliciousInput);
    
    // Verify: Miner A's PreviousInValue in state is now the fake value
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerAInfo = currentRound.RealTimeMinersInformation[minerA.PublicKey.ToHex()];
    
    // VULNERABILITY CONFIRMED: The fake value is written despite not matching the commitment
    Assert.Equal(fakeInValueForA, minerAInfo.PreviousInValue);
    Assert.NotEqual(HashHelper.ComputeFrom(minerAInfo.PreviousInValue), outValueA);
}
```

**Notes:**
- This vulnerability requires secret sharing to be enabled via the Configuration contract
- The attack is most effective when targeting miners who miss their time slots, as their corrupted `PreviousInValue` will be used in `SupplyCurrentRoundInformation`
- The impact extends to random number generation through the signature calculation mechanism, which is critical for consensus fairness
- The vulnerability violates the fundamental cryptographic invariant that `hash(PreviousInValue) == previous OutValue`, which is essential for the security of the commitment scheme in AEDPoS consensus

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L186-199)
```csharp
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
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

**File:** protobuf/aedpos_contract.proto (L215-216)
```text
    // The InValue in the previous round, miner public key -> InValue.
    map<string, aelf.Hash> miners_previous_in_values = 11;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L30-33)
```csharp
        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);
```
