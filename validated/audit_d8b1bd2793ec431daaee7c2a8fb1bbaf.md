# Audit Report

## Title
Unvalidated DecryptedPieces Allow Manipulation of Revealed InValues in Secret Sharing Consensus

## Summary
The AEDPoS consensus contract's secret sharing mechanism lacks cryptographic validation when reconstructing InValues from DecryptedPieces. Malicious miners can provide corrupted decrypted pieces that cause incorrect InValue reconstruction for offline miners, compromising consensus randomness and next-round miner ordering.

## Finding Description

The AEDPoS consensus uses Shamir's Secret Sharing to reveal InValues for miners who fail to produce blocks. However, the protocol does not validate that reconstructed InValues match the original miner's committed OutValues, creating an exploitable vulnerability.

**Vulnerable Flow:**

1. **Unvalidated Collection**: The `ExtractInformationToUpdateConsensus()` method collects DecryptedPieces from round state without any cryptographic verification. [1](#0-0) 

2. **Unvalidated Storage**: The `PerformSecretSharing()` method directly stores attacker-provided DecryptedPieces into other miners' records without validation. [2](#0-1) 

3. **Unvalidated Reconstruction**: The `RevealSharedInValues()` method reconstructs InValues using `SecretSharingHelper.DecodeSecret()` but never validates the result against the original miner's OutValue from the previous round. [3](#0-2) 

The critical missing check is: `HashHelper.ComputeFrom(revealedInValue) == previousRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].OutValue`

4. **Usage Without Validation**: The `SupplyCurrentRoundInformation()` method uses these potentially corrupted PreviousInValues to calculate signatures for offline miners. [4](#0-3) 

**Why Existing Protections Fail:**

The `UpdateValueValidationProvider` validates self-provided PreviousInValues by checking the hash matches the previous OutValue. [5](#0-4) 

However, this validator is only invoked for UpdateValue transactions when miners provide their own PreviousInValue. It does NOT validate InValues reconstructed via secret sharing during NextRound transitions. [6](#0-5) 

## Impact Explanation

**HIGH Severity** - This vulnerability breaks fundamental consensus invariants:

1. **Signature Manipulation**: Corrupted InValues lead to incorrect signature calculations via `previousRound.CalculateSignature(previousInValue)`, which XORs signatures from all miners. This pollutes the consensus randomness pool. [7](#0-6) 

2. **Mining Order Manipulation**: Signatures determine `SupposedOrderOfNextRound` through modulus operations in `ApplyNormalConsensusData()`, allowing attackers to influence miner scheduling. [8](#0-7) 

3. **Consensus Integrity**: The attack violates the cryptographic chain where each round's InValue must hash to the previous round's OutValue. This breaks the verifiable randomness property essential for fair consensus.

**Affected Components:**
- Offline miners whose InValues are reconstructed
- All participants depending on consensus randomness
- LIB (Last Irreversible Block) calculations relying on correct round progression

## Likelihood Explanation

**MEDIUM-HIGH Likelihood** - The attack is feasible under realistic conditions:

**Attacker Requirements:**
- Must be an active miner in the current mining set (no special privileges required)
- Can call the public `UpdateValue()` method with arbitrary DecryptedPieces [9](#0-8) 

**Preconditions:**
- Target miner must miss their time slot (common due to network issues, downtime, or maintenance)
- Secret sharing must be enabled via configuration [10](#0-9) 
- Attacker's corrupted piece is included in reconstruction (highly likely since threshold is 2/3 of miners)

**Attack Complexity:** LOW - Simply provide corrupted byte arrays as DecryptedPieces with no technical barriers since validation is absent.

## Recommendation

Add cryptographic validation in `RevealSharedInValues()` after reconstructing each InValue:

```csharp
var revealedInValue = 
    HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

// Validate reconstructed InValue matches original OutValue
if (HashHelper.ComputeFrom(revealedInValue) != 
    anotherMinerInPreviousRound.OutValue)
{
    // Skip invalid reconstruction - don't set PreviousInValue
    Context.LogDebug($"Invalid reconstructed InValue for {publicKeyOfAnotherMiner}");
    continue;
}

currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

This ensures only cryptographically valid reconstructions are used, maintaining the InValue→OutValue hash chain integrity.

## Proof of Concept

```csharp
// POC: Malicious miner provides corrupted DecryptedPieces for offline target

[Fact]
public async Task MaliciousMiner_CorruptsDecryptedPieces_ManipulatesTargetInValue()
{
    // Setup: Initialize consensus with multiple miners
    var miners = await InitializeConsensusWithMiners(5);
    var attacker = miners[0];
    var target = miners[1]; 
    
    // Target goes offline (doesn't produce block)
    await ProduceBlocksExceptTarget(miners, target);
    
    // Attacker submits UpdateValue with corrupted DecryptedPieces for target
    var corruptedPieces = GenerateCorruptedDecryptedPieces(target.PublicKey);
    await attacker.UpdateValue(new UpdateValueInput {
        DecryptedPieces = { corruptedPieces },
        // ... other fields
    });
    
    // Extra block producer triggers NextRound
    await miners.Last().NextRound(nextRoundInput);
    
    // Verify: Target's reconstructed InValue is corrupted
    var currentRound = await GetCurrentRound();
    var targetInValue = currentRound.RealTimeMinersInformation[target.PublicKey].InValue;
    var previousRound = await GetPreviousRound();
    var expectedOutValue = previousRound.RealTimeMinersInformation[target.PublicKey].OutValue;
    
    // This assertion FAILS - proving InValue doesn't match original OutValue
    Assert.NotEqual(HashHelper.ComputeFrom(targetInValue), expectedOutValue);
    
    // Corrupted InValue affects consensus randomness and next round ordering
    var signature = currentRound.RealTimeMinersInformation[target.PublicKey].Signature;
    Assert.True(IsSignatureCorrupted(signature, targetInValue));
}
```

**Notes:**
- The vulnerability exists because `SecretSharingHelper.DecodeSecret()` is a pure mathematical function that returns a result regardless of input validity [11](#0-10) 
- Without validation, all nodes deterministically compute the same incorrect InValue, making the corruption consensus-compatible but cryptographically invalid
- The off-chain `RevealPreviousInValues()` service exhibits identical lack of validation [12](#0-11)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L26-28)
```csharp
        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L291-293)
```csharp
        foreach (var decryptedPreviousInValue in input.DecryptedPieces)
            round.RealTimeMinersInformation[decryptedPreviousInValue.Key].DecryptedPieces
                .Add(publicKey, decryptedPreviousInValue.Value);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L56-78)
```csharp
    private bool IsSecretSharingEnabled()
    {
        if (State.ConfigurationContract.Value == null)
        {
            var configurationContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConfigurationContractSystemName);
            if (configurationContractAddress == null)
            {
                // Which means Configuration Contract hasn't been deployed yet.
                return false;
            }

            State.ConfigurationContract.Value = configurationContractAddress;
        }

        var secretSharingEnabled = new BoolValue();
        secretSharingEnabled.MergeFrom(State.ConfigurationContract.GetConfiguration.Call(new StringValue
        {
            Value = AEDPoSContractConstants.SecretSharingEnabledConfigurationKey
        }).Value);

        return secretSharingEnabled.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L48-48)
```csharp
        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-80)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L44-65)
```csharp
        public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
        {
            var result = BigInteger.Zero;

            for (var i = 0; i < threshold; i++)
            {
                var numerator = new BigInteger(sharedParts[i]);
                var denominator = BigInteger.One;
                for (var j = 0; j < threshold; j++)
                {
                    if (i == j) continue;

                    (numerator, denominator) =
                        MultiplyRational(numerator, denominator, orders[j], orders[j] - orders[i]);
                }

                result += RationalToWhole(numerator, denominator);
                result %= SecretSharingConsts.FieldPrime;
            }

            return result.ToBytesArray();
        }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L175-176)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
```
