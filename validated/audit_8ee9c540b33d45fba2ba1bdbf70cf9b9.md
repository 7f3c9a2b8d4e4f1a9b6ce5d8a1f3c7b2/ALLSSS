# Audit Report

## Title
Insufficient Order Validation Allows Duplicate Mining Orders to Break Secret Sharing Reconstruction

## Summary
The AEDPoS consensus mechanism contains three interconnected validation failures that allow a malicious miner to create duplicate `FinalOrderOfNextRound` values through crafted `TuneOrderInformation`. These duplicate orders propagate to subsequent rounds and cause the Shamir's Secret Sharing reconstruction in `DecodeSecret` to produce incorrect results due to division by zero in Lagrange interpolation, compromising the consensus secret sharing verification mechanism.

## Finding Description

The vulnerability exists due to three interconnected validation failures:

**Root Cause #1 - Flawed Duplicate Detection:**

The `NextRoundMiningOrderValidationProvider` attempts to validate mining order uniqueness but the implementation is incorrect. [1](#0-0) 

The `Distinct()` method operates on `MinerInRound` objects rather than extracting and checking the `FinalOrderOfNextRound` property values themselves. Since each miner has a unique `MinerInRound` instance, the distinctness check always passes regardless of whether the actual `FinalOrderOfNextRound` values are duplicates.

**Root Cause #2 - Unvalidated TuneOrderInformation:**

When processing `UpdateValue`, the contract blindly applies whatever `TuneOrderInformation` is provided without validating uniqueness or range. [2](#0-1) 

A malicious miner can craft an `UpdateValueInput` with duplicate `FinalOrderOfNextRound` values in `TuneOrderInformation`, and these will be directly applied to the round state. The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`. [3](#0-2) 

Additionally, the validation framework only applies `NextRoundMiningOrderValidationProvider` for `NextRound` behavior, not for `UpdateValue` behavior. [4](#0-3) 

**Root Cause #3 - Missing Duplicate Order Validation in DecodeSecret:**

When a new round is generated, the `FinalOrderOfNextRound` values from the current round become the `Order` values in the next round. [5](#0-4) 

Subsequently, `RevealSharedInValues` extracts order values from the previous round's miner information and passes them to `DecodeSecret`. [6](#0-5) 

The `DecodeSecret` function performs Shamir's Secret Sharing reconstruction using Lagrange interpolation but does not validate that the `orders` parameter contains unique values. [7](#0-6) 

When duplicate orders exist (e.g., `orders[j] == orders[i]` for `j != i`), the denominator calculation `orders[j] - orders[i]` becomes zero. [8](#0-7) 

This zero denominator flows through `MultiplyRational` [9](#0-8) , then `RationalToWhole` calls `Inverse(0)` [10](#0-9) . The `Inverse` function with input 0 returns 0 through the Extended Euclidean Algorithm [11](#0-10) , causing the Lagrange basis polynomial term to evaluate incorrectly, resulting in incorrect secret reconstruction.

**Attack Sequence:**

1. Round N: Malicious miner (who must be in the active miner set) submits `UpdateValue` with duplicate `FinalOrderOfNextRound` values in `TuneOrderInformation`
2. `ProcessUpdateValue` applies these duplicate values without validation
3. Round N+1: When `NextRound` is called, `GenerateNextRoundInformation` sets the `Order` values in the new round based on `FinalOrderOfNextRound` from Round N, creating duplicate `Order` values
4. Round N+1: Miners perform secret sharing with `DecryptedPieces`
5. Round N+2: When `RevealSharedInValues` is called, it extracts the duplicate `Order` values and passes them to `DecodeSecret`
6. `DecodeSecret` produces incorrect results due to division by zero, setting wrong `PreviousInValue` hashes

## Impact Explanation

**Consensus Integrity Compromise:**

The secret sharing mechanism is a critical component of AEDPoS consensus designed to reconstruct and verify miners' `PreviousInValue` through Lagrange interpolation. This ensures miners cannot cheat on their random value commitments, which are fundamental to consensus security and random number generation.

When `DecodeSecret` produces incorrect results due to duplicate orders:
- Miners' `PreviousInValue` fields are set to wrong hash values in the current round
- The cryptographic integrity of the random number generation chain is broken
- The consensus validation mechanism for miner behavior becomes unreliable
- Subsequent rounds may fail validation or accept invalid consensus states
- The network may experience consensus disruption requiring manual intervention

**Affected Parties:**
- All consensus participants are affected as the secret sharing verification becomes unreliable
- The entire network's consensus security is degraded when this mechanism fails
- Honest miners may be falsely flagged or malicious behavior may go undetected

**Severity Assessment: Medium**
- Does not directly result in fund theft or unauthorized token minting
- Compromises consensus integrity and random number generation security
- Could enable secondary attacks by breaking miner behavior verification
- May cause consensus disruption but does not permanently halt the chain

## Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an active miner in the consensus set (requires winning election through governance)
- No special privileges beyond normal miner capabilities required
- Can craft malicious `UpdateValueInput` with duplicate `TuneOrderInformation` values

**Attack Complexity:**
- Low technical complexity: Simply requires modifying the `TuneOrderInformation` field when calling `UpdateValue`
- No sophisticated cryptographic attacks or precise timing manipulation needed
- Can be executed in a single transaction during the attacker's designated mining slot
- The flawed validation allows the attack to succeed on-chain

**Feasibility Conditions:**
- Requires the attacker to be selected as a miner through the election process
- Secret sharing must be enabled (checked via configuration contract) [12](#0-11) 
- The malicious round must successfully transition through `NextRound` to propagate duplicate orders
- Effects manifest two rounds later when `RevealSharedInValues` is called

**Detection Constraints:**
- The incorrect `PreviousInValue` values would be detectable through off-chain monitoring
- However, the flawed validation allows the attack to succeed on-chain before detection
- May cause observable consensus anomalies that alert network operators

**Likelihood Assessment: Medium**
- Requires compromised miner position, but miners are elected through governance mechanisms
- Easy to execute once in position with low technical barriers
- Detectable through monitoring but may cause temporary disruption before remediation

## Recommendation

**Fix 1: Correct the Duplicate Detection Logic**

In `NextRoundMiningOrderValidationProvider.cs`, change the distinctness check to operate on the `FinalOrderOfNextRound` values:

```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)  // Extract the value first
    .Distinct()
    .Count();
```

**Fix 2: Add Validation for TuneOrderInformation**

In `AEDPoSContract_ProcessConsensusInformation.cs`, validate `TuneOrderInformation` before applying it:

```csharp
// Validate uniqueness and range
var tuneOrderValues = updateValueInput.TuneOrderInformation.Values.ToList();
if (tuneOrderValues.Distinct().Count() != tuneOrderValues.Count)
{
    Assert(false, "Duplicate values in TuneOrderInformation.");
}
foreach (var value in tuneOrderValues)
{
    if (value < 1 || value > currentRound.RealTimeMinersInformation.Count)
    {
        Assert(false, "Invalid order value in TuneOrderInformation.");
    }
}

// Then apply
foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
    currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**Fix 3: Add Duplicate Order Validation in DecodeSecret**

In `SecretSharingHelper.cs`, validate that orders are unique before performing Lagrange interpolation:

```csharp
public static byte[] DecodeSecret(List<byte[]> sharedParts, List<int> orders, int threshold)
{
    // Validate unique orders
    if (orders.Distinct().Count() != orders.Count)
    {
        throw new ArgumentException("Orders must be unique for Lagrange interpolation.");
    }
    
    var result = BigInteger.Zero;
    // ... rest of implementation
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DuplicateOrdersBreakSecretSharing()
{
    // Setup: Initialize consensus with secret sharing enabled
    await InitializeConsensusWith3Miners();
    await EnableSecretSharing();
    
    // Round N: Malicious miner crafts UpdateValue with duplicate TuneOrderInformation
    var maliciousMiner = _initialMiners[0];
    var updateInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = _minerSignatures[maliciousMiner],
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        SupposedOrderOfNextRound = 1,
        TuneOrderInformation = 
        {
            { _initialMiners[1].ToHex(), 2 },  // Duplicate value
            { _initialMiners[2].ToHex(), 2 }   // Duplicate value
        },
        EncryptedPieces = { /* encrypted pieces */ },
        DecryptedPieces = { /* decrypted pieces */ },
        RandomNumber = ByteString.CopyFrom(new byte[64])
    };
    
    // Execute malicious UpdateValue - should apply duplicates without validation
    var updateResult = await ExecuteUpdateValue(maliciousMiner, updateInput);
    updateResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Transition to Round N+1 via NextRound
    await ExecuteNextRound();
    
    var currentRound = await GetCurrentRound();
    
    // Verify duplicate Order values exist in Round N+1
    var orderValues = currentRound.RealTimeMinersInformation.Values
        .Select(m => m.Order).ToList();
    orderValues.Count.ShouldBe(3);
    orderValues.Distinct().Count().ShouldBeLessThan(3); // Proves duplicates exist
    
    // Round N+2: RevealSharedInValues calls DecodeSecret with duplicate orders
    await AdvanceToNextRound();
    
    // At this point, DecodeSecret is called with duplicate orders
    // This causes division by zero in Lagrange interpolation
    // Resulting in incorrect PreviousInValue reconstruction
    
    var finalRound = await GetCurrentRound();
    
    // Verify that PreviousInValue was incorrectly reconstructed
    // The secret sharing mechanism has been compromised
    Assert.True(SecretSharingMechanismCompromised(finalRound));
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-88)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-32)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L40-50)
```csharp
            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));
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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L48-62)
```csharp
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
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L67-70)
```csharp
        private static BigInteger RationalToWhole(BigInteger numerator, BigInteger denominator)
        {
            return numerator * Inverse(denominator) % SecretSharingConsts.FieldPrime;
        }
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L93-96)
```csharp
        private static BigInteger Inverse(BigInteger integer)
        {
            return GetGreatestCommonDivisor2(SecretSharingConsts.FieldPrime, integer).invB.Abs();
        }
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L98-106)
```csharp
        private static (BigInteger numerator, BigInteger denominator) MultiplyRational(
            BigInteger numeratorLhs, BigInteger denominatorLhs,
            BigInteger numeratorRhs, BigInteger denominatorRhs)
        {
            var numerator = numeratorLhs * numeratorRhs % SecretSharingConsts.FieldPrime;
            var denominator = denominatorLhs * denominatorRhs % SecretSharingConsts.FieldPrime;
            var gcd = GetGreatestCommonDivisor(numerator, denominator);
            return (numerator / gcd, denominator / gcd);
        }
```
