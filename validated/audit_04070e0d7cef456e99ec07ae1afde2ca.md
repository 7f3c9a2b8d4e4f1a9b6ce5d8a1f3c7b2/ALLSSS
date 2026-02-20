# Audit Report

## Title
Consensus Breakdown via Duplicate Mining Orders Through Broken Validation and Lagrange Interpolation Failure

## Summary
A malicious miner can exploit unvalidated `TuneOrderInformation` in the `UpdateValue` transaction to assign duplicate `FinalOrderOfNextRound` values to multiple miners. The flawed `NextRoundMiningOrderValidationProvider` fails to detect these duplicates, allowing them to propagate into the next round as duplicate `Order` values. This causes critical consensus failures: `GetMiningInterval()` returns 0ms (eliminating time-slot separation), and Lagrange interpolation in secret sharing silently corrupts randomness generation. A single malicious miner can halt the entire blockchain network.

## Finding Description

The vulnerability consists of five interconnected components that break the AEDPoS consensus protocol:

**1. Unvalidated TuneOrderInformation Input**

When a miner produces a block via `UpdateValue`, they provide an `UpdateValueInput` containing `TuneOrderInformation` that directly modifies miners' `FinalOrderOfNextRound` values. The public method accepts any input from an authorized miner. [1](#0-0) 

The modification is applied unconditionally in `ProcessUpdateValue` without any validation of the `TuneOrderInformation` contents. [2](#0-1) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue` fields, completely ignoring `TuneOrderInformation`. [3](#0-2) 

**2. Ineffective Duplicate Detection**

The `NextRoundMiningOrderValidationProvider` attempts to validate mining orders but contains a critical flaw. It calls `.Distinct()` on the collection of `MinerInRound` objects themselves rather than on their `FinalOrderOfNextRound` values. [4](#0-3) 

Since `MinerInRound` is a protobuf-generated class with value equality comparing all fields (pubkey, signature, out value, etc.), two miners with identical `FinalOrderOfNextRound` but different other fields are considered distinct. The validator never detects duplicate order values.

**3. Duplicate Orders Propagate to Next Round**

When `GenerateNextRoundInformation` creates the next round, it directly assigns each miner's `Order` from their `FinalOrderOfNextRound` value. If multiple miners have the same `FinalOrderOfNextRound` (set by malicious tuning), they all receive the same `Order` in the next round. [5](#0-4) 

**4. GetMiningInterval() Breakdown**

The `GetMiningInterval()` method retrieves miners with `Order == 1` and `Order == 2` to calculate the mining interval. [6](#0-5) 

With duplicate orders (e.g., two miners both having `Order = 1`), both miners have identical `ExpectedMiningTime` values (calculated as `currentBlockTimestamp + miningInterval * order`), resulting in a time difference of 0 milliseconds. This completely breaks time-slot-based consensus.

**5. Lagrange Interpolation Failure in Secret Sharing**

The `RevealSharedInValues` method constructs an `orders` list from miners' `Order` values to reconstruct shared secrets via Lagrange interpolation. [7](#0-6) 

The `DecodeSecret` function performs Lagrange interpolation by computing denominator terms as `orders[j] - orders[i]`. [8](#0-7) 

When `orders[j] == orders[i]` for `i != j`, the denominator becomes 0. The `Inverse(0)` function returns 0 rather than throwing an error, causing the interpolation to proceed with incorrect values and silently corrupt the reconstructed secrets. [9](#0-8) 

## Impact Explanation

**Consensus Protocol Breakdown (CRITICAL)**: With a mining interval of 0 milliseconds, the consensus protocol cannot function. All miners receive identical `ExpectedMiningTime` values, eliminating the time-slot separation that AEDPoS relies on. Time-slot validation fails across the network, multiple miners attempt simultaneous block production, and the network cannot progress to subsequent rounds without emergency manual intervention.

**Secret Sharing Compromise (HIGH)**: The incorrect Lagrange interpolation breaks the commit-reveal randomness scheme. Revealed in-values are reconstructed with wrong values due to division by zero in the denominator. This compromises random number generation integrity, prevents detection of dishonest miners, and allows manipulation of consensus randomness.

**Network-Wide Availability Loss**: The entire blockchain experiences complete consensus failure. All miners, validators, and users are affected. All blockchain operations halt, requiring emergency governance intervention or hard fork to recover.

**Severity Assessment**: HIGH - A single malicious miner can halt the entire network without collusion, significant capital, or special privileges beyond being an active block producer in the current round.

## Likelihood Explanation

**Attacker Requirements**: 
- Must be an elected miner in the current round (achieved through normal election process)
- Must construct a custom `UpdateValueInput` transaction with malicious `TuneOrderInformation`
- Must submit during their allocated time slot (guaranteed opportunity for active miners)

**Attack Complexity**: LOW
- Single-party attack (no collusion required)
- Straightforward transaction construction (simple map manipulation)
- No cryptographic complexity or timing dependencies
- Passes all validation checks silently

**Feasibility**: HIGH - While legitimate consensus operation uses `ExtractInformationToUpdateConsensus` to generate proper `TuneOrderInformation` [10](#0-9) , nothing enforces this pattern. The `UpdateValue` method is public and accepts any `UpdateValueInput` that passes validation. Since `TuneOrderInformation` is never validated, miners can provide arbitrary values.

**Detection Difficulty**: The attack passes all validation checks and only manifests when the next round begins, making preemptive detection nearly impossible without external monitoring.

**Economic Motivation**: Competitor chain operators, disgruntled miners, or attackers seeking ransom can execute this at minimal cost (only transaction fees).

## Recommendation

Implement comprehensive validation of `TuneOrderInformation` in the `UpdateValueValidationProvider`:

1. **Validate Uniqueness**: Add validation to check that all `FinalOrderOfNextRound` values are unique across miners who produced blocks:
   - Extract the distinct count of `FinalOrderOfNextRound` VALUES (not objects)
   - Compare against the count of miners with `OutValue != null`
   - Reject if duplicates exist

2. **Fix NextRoundMiningOrderValidationProvider**: Change the duplicate detection to operate on the order values themselves:
   - Use `.Select(m => m.FinalOrderOfNextRound).Distinct().Count()` instead of calling `.Distinct()` on the objects

3. **Range Validation**: Ensure `TuneOrderInformation` values are within valid bounds (1 to miner count)

4. **Authorization Check**: Verify that miners can only tune orders for miners who actually mined in the current round

## Proof of Concept

A malicious miner in a round with 3 total miners can execute this attack by:

1. Waiting for their mining time slot
2. Constructing an `UpdateValueInput` with legitimate `OutValue`, `Signature`, etc.
3. Setting `TuneOrderInformation = { "MinerA_Pubkey": 1, "MinerB_Pubkey": 1 }` (duplicate order 1)
4. Calling `UpdateValue` - passes all validation
5. When `NextRound` is called, both MinerA and MinerB receive `Order = 1`
6. `GetMiningInterval()` calculates: `ExpectedMiningTime[1] - ExpectedMiningTime[1] = 0ms`
7. All subsequent time-slot validations fail
8. Secret sharing reconstruction produces incorrect values due to division by zero
9. Network halts - no more blocks can be produced

The attack is deterministic and requires no special timing or race conditions. Any elected miner can execute it during their allocated time slot.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-20)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
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

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L52-58)
```csharp
                for (var j = 0; j < threshold; j++)
                {
                    if (i == j) continue;

                    (numerator, denominator) =
                        MultiplyRational(numerator, denominator, orders[j], orders[j] - orders[i]);
                }
```

**File:** src/AElf.Cryptography/SecretSharing/SecretSharingHelper.cs (L93-96)
```csharp
        private static BigInteger Inverse(BigInteger integer)
        {
            return GetGreatestCommonDivisor2(SecretSharingConsts.FieldPrime, integer).invB.Abs();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-24)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);
```
