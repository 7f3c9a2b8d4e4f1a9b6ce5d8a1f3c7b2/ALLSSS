# Audit Report

## Title
Consensus Breakdown via Duplicate Mining Orders Through Unvalidated TuneOrderInformation

## Summary
A malicious miner can exploit the complete absence of validation for `TuneOrderInformation` in the `UpdateValue` method to assign duplicate `FinalOrderOfNextRound` values to multiple miners. This bypasses the broken duplicate detection mechanism and propagates duplicate `Order` values to subsequent rounds, causing consensus protocol breakdown through `GetMiningInterval()` returning 0 milliseconds and Lagrange interpolation failures in secret sharing, ultimately halting the blockchain network.

## Finding Description

This vulnerability exploits three critical flaws in the AEDPoS consensus validation system:

**Flaw 1: Unvalidated TuneOrderInformation**

The `ProcessUpdateValue` method directly applies arbitrary `TuneOrderInformation` from miner-provided input without any validation [1](#0-0) 

The `UpdateValueValidationProvider` only validates `OutValue`, `Signature`, and `PreviousInValue`, completely ignoring `TuneOrderInformation` [2](#0-1) 

**Flaw 2: Broken Duplicate Detection**

The `NextRoundMiningOrderValidationProvider` calls `.Distinct()` on `MinerInRound` objects rather than their `FinalOrderOfNextRound` values [3](#0-2) 

Since `MinerInRound` is a protobuf-generated class using reference equality, this never detects duplicate `FinalOrderOfNextRound` values.

**Flaw 3: Duplicate Order Propagation**

The `GenerateNextRoundInformation` method directly uses each miner's `FinalOrderOfNextRound` to assign their `Order` in the next round [4](#0-3) 

When multiple miners have identical `FinalOrderOfNextRound`, they receive identical `Order` values with identical `ExpectedMiningTime` values.

**Attack Execution:**

1. Malicious miner (verified by `PreCheck()`) [5](#0-4)  constructs `UpdateValueInput` with:
   - Valid `OutValue`, `Signature`, `PreviousInValue` (to pass validation)
   - Malicious `TuneOrderInformation` setting multiple miners to same `FinalOrderOfNextRound` (e.g., both MinerA and MinerB to value 1)

2. Transaction passes validation and updates state with duplicate values

3. Next round generation assigns duplicate `Order` values to multiple miners

**Impact Chain 1: GetMiningInterval() Collapse**

The `GetMiningInterval()` method retrieves miners with `Order == 1` or `Order == 2` [6](#0-5) 

When two miners have `Order == 1` with identical `ExpectedMiningTime`, the calculation returns 0 milliseconds, preventing:
- Proper time slot calculations
- Mining interval determinations  
- Round progression
- Consensus operation

**Impact Chain 2: Lagrange Interpolation Failure**

During secret sharing reconstruction, `RevealSharedInValues` extracts miner `Order` values [7](#0-6) 

The `DecodeSecret` Lagrange interpolation uses these orders as x-coordinates [8](#0-7) 

When duplicate orders exist (`orders[j] == orders[i]` with `i != j`), the denominator becomes 0, causing `Inverse(0)` to return 0 [9](#0-8) , producing incorrect secret reconstruction that breaks the commit-reveal randomness scheme.

## Impact Explanation

**Severity: CRITICAL** - Complete consensus breakdown and network halt.

1. **Consensus Protocol Failure**: The 0-millisecond mining interval makes time slot validation impossible. Multiple miners believe they should mine simultaneously, causing block production conflicts and preventing round progression.

2. **Randomness Generation Compromise**: Incorrect Lagrange interpolation produces invalid `InValue` reconstructions, undermining the verifiable randomness generation scheme essential to consensus security properties.

3. **Network-Wide Availability Loss**: The entire blockchain network experiences consensus failure, affecting all miners, validators, and users. Transaction processing halts completely.

4. **No Automated Recovery**: Once duplicate orders are written to state, the broken round persists indefinitely until manual intervention (chain rollback or emergency patch).

## Likelihood Explanation

**Likelihood: HIGH** - Any active miner can execute this attack trivially.

**Attacker Prerequisites:**
- Must be an active miner in current or previous round (verified by `PreCheck()`)
- This is a standard participant role, not a privileged position

**Attack Complexity: LOW**
- Single miner can execute independently (no collusion)
- Simple transaction construction with custom `TuneOrderInformation` dictionary
- No complex cryptographic operations required
- No timing dependencies or race conditions
- Deterministic outcome

**Detection Difficulty:**
While `ExtractInformationToUpdateConsensus` shows how legitimate `TuneOrderInformation` should be generated [10](#0-9) , miners can construct arbitrary `UpdateValue` transactions since no validation exists to enforce proper generation.

The attack passes all validation checks silently and only manifests when the next round begins, making preemptive detection difficult without additional monitoring.

## Recommendation

**Immediate Fix:**

1. **Validate TuneOrderInformation in UpdateValueValidationProvider:**
   - Check that all `FinalOrderOfNextRound` values in the tuned set are unique
   - Verify values are within valid range [1, minersCount]
   - Ensure tuning only affects miners who haven't yet set their orders

2. **Fix NextRoundMiningOrderValidationProvider:**
   - Change `.Distinct()` to operate on `FinalOrderOfNextRound` values, not objects:
   ```csharp
   var distinctCount = providedRound.RealTimeMinersInformation.Values
       .Where(m => m.FinalOrderOfNextRound > 0)
       .Select(m => m.FinalOrderOfNextRound)
       .Distinct()
       .Count();
   ```

3. **Add Defensive Check in GenerateNextRoundInformation:**
   - Validate that all `FinalOrderOfNextRound` values are unique before generating next round
   - Assert/throw if duplicates detected

4. **Add Runtime Check in GetMiningInterval:**
   - Assert that interval > 0 to fail-fast if duplicates exist
   - Prevents silent corruption of consensus state

## Proof of Concept

A complete POC would require:
1. Setting up AEDPoS consensus test environment with multiple miners
2. Constructing malicious `UpdateValueInput` with duplicate `TuneOrderInformation` entries
3. Calling `UpdateValue` and observing state corruption
4. Triggering next round generation showing duplicate `Order` values
5. Demonstrating `GetMiningInterval()` returning 0
6. Showing Lagrange interpolation producing incorrect results

The vulnerability is directly reachable through the public `UpdateValue` method with no additional setup required beyond being an active miner.

**Notes:**

This is a critical consensus-layer vulnerability that breaks fundamental protocol invariants. The combination of missing validation and broken duplicate detection creates a single-point-of-failure that any malicious miner can exploit to halt the entire network. The issue affects both time-slot scheduling and secret sharing cryptography, demonstrating systemic validation gaps in the consensus implementation. Immediate patching is required as this represents an existential threat to network availability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
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

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L22-44)
```csharp
        var tuneOrderInformation = RealTimeMinersInformation.Values
            .Where(m => m.FinalOrderOfNextRound != m.SupposedOrderOfNextRound)
            .ToDictionary(m => m.Pubkey, m => m.FinalOrderOfNextRound);

        var decryptedPreviousInValues = RealTimeMinersInformation.Values.Where(v =>
                v.Pubkey != pubkey && v.DecryptedPieces.ContainsKey(pubkey))
            .ToDictionary(info => info.Pubkey, info => info.DecryptedPieces[pubkey]);

        var minersPreviousInValues =
            RealTimeMinersInformation.Values.Where(info => info.PreviousInValue != null).ToDictionary(
                info => info.Pubkey,
                info => info.PreviousInValue);

        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
            TuneOrderInformation = { tuneOrderInformation },
```
