# Audit Report

## Title
Missing On-Chain Validation of SupposedOrderOfNextRound Allows Miners to Manipulate Next Round Position

## Summary
The AEDPoS consensus contract accepts miner-provided `SupposedOrderOfNextRound` values without validating them against the deterministic calculation formula. This allows any miner to arbitrarily set their position in the next consensus round, breaking the fundamental fairness guarantee of the mining order mechanism.

## Finding Description

The vulnerability exists in the consensus validation and state update flow where `SupposedOrderOfNextRound` is trusted without verification.

**Root Cause Analysis:**

The `SupposedOrderOfNextRound` should be deterministically calculated as `GetAbsModulus(signature.ToInt64(), minersCount) + 1` [1](#0-0) . However, this calculation only happens off-chain during consensus extra data generation.

**Validation Failure:**

The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are non-empty, and that `PreviousInValue` is correct [2](#0-1) . There is **no validation** that recalculates or verifies `SupposedOrderOfNextRound` matches the signature-based formula.

**Circular Validation Issue:**

During `ValidateBeforeExecution`, the system calls `RecoverFromUpdateValue` which blindly copies `SupposedOrderOfNextRound` from the miner-provided round data without any validation [3](#0-2) . This creates a circular validation where the system only checks that state matches the header, but both were derived from the same unvalidated input.

**Direct State Update:**

The `ProcessUpdateValue` function directly assigns the miner-provided `SupposedOrderOfNextRound` to state without any verification [4](#0-3) .

**Attack Vector:**

When generating the next round, miners are sorted by their `FinalOrderOfNextRound` values [5](#0-4) , which are initially set from the unvalidated `SupposedOrderOfNextRound`. A malicious miner can:

1. Generate a valid signature (normal operation)
2. Modify their `SupposedOrderOfNextRound` to any desired value (e.g., always 1 for first position)
3. Submit the `UpdateValue` transaction
4. Pass all validation checks (which don't verify the order calculation)
5. Have their manipulated order accepted into state
6. Gain their chosen position in the next mining round

## Impact Explanation

This is a **High severity** consensus integrity violation.

**Consensus Fairness Breach:**

The deterministic but unpredictable order calculation based on signatures is a core security property of AEDPoS consensus. By allowing miners to choose their order, the system loses:
- Fair randomness in mining order
- Protection against MEV extraction
- Equal opportunity for all miners
- Resistance to position manipulation

**Practical Impact:**

A malicious miner can:
- Always position themselves first (order = 1) to maximize MEV extraction from transaction ordering
- Coordinate with colluding miners to arrange consecutive favorable positions
- Use `TuneOrderInformation` to push honest miners to unfavorable late positions
- Gain systematic advantages in block production timing

**Affected Parties:**

- Honest miners lose the consensus fairness guarantee
- Users face increased MEV extraction and potential censorship
- The blockchain's consensus security model is fundamentally compromised

While this doesn't directly enable fund theft, it violates a critical consensus invariant that ensures fair participation and decentralization.

## Likelihood Explanation

**Exploitability: High**

Any active miner can exploit this vulnerability with minimal effort:
- Requires only standard miner infrastructure
- Attack involves modifying off-chain consensus data generation logic
- No special privileges needed beyond being in the active miner set

**Attack Simplicity:**

The exploit is straightforward:
1. Generate valid signature (normal consensus operation)
2. Calculate what the order *should* be (for comparison)
3. Override `SupposedOrderOfNextRound` to desired value in `UpdateValueInput`
4. Submit transaction - validation passes since it only checks signature validity

**Detection Difficulty:**

The system has **no mechanism** to detect this manipulation:
- No validation compares provided order against calculated order
- No logging or events track order discrepancies
- Honest nodes cannot distinguish malicious orders from legitimate ones

**Economic Incentive:**

Attack cost is negligible (normal block production transaction fee), while benefits include:
- MEV extraction from optimal positioning
- Competitive advantage in transaction ordering
- Censorship capabilities through position control

## Recommendation

Add explicit validation in `UpdateValueValidationProvider` to recalculate and verify `SupposedOrderOfNextRound`:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    var signature = minerInRound.Signature;
    var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
    
    // Recalculate expected order
    var sigNum = signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    // Verify provided order matches calculation
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Add this check to the `ValidateHeaderInformation` method in `UpdateValueValidationProvider` [6](#0-5)  before returning success.

## Proof of Concept

```csharp
[Fact]
public async Task ExploitSupposedOrderManipulation()
{
    // Setup: Initialize consensus with 3 miners
    var miners = GenerateMiners(3);
    var currentRound = GenerateRound(miners, 1);
    
    // Attacker is miner at index 0
    var attackerKey = miners[0];
    var attackerPubkey = attackerKey.PublicKey.ToHex();
    
    // Generate valid signature
    var inValue = Hash.FromString("test_in_value");
    var outValue = HashHelper.ComputeFrom(inValue);
    var signature = HashHelper.ConcatAndCompute(outValue, inValue);
    
    // Calculate what order SHOULD be based on signature
    var minersCount = 3;
    var sigNum = signature.ToInt64();
    var legitimateOrder = Math.Abs(sigNum % minersCount) + 1;
    
    // EXPLOIT: Set arbitrary order (always want to be first)
    var maliciousOrder = 1;
    Assert.NotEqual(legitimateOrder, maliciousOrder); // Confirm we're manipulating
    
    // Create UpdateValueInput with manipulated order
    var updateInput = new UpdateValueInput
    {
        OutValue = outValue,
        Signature = signature,
        PreviousInValue = Hash.Empty,
        SupposedOrderOfNextRound = maliciousOrder, // <-- Malicious value
        ActualMiningTime = TimestampHelper.GetUtcNow(),
        RoundId = currentRound.RoundIdForValidation
    };
    
    // Submit UpdateValue - should fail but WILL PASS
    var result = await ConsensusStub.UpdateValue.SendAsync(updateInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Passes!
    
    // Verify: Check that manipulated order was accepted into state
    var updatedRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerInfo = updatedRound.RealTimeMinersInformation[attackerPubkey];
    
    // VULNERABILITY CONFIRMED: Manipulated order is in state
    attackerInfo.SupposedOrderOfNextRound.ShouldBe(maliciousOrder);
    attackerInfo.FinalOrderOfNextRound.ShouldBe(maliciousOrder);
    
    // Impact: Attacker will be first in next round regardless of signature
    updatedRound.GenerateNextRoundInformation(
        TimestampHelper.GetUtcNow(), 
        TimestampHelper.GetUtcNow(), 
        out var nextRound);
    
    var firstMiner = nextRound.RealTimeMinersInformation.Values
        .OrderBy(m => m.Order).First();
    firstMiner.Pubkey.ShouldBe(attackerPubkey); // Attacker succeeded!
}
```

## Notes

This vulnerability fundamentally breaks the AEDPoS consensus fairness guarantee. The `SupposedOrderOfNextRound` calculation using `GetAbsModulus(signature.ToInt64(), minersCount) + 1` is designed to provide deterministic but unpredictable ordering based on cryptographic signatures. By accepting miner-provided values without validation, the system allows arbitrary position manipulation.

The validation pipeline at [7](#0-6)  shows that `UpdateValueValidationProvider` is the only validator for `UpdateValue` behavior (besides basic checks), and it has no logic to verify order calculations.

The `NextRoundMiningOrderValidationProvider` only validates `NextRound` behavior (not `UpdateValue`), and even then it only checks that orders are distinct [8](#0-7) , not that they match the signature-based calculation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-25)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-26)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-82)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```
