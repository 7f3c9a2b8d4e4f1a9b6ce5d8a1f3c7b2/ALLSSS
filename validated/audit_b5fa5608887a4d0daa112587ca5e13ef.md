# Audit Report

## Title
Unvalidated SupposedOrderOfNextRound Causes Consensus Failure in Next Round Generation

## Summary
The AEDPoS consensus contract accepts user-provided `SupposedOrderOfNextRound` values without validating they were correctly calculated from the miner's signature. A malicious miner can set invalid order values (0, negative, or exceeding miner count), causing next round generation to fail with exceptions, resulting in complete consensus halt.

## Finding Description

The consensus system correctly calculates `SupposedOrderOfNextRound` using the formula `GetAbsModulus(sigNum, minersCount) + 1` to ensure values are in the valid range [1, minersCount]. [1](#0-0) 

However, when processing `UpdateValue` transactions, the system accepts order values directly from user input without verification. The `ExtractInformationToUpdateConsensus` method reads `SupposedOrderOfNextRound` from miner state and includes it in the `UpdateValueInput`. [2](#0-1) 

The `ProcessUpdateValue` method then directly sets both `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` from the unvalidated input without recalculating them from the signature: [3](#0-2) 

The validation system fails to catch this. The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are filled and that `PreviousInValue` is correct, but does not validate the order calculation: [4](#0-3) 

Additionally, the `RecoverFromUpdateValue` method used during validation directly applies the provided order values without validation: [5](#0-4) 

**Attack Execution:**
A malicious miner can modify both the consensus header information and the `UpdateValue` transaction to contain invalid `SupposedOrderOfNextRound` values. Since validation only compares the header against state (both containing the same invalid values), the block passes validation.

**Failure Mechanism:**
When next round generation occurs, invalid order values cause failures:

1. **Order = 0**: The miner is excluded from miners who mined via the filter in `GetMinedMiners()`: [6](#0-5) 

2. **Missing required orders**: The `BreakContinuousMining()` function expects specific order positions to exist and uses `First()` which throws `InvalidOperationException` when no element matches: [7](#0-6) 

The same issue occurs when checking for miners with order equals minersCount or minersCount-1: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Failure:**
Invalid `SupposedOrderOfNextRound` values break the round transition mechanism, which is critical for consensus progression. When the next round cannot be generated due to exceptions in `BreakContinuousMining()` or incorrect miner filtering, the blockchain halts entirely.

**Operational Impact:**
- Complete denial of service of the consensus mechanism at round boundaries
- No new blocks can be produced until manual intervention
- All network participants are affected as block production stops
- Requires chain restart or state recovery to resume operation

**Severity Justification:**
High severity because:
- Causes complete consensus failure and blockchain halt
- Deterministic attack with guaranteed success once triggered
- Low cost for attacker (only needs one block production slot)
- Affects entire network availability

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an active miner in the current consensus round
- This is a significant requirement but represents the realistic threat model for consensus attacks
- Any miner can execute this attack

**Attack Complexity:**
- Low complexity: Modify consensus data fields before block finalization
- No cryptographic barriers prevent this modification
- Block producers control both block header and transaction contents
- Attack succeeds immediately when the modified block is accepted by the network

**Detection:**
- Impact is immediately obvious (consensus halts)
- Root cause attribution requires investigation of consensus state
- Difficult to identify malicious miner before consensus breaks

**Feasibility:**
Moderate-to-high probability given that any active miner can execute this attack with modified client software.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify that `SupposedOrderOfNextRound` was correctly calculated from the signature:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var publicKey = validationContext.SenderPubkey;
    var minerInRound = validationContext.ExtraData.Round.RealTimeMinersInformation[publicKey];
    
    if (minerInRound.Signature == null || minerInRound.Signature.Value.IsEmpty)
        return false;
    
    var minersCount = validationContext.ExtraData.Round.RealTimeMinersInformation.Count;
    var sigNum = minerInRound.Signature.ToInt64();
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
        return false;
        
    return true;
}

private static int GetAbsModulus(long longValue, int intValue)
{
    return (int)Math.Abs(longValue % intValue);
}
```

Call this validation method in `UpdateValueValidationProvider.ValidateHeaderInformation()` and reject blocks where the order doesn't match the expected calculation.

## Proof of Concept

A proof of concept would require:
1. Setting up an AElf test environment with multiple miners
2. Modifying a miner node to produce a block with `SupposedOrderOfNextRound = 0` in the `UpdateValue` transaction
3. Observing that the block is accepted (passes validation)
4. Triggering next round generation
5. Observing consensus failure when `GetMinedMiners()` excludes the miner or `BreakContinuousMining()` throws an exception

The test would demonstrate that no validation prevents invalid order values from being accepted, leading to consensus halt.

## Notes

The vulnerability exists because there is no cryptographic or mathematical binding between the miner's signature and their claimed next round order. While the signature itself is validated for authenticity, the derived order value is trusted without verification. This allows miners to claim arbitrary order positions that violate consensus rules, breaking the deterministic round generation algorithm.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L43-43)
```csharp
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-84)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L94-101)
```csharp
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;

        var extraBlockProducerOfNextRound = nextRound.GetExtraBlockProducerInformation();
        if (lastMinerOfNextRound.Pubkey == extraBlockProducerOfNextRound.Pubkey)
        {
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L128-128)
```csharp
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
```
