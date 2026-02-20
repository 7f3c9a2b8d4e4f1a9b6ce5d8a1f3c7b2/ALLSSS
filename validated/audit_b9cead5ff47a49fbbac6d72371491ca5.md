# Audit Report

## Title
Missing Validation of Next Round Mining Order Allows Position Manipulation

## Summary
The AEDPoS consensus contract fails to validate that miners provide correctly calculated `SupposedOrderOfNextRound` values derived from their cryptographic signatures. Miners can submit arbitrary order values in `UpdateValue` transactions, allowing them to manipulate their mining position in subsequent rounds for unfair advantages in block rewards and MEV extraction.

## Finding Description

The AEDPoS consensus mechanism is designed to deterministically calculate each miner's position in the next round using the formula: `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [1](#0-0)  However, the contract accepts miner-provided order values without validating they match this calculation.

**Root Cause:**

When processing consensus updates, `ProcessUpdateValue` directly accepts the `SupposedOrderOfNextRound` from the transaction input without verification: [2](#0-1) 

The deterministic calculation correctly computes the order from the signature in `ApplyNormalConsensusData`, [3](#0-2)  but this calculated value is only used when honest mining software generates consensus data - it is not enforced during validation.

**Validation Failures:**

The `UpdateValueValidationProvider` only verifies that `OutValue` and `Signature` fields are present, but does not check if the order matches the signature-based calculation: [4](#0-3) 

The `NextRoundMiningOrderValidationProvider` only validates during `NextRound` behavior, not `UpdateValue`: [5](#0-4) 

During validation recovery, `RecoverFromUpdateValue` blindly copies all miners' order values from the provided round without recalculation: [6](#0-5) 

**Exploitation Path:**

When the next round is generated, miners are ordered by their `FinalOrderOfNextRound` values (which are set from the unvalidated `SupposedOrderOfNextRound`): [7](#0-6) 

A malicious miner can:
1. Modify their mining node software to generate custom `UpdateValueInput`
2. Provide a valid `Signature` and `OutValue` (which are validated)
3. Include an arbitrary `SupposedOrderOfNextRound` value of their choosing
4. Submit the `UpdateValue` transaction which sets their manipulated order value
5. In the next round, this manipulated order determines the miner's position

The transaction input is extracted from consensus data: [8](#0-7) 

## Impact Explanation

This vulnerability breaks the cryptographic randomness guarantee of AEDPoS consensus order determination. The impact includes:

**Direct Economic Harm:**
- Miners can position themselves as first producer in the next round, capturing MEV opportunities
- Unfair distribution of block rewards favoring manipulating miners over honest participants
- Systematic competitive advantage across multiple rounds

**Protocol Integrity:**
- Undermines the deterministic yet unpredictable miner ordering that consensus security relies upon
- Allows strategic miners to consistently obtain favorable positions
- Compromises the fundamental security model that mining positions are cryptographically determined

**Affected Parties:**
- Honest miners experience reduced rewards due to unfair competition
- Network decentralization degraded as consensus becomes predictable and gameable
- Token holders affected by compromised consensus integrity

**Severity: MEDIUM** - While not directly stealing funds, this provides systematic unfair advantages that translate to significant economic benefits over time and fundamentally undermines consensus fairness.

## Likelihood Explanation

**Attacker Requirements:**
- Must be an active miner in the current round (privileged but common position for consensus participants)
- Requires ability to modify mining node software to generate custom transaction inputs
- No additional cryptographic keys or governance permissions needed

**Attack Complexity:**
- LOW - Attacker provides manipulated `SupposedOrderOfNextRound` value while maintaining valid `OutValue` and `Signature`
- The miner controls both block header generation and transaction creation
- Mining software naturally generates both components, making modification straightforward

**Detection Difficulty:**
- Manipulated orders appear as normal consensus data in blockchain state
- No events or alerts triggered when orders deviate from expected signature-based calculations
- Would require offline analysis comparing each miner's signature to their reported order value

**Probability: HIGH** - Straightforward exploit with significant economic incentives and low detection risk for miners willing to modify their node software.

## Recommendation

Add validation in `UpdateValueValidationProvider` or `ProcessUpdateValue` to verify that the provided `SupposedOrderOfNextRound` matches the cryptographic calculation:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation or ProcessUpdateValue
var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
var signature = minerInRound.Signature;
var minersCount = validationContext.ProvidedRound.RealTimeMinersInformation.Count;
var expectedOrder = GetAbsModulus(signature.ToInt64(), minersCount) + 1;

if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
{
    return new ValidationResult { Message = "Invalid SupposedOrderOfNextRound - does not match signature-based calculation." };
}
```

Alternatively, the contract could recalculate the value rather than accepting it from the input, ensuring the cryptographic calculation is always enforced.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrder_Test()
{
    // Setup: Initialize consensus with multiple miners
    await InitializeCandidates(3);
    var firstRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Get first miner
    var firstMiner = firstRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).First();
    var firstMinerKeyPair = InitialCoreDataCenterKeyPairs.First(p => p.PublicKey.ToHex() == firstMiner.Pubkey);
    
    // Generate valid consensus data
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(firstMinerKeyPair.PublicKey),
        InValue = HashHelper.ComputeFrom("test_invalue")
    };
    
    var headerInformation = (await AEDPoSContractStub.GetConsensusExtraData.CallAsync(
        triggerInfo.ToBytesValue())).ToConsensusHeaderInformation();
    
    // Extract the transaction input
    var randomNumber = await GenerateRandomProofAsync(firstMinerKeyPair);
    var updateInput = headerInformation.Round.ExtractInformationToUpdateConsensus(
        firstMiner.Pubkey, ByteString.CopyFrom(randomNumber));
    
    // Record the correctly calculated order
    var correctOrder = updateInput.SupposedOrderOfNextRound;
    
    // ATTACK: Manipulate the order to be first (order = 1)
    updateInput.SupposedOrderOfNextRound = 1;
    
    // Submit the manipulated transaction
    var tester = GetAEDPoSContractStub(firstMinerKeyPair);
    var result = await tester.UpdateValue.SendAsync(updateInput);
    
    // Verify the transaction succeeded (vulnerability confirmed)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify the manipulated order was stored
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var updatedMiner = updatedRound.RealTimeMinersInformation[firstMiner.Pubkey];
    
    // The attack succeeds: manipulated order (1) is stored instead of correct order
    updatedMiner.SupposedOrderOfNextRound.ShouldBe(1);
    updatedMiner.FinalOrderOfNextRound.ShouldBe(1);
    Assert.NotEqual(correctOrder, 1); // Confirm we changed it from the correct value
}
```

## Notes

The vulnerability is confirmed through code analysis. The contract accepts arbitrary `SupposedOrderOfNextRound` values without validating them against the cryptographic calculation defined in `ApplyNormalConsensusData`. This allows miners to manipulate their position in subsequent rounds, undermining the consensus protocol's security guarantees about unpredictable, cryptographically-determined mining order.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-44)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-88)
```csharp
        switch (extraData.Behaviour)
        {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-50)
```csharp
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
            EncryptedPieces = { minerInRound.EncryptedPieces },
            DecryptedPieces = { decryptedPreviousInValues },
            MinersPreviousInValues = { minersPreviousInValues },
            ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
            RandomNumber = randomNumber
        };
```
