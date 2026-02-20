# Audit Report

## Title
Unvalidated SupposedOrderOfNextRound Causes Consensus Failure in Next Round Generation

## Summary
The AEDPoS consensus contract accepts miner-provided `SupposedOrderOfNextRound` values without validating they were correctly calculated from the miner's signature. A malicious miner can inject invalid order values (0, negative, or exceeding miner count) that pass validation but cause next round generation to fail with exceptions, resulting in complete consensus halt.

## Finding Description

The consensus system correctly calculates `SupposedOrderOfNextRound` using the formula when initially processing consensus data. [1](#0-0)  The calculation ensures values are in the valid range [1, minersCount] using modulo arithmetic. [2](#0-1) 

However, when processing `UpdateValue` transactions, the system accepts order values directly from input without verification. The `ExtractInformationToUpdateConsensus` method reads `SupposedOrderOfNextRound` from the miner's state and includes it in the `UpdateValueInput`. [3](#0-2) 

The `ProcessUpdateValue` method then directly assigns these values from the unvalidated input without recalculating them from the signature. [4](#0-3) 

**Validation Failure:**

The validation system fails to catch invalid values. The `UpdateValueValidationProvider` only validates that `OutValue` and `Signature` are filled and that `PreviousInValue` is correct, but does not validate the order calculation. [5](#0-4) 

During validation, the `RecoverFromUpdateValue` method applies the provided order values to the base round state without independent verification. [6](#0-5)  The validation logic then compares the header against this recovered state, so if both contain the same invalid values, validation passes. [7](#0-6) 

**Attack Execution:**

A malicious miner controls both the block header consensus data and the consensus transaction content. [8](#0-7)  They can generate correct consensus data, then modify both the header and transaction to contain the same invalid `SupposedOrderOfNextRound` value. Since validation recovers state from the header and compares against the transaction (both containing matching invalid values), the block passes validation.

**Failure Mechanism:**

When next round generation occurs, invalid order values cause failures. If order equals 0, the miner is excluded from miners who mined via the filter in `GetMinedMiners()`. [9](#0-8) 

This causes incorrect miner lists for next round generation. The `BreakContinuousMining()` function expects specific order positions to exist and uses `First()` operations that throw `InvalidOperationException` when no element matches the predicate. [10](#0-9) [11](#0-10) [12](#0-11) 

## Impact Explanation

**Consensus Integrity Failure:**

Invalid `SupposedOrderOfNextRound` values break the round transition mechanism, which is critical for consensus progression. When the next round cannot be generated due to exceptions in `BreakContinuousMining()` or incorrect miner filtering, the blockchain halts entirely at the round boundary. [13](#0-12) 

**Operational Impact:**
- Complete denial of service of the consensus mechanism at round boundaries
- No new blocks can be produced until manual intervention
- All network participants are affected as block production stops
- Requires chain restart or state recovery to resume operation

**Severity Justification:**
High severity because it causes complete consensus failure and blockchain halt with deterministic success, low cost for attacker (only needs one block production slot), and affects entire network availability.

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an active miner in the current consensus round
- This represents the realistic threat model for consensus attacks where any miner can potentially act maliciously

**Attack Complexity:**
- Low complexity: Modify consensus data fields before block finalization
- No cryptographic barriers prevent this modification
- Block producers control both block header and transaction contents via the consensus data generation flow [14](#0-13) 
- Attack succeeds immediately when the modified block is accepted by the network

**Feasibility:**
High probability - any active miner can execute this attack with modified client software to inject invalid order values into both the consensus header and transaction.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify that `SupposedOrderOfNextRound` was correctly calculated from the signature:

```csharp
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var providedRound = validationContext.ProvidedRound;
    var senderPubkey = validationContext.SenderPubkey;
    var minerInRound = providedRound.RealTimeMinersInformation[senderPubkey];
    
    if (minerInRound.Signature == null) return false;
    
    var sigNum = minerInRound.Signature.ToInt64();
    var minersCount = providedRound.RealTimeMinersInformation.Count;
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    return minerInRound.SupposedOrderOfNextRound == expectedOrder;
}
```

Add this check to the `ValidateHeaderInformation` method to ensure order values are deterministically correct before accepting the block.

## Proof of Concept

A proof of concept would involve:
1. Setting up a test network with multiple miners
2. Modifying a miner's client to inject `SupposedOrderOfNextRound = 0` into both the consensus header and UpdateValue transaction
3. Observing that validation passes (due to matching values in header and state)
4. Observing that when the current round ends and next round generation is attempted, `GetMinedMiners()` excludes the malicious miner
5. Observing that `BreakContinuousMining()` throws `InvalidOperationException` when expected order positions are missing
6. Confirming the blockchain halts and cannot produce new blocks

The test would validate that the missing order calculation verification allows invalid values to persist in state and break consensus at the next round boundary.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L245-248)
```csharp
    private static int GetAbsModulus(long longValue, int intValue)
    {
        return (int)Math.Abs(longValue % intValue);
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L47-47)
```csharp
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L61-74)
```csharp
    public override TransactionList GenerateConsensusTransactions(BytesValue input)
    {
        var triggerInformation = new AElfConsensusTriggerInformation();
        triggerInformation.MergeFrom(input.Value);
        // Some basic checks.
        Assert(triggerInformation.Pubkey.Any(),
            "Data to request consensus information should contain pubkey.");

        var pubkey = triggerInformation.Pubkey;
        var randomNumber = triggerInformation.RandomNumber;
        var consensusInformation = new AElfConsensusHeaderInformation();
        consensusInformation.MergeFrom(GetConsensusBlockExtraData(input, true).Value);
        var transactionList = GenerateTransactionListByExtraData(consensusInformation, pubkey, randomNumber);
        return transactionList;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-67)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-79)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L84-84)
```csharp
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L101-101)
```csharp
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-133)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);

        Context.LogDebug(
            () => "Previous in value after ApplyNormalConsensusData: " +
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;

        // Update secret pieces of latest in value.
        
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }

        // To publish Out Value.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
```
