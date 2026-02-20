# Audit Report

## Title
Miners Can Manipulate FinalOrderOfNextRound to Control Next Round Mining Position

## Summary
The AEDPoS consensus contract allows miners to arbitrarily set their `SupposedOrderOfNextRound` and manipulate other miners' `FinalOrderOfNextRound` values through the `UpdateValue` method without any validation. This bypasses the intended deterministic order calculation based on signature hashes, enabling malicious miners to consistently secure favorable mining positions across multiple rounds.

## Finding Description

The AEDPoS consensus mechanism is designed to ensure fair rotation of mining opportunities through deterministic order calculation. The intended behavior calculates a miner's next round position as `supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1`, ensuring cryptographic randomness based on the signature hash. [1](#0-0) 

However, the `ProcessUpdateValue` method directly accepts miner-provided order values without performing this calculation or validating correctness: [2](#0-1) 

Furthermore, miners can modify OTHER miners' positions through the `TuneOrderInformation` field, which is applied without validation: [3](#0-2) 

The `UpdateValueValidationProvider` only checks cryptographic correctness of signatures and hashes, completely ignoring order field validation: [4](#0-3) 

During validation recovery, the system blindly copies the provided order values without recalculating them based on the signature hash: [5](#0-4) 

The `NextRoundMiningOrderValidationProvider` only validates that the count of miners with orders matches those who produced blocks, not the correctness of the order values themselves: [6](#0-5) 

Most critically, these manipulated values directly determine the mining order in the next round without any recalculation: [7](#0-6) 

The attack flow is straightforward: A malicious miner calls the public `UpdateValue` method: [8](#0-7) 

The only precondition check verifies the miner is in the miner list, which any active miner satisfies: [9](#0-8) 

The proper calculation via `ApplyNormalConsensusData` is only used during consensus data generation for honest miners, NOT during validation of incoming UpdateValue transactions: [10](#0-9) 

## Impact Explanation

This vulnerability represents a critical breach of consensus integrity with severe consequences:

**Consensus Fairness Violation**: The AEDPoS mechanism's core fairness guarantee—that mining order is determined by unpredictable signature hashes—is completely bypassed. Malicious miners can consistently secure position 1, gaining systematic advantages in transaction ordering, MEV extraction, and block rewards.

**Economic Impact**: The first miner in each round gains priority in transaction selection and fee collection. By consistently mining first, an attacker can extract maximum value from transaction ordering while other honest miners lose their fair share of mining opportunities and associated rewards.

**Protocol Integrity**: This breaks the critical invariant that miner schedule integrity must be maintained. The deterministic, cryptographically-derived mining order is replaced with arbitrary attacker-controlled values, fundamentally undermining the consensus mechanism's design principles.

**Systemic Risk**: Unlike a one-time attack, this manipulation persists across rounds. Once an attacker establishes favorable positioning, they can maintain it indefinitely through repeated manipulation, creating a permanent advantage that compounds over time.

## Likelihood Explanation

This vulnerability has HIGH likelihood of exploitation:

**Attacker Accessibility**: Any active miner in the consensus set can execute this attack. The only requirement is being part of the legitimate miner list, which is the normal operating condition for all consensus participants.

**Technical Simplicity**: The attack requires no cryptographic bypasses, complex state manipulation, or sophisticated tooling. An attacker simply needs to construct a custom `UpdateValueInput` message with arbitrary order values instead of using the helper function `ExtractInformationToUpdateConsensus`. [11](#0-10) 

**No Additional Barriers**: The validation system runs during block execution but adds no validators for order fields during `UpdateValue` behavior: [12](#0-11) 

**Low Detection Risk**: The manipulated values appear structurally valid (they're just integers within the valid range). Without explicit comparison against expected calculated values, the manipulation is invisible to on-chain monitoring.

## Recommendation

Add validation in `ProcessUpdateValue` to verify that the provided `SupposedOrderOfNextRound` matches the expected calculation from the signature hash:

1. Calculate expected order: `expectedOrder = GetAbsModulus(minerInRound.Signature.ToInt64(), currentRound.RealTimeMinersInformation.Count) + 1`
2. Assert: `updateValueInput.SupposedOrderOfNextRound == expectedOrder`
3. Validate `TuneOrderInformation` entries against a recalculated conflict resolution algorithm
4. Add a validation provider that verifies order value correctness, not just count

Alternatively, remove these fields from `UpdateValueInput` entirely and calculate them server-side during `ProcessUpdateValue` using the provided signature, eliminating user control over these critical consensus parameters.

## Proof of Concept

```csharp
[Fact]
public async Task Miner_Can_Manipulate_Mining_Order_Test()
{
    // Initialize consensus with multiple miners
    await InitializeCandidates(3);
    var firstRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Get first miner
    var firstMiner = firstRound.RealTimeMinersInformation.Values.OrderBy(m => m.Order).First();
    var attackerKeyPair = InitialCoreDataCenterKeyPairs.First(k => k.PublicKey.ToHex() == firstMiner.Pubkey);
    
    // Attacker crafts malicious UpdateValueInput
    var maliciousInput = new UpdateValueInput
    {
        OutValue = HashHelper.ComputeFrom("test"),
        Signature = HashHelper.ComputeFrom("signature"),
        SupposedOrderOfNextRound = 1, // Attacker chooses position 1
        TuneOrderInformation = { /* Push others to higher positions */ },
        ActualMiningTime = Context.CurrentBlockTime,
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(attackerKeyPair))
    };
    
    // Execute attack
    var attackerStub = GetAEDPoSContractStub(attackerKeyPair);
    await attackerStub.UpdateValue.SendAsync(maliciousInput);
    
    // Verify manipulation succeeded
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var attackerInfo = updatedRound.RealTimeMinersInformation[firstMiner.Pubkey];
    
    // Attack succeeds: attacker's chosen order is accepted
    attackerInfo.FinalOrderOfNextRound.ShouldBe(1);
}
```

## Notes

The vulnerability exists because the system trusts miners to provide correct order calculations rather than enforcing them through validation. The `ApplyNormalConsensusData` method contains the proper calculation logic but is only used during honest consensus data generation, not during validation of incoming transactions. This creates a critical gap where malicious miners can bypass deterministic order assignment.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-20)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L43-44)
```csharp
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
            TuneOrderInformation = { tuneOrderInformation },
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```
