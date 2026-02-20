# Audit Report

## Title
Consensus Behavior Substitution Allows Miners to Bypass Cryptographic Value Publication

## Summary
The AEDPoS consensus validation lacks enforcement that miners producing their first block in a round use the required `UpdateValue` behavior. Miners can substitute `TinyBlock` behavior to bypass cryptographic value publication (OutValue, Signature, PreviousInValue), breaking the consensus randomness mechanism and creating state inconsistencies. Coordinated exploitation degrades protocol-level consensus security.

## Finding Description

The AEDPoS consensus protocol defines two block production behaviors with distinct cryptographic requirements:
- `UpdateValue`: Required for first block in round, must publish OutValue, Signature, PreviousInValue
- `TinyBlock`: For subsequent blocks within time slot, excludes cryptographic fields

**Correct Behavior Determination**: The system correctly determines that miners with `OutValue == null` should use `UpdateValue` behavior. [1](#0-0) 

**Missing Validation**: The validation logic accepts whatever behavior is claimed in `extraData.Behaviour` without verifying it matches the miner's state. The validator blindly recovers data based on the claimed behavior: [2](#0-1) 

**Validation Provider Bypass**: The `UpdateValueValidationProvider` (which validates OutValue/Signature presence) is only added for `UpdateValue` behavior, not for `TinyBlock`: [3](#0-2) 

**Recovery Divergence**: `RecoverFromTinyBlock` only copies basic mining times, completely ignoring cryptographic fields: [4](#0-3) 

In contrast, `RecoverFromUpdateValue` properly recovers all cryptographic fields including OutValue, Signature, and PreviousInValue: [5](#0-4) 

**Processing Divergence**: `ProcessUpdateValue` sets critical consensus values including SupposedOrderOfNextRound: [6](#0-5) 

But `ProcessTinyBlock` only updates block counts without setting any cryptographic consensus values: [7](#0-6) 

**State Inconsistency**: Since `SupposedOrderOfNextRound` remains at default value 0, next round generation logic incorrectly classifies the miner as non-mining: [8](#0-7) 

This causes `MissedTimeSlots` to increment despite block production: [9](#0-8) 

**Randomness Degradation**: Extra block producer selection depends on signature availability, defaulting to predictable order 1 when signatures are missing: [10](#0-9) 

## Impact Explanation

**Protocol-Level Consensus Security Degradation**:

1. **Cryptographic Chain Broken**: The AEDPoS commit-reveal scheme requires all miners to publish OutValue (commitment) and Signature for proper randomness generation. Missing values break the cryptographic chain securing consensus ordering.

2. **State Inconsistency**: The protocol enters an inconsistent state where `ProducedBlocks` increments (indicating block production) while `OutValue`, `Signature`, and `PreviousInValue` remain null (indicating no consensus contribution), and `SupposedOrderOfNextRound` remains 0 (classified as non-mining).

3. **Consensus Randomness Collapse**: If multiple miners coordinate this attack, signature-based mining order determination fails, extra block producer selection becomes deterministic (defaults to order 1), and the consensus security model collapses from cryptographically random to predictable.

4. **Network-Wide Impact**: All network participants suffer from compromised consensus integrity and potentially manipulable block producer ordering, affecting protocol security beyond individual miner penalties.

## Likelihood Explanation

**Attacker Profile**: Requires elected miner status (obtainable through Election contract), active time slot, and ability to construct TinyBlock transactions.

**Attack Complexity**: Low - simply send `TinyBlock` input instead of `UpdateValue` input when producing first block in round. No complex state manipulation required.

**Feasibility**: Validation providers only check mining permission, time slot constraints, and continuous block limits. None verify behavior type correctness relative to miner state. The basic validation providers pass because: [11](#0-10) 

**Economic Considerations**: Individual miner suffers penalty (MissedTimeSlots increment, potential next round exclusion), making solo exploitation irrational. However, coordinated griefing by multiple miners can manipulate consensus ordering if enough participants collude to eliminate randomness sources.

**Probability**: Medium - requires miner role (limited access) but trivial execution once obtained. More viable as coordinated attack than individual exploitation.

## Recommendation

Add validation to enforce behavior correctness based on miner state. Before line 77 in `AEDPoSContract_Validation.cs`, insert:

```csharp
// Validate behavior matches miner state
var minerInRound = baseRound.RealTimeMinersInformation[extraData.SenderPubkey.ToHex()];
if (minerInRound.OutValue == null && extraData.Behaviour != AElfConsensusBehaviour.UpdateValue)
{
    return new ValidationResult 
    { 
        Success = false, 
        Message = "Miner must use UpdateValue behavior for first block in round." 
    };
}
```

This ensures miners cannot bypass cryptographic value publication by substituting TinyBlock behavior when UpdateValue is required.

## Proof of Concept

```csharp
[Fact]
public async Task Miner_Can_Bypass_UpdateValue_With_TinyBlock()
{
    // Setup: Initialize consensus with first round
    await AEDPoSContract_FirstRound_BootMiner_Test();
    
    var currentRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var firstMiner = currentRound.RealTimeMinersInformation.Values.First();
    
    // Verify miner has OutValue == null (should use UpdateValue)
    firstMiner.OutValue.ShouldBeNull();
    
    // Attack: Miner uses TinyBlock instead of UpdateValue for first block
    var tinyBlockInput = new TinyBlockInput
    {
        RoundId = currentRound.RoundId,
        ActualMiningTime = BlockTimeProvider.GetBlockTime(),
        RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(BootMinerKeyPair))
    };
    
    // This should fail but currently passes validation
    var result = await AEDPoSContractStub.UpdateTinyBlockInformation.SendAsync(tinyBlockInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify vulnerability: Block produced but no OutValue/Signature published
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var updatedMiner = updatedRound.RealTimeMinersInformation[firstMiner.Pubkey];
    
    updatedMiner.ProducedBlocks.ShouldBeGreaterThan(0); // Block produced
    updatedMiner.OutValue.ShouldBeNull(); // But no cryptographic value published
    updatedMiner.Signature.ShouldBeNull();
    updatedMiner.SupposedOrderOfNextRound.ShouldBe(0); // Will be treated as non-mining
}
```

## Notes

This vulnerability breaks fundamental AEDPoS security guarantees by allowing miners to produce blocks without contributing to the cryptographic randomness chain. While individual exploitation results in miner penalties (self-harm), coordinated exploitation by multiple miners constitutes a protocol-level griefing attack that degrades consensus security from cryptographically random to deterministically predictable. The validation gap exists because behavior type selection is advisory (determined by `GetConsensusBehaviour`) but not enforced during validation, creating a trust assumption that miners will honestly select the correct behavior.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L49-56)
```csharp
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-75)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
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
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L35-47)
```csharp
    public Round RecoverFromTinyBlock(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L39-56)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-135)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }

    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
```
