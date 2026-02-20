# Audit Report

## Title
Miner Can Manipulate Next Round Order by Setting Invalid SupposedOrderOfNextRound Without Validation

## Summary
The AEDPoS consensus contract allows miners to manipulate their position in the next round's mining order by providing an arbitrary `SupposedOrderOfNextRound` value without validation. The `ProcessUpdateValue` method directly trusts miner-provided values, and the `NextRoundMiningOrderValidationProvider` validates the wrong round data, enabling miners to bypass deterministic order assignment.

## Finding Description

The vulnerability consists of two root causes working in combination:

**Root Cause 1: Missing Validation in ProcessUpdateValue**

The `ProcessUpdateValue` method directly assigns `SupposedOrderOfNextRound` from the miner-provided `UpdateValueInput` without validating that it matches the deterministic calculation. [1](#0-0) 

The correct calculation formula exists in `ApplyNormalConsensusData` where `SupposedOrderOfNextRound` should equal `GetAbsModulus(signature.ToInt64(), minersCount) + 1`. [2](#0-1) 

However, `UpdateValueValidationProvider` only checks that `OutValue` and `Signature` are non-empty, but never validates the `SupposedOrderOfNextRound` field matches the signature-derived calculation. [3](#0-2) 

**Root Cause 2: Broken NextRoundMiningOrderValidationProvider**

The `NextRoundMiningOrderValidationProvider` is supposed to validate mining order correctness, but it checks `providedRound` which represents the proposed NEXT round, not the current round. [4](#0-3) 

The `ProvidedRound` property returns `ExtraData.Round`, which contains the proposed next round information. [5](#0-4) 

When `GenerateNextRoundInformation` creates the next round, it generates fresh `MinerInRound` objects that do not have `OutValue` or `FinalOrderOfNextRound` fields populated (they default to null/0). [6](#0-5) 

This causes both validation counts to be 0 (no miners with `FinalOrderOfNextRound > 0` and no miners with `OutValue != null` in the next round), making the validation always pass regardless of actual behavior in the current round.

**Exploitation Mechanism**

The attack exploits how `GetMinedMiners()` determines which miners successfully produced blocks. This method filters miners by checking `SupposedOrderOfNextRound != 0`. [7](#0-6) 

A malicious miner can:
1. Produce a valid block with correct `OutValue`, `Signature`, and other required fields
2. Set `SupposedOrderOfNextRound = 0` in their `UpdateValueInput` 
3. Pass all validations since `ProcessUpdateValue` doesn't validate this field
4. When `GenerateNextRoundInformation` is called, they are classified as "not mined" (because `SupposedOrderOfNextRound == 0`)
5. Get assigned to an arbitrary available order slot instead of their deterministic `FinalOrderOfNextRound`
6. Have their `MissedTimeSlots` incorrectly incremented despite producing blocks [8](#0-7) 

The normal flow uses `ExtractInformationToUpdateConsensus` to populate `UpdateValueInput` with the calculated value, but a malicious client can modify this before sending. [9](#0-8) 

## Impact Explanation

**Consensus Integrity Compromise:**
- Breaks the fundamental guarantee that mining order is deterministically calculated from unpredictable cryptographic signatures
- Enables miners to manipulate their position in the next round, selecting favorable time slots for block production
- Allows coordination with other malicious miners to cluster blocks at advantageous positions
- Incorrectly increments `MissedTimeSlots` for miners who actually produced blocks, corrupting reward calculations

**Protocol-Wide Effects:**
- Undermines the randomness of mining order assignment that is core to AEDPoS consensus fairness
- Can be used to manipulate Last Irreversible Block (LIB) calculation by controlling block production timing
- Affects evil miner detection mechanisms that rely on accurate `MissedTimeSlots` tracking [10](#0-9) 
- Compromises cross-chain verification that assumes predictable consensus behavior

**Affected Parties:**
- Honest miners who follow deterministic ordering lose their guaranteed time slots
- Reward distribution mechanisms dependent on accurate mining statistics
- Cross-chain indexing relying on predictable consensus patterns
- Overall network security through consensus manipulation

## Likelihood Explanation

**Trivially Reachable:**
The attack uses the standard `UpdateValue` public method that all miners must call during normal block production. No special privileges beyond being an active miner are required. [11](#0-10) 

**Low Execution Complexity:**
Exploitation requires only:
1. Modifying the consensus client to set `SupposedOrderOfNextRound = 0` in the `UpdateValueInput` structure
2. Keeping all other fields valid (`OutValue`, `Signature`, `PreviousInValue`)
3. No timing coordination, no collusion, no economic cost beyond standard block production

**Difficult to Detect:**
- The `UpdateValue` transaction passes all existing validations [12](#0-11) 
- The miner's block is accepted into the chain normally
- Only the next round generation treats them differently
- No error events or failed transactions signal the manipulation
- The deviation only appears in round transition logic

**High Probability:**
The vulnerability is deterministic - it works every time. Any miner can execute it with minimal sophistication. The benefit (order manipulation) is clear while the risk is essentially zero, making exploitation highly likely once discovered.

## Recommendation

Add validation in `ProcessUpdateValue` to verify that the provided `SupposedOrderOfNextRound` matches the deterministic calculation:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    
    // Validate SupposedOrderOfNextRound matches signature-derived calculation
    var minersCount = currentRound.RealTimeMinersInformation.Count;
    var expectedOrder = GetAbsModulus(updateValueInput.Signature.ToInt64(), minersCount) + 1;
    Assert(updateValueInput.SupposedOrderOfNextRound == expectedOrder, 
        "Invalid SupposedOrderOfNextRound: does not match signature-derived calculation.");
    
    // Continue with existing logic...
}
```

Alternatively, fix `NextRoundMiningOrderValidationProvider` to validate the current round instead of the proposed next round, or remove reliance on `SupposedOrderOfNextRound` from the miner classification logic and use `OutValue != null` directly.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateNextRoundOrderBySettingInvalidSupposedOrder()
{
    // Setup: Initialize round with miners
    var miners = await InitializeConsensusWithMiners(5);
    var maliciousMiner = miners[0];
    
    // Malicious miner produces a block
    var currentRound = await GetCurrentRound();
    var updateInput = currentRound.ExtractInformationToUpdateConsensus(
        maliciousMiner.PublicKey, RandomNumber);
    
    // Attack: Set SupposedOrderOfNextRound to 0 instead of correct value
    var correctOrder = updateInput.SupposedOrderOfNextRound; // Should be non-zero
    updateInput.SupposedOrderOfNextRound = 0; // Malicious modification
    
    // Execute UpdateValue - should pass validation despite invalid order
    await MaliciousMinerStub.UpdateValue.SendAsync(updateInput);
    
    // Trigger next round generation
    await TriggerNextRound();
    
    // Verify: Malicious miner treated as "not mined" despite producing block
    var nextRound = await GetCurrentRound();
    var maliciousMinerNextRound = nextRound.RealTimeMinersInformation[maliciousMiner.PublicKey];
    
    // Assertion 1: MissedTimeSlots incorrectly incremented
    Assert.True(maliciousMinerNextRound.MissedTimeSlots > 0, 
        "MissedTimeSlots should be incorrectly incremented");
    
    // Assertion 2: Order not deterministic (gets arbitrary assignment)
    Assert.NotEqual(correctOrder, maliciousMinerNextRound.Order,
        "Order should be manipulated, not deterministic");
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L45-48)
```csharp
            case UpdateValueInput updateValueInput:
                randomNumber = updateValueInput.RandomNumber;
                ProcessUpdateValue(updateValueInput);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-247)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-17)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L42-56)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L43-43)
```csharp
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-82)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
```
