# Audit Report

## Title
Missing Validation of TuneOrderInformation Allows Miners to Corrupt Next Round Mining Schedule

## Summary
The `ProcessUpdateValue` function applies `TuneOrderInformation` from `UpdateValueInput` to miners' `FinalOrderOfNextRound` values without validating that order values are within the valid range [1, minersCount] or checking for duplicates. A malicious miner can inject arbitrary order values during their time slot, corrupting the mining schedule and potentially causing consensus failures or denial of service.

## Finding Description

The vulnerability exists in the consensus update mechanism where `ProcessUpdateValue` directly applies order values from user input to the round state without validation. [1](#0-0) 

The `UpdateValueInput` message structure allows arbitrary integer values in the `tune_order_information` map: [2](#0-1) 

The `UpdateValueValidationProvider` only validates OutValue, Signature, and PreviousInValue, completely ignoring TuneOrderInformation: [3](#0-2) 

When the next round is generated, these corrupted `FinalOrderOfNextRound` values become `Order` values that determine mining schedule: [4](#0-3) 

The `BreakContinuousMining` logic expects specific order values (1, 2, minersCount-1, minersCount) to exist. If these orders are missing due to malicious values, the code will throw exceptions: [5](#0-4) [6](#0-5) 

The `NextRoundMiningOrderValidationProvider` cannot detect this issue because it calls `.Distinct()` on `MinerInRound` objects (using reference equality) rather than on the order values themselves: [7](#0-6) 

Moreover, this validator only runs for `NextRound` behavior, not for `UpdateValue`: [8](#0-7) 

## Impact Explanation

This vulnerability breaks the fundamental consensus guarantee of deterministic round generation across all nodes:

1. **Duplicate Order Values**: If multiple miners receive the same order (e.g., two miners with Order=3), the system generates non-deterministic or inconsistent round states across nodes, causing consensus failure.

2. **Out-of-Range Order Values**: If a miner is assigned Order=999 when there are only 7 miners, their `ExpectedMiningTime` is pushed far into the future, effectively excluding them from mining. More critically, `BreakContinuousMining` expects orders 1, 2, minersCount-1, and minersCount to exist. Missing these values causes `First()` operations to throw `InvalidOperationException`, halting block production entirely.

3. **Protocol-Level DoS**: Once the round state is corrupted, ALL nodes fail to generate the next round or generate inconsistent rounds, halting the entire network's block production and consensus progression.

The impact is protocol-wide, affecting all miners and nodes, not just the attacker.

## Likelihood Explanation

The vulnerability is highly exploitable:

**Attacker Prerequisites**: Must be an elected miner, which is verified by `PreCheck`: [9](#0-8) 

**Attack Execution**: The `UpdateValue` method is publicly accessible: [10](#0-9) 

The attacker simply:
1. Crafts a custom `UpdateValueInput` with malicious `TuneOrderInformation` values
2. Submits it as a transaction during their legitimate time slot
3. Provides valid OutValue, Signature, and VRF proof to pass basic validation

**Cost**: Only the transaction fee. The attack succeeds immediately upon execution.

**Detection**: Only becomes evident when the next round fails to generate, but by then the damage is permanent in that round's state.

## Recommendation

Add validation for `TuneOrderInformation` in the `UpdateValueValidationProvider`:

1. Verify all order values are within valid range [1, minersCount]
2. Check for duplicate order values across all miners
3. Validate that critical orders (1, 2, minersCount-1, minersCount) are assigned
4. Optionally, restrict which miners can be tuned (e.g., only allow tuning for miners with signature-based conflicts as determined by `ApplyNormalConsensusData`)

Additionally, consider adding defensive checks in `ProcessUpdateValue` to validate `TuneOrderInformation` entries before applying them.

## Proof of Concept

The PoC would involve:

1. Setting up a test consensus round with 7 miners
2. Having one miner call `UpdateValue` with a malicious `UpdateValueInput` where `TuneOrderInformation` sets:
   - Miner A: FinalOrderOfNextRound = 999
   - Miner B: FinalOrderOfNextRound = 999  
   - Leave other critical orders (1, 2, 6, 7) unassigned
3. Attempting to execute `NextRound` which calls `GenerateNextRoundInformation`
4. Observing that `BreakContinuousMining` throws `InvalidOperationException` when calling `.First(i => i.Order == 1)` because no miner has Order=1
5. Demonstrating that consensus is halted and no blocks can be produced

The test demonstrates that unvalidated `TuneOrderInformation` allows corruption of the consensus state, leading to protocol-level DoS.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L259-260)
```csharp
        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-330)
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
```

**File:** protobuf/aedpos_contract.proto (L207-208)
```text
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-84)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L100-101)
```csharp
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-86)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
