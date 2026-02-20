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

The `BreakContinuousMining` logic expects specific order values (1, 2, minersCount-1, minersCount) to exist. If these orders are missing due to malicious values, the code will throw exceptions: [5](#0-4) 

Even the `NextRoundMiningOrderValidationProvider` cannot detect this issue because it calls `.Distinct()` on `MinerInRound` objects (using reference equality) rather than on the order values themselves: [6](#0-5) 

Moreover, this validator only runs for `NextRound` behavior, not for `UpdateValue`: [7](#0-6) 

A malicious miner producing a block can craft both the consensus extra data and the UpdateValue transaction with arbitrary `TuneOrderInformation` values. While the intended flow uses `ApplyNormalConsensusData` to calculate correct order values, the validation system does not verify that the provided values match this expected calculation. The miner controls both the block header (consensus extra data) and the transactions included in the block, allowing them to inject consistent but malicious values that pass validation.

## Impact Explanation

This vulnerability breaks the fundamental consensus guarantee of deterministic round generation across all nodes:

1. **Duplicate Order Values**: If multiple miners receive the same order (e.g., two miners with Order=3), the `OrderBy` operation produces non-deterministic ordering. Different nodes may order miners differently, generating different `nextRound` hashes and causing block consensus failure.

2. **Out-of-Range Order Values**: If a miner is assigned Order=999 when there are only 7 miners, their `ExpectedMiningTime` is pushed far into the future, effectively excluding them from mining. More critically, `BreakContinuousMining` expects orders 1, 2, minersCount-1, and minersCount to exist. Missing these values causes `First()` operations to throw `InvalidOperationException`, halting block production entirely.

3. **Protocol-Level DoS**: Once the round state is corrupted, ALL nodes fail to generate the next round or generate inconsistent rounds, halting the entire network's block production and consensus progression.

The impact is protocol-wide, affecting all miners and nodes, not just the attacker.

## Likelihood Explanation

The vulnerability is highly exploitable:

**Attacker Prerequisites**: Must be an elected miner (verified by `PreCheck`): [8](#0-7) 

**Attack Execution**: The `UpdateValue` method is publicly accessible: [9](#0-8) 

The attacker:
1. Crafts custom consensus extra data with malicious `FinalOrderOfNextRound` values
2. Crafts a matching `UpdateValueInput` with malicious `TuneOrderInformation` values  
3. Includes both in their block during their legitimate mining time slot
4. Provides valid OutValue, Signature, and VRF proof to pass basic validation

**Cost**: Only the transaction fee. The attack succeeds immediately upon block acceptance.

**Detection**: Only becomes evident when the next round fails to generate, but by then the damage is permanent in that round's state.

## Recommendation

Add validation in `UpdateValueValidationProvider` to verify `TuneOrderInformation`:

1. Validate that all order values are within the valid range [1, minersCount]
2. Validate that there are no duplicate order values
3. Optionally, validate that the provided values match the expected calculation from `ApplyNormalConsensusData`

Alternatively, remove `TuneOrderInformation` from the user-controlled `UpdateValueInput` and have the system calculate these values internally based on the consensus rules, preventing user manipulation.

## Proof of Concept

A malicious miner can exploit this by:

1. During their mining time slot, generate a block with:
   - Consensus extra data containing malicious `FinalOrderOfNextRound` values (e.g., all set to 1)
   - UpdateValue transaction with matching malicious `TuneOrderInformation` map

2. The validation passes because:
   - `UpdateValueValidationProvider` doesn't check `TuneOrderInformation`
   - `ValidateConsensusAfterExecution` compares hashes which match since both are consistently malicious
   - `PreCheck` passes since attacker is an elected miner

3. The malicious values are applied to `currentRound.RealTimeMinersInformation[].FinalOrderOfNextRound`

4. When `GenerateNextRoundInformation` is called:
   - If duplicate orders: Non-deterministic `OrderBy` results cause consensus failure
   - If missing critical orders (1, 2, n-1, n): `BreakContinuousMining` throws `InvalidOperationException`

The test would demonstrate that a miner can submit an UpdateValue transaction with arbitrary TuneOrderInformation values that bypass all validation checks and corrupt the next round's mining schedule, causing either consensus divergence or complete halt of block production.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-101)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }

        // Last miner of next round != Extra block producer of next round
        var lastMinerOfNextRound =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(i => i.Order == minersCount);
        if (lastMinerOfNextRound == null) return;

        var extraBlockProducerOfNextRound = nextRound.GetExtraBlockProducerInformation();
        if (lastMinerOfNextRound.Pubkey == extraBlockProducerOfNextRound.Pubkey)
        {
            var lastButOneMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == minersCount.Sub(1));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-17)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
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
