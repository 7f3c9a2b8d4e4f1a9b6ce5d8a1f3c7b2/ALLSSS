# Audit Report

## Title
Continuous Blocks Validation Bypass via Negative RoundNumber in UpdateValue/TinyBlock Behaviors

## Summary
The `ContinuousBlocksValidationProvider` validation can be bypassed by an authorized miner providing a negative `RoundNumber` in consensus extra data for UpdateValue or TinyBlock behaviors. This allows the miner to produce more consecutive blocks than the maximum allowed threshold (8 blocks), defeating the anti-centralization mechanism.

## Finding Description

The AEDPoS consensus system enforces a consecutive block production limit through `ContinuousBlocksValidationProvider` to ensure fair distribution among miners. However, this validation contains a critical bypass condition.

The `Round` protobuf message defines `RoundNumber` as `int64`, accepting negative values without type-level constraints: [1](#0-0) 

The `ConsensusValidationContext` exposes `ProvidedRound` directly from block header extra data without validating that `RoundNumber` is positive: [2](#0-1) 

For UpdateValue and TinyBlock behaviors, the validation pipeline includes `ContinuousBlocksValidationProvider` but does NOT include any validator that checks `RoundNumber` validity: [3](#0-2) 

The continuous blocks validation only executes when `ProvidedRound.RoundNumber > 2`. When a miner provides a negative `RoundNumber`, this condition evaluates to false, causing the entire validation block to be skipped: [4](#0-3) 

The system tracks consecutive blocks through `LatestPubkeyToTinyBlocksCount.BlocksCount`, which decrements on each block and becomes negative when the limit is exceeded: [5](#0-4) 

The maximum consecutive blocks allowed is 8: [6](#0-5) 

**Attack Path:**
1. Authorized miner produces 8 consecutive blocks (MaximumTinyBlocksCount limit)
2. `BlocksCount` becomes negative (e.g., -1 on 9th block)
3. Miner crafts block header with TinyBlock/UpdateValue behavior and sets `Round.RoundNumber = -1`
4. Validation bypass: condition `-1 > 2` is false, validation skipped
5. Miner continues producing blocks beyond limit

In contrast, `RoundTerminateValidationProvider` explicitly validates `RoundNumber` increments for NextRound/NextTerm behaviors: [7](#0-6) 

State integrity is maintained because `RecoverFromUpdateValue` and `RecoverFromTinyBlock` only merge specific fields and don't use the invalid `ProvidedRound.RoundNumber`: [8](#0-7) 

The consensus extra data generation includes `RoundNumber` in both simplified round methods: [9](#0-8) 

The extraction layer only validates sender pubkey matches signer, not `RoundNumber` validity: [10](#0-9) 

## Impact Explanation

**Severity: LOW**

A malicious miner who has reached the consecutive block limit can bypass the anti-centralization check by crafting block headers with negative `RoundNumber` values. This allows them to:

1. Produce blocks beyond the 8-block consecutive limit
2. Dominate block production within their time slot
3. Reduce other miners' opportunities for block production

**Why LOW and not MEDIUM/HIGH:**
- The attacker must be a validly elected miner with mining permissions
- Time slot validation still applies (cannot mine outside assigned time)
- Mining permission validation still applies (must be in miner list)
- State integrity is maintained (actual round state uses `BaseRound` from state, not `ProvidedRound`)
- No direct fund theft, supply manipulation, or complete consensus break
- Impact is limited to consensus fairness and decentralization
- The attack is observable (negative `RoundNumber` values in block headers are anomalous)

## Likelihood Explanation

**Likelihood: MODERATE**

The attack is practically exploitable:

**Attacker Capabilities Required:**
- Must be an authorized miner in the current miner list
- Must be within assigned time slot
- Must have technical capability to craft custom block headers with modified consensus extra data

**Attack Feasibility:**
- Miners have full control over block header content before broadcasting
- The protobuf format accepts any `int64` value without additional validation
- The extraction layer only validates sender pubkey matches signer, not `RoundNumber` validity
- No additional round number validation exists for UpdateValue/TinyBlock behaviors

**Economic Incentive:**
- Elected miners have incentive to maximize block production for increased rewards
- Cost is minimal (just modify consensus extra data)
- Benefit is increased block production share

**Detection:**
- Observable through negative `RoundNumber` in block headers
- May not trigger immediate detection if used sparingly
- Could be confused with legitimate early-round blocks (which also skip validation for RoundNumber ≤ 2)

## Recommendation

Add explicit validation that `ProvidedRound.RoundNumber` matches `BaseRound.RoundNumber` for UpdateValue and TinyBlock behaviors. Modify the validation pipeline to include a round number consistency check:

**Option 1:** Add validation before the early-round skip:
```csharp
if (validationContext.ProvidedRound.RoundNumber != validationContext.BaseRound.RoundNumber)
{
    validationResult.Message = "Provided round number does not match current round.";
    return validationResult;
}
```

**Option 2:** Remove the early-round skip condition and always validate consecutive blocks, or add an additional check for negative round numbers:
```csharp
if (validationContext.ProvidedRound.RoundNumber <= 0)
{
    validationResult.Message = "Invalid round number.";
    return validationResult;
}
```

**Option 3:** Add a dedicated `RoundNumberValidationProvider` to the UpdateValue and TinyBlock validation pipelines that ensures consistency with `BaseRound`.

## Proof of Concept

A malicious miner can execute the following attack:

1. Monitor `LatestPubkeyToTinyBlocksCount.BlocksCount` while producing consecutive blocks
2. After 8 blocks, `BlocksCount` becomes 0, then -1 on the 9th block
3. Craft a block with UpdateValue or TinyBlock behavior
4. Set consensus extra data with `Round.RoundNumber = -1` (or any value ≤ 2)
5. Submit the block
6. The `ContinuousBlocksValidationProvider` validation is bypassed because `-1 > 2` evaluates to false
7. Block is accepted despite exceeding the 8-block consecutive limit
8. Repeat to continue producing blocks beyond the intended limit

The vulnerability is exploitable because:
- The validation condition only checks `ProvidedRound.RoundNumber > 2`
- No other validator in the UpdateValue/TinyBlock pipeline verifies round number correctness
- The extraction layer accepts any `int64` value without bounds checking
- State updates use `BaseRound` from state, so no corruption occurs despite the bypass

### Citations

**File:** protobuf/aedpos_contract.proto (L243-245)
```text
message Round {
    // The round number.
    int64 round_number = 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L65-92)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L8-28)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Is sender produce too many continuous blocks?
        var validationResult = new ValidationResult();

        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-47)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L11-82)
```csharp
    public Round GetUpdateValueRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = pubkey,
                    OutValue = minerInRound.OutValue,
                    Signature = minerInRound.Signature,
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    PreviousInValue = minerInRound.PreviousInValue,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight,
                    Order = minerInRound.Order,
                    IsExtraBlockProducer = minerInRound.IsExtraBlockProducer
                }
            }
        };
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
            }

        return round;
    }

    public Round GetTinyBlockRound(string pubkey)
    {
        var minerInRound = RealTimeMinersInformation[pubkey];
        var round = new Round
        {
            RoundNumber = RoundNumber,
            RoundIdForValidation = RoundId,
            RealTimeMinersInformation =
            {
                [pubkey] = new MinerInRound
                {
                    Pubkey = minerInRound.Pubkey,
                    ActualMiningTimes = { minerInRound.ActualMiningTimes },
                    ProducedBlocks = minerInRound.ProducedBlocks,
                    ProducedTinyBlocks = minerInRound.ProducedTinyBlocks,
                    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight
                }
            }
        };

        foreach (var otherPubkey in RealTimeMinersInformation.Keys.Except(new List<string> { pubkey }))
            round.RealTimeMinersInformation.Add(otherPubkey, new MinerInRound());

        return round;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```
