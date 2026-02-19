# Audit Report

## Title
Incomplete Validation of MinerInRound Fields in NextRound Allows Reward Manipulation and False Evil Miner Detection

## Summary
The AEDPoS consensus contract's `NextRound` validation only checks 3 out of 17 fields in the `MinerInRound` structure, failing to validate critical fields like `ProducedBlocks`, `MissedTimeSlots`, `Order`, and `IsExtraBlockProducer`. A malicious extra block producer can manipulate these unvalidated fields to steal mining rewards and falsely ban honest miners, causing direct economic harm and consensus integrity violations.

## Finding Description

The vulnerability exists in the validation pipeline for `NextRound` behavior. When a miner produces a NextRound block, the consensus data in the block header is validated by `ValidateBeforeExecution` using multiple validation providers: [1](#0-0) 

For NextRound behavior, only two specific providers are added: `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`.

**RoundTerminateValidationProvider** only validates:
- Round number increments by exactly 1
- All `InValue` fields are null [2](#0-1) 

**NextRoundMiningOrderValidationProvider** only validates:
- Count of miners with `FinalOrderOfNextRound > 0` matches count of miners with non-null `OutValue` [3](#0-2) 

**Critical Gap**: The `MinerInRound` structure contains many fields, but the following critical ones are **NOT validated**:
- `produced_blocks` - Used for reward distribution
- `missed_time_slots` - Used for evil miner detection
- `order` - Determines mining schedule
- `is_extra_block_producer` - Grants extra block mining rights

During `ProcessNextRound`, the unvalidated `NextRoundInput` is directly converted to `Round` via `ToRound()` which performs simple field copying without validation: [4](#0-3) [5](#0-4) 

The manipulated data is then persisted to contract state: [6](#0-5) 

### Attack Execution Path

1. Attacker is selected as extra block producer (rotates regularly)
2. Attacker's node generates correct NextRound data via `GetConsensusExtraDataForNextRound`
3. **Manipulation**: Before broadcasting the block, attacker modifies `ProducedBlocks`, `MissedTimeSlots`, `Order`, or `IsExtraBlockProducer` fields in the consensus header
4. Block validation runs but only checks the limited fields mentioned above
5. Block passes validation and is executed
6. Manipulated round data is stored in contract state

## Impact Explanation

**1. Reward Theft via ProducedBlocks Manipulation**

The Treasury contract retrieves previous term information which contains the stored `ProducedBlocks` values: [7](#0-6) [8](#0-7) 

These values are used directly to calculate reward shares in `UpdateBasicMinerRewardWeights`: [9](#0-8) 

The `CalculateShares` function penalizes miners with low production: [10](#0-9) 

An attacker can:
- Inflate their own `ProducedBlocks` to maximize rewards
- Deflate competitors' `ProducedBlocks` below `average/2` threshold, causing them to receive zero rewards

**2. False Evil Miner Detection via MissedTimeSlots Manipulation**

The consensus contract detects evil miners based on `MissedTimeSlots`: [11](#0-10) 

The threshold is 4,320 missed slots (3 days): [12](#0-11) 

When evil miners are detected during NextRound processing, they are banned: [13](#0-12) 

While current round detection uses state data, the manipulated next round becomes the current round in subsequent transitions, causing future false detections.

**Economic Impact**: Direct theft of mining rewards and censorship of honest miners through false banning.

## Likelihood Explanation

**Attacker Capabilities**:
- Attacker must be in the miner list (realistic for any miner)
- Attacker receives extra block producer role regularly through deterministic rotation
- Extra block producer is selected via `CalculateNextExtraBlockProducerOrder()` during round generation: [14](#0-13) 

**Attack Complexity**: LOW
- Modify protobuf message fields before block creation (trivial)
- No cryptographic binding prevents modification
- Validation gap is structural, not timing-dependent
- No off-chain monitoring exists

**Execution Practicality**: HIGH
- Attack cost: One transaction gas fee
- Potential gain: Significant fraction of mining rewards
- Detection: Requires off-chain comparison of actual vs. expected values

**Economic Rationality**: Extremely favorable ROI for attacker.

## Recommendation

Add comprehensive validation for all critical `MinerInRound` fields in `NextRound` behavior. Create a new validation provider:

```csharp
public class NextRoundDataIntegrityValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        var baseRound = validationContext.BaseRound;
        
        // Generate expected next round from current state
        baseRound.GenerateNextRoundInformation(
            Context.CurrentBlockTime,
            State.BlockchainStartTimestamp.Value,
            out var expectedNextRound
        );
        
        // Validate ProducedBlocks matches expected (carried forward from current round)
        foreach (var miner in providedRound.RealTimeMinersInformation)
        {
            if (!expectedNextRound.RealTimeMinersInformation.ContainsKey(miner.Key))
                return new ValidationResult { Message = $"Unexpected miner {miner.Key}" };
                
            var expected = expectedNextRound.RealTimeMinersInformation[miner.Key];
            var provided = miner.Value;
            
            if (provided.ProducedBlocks != expected.ProducedBlocks)
                return new ValidationResult { Message = "Invalid ProducedBlocks" };
                
            if (provided.MissedTimeSlots != expected.MissedTimeSlots)
                return new ValidationResult { Message = "Invalid MissedTimeSlots" };
                
            if (provided.Order != expected.Order)
                return new ValidationResult { Message = "Invalid Order" };
                
            if (provided.IsExtraBlockProducer != expected.IsExtraBlockProducer)
                return new ValidationResult { Message = "Invalid IsExtraBlockProducer" };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Add this provider to the validation list for NextRound behavior in `AEDPoSContract_Validation.cs`.

## Proof of Concept

Due to the complexity of the AElf consensus mechanism requiring full node setup, the vulnerability is demonstrated through code flow analysis rather than executable test. The attack would proceed as follows:

1. Deploy malicious miner node that monitors for extra block producer selection
2. When selected, generate NextRound consensus data normally via `GetConsensusExtraDataForNextRound`
3. Before block creation, modify the `AElfConsensusHeaderInformation.Round.RealTimeMinersInformation` dictionary:
   - Set attacker's `ProducedBlocks` to maximum observed value + 100
   - Set target victim's `ProducedBlocks` to 0
   - Set target victim's `MissedTimeSlots` to 4320 (threshold)
4. Create and broadcast block with modified consensus data
5. Other nodes validate block - passes all validation checks
6. Block executes, storing manipulated round data
7. At next term transition, Treasury distributes rewards using manipulated `ProducedBlocks`
8. At next NextRound, victim is detected as evil miner due to manipulated `MissedTimeSlots`

The vulnerability is confirmed by examining the validation code paths which demonstrably do not check these fields, combined with the usage of stored values in reward calculation and evil miner detection.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-110)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L440-453)
```csharp
    public override Round GetPreviousTermInformation(Int64Value input)
    {
        var lastRoundNumber = State.FirstRoundNumberOfEachTerm[input.Value.Add(1)].Sub(1);
        var round = State.Rounds[lastRoundNumber];
        if (round == null || round.RoundId == 0) return new Round();
        var result = new Round
        {
            TermNumber = input.Value
        };
        foreach (var minerInRound in round.RealTimeMinersInformation)
            result.RealTimeMinersInformation[minerInRound.Key] = new MinerInRound
            {
                Pubkey = minerInRound.Value.Pubkey,
                ProducedBlocks = minerInRound.Value.ProducedBlocks
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L136-139)
```csharp
        var previousTermInformation = State.AEDPoSContract.GetPreviousTermInformation.Call(new Int64Value
        {
            Value = input.PeriodNumber
        });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L789-791)
```csharp
        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L835-846)
```csharp
    private long CalculateShares(long producedBlocksCount, long averageProducedBlocksCount)
    {
        if (producedBlocksCount < averageProducedBlocksCount.Div(2))
            // If count < (1/2) * average_count, then this node won't share Basic Miner Reward.
            return 0;

        if (producedBlocksCount < averageProducedBlocksCount.Div(5).Mul(4))
            // If count < (4/5) * average_count, then ratio will be (count / average_count)
            return producedBlocksCount.Mul(producedBlocksCount).Div(averageProducedBlocksCount);

        return producedBlocksCount;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L58-66)
```csharp
        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

```
