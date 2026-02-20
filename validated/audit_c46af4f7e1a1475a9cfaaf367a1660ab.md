# Audit Report

## Title
Insufficient Validation of ProducedBlocks in NextRound Allows Mining Reward Inflation

## Summary
The AEDPoS consensus contract accepts and stores `ProducedBlocks` values from miner-submitted `NextRound` transactions without validating them against the current round state. A malicious miner can inflate these values to multiply mining rewards, causing token supply inflation and corrupted election statistics.

## Finding Description
The vulnerability exists in the asymmetric treatment of `ProducedBlocks` validation between different consensus behaviors.

For `UpdateValue` transactions, the contract explicitly protects against manipulation by loading the current state and incrementing by 1, completely ignoring any submitted values [1](#0-0) 

However, for `NextRound` transactions, the `ProcessNextRound` method accepts the input and converts it directly to a `Round` object [2](#0-1)  then stores it via `AddRoundInformation` without any validation of the `ProducedBlocks` values [3](#0-2) 

The `NextRoundInput.ToRound()` method simply copies all fields including `RealTimeMinersInformation` which contains the `ProducedBlocks` values [4](#0-3)  and `AddRoundInformation` stores the round directly to state without validation [5](#0-4) 

The validation system for `NextRound` only adds two validation providers: `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider` [6](#0-5) 

The `NextRoundMiningOrderValidationProvider` only validates that miners with `FinalOrderOfNextRound` match those who mined [7](#0-6)  and the `RoundTerminateValidationProvider` only checks that round number increments by 1 and `InValue` fields are null [8](#0-7) 

Critically, there is NO validation that reconstructs the expected `ProducedBlocks` values from current state and compares them against the submitted input.

Honest nodes generate next round information by copying `ProducedBlocks` from the current round state [9](#0-8)  and then incrementing the producer's count by 1 [10](#0-9) 

However, the contract does not enforce this invariant during validation. A malicious miner can modify their node to inflate these values before submitting the `NextRound` transaction.

## Impact Explanation
The inflated `ProducedBlocks` values directly impact mining reward calculations. During term changes, the `DonateMiningReward` method calculates total rewards by summing all miners' `ProducedBlocks` values via `GetMinedBlocks()` [11](#0-10)  which is then used to calculate the donation amount [12](#0-11) 

An attacker inflating `ProducedBlocks` values (e.g., doubling all counts from [10, 15, 12] to [20, 30, 24]) would double the mining rewards donated to Treasury (from 37 to 74 blocks worth), causing significant token supply inflation over multiple terms. This directly breaks the economic security guarantees of controlled token issuance.

Additionally, these inflated values are sent to the Election contract via `UpdateMultipleCandidateInformation` [13](#0-12)  where they accumulate in candidate statistics [14](#0-13)  This corrupts governance metrics and impacts future reward distributions based on production history.

## Likelihood Explanation
**Attacker Capabilities:** Any miner who produces a block triggering `NextRound` behavior. This occurs naturally at the end of each round when the extra block producer mines.

**Attack Complexity:** Moderate. The attacker must:
1. Run a modified node that alters the consensus extra data generation logic
2. Inflate `ProducedBlocks` values in the generated `NextRoundInput`
3. Produce a block at the appropriate time slot to trigger `NextRound`

**Feasibility:** High. Miners regularly produce `NextRound` blocks as part of normal consensus operation. The validation system checks only structural properties (round number incrementation, `InValue` nullity, mining order) but does NOT reconstruct and compare the expected `ProducedBlocks` values from current state.

**Detection:** Difficult. The manipulation occurs within consensus data that legitimately varies between rounds. Without explicit validation comparing submitted values against state-derived expectations, other nodes cannot detect the inflation during block validation.

## Recommendation
Add a validation provider for `NextRound` behavior that:

1. Loads the current round from state
2. For each miner in the submitted `NextRoundInput`, validates that:
   - If the miner's `ProducedBlocks` equals `currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks` (for non-producing miners)
   - OR equals `currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks + 1` (for the NextRound block producer)
3. Rejects the transaction if validation fails

Add this validation provider to the list in `AEDPoSContract_Validation.cs` for the `NextRound` behavior case.

## Proof of Concept
A proof of concept would require:
1. Setting up an AElf test environment with multiple miner nodes
2. Modifying one miner node to inflate `ProducedBlocks` values in `GenerateNextRoundInformation`
3. Having that miner produce the NextRound block at end of round
4. Observing that the inflated values are accepted and stored
5. Verifying inflated mining rewards are calculated at term change

The test would demonstrate that the validation providers do not prevent acceptance of inflated `ProducedBlocks` values, confirming the absence of state-comparison validation.

---

## Notes
This vulnerability represents a critical break in consensus integrity. The asymmetric validation treatment between `UpdateValue` (protected) and `NextRound` (unprotected) creates an exploitable gap. The impact is severe because it affects both token economics (supply inflation through mining rewards) and governance (corrupted election statistics). The attack is practical because miners naturally produce `NextRound` blocks as part of consensus operation, requiring only client-side modification without any cryptographic or consensus-level bypass.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L110-110)
```csharp
        var nextRound = input.ToRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L250-252)
```csharp
        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L34-34)
```csharp
                ProducedBlocks = minerInRound.ProducedBlocks,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L191-192)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L124-127)
```csharp
    public long GetMinedBlocks()
    {
        return RealTimeMinersInformation.Values.Sum(minerInRound => minerInRound.ProducedBlocks);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L39-50)
```csharp
        State.ElectionContract.UpdateMultipleCandidateInformation.Send(new UpdateMultipleCandidateInformationInput
        {
            Value =
            {
                previousRound.RealTimeMinersInformation.Select(i => new UpdateCandidateInformationInput
                {
                    Pubkey = i.Key,
                    RecentlyProducedBlocks = i.Value.ProducedBlocks,
                    RecentlyMissedTimeSlots = i.Value.MissedTimeSlots
                })
            }
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L119-120)
```csharp
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L115-115)
```csharp
        candidateInformation.ProducedBlocks = candidateInformation.ProducedBlocks.Add(input.RecentlyProducedBlocks);
```
