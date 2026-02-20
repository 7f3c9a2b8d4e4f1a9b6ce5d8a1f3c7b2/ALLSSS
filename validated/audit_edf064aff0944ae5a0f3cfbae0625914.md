# Audit Report

## Title
Insufficient Validation of OutValue in NextRound Allows Denial of Service Against Miners

## Summary
The `ValidationForNextRound()` method in the AEDPoS consensus contract only validates that `InValue` is null for all miners in the next round, but fails to validate that `OutValue` is also null. This validation gap allows a malicious miner to inject arbitrary non-null `OutValue` data when creating NextRound transactions, causing victim miners to be incorrectly treated as having already mined, preventing them from producing UPDATE_VALUE blocks and incrementing their missed time slot counters until they are eventually removed from the consensus set.

## Finding Description

The AEDPoS consensus contract validates round transitions through the `RoundTerminateValidationProvider`. The `ValidationForNextRound()` method contains an incomplete validation check that only verifies `InValue` is null but does not validate `OutValue`: [1](#0-0) 

However, when legitimate next round information is generated, both `InValue` AND `OutValue` should be null since miners haven't participated in the new round yet. The `GenerateNextRoundInformation` method creates new `MinerInRound` objects with only specific fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots), leaving OutValue as null: [2](#0-1) 

When a miner creates NextRound data, they provide a `NextRoundInput` which is directly converted to a `Round` object through `ToRound()`, giving them full control over all miner fields including `OutValue`: [3](#0-2) 

This malicious round data is then stored directly in `ProcessNextRound` without additional OutValue validation: [4](#0-3) 

The attack succeeds because consensus behavior determination in `GetConsensusBehaviour()` relies on `OutValue` being null to identify miners who haven't mined yet. When OutValue is null, the code calls `HandleMinerInNewRound()` which returns UPDATE_VALUE behavior: [5](#0-4) 

However, if `OutValue` is non-null due to malicious injection, the miner instead receives TinyBlock behavior: [6](#0-5) 

Critically, `ProcessUpdateValue` sets the `SupposedOrderOfNextRound` field when handling UPDATE_VALUE behavior: [7](#0-6) 

But `ProcessTinyBlock` does NOT set this field: [8](#0-7) 

When generating the next round, `GetNotMinedMiners()` identifies miners with `SupposedOrderOfNextRound == 0` as having not mined: [9](#0-8) 

These miners have their `MissedTimeSlots` counter incremented: [10](#0-9) 

After reaching the threshold of 4,320 missed time slots (defined as 3 days at one slot per minute), miners are detected as evil: [11](#0-10) [12](#0-11) 

These detected evil miners are then marked and removed from the consensus set: [13](#0-12) 

## Impact Explanation

This vulnerability has severe consensus integrity impacts:

**Direct Consensus Disruption:**
- Victim miners are prevented from producing UPDATE_VALUE blocks, which are the primary consensus participation mechanism
- Each affected victim's `MissedTimeSlots` counter increments every round (typically every minute)
- After 4,320 missed slots (approximately 3 days), victims are permanently marked as evil nodes

**Validator Set Degradation:**
- Honest miners are falsely removed from the consensus set
- The effective number of active validators decreases, weakening consensus security
- Network liveness may be compromised if multiple miners are simultaneously targeted

**Economic and Reputational Damage:**
- Victims lose all mining rewards for blocks they cannot produce
- Honest miners suffer reputational damage through false "evil node" marking
- Potential loss of staked tokens if evil node penalties apply

The severity is **HIGH** because it directly breaks consensus integrity by enabling the removal of honest validators through a false-positive evil detection mechanism, fundamentally compromising the security model of the blockchain.

## Likelihood Explanation

The attack is highly feasible with realistic preconditions:

**Attacker Capabilities:**
- Attacker must be a current consensus miner (verified in PreCheck): [14](#0-13) 

- Attacker must be selected to produce the extra block that triggers round transition (this occurs naturally in rotation as miners cycle through the extra block producer role)
- Attacker modifies their node software to inject malicious `OutValue` data in NextRoundInput

**Attack Complexity:**
- **VERY LOW**: Simply set non-null `OutValue` values for target miners when constructing NextRoundInput
- No complex timing requirements, race conditions, or multi-step coordination needed
- Single transaction executes the entire attack
- Attack is deterministic and guaranteed to succeed if validation passes

**Feasibility:**
- Entry point is the public `NextRound` method accessible to all miners: [15](#0-14) 

- Miners regularly rotate through the extra block producer role
- No economic cost beyond normal mining operations
- Attack can be repeated across multiple rounds to target different victims

**Detection Difficulty:**
- Malicious `OutValue` data is visible in block data but may not trigger immediate alarms
- Effects could initially be misattributed to network issues or node failures
- Requires detailed blockchain state analysis to identify the root cause
- By the time detection occurs, damage (MissedTimeSlots accumulation) has already begun

**Probability:** **MEDIUM-HIGH** - While requiring miner status, the attack is trivial to execute once in position, has no additional costs, regularly available opportunities, and would be difficult to detect and prevent in real-time.

## Recommendation

Add explicit validation in `ValidationForNextRound()` to ensure all `OutValue` fields are null in next round information:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    // Is next round information correct?
    // Currently three aspects:
    //   Round Number
    //   In Values Should Be Null
    //   Out Values Should Be Null (NEW)
    var extraData = validationContext.ExtraData;
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Check InValue is null
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information: InValue must be null." };
    
    // Check OutValue is null (FIX)
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.OutValue != null))
        return new ValidationResult { Message = "Incorrect next round information: OutValue must be null." };
        
    return new ValidationResult { Success = true };
}
```

This ensures that next round data matches the legitimate generation logic where both InValue and OutValue are null for all miners at round start.

## Proof of Concept

A proof of concept would require:
1. Set up a test AEDPoS consensus network with multiple miners
2. Have the attacker miner wait to be selected as extra block producer
3. Construct a malicious `NextRoundInput` with non-null `OutValue` (e.g., Hash.FromString("malicious")) for target victim miners
4. Submit the `NextRound` transaction with this malicious input
5. Observe validation passes (only InValue checked, not OutValue)
6. Observe victim miner attempts to mine but receives TinyBlock behavior instead of UPDATE_VALUE
7. Observe victim's `SupposedOrderOfNextRound` remains 0
8. Progress to next round and verify victim's `MissedTimeSlots` incremented in round generation
9. Repeat over multiple rounds and verify accumulation toward evil threshold of 4,320

The test would demonstrate that the validation gap allows injection of OutValue data that disrupts victim miners' consensus participation.

---

## Notes

This is a critical consensus security vulnerability that exploits an incomplete validation check. The fix is straightforward - adding OutValue null validation alongside the existing InValue check - but the impact without it is severe as it enables targeted DoS against honest validators through false evil node detection. The attack leverages the fact that consensus behavior determination depends on OutValue state, making this field safety-critical for round transition validation.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L46-55)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L131-135)
```csharp
    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-252)
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

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L48-56)
```csharp
            // If out value is null, it means provided pubkey hasn't mine any block during current round period.
            if (_minerInRound.OutValue == null)
            {
                var behaviour = HandleMinerInNewRound();

                // It's possible HandleMinerInNewRound can't handle all the situations, if this method returns Nothing,
                // just go ahead. Otherwise, return it's result.
                if (behaviour != AElfConsensusBehaviour.Nothing) return behaviour;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-62)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
