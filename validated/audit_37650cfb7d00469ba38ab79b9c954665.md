# Audit Report

## Title
Insufficient Validation of OutValue in NextRound Allows Denial of Service Against Miners

## Summary
The `ValidationForNextRound()` method only validates that `InValue` is null for all miners in the next round, but fails to validate that `OutValue` is also null. This allows a malicious miner to inject arbitrary non-null `OutValue` data when creating NextRound transactions, causing victim miners to be incorrectly treated as having already mined, preventing them from producing blocks and incrementing their missed time slot counters.

## Finding Description

The AEDPoS consensus contract validates round transitions through the `RoundTerminateValidationProvider`. However, the `ValidationForNextRound()` method contains an incomplete validation check: [1](#0-0) 

The validation only checks that `InValue` is null, but does NOT validate `OutValue`. When a legitimate next round is generated, both fields should be null as shown in the generation logic: [2](#0-1) [3](#0-2) 

When a miner creates NextRound data, they provide a `NextRoundInput` which is directly converted to a `Round` object with full control over all miner fields: [4](#0-3) 

The malicious round data is stored directly without additional validation: [5](#0-4) 

The attack succeeds because consensus behavior determination relies on `OutValue` being null to identify miners who haven't mined yet: [6](#0-5) 

If `OutValue` is non-null due to malicious injection, the miner skips the `UPDATE_VALUE` behavior and receives `TinyBlock` behavior instead: [7](#0-6) 

Miners producing only `TinyBlock` do not set their `SupposedOrderOfNextRound`: [8](#0-7) 

When generating the next round, miners with `SupposedOrderOfNextRound == 0` are treated as "not mined" and their `MissedTimeSlots` counter is incremented: [9](#0-8) [10](#0-9) 

## Impact Explanation

**Consensus Integrity Impact:**
- Victim miners are prevented from producing `UPDATE_VALUE` blocks, which are essential for consensus participation
- Each victim's `MissedTimeSlots` counter increments every round they are affected
- After reaching the threshold, victims are marked as evil nodes: [11](#0-10) [12](#0-11) 

After 4,320 missed time slots (approximately 3 days at one slot per minute), victims are removed from the consensus set: [13](#0-12) 

**Operational Impact:**
- Reduces effective number of active miners, weakening consensus security
- Victims lose mining rewards for missed blocks
- Chain liveness may be affected if multiple miners are targeted
- Honest miners suffer reputational damage through false evil node marking

The severity is **MEDIUM-HIGH** because while it doesn't directly steal funds, it severely disrupts consensus operations and can result in honest miners being removed from the validator set.

## Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a current consensus miner (verified in PreCheck): [14](#0-13) 

- Attacker must be selected to produce the extra block that triggers round transition (occurs naturally in rotation)
- Attacker modifies their node software to inject malicious `OutValue` data

**Attack Complexity:**
- **LOW**: Simply set non-null `OutValue` values for target miners when creating NextRound data
- No complex timing requirements or race conditions
- Single transaction executes the attack

**Feasibility:**
- Entry point is the public `NextRound` method: [15](#0-14) 

- Miners rotate through extra block producer role regularly
- No economic cost beyond normal mining operations

**Detection:**
- Malicious `OutValue` data visible in block data but might not trigger alarms
- Effects could initially be attributed to network issues
- Requires blockchain analysis to identify root cause

**Probability:** **MEDIUM-HIGH** - While requiring a malicious miner, the attack is simple to execute, has no additional cost, and would be difficult to detect initially.

## Recommendation

Add validation for `OutValue` in the `ValidationForNextRound()` method:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Validate both InValue and OutValue are null
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null || m.OutValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    return new ValidationResult { Success = true };
}
```

This ensures that when a new round is created, all miners start with clean consensus state (null `InValue` and `OutValue`), preventing malicious miners from injecting false mining state.

## Proof of Concept

A test would demonstrate:
1. Miner A creates a legitimate NextRound for Round N+1
2. Miner B (attacker) creates a malicious NextRound with Miner C's `OutValue` set to a non-null hash
3. The validation passes (only checks `InValue`)
4. Miner C attempts to mine in Round N+1
5. Miner C receives `TinyBlock` behavior instead of `UPDATE_VALUE`
6. When Round N+2 is generated, Miner C's `MissedTimeSlots` is incremented
7. After 4,320 rounds, Miner C is marked as an evil node despite being honest

The vulnerability allows consensus manipulation through incomplete round transition validation, breaking the security guarantee that honest miners cannot be prevented from participating in consensus.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L46-56)
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
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-106)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

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
