# Audit Report

## Title
NextTerm Block Production Bypasses Tiny Block Limit Due to ActualMiningTimes/ProducedTinyBlocks Desynchronization

## Summary
The `GetConsensusExtraDataForNextTerm` function sets `ProducedTinyBlocks` to 1 but fails to add an entry to `ActualMiningTimes`, creating a state desynchronization. This allows miners producing NextTerm blocks to bypass the 8-block maximum limit and produce 9 total blocks in their time slot, violating the fork prevention mechanism.

## Finding Description

When a miner produces a NextTerm block (transitioning to a new term), the consensus contract creates inconsistent state where `ProducedTinyBlocks` is incremented but `ActualMiningTimes` remains empty.

**Root Cause:**

In `GetConsensusExtraDataForNextTerm`, only `ProducedTinyBlocks` is set to 1 without updating `ActualMiningTimes`: [1](#0-0) 

This contrasts with `GetConsensusExtraDataForNextRound`, which correctly updates both fields: [2](#0-1) 

Similarly, `GetConsensusExtraDataForTinyBlock` and `GetConsensusExtraDataToPublishOutValue` both synchronize these fields: [3](#0-2) [4](#0-3) 

**Why Protections Fail:**

The block production limit enforcement uses `ActualMiningTimes.Count`, not `ProducedTinyBlocks`: [5](#0-4) 

The calculation in `IsLastTinyBlockOfCurrentSlot` uses `ActualMiningTimes.Count` to determine `blocksBeforeCurrentRound`: [6](#0-5) 

After NextTerm processing, the stored round has `ProducedTinyBlocks = 1` but `ActualMiningTimes = []` (empty). The `UpdateProducedBlocksNumberOfSender` method called during `ProcessNextTerm` only updates `ProducedBlocks`, not `ActualMiningTimes`: [7](#0-6) [8](#0-7) 

**Execution Path:**

1. Miner produces NextTerm block → `ProducedTinyBlocks = 1`, `ActualMiningTimes = []`
2. For subsequent tiny blocks, `GetConsensusBehaviour` checks `ActualMiningTimes.Count < 8` (0 < 8 → true)
3. Each tiny block increments both counters via `ProcessTinyBlock`: [9](#0-8) 
4. Miner can produce 8 additional tiny blocks before `ActualMiningTimes.Count = 8`
5. Total: 1 NextTerm + 8 tiny blocks = 9 blocks, exceeding the 8-block limit

The limit is defined as: [10](#0-9) 

## Impact Explanation

**Consensus Integrity Violation**: Miners bypass the fork prevention mechanism that limits blocks to 8 per time slot. The 8-block limit exists explicitly to "avoid too many forks": [11](#0-10) 

**Increased Fork Risk**: Allowing 9 blocks instead of 8 (12.5% increase) directly contradicts the design principle that adjusts tiny block counts to reduce forks during abnormal blockchain status.

**Unfair Advantage**: Only miners producing NextTerm blocks can exceed the limit, creating an unfair advantage over other miners.

**Protocol Safety Degradation**: Undermines the carefully designed block production throttling mechanism that dynamically adjusts based on blockchain health.

**Who is Affected:**
- All network participants suffer from increased fork probability
- Miners not producing NextTerm blocks are disadvantaged  
- Consensus stability and finality are compromised

**Quantification:**
- 1 extra block per NextTerm (12.5% over the 8-block limit)
- Affects every term transition (periodic election cycles)
- Cumulative impact on network fork rate over time

## Likelihood Explanation

**Attacker Capabilities:**
- Requires only being a miner at term transition (no special privileges required)
- No additional authority beyond normal miner role
- Exploitation is automatic—occurs without deliberate malicious action

**Attack Complexity:**
- Low: The vulnerability triggers naturally during NextTerm block production
- No special transaction crafting required
- State desynchronization persists automatically once the NextTerm block is produced

**Feasibility:**
- Occurs at every term transition (periodic and predictable)
- No preconditions beyond being in the miner set during term change
- Publicly observable and verifiable by examining `ActualMiningTimes` vs `ProducedTinyBlocks`

**Detection Difficulty:**
- Hard to detect as it appears as normal block production
- The extra block is produced within normal consensus flow
- Only detectable through careful analysis comparing `ActualMiningTimes.Count` vs `ProducedTinyBlocks`

**Probability:** High - Executes automatically at every term transition for miners producing NextTerm blocks.

## Recommendation

Modify `GetConsensusExtraDataForNextTerm` to synchronize both `ProducedTinyBlocks` and `ActualMiningTimes`, matching the pattern used in `GetConsensusExtraDataForNextRound`:

```csharp
private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
    AElfConsensusTriggerInformation triggerInformation)
{
    var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
    Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
    if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
    {
        firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        // ADD THIS LINE to synchronize ActualMiningTimes:
        firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
    }

    return new AElfConsensusHeaderInformation
    {
        SenderPubkey = ByteStringHelper.FromHexString(pubkey),
        Round = firstRoundOfNextTerm,
        Behaviour = triggerInformation.Behaviour
    };
}
```

This ensures the state remains consistent and the 8-block limit is properly enforced for NextTerm blocks.

## Proof of Concept

```csharp
[Fact]
public async Task NextTerm_ProducesNineBlocks_ViolatesEightBlockLimit()
{
    // Setup: Initialize consensus with a miner about to produce NextTerm
    var initialMiners = await InitializeConsensusWithMiners();
    var nextTermMiner = initialMiners[0];
    
    // Step 1: Produce NextTerm block
    var nextTermResult = await ConsensusStub.NextTerm.SendAsync(new NextTermInput
    {
        // NextTerm input data
    });
    
    // Verify state after NextTerm
    var round = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var minerInfo = round.RealTimeMinersInformation[nextTermMiner];
    
    // VULNERABILITY: ProducedTinyBlocks = 1, but ActualMiningTimes.Count = 0
    minerInfo.ProducedTinyBlocks.ShouldBe(1);
    minerInfo.ActualMiningTimes.Count.ShouldBe(0); // Desynchronization!
    
    // Step 2: Produce 8 additional tiny blocks
    for (int i = 0; i < 8; i++)
    {
        await ConsensusStub.UpdateTinyBlockInformation.SendAsync(new TinyBlockInput
        {
            // Tiny block input data
        });
    }
    
    // Verify final state
    round = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    minerInfo = round.RealTimeMinersInformation[nextTermMiner];
    
    // PROOF OF VULNERABILITY: 9 blocks produced instead of 8
    minerInfo.ProducedTinyBlocks.ShouldBe(9); // 1 NextTerm + 8 Tiny = 9 blocks
    minerInfo.ActualMiningTimes.Count.ShouldBe(8); // Only 8 recorded in ActualMiningTimes
    
    // Expected: Should not allow more than 8 blocks total
    // Actual: Allowed 9 blocks due to desynchronization
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L55-134)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataToPublishOutValue(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.

        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
            if (triggerInformation.PreviousInValue != null &&
                triggerInformation.PreviousInValue != Hash.Empty)
            {
                Context.LogDebug(
                    () => $"Previous in value in trigger information: {triggerInformation.PreviousInValue}");
                // Self check.
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
            }
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
            }
        }

        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);

        Context.LogDebug(
            () => "Previous in value after ApplyNormalConsensusData: " +
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;

        // Update secret pieces of latest in value.
        
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }

        // To publish Out Value.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L155-171)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForTinyBlock(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L57-79)
```csharp
            else if (!_isTimeSlotPassed
                    ) // Provided pubkey mined blocks during current round, and current block time is still in his time slot.
            {
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;

                var blocksBeforeCurrentRound =
                    _minerInRound.ActualMiningTimes.Count(t => t <= CurrentRound.GetRoundStartTime());

                // If provided pubkey is the one who terminated previous round, he can mine
                // (_maximumBlocksCount + blocksBeforeCurrentRound) blocks
                // because he has two time slots recorded in current round.

                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L54-63)
```csharp
        private bool IsLastTinyBlockOfCurrentSlot()
        {
            var producedBlocksOfCurrentRound = MinerInRound.ProducedTinyBlocks;
            var roundStartTime = CurrentRound.GetRoundStartTime();

            if (CurrentBlockTime < roundStartTime) return producedBlocksOfCurrentRound == _maximumBlocksCount;

            var blocksBeforeCurrentRound = MinerInRound.ActualMiningTimes.Count(t => t < roundStartTime);
            return producedBlocksOfCurrentRound == blocksBeforeCurrentRound.Add(_maximumBlocksCount);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L20-35)
```csharp
    private void UpdateProducedBlocksNumberOfSender(Round input)
    {
        var senderPubkey = Context.RecoverPublicKey().ToHex();

        // Update produced block number of transaction sender.
        if (input.RealTimeMinersInformation.ContainsKey(senderPubkey))
            input.RealTimeMinersInformation[senderPubkey].ProducedBlocks =
                input.RealTimeMinersInformation[senderPubkey].ProducedBlocks.Add(1);
        else
            // If the sender isn't in miner list of next term.
            State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
            {
                Pubkey = senderPubkey,
                RecentlyProducedBlocks = 1
            });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L17-22)
```csharp
    /// <summary>
    ///     Implemented GitHub PR #1952.
    ///     Adjust (mainly reduce) the count of tiny blocks produced by a miner each time to avoid too many forks.
    /// </summary>
    /// <returns></returns>
    private int GetMaximumBlocksCount()
```
