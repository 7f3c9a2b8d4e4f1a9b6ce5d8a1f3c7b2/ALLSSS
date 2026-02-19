### Title
Missing ProducedBlocks Counter Validation in Next Round Transitions Allows Reward Manipulation

### Summary
The `ValidationForNextRound()` function in `RoundTerminateValidationProvider` does not validate that ProducedBlocks counters are correctly carried forward from the current round to the next round. A malicious miner producing the round-terminating block can manipulate these counters in the next round information they provide, directly affecting reward distribution calculations in the Treasury contract where ProducedBlocks determines each miner's share of BasicMinerReward.

### Finding Description

**Root Cause:**

The validation logic for NextRound behavior only checks round number increment and InValue nullness, but completely omits validation of ProducedBlocks counters: [1](#0-0) 

When generating next round information, ProducedBlocks counters are correctly copied from the current round: [2](#0-1) [3](#0-2) 

However, the miner's node software generates this data and can modify ProducedBlocks values before submission: [4](#0-3) 

The validation providers for NextRound behavior do not include any check for ProducedBlocks integrity: [5](#0-4) 

In `ProcessNextRound()`, the input is directly converted to Round via `ToRound()` which performs a simple field copy without validation: [6](#0-5) [7](#0-6) 

### Impact Explanation

**Direct Financial Impact:**

ProducedBlocks counters directly determine reward distribution in the Treasury contract's BasicMinerReward scheme: [8](#0-7) 

The `CalculateShares()` function implements penalty thresholds based on ProducedBlocks relative to average: [9](#0-8) 

A malicious miner can:
1. **Inflate their own ProducedBlocks** → increase their reward share above legitimate value
2. **Deflate competitors' ProducedBlocks** → push victims below 50% average threshold (0 shares) or 80% threshold (quadratic penalty)
3. **Manipulate the average calculation** → affect threshold boundaries for all miners

The BasicMinerReward scheme receives a significant portion of mining rewards (default 2/4 weight of MinerReward): [10](#0-9) 

This directly misallocates rewards across all miners in the term.

### Likelihood Explanation

**Attack Feasibility:**

- **Entry Point:** The attacker must be a legitimate miner in the miner list who produces the round-terminating block (last block producer or extra block producer of a round)
- **Attack Complexity:** Requires modifying node software to alter ProducedBlocks values after `GenerateNextRoundInformation()` but before block submission - technically straightforward for a miner operator
- **Detection Difficulty:** Manipulated values would appear consistent with round transitions; no on-chain mechanism exists to detect the manipulation since validation is missing
- **Economic Rationality:** High reward for low risk - the attacker gains increased rewards while reducing competitors' shares, with minimal detection risk
- **Frequency:** Occurs every round transition (approximately every few hours based on round duration), providing multiple exploitation opportunities per term

The attack is practically feasible for any miner with the technical capability to modify their consensus node software, which is a realistic assumption for sophisticated mining operators motivated by financial gain.

### Recommendation

**Immediate Fix:**

Add ProducedBlocks validation to `ValidationForNextRound()` in `RoundTerminateValidationProvider.cs`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing validations
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // ADD: Validate ProducedBlocks counters match current round
    foreach (var miner in extraData.Round.RealTimeMinersInformation)
    {
        var pubkey = miner.Key;
        if (!validationContext.BaseRound.RealTimeMinersInformation.ContainsKey(pubkey))
            continue; // New miner in next round
            
        var expectedProducedBlocks = validationContext.BaseRound.RealTimeMinersInformation[pubkey].ProducedBlocks;
        
        // Account for the current block producer incrementing their own counter
        if (pubkey == extraData.SenderPubkey.ToHex())
            expectedProducedBlocks = expectedProducedBlocks.Add(1);
            
        if (miner.Value.ProducedBlocks != expectedProducedBlocks)
            return new ValidationResult { Message = $"Invalid ProducedBlocks counter for miner {pubkey}." };
    }
    
    return new ValidationResult { Success = true };
}
```

**Additional Safeguards:**

1. Add similar validation for MissedTimeSlots counters
2. Implement regression tests validating ProducedBlocks integrity across round transitions
3. Add monitoring/alerting for anomalous ProducedBlocks patterns in block validation logs

### Proof of Concept

**Initial State:**
- Current round has 5 miners: Alice, Bob, Charlie, Dave, Eve
- Alice: ProducedBlocks = 100
- Bob: ProducedBlocks = 95  
- Charlie: ProducedBlocks = 90
- Dave: ProducedBlocks = 85
- Eve: ProducedBlocks = 80
- Average = 90 blocks

**Attack Sequence:**

1. Eve is the extra block producer of current round who will produce the round-terminating block
2. Eve's node calls `GetConsensusExtraDataForNextRound()` which correctly generates next round with:
   - Alice: ProducedBlocks = 100
   - Bob: ProducedBlocks = 95
   - Charlie: ProducedBlocks = 90
   - Dave: ProducedBlocks = 85
   - Eve: ProducedBlocks = 81 (incremented for current block)

3. Eve modifies her node software to alter the next round data before block submission:
   - Alice: ProducedBlocks = 40 (deflated to 44% of average → 0 shares)
   - Bob: ProducedBlocks = 60 (deflated to 67% of average → quadratic penalty)
   - Charlie: ProducedBlocks = 90 (unchanged)
   - Dave: ProducedBlocks = 85 (unchanged)
   - Eve: ProducedBlocks = 150 (inflated to 167% of average)

4. Eve submits block with manipulated NextRoundInput
5. Validation passes (only checks round number and InValues)
6. `ProcessNextRound()` stores manipulated counters in state
7. At term end, Treasury calculates rewards with manipulated values:
   - New average = (40 + 60 + 90 + 85 + 150) / 5 = 85
   - Alice gets 0 shares (< 50% average)
   - Bob gets (60 * 60) / 85 = 42 shares (quadratic penalty)
   - Charlie gets 90 shares
   - Dave gets 85 shares
   - Eve gets 150 shares

**Expected Result:** ProducedBlocks should match current round values (with +1 for block producer)

**Actual Result:** Eve successfully manipulates counters, stealing reward share from Alice and Bob while inflating her own rewards

**Success Condition:** Eve receives disproportionately higher BasicMinerReward share compared to her legitimate block production

### Notes

This vulnerability specifically affects round-to-round transitions within the same term. During term transitions (`ProcessNextTerm`), ProducedBlocks counters are correctly reset to 0 for all miners, preventing counter manipulation from persisting across terms. However, since terms are significantly longer than rounds (typically 7 days vs a few hours), this provides substantial exploitation windows within each term where the manipulated counters affect multiple reward distribution calculations.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L480-488)
```csharp
    private MinerRewardWeightSetting GetDefaultMinerRewardWeightSetting()
    {
        return new MinerRewardWeightSetting
        {
            BasicMinerRewardWeight = 2,
            WelcomeRewardWeight = 1,
            FlexibleRewardWeight = 1
        };
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L777-822)
```csharp
    private void UpdateBasicMinerRewardWeights(IReadOnlyCollection<Round> previousTermInformation)
    {
        if (previousTermInformation.First().RealTimeMinersInformation != null)
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.BasicRewardHash.Value,
                Beneficiaries =
                {
                    GetAddressesFromCandidatePubkeys(previousTermInformation.First().RealTimeMinersInformation.Keys)
                }
            });

        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
                    }

                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
        });
    }
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
