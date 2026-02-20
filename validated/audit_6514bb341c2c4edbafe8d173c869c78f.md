# Audit Report

## Title
Miner List Manipulation During NextRound Transition - Complete Consensus Takeover

## Summary
The AEDPoS consensus contract fails to validate that the miner list remains consistent during NextRound transitions. A malicious miner can arbitrarily replace all miners with attacker-controlled nodes in a single NextRound transaction, achieving immediate and complete consensus control.

## Finding Description

The vulnerability stems from **missing miner list validation** across the entire NextRound validation pipeline, enabling a protocol-level consensus takeover.

**Before-Execution Validation Gap:**

The `ValidationForNextRound()` method only validates round number increment and null InValues, but completely omits validation of miner list consistency. [1](#0-0) 

The `NextRoundMiningOrderValidationProvider` only checks internal consistency within the provided round (that miners with FinalOrderOfNextRound match those with OutValue), not against the base round's miner list. [2](#0-1) 

**Direct Unvalidated State Write:**

During execution, `ProcessNextRound` converts the input via `ToRound()` and directly writes it to state via `AddRoundInformation` without any miner list validation against the current round. [3](#0-2) 

The `AddRoundInformation` method performs a direct state write without any validation of the miner list. [4](#0-3) 

**Circular After-Execution Validation:**

The after-execution validation in `ValidateConsensusAfterExecution` retrieves `currentRound` from state after the transaction has already updated it (State.CurrentRoundNumber was incremented to 101 and State.Rounds[101] was written). When comparing headerMiners vs stateMiners, both refer to the same data since state was just updated, causing the validation to pass circularly. [5](#0-4) 

**Protocol Invariant Violation:**

The legitimate generation path in `GenerateNextRoundInformation` preserves the miner list from the current round, using `GetMinedMiners()` and `GetNotMinedMiners()` to build the next round from existing miners. [6](#0-5) 

The `isMinerListChanged` parameter is only set to `true` during evil miner replacements within the same term, never for normal NextRound transitions, confirming that NextRound should preserve the miner list. [7](#0-6) 

**Attack Execution:**

A malicious miner passes the `PreCheck` validation which only confirms the sender is in the current or previous miner list, without validating the input's miner list. [8](#0-7) 

The attacker crafts a `NextRoundInput` with completely different `RealTimeMinersInformation` containing only attacker-controlled nodes. The `ToRound()` conversion performs no validation. [9](#0-8) 

The public `NextRound` entry point simply calls `SupplyCurrentRoundInformation()` then `ProcessConsensusInformation(input)` without any miner list validation. [10](#0-9) 

## Impact Explanation

**Severity: CRITICAL**

This vulnerability enables **complete consensus takeover** by a single malicious miner:

1. **Immediate Control**: The attacker gains 100% consensus control in a single block
2. **Double-Spending**: Can revert transactions and execute double-spend attacks  
3. **Censorship**: Can exclude any transactions or blocks from honest participants
4. **Chain Reorganization**: Can rewrite blockchain history with full mining power
5. **Economic Destruction**: Can manipulate all consensus-dependent operations including token minting, Treasury releases, profit distributions, and governance execution
6. **Permanent Takeover**: Can continuously maintain the manipulated miner list through subsequent NextRound transitions

Unlike typical 51% attacks requiring external resources and infrastructure, this exploit allows instant seizure of 100% control through protocol manipulation alone.

**Affected Parties:**
- All token holders (asset value destruction)
- All dApp users (service disruption)  
- Entire blockchain ecosystem (trust collapse)

## Likelihood Explanation

**Probability: HIGH**

**Attacker Requirements:**
- Control one current miner position (obtained through normal election process)
- Wait for appropriate timing to produce NextRound block (normal operation)
- Craft malicious `NextRoundInput` (trivial - simple protobuf modification)

**Attack Characteristics:**
- **Zero Additional Cost**: No extra stake or resources beyond existing miner position
- **Low Technical Barrier**: Straightforward message manipulation
- **Single Transaction**: Entire attack completes in one block
- **No Detection Window**: State corrupted before detection possible
- **No Preconditions**: Works at any point during miner's NextRound opportunity

Given that multiple miners exist on the network, miner positions are publicly elected (any candidate can become a miner), and the attack is trivial to execute once in position, the probability of at least one malicious actor attempting this exploit is significant.

## Recommendation

Add miner list validation in `ValidationForNextRound()` to verify that the next round's miner list matches the base round's miner list:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing validations
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };

    // ADD MINER LIST VALIDATION
    var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var nextMiners = extraData.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    
    if (baseMiners.Count != nextMiners.Count || !baseMiners.SequenceEqual(nextMiners))
        return new ValidationResult { Message = "Miner list must remain unchanged during NextRound transition." };

    return new ValidationResult { Success = true };
}
```

This ensures NextRound transitions preserve the miner list, while NextTerm transitions (which legitimately change miners) continue to work as designed.

## Proof of Concept

```csharp
[Fact]
public async Task NextRound_MinerListManipulation_ShouldFail()
{
    // Setup: Initialize consensus with legitimate miners
    var initialMiners = new[] { "miner1", "miner2", "miner3" };
    await InitializeConsensusWithMiners(initialMiners);
    
    // Current state: Round 100 with legitimate miners
    var currentRound = await GetCurrentRound();
    Assert.Equal(initialMiners.Length, currentRound.RealTimeMinersInformation.Count);
    
    // Attack: Craft malicious NextRoundInput with different miner list
    var maliciousMiners = new[] { "attacker1", "attacker2", "attacker3" };
    var maliciousNextRound = CreateRoundWithMiners(
        roundNumber: currentRound.RoundNumber + 1,
        miners: maliciousMiners
    );
    
    var maliciousInput = new NextRoundInput
    {
        RoundNumber = maliciousNextRound.RoundNumber,
        RealTimeMinersInformation = { maliciousNextRound.RealTimeMinersInformation }
        // ... other fields
    };
    
    // Execute: Call NextRound with malicious input
    // VULNERABILITY: This should fail but currently succeeds
    var result = await ConsensusContract.NextRound.SendAsync(maliciousInput);
    
    // Verify: Miner list was illegitimately changed
    var newRound = await GetCurrentRound();
    Assert.Equal(maliciousMiners.Length, newRound.RealTimeMinersInformation.Count);
    Assert.True(newRound.RealTimeMinersInformation.Keys.All(k => maliciousMiners.Contains(k)));
    
    // Consensus is now completely controlled by attacker
}
```

## Notes

This vulnerability represents a fundamental flaw in the consensus validation layer. The validation framework has access to both the `baseRound` (current round before execution) and `extraData.Round` (proposed next round) in `ValidateBeforeExecution`, making it straightforward to add the missing miner list comparison. The circular nature of `ValidateConsensusAfterExecution` makes it unsuitable for this validation since state has already been modified. The fix must be implemented in the before-execution validation pipeline, specifically in `RoundTerminateValidationProvider.ValidationForNextRound()`.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
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

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L285-347)
```csharp
    private void GenerateNextRoundInformation(Round currentRound, Timestamp currentBlockTime, out Round nextRound)
    {
        TryToGetPreviousRoundInformation(out var previousRound);
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();
        var isMinerListChanged = false;
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }

        currentRound.GenerateNextRoundInformation(currentBlockTime, blockchainStartTimestamp, out nextRound,
            isMinerListChanged);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
