### Title
Miner List Manipulation via Unvalidated NextRound Input Allows Unauthorized Consensus Participation

### Summary
A malicious miner can inject unauthorized miners into the consensus round by submitting a `NextRoundInput` with additional entries in `RealTimeMinersInformation`. The contract fails to validate that the proposed next round's miner list matches the current round's authorized miners, allowing the manipulated round to be stored in state. Subsequently, these unauthorized miners can obtain valid consensus commands through `GetConsensusCommand` and participate in block production, compromising consensus integrity.

### Finding Description

**Root Cause:** Missing miner list validation during `NextRound` processing.

The vulnerability exists in the consensus round transition flow:

1. **Entry Point:** The `NextRound` method is publicly callable by any current miner [1](#0-0) 

2. **Authorization Check:** `PreCheck()` only validates that the transaction sender is in the current or previous round's miner list, but does NOT validate the miner list in the proposed next round [2](#0-1) 

3. **Processing Without Validation:** `ProcessNextRound` converts the input to a Round object and stores it directly without comparing the miner list against the current round [3](#0-2) 

4. **Data Conversion:** The `ToRound()` method simply copies `RealTimeMinersInformation` from the input without any validation [4](#0-3) 

5. **Validation Gaps:** The validation providers for `NextRound` behavior check round numbers and mining order counts, but NOT the actual miner list membership:
   - `NextRoundMiningOrderValidationProvider` only validates that count of miners with `FinalOrderOfNextRound > 0` equals count with `OutValue != null` [5](#0-4) 
   - `RoundTerminateValidationProvider` only checks round number increment and null InValues [6](#0-5) 

6. **Exploitation:** Once the manipulated round is stored, `GetConsensusCommand` retrieves it from state and validates miners using `IsInMinerList`, which simply checks dictionary key existence [7](#0-6) [8](#0-7) 

7. **Vulnerable Target:** For side chains, the manipulated round is passed to `SideChainConsensusBehaviourProvider` constructor, which accesses the unauthorized miners without additional validation [9](#0-8) [10](#0-9) 

**Why Expected Protections Fail:**

The contract correctly generates next rounds using `GenerateNextRoundInformation`, which preserves the miner list from the current round [11](#0-10) . However, there is no validation that enforces the submitted `NextRoundInput` was actually generated using this method or that its miner list matches the current round's authorized miners.

### Impact Explanation

**Consensus Integrity Compromise (Critical):**
- Unauthorized entities gain ability to produce blocks and participate in consensus
- BFT security assumptions are violated as the attacker can add controlled nodes beyond the authorized miner set
- If attacker adds enough unauthorized miners to exceed 1/3 of total miners, they can prevent finality or cause chain reorganizations

**Concrete Attack Scenarios:**
1. A malicious miner adds 5 unauthorized nodes to a 10-miner round, gaining 33% control
2. These unauthorized miners can produce blocks, potentially including malicious transactions
3. The unauthorized miners can manipulate LIB (Last Irreversible Block) calculations
4. Network may split between nodes accepting/rejecting blocks from unauthorized miners

**Affected Parties:**
- All nodes in the blockchain network (both main chain and side chains)
- Token holders whose assets depend on consensus integrity
- DApps relying on transaction finality guarantees

**Severity Justification:** Critical - This directly violates the fundamental security property of the consensus mechanism: only authorized miners should produce blocks. The attack enables complete bypass of the election/authorization system.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be a currently authorized miner (legitimate prerequisite)
- Must have ability to construct and sign transactions
- No special privileges beyond being in the current miner list

**Attack Complexity:** Low
1. Monitor for when it's their turn to produce the extra block triggering NextRound
2. Generate valid `NextRoundInput` using legitimate `GenerateNextRoundInformation` 
3. Modify the `RealTimeMinersInformation` dictionary to add unauthorized miner entries
4. Submit the modified `NextRoundInput` via `NextRound` transaction
5. Wait for the next round where unauthorized miners can call `GetConsensusCommand`

**Feasibility Conditions:**
- Attacker must wait for their time slot as extra block producer (happens periodically in round-robin fashion)
- Transaction must be included in a block (attacker controls this as the block producer)
- No special economic cost beyond normal transaction fees

**Detection Constraints:**
- The manipulated round gets stored in contract state, making the attack persistent
- Validators might detect unauthorized block producers during block validation, but the consensus contract itself allows it
- Post-execution validation doesn't catch this for NextRound behavior

**Probability:** High - Any malicious miner can execute this attack during their designated time slot with minimal technical barriers.

### Recommendation

**Immediate Fix:** Add miner list validation in `ProcessNextRound`:

```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // CRITICAL: Validate miner list hasn't been manipulated
    var currentMiners = currentRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var nextMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    
    Assert(currentMiners.Count == nextMiners.Count && 
           currentMiners.SequenceEqual(nextMiners),
           "Miner list mismatch: unauthorized miners detected in next round");
    
    // ... rest of existing logic
}
```

**Location to apply fix:** [12](#0-11) 

**Additional Validation:** Create a dedicated validation provider:

```csharp
public class MinerListConsistencyValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.NextRound)
            return new ValidationResult { Success = true };
            
        var baseMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k);
        var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.OrderBy(k => k);
        
        if (!baseMiners.SequenceEqual(providedMiners))
            return new ValidationResult { 
                Success = false, 
                Message = "Miner list changed without authorization during NextRound" 
            };
            
        return new ValidationResult { Success = true };
    }
}
```

Add this provider to the validation chain in `ValidateBeforeExecution` for NextRound behavior [13](#0-12) 

**Regression Test Cases:**
1. Test that NextRound fails when extra miners are added to RealTimeMinersInformation
2. Test that NextRound fails when miners are removed from RealTimeMinersInformation  
3. Test that NextRound succeeds when miner list is unchanged (reordering is allowed)
4. Test that legitimate miner list changes during NextTerm still work correctly

### Proof of Concept

**Initial State:**
- Current round has 3 authorized miners: [MinerA, MinerB, MinerC]
- MinerC is the extra block producer for this round
- Round number is 100

**Attack Steps:**

1. **MinerC generates malicious NextRoundInput:**
   - Calls legitimate `GenerateNextRoundInformation` to create round 101
   - Modifies the result to add unauthorized `MinerX` to `RealTimeMinersInformation`
   - Sets valid order, expected mining times for all 4 miners
   - Ensures `FinalOrderOfNextRound` counts match to pass validation

2. **MinerC submits transaction:**
   ```
   Transaction: NextRound(malicious_input)
   Sender: MinerC (signed with MinerC's key)
   ```

3. **Contract Processing:**
   - `PreCheck()` passes: MinerC is in current round's miner list ✓
   - `ValidateBeforeExecution` passes: 
     - Round number 100→101 ✓
     - Mining order counts match ✓  
     - **Missing check:** miner list validation ✗
   - `ProcessNextRound` stores malicious round 101 with 4 miners
   - `AddRoundInformation` persists to `State.Rounds[101]`

4. **Exploitation in Next Round:**
   - MinerX calls `GetConsensusCommand(MinerX_pubkey)`
   - Contract retrieves round 101 from state
   - `currentRound.IsInMinerList(MinerX_pubkey)` returns TRUE
   - `SideChainConsensusBehaviourProvider` created with MinerX
   - MinerX receives valid consensus command (UpdateValue, TinyBlock, or NextRound)
   - MinerX produces blocks during their assigned time slot

**Expected Result:** NextRound transaction should fail with "Unauthorized miner list modification"

**Actual Result:** NextRound transaction succeeds, unauthorized MinerX participates in consensus

**Success Condition:** MinerX successfully produces a block and updates consensus state, proven by transaction logs showing `MiningInformationUpdated` event with MinerX's pubkey [14](#0-13)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L55-65)
```csharp
        var miningInformationUpdated = new MiningInformationUpdated
        {
            // _processingBlockMinerPubkey is set during PreCheck.
            Pubkey = _processingBlockMinerPubkey,
            Behaviour = callerMethodName,
            MiningTime = Context.CurrentBlockTime,
            BlockHeight = Context.CurrentHeight,
            PreviousBlockHash = Context.PreviousBlockHash
        };
        Context.Fire(miningInformationUpdated);
        Context.LogDebug(() => $"Synced mining information: {miningInformationUpdated}");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-54)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
    {
        _processingBlockMinerPubkey = input.Value.ToHex();

        if (Context.CurrentHeight < 2) return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!TryToGetCurrentRoundInformation(out var currentRound))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;

        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);

        var blockchainStartTimestamp = GetBlockchainStartTimestamp();

        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();

        Context.LogDebug(() =>
            $"{currentRound.ToString(_processingBlockMinerPubkey)}\nArranged behaviour: {behaviour.ToString()}");

        return behaviour == AElfConsensusBehaviour.Nothing
            ? ConsensusCommandProvider.InvalidConsensusCommand
            : GetConsensusCommand(behaviour, currentRound, _processingBlockMinerPubkey, Context.CurrentBlockTime);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L9-24)
```csharp
    private class SideChainConsensusBehaviourProvider : ConsensusBehaviourProviderBase
    {
        public SideChainConsensusBehaviourProvider(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime) : base(currentRound, pubkey, maximumBlocksCount, currentBlockTime)
        {
        }

        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L26-37)
```csharp
        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;

            _pubkey = pubkey;
            _maximumBlocksCount = maximumBlocksCount;
            _currentBlockTime = currentBlockTime;

            _isTimeSlotPassed = CurrentRound.IsTimeSlotPassed(_pubkey, _currentBlockTime);
            _minerInRound = CurrentRound.RealTimeMinersInformation[_pubkey];
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```
