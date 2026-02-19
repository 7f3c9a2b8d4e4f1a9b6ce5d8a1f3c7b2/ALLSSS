### Title
Miner List Manipulation Bypasses Solitary Miner Detection via Unvalidated Round Transitions

### Summary
The `SolitaryMinerDetection` mechanism can be bypassed by a malicious extra block producer who crafts `NextRound` or `NextTerm` transactions with a reduced miner list (≤2 miners). The validation logic fails to verify that the submitted round's miner list matches the expected miners, allowing an attacker to permanently disable solitary mining detection and monopolize block production.

### Finding Description

**Location of Vulnerability:**

The solitary miner detection mechanism checks if the miner count exceeds 2 before running detection logic: [1](#0-0) 

**Root Cause:**

When processing `NextRound` or `NextTerm` transitions, the validation logic fails to verify the integrity of the miner list. Specifically:

1. **NextRound Validation** only checks round number incrementation and that InValues are null, but does NOT validate the miner count or list membership: [2](#0-1) 

2. **RoundTerminateValidationProvider** only validates round/term numbers and InValue nullness: [3](#0-2) 

3. **NextRoundMiningOrderValidationProvider** only checks internal consistency within the provided round itself, not against the baseline miner list: [4](#0-3) 

4. **ProcessNextRound** directly accepts and stores the provided round without miner list validation: [5](#0-4) 

5. **ProcessNextTerm** similarly accepts rounds without validating against the election contract's `GetVictories` result: [6](#0-5) 

**Why Existing Protections Fail:**

The legitimate round generation includes all miners from the current round: [7](#0-6) 

However, since miners generate consensus extra data off-chain and submit it via `NextRound`/`NextTerm` transactions, and no validation compares the submitted miner list against the expected list, a malicious miner can craft a round with arbitrary miner count.

The validation context distinguishes between `BaseRound` (current state) and `ProvidedRound` (submitted data): [8](#0-7) 

But no validator compares the miner lists between these rounds.

### Impact Explanation

**Consensus Integrity Compromise:**

1. **Solitary Mining Attack**: By reducing `RealTimeMinersInformation.Count` to ≤2, the attacker bypasses the solitary miner detection that should prevent a single miner from continuously producing blocks alone.

2. **Consensus Centralization**: The attacker can effectively control the blockchain by solo mining indefinitely without triggering protection mechanisms, violating the fundamental assumption of decentralized consensus.

3. **Chain Validity**: While other nodes validate using the same flawed logic, they would accept the manipulated round, allowing the attack to persist across the network.

4. **Permanent State Corruption**: Once the malicious round is committed, future rounds build upon it, maintaining the reduced miner set until a new term transition (if NextTerm is also compromised, the attack persists indefinitely).

**Affected Parties:**
- Honest miners are excluded from block production and rewards
- Token holders suffer from centralized block production
- The entire network's security degrades to single-party control

### Likelihood Explanation

**Attacker Capabilities Required:**

The attacker must be the extra block producer for the current round to propose `NextRound`, or be able to propose `NextTerm`. The extra block producer rotates based on miner signatures: [9](#0-8) 

**Attack Complexity: Medium**

1. **Prerequisite**: Attacker must be part of the current miner set and wait for their turn as extra block producer (occurs naturally in rotation).

2. **Execution**: Instead of using the legitimately generated round from `GetConsensusExtraDataForNextRound`: [10](#0-9) 

The attacker crafts a custom `NextRoundInput` with only 2 miner entries and submits it.

3. **Detection Difficulty**: The manipulation occurs in the consensus extra data which is validated before execution: [11](#0-10) 

However, since the validation is insufficient, the attack succeeds silently.

**Feasibility: High**

- No special privileges required beyond being a miner
- No cryptographic breaking needed
- No race conditions or timing dependencies
- Validation logic deterministically passes for malicious input
- Economic cost is minimal (just transaction fees)

### Recommendation

**Immediate Mitigation:**

Add miner list integrity validation in `RoundTerminateValidationProvider`:

1. **For NextRound behavior**: Validate that `providedRound.RealTimeMinersInformation.Keys` equals `baseRound.RealTimeMinersInformation.Keys` (same miners, same count).

2. **For NextTerm behavior**: Call `GetVictories()` and validate that `providedRound.RealTimeMinersInformation.Keys` matches the returned miner list.

**Specific Code Changes:**

In `RoundTerminateValidationProvider.ValidationForNextRound()`:
```csharp
// After existing checks, add:
if (validationContext.ProvidedRound.RealTimeMinersInformation.Count != 
    validationContext.BaseRound.RealTimeMinersInformation.Count)
    return new ValidationResult { Message = "Miner count mismatch." };

var expectedMiners = validationContext.BaseRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
var providedMiners = validationContext.ProvidedRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
if (!expectedMiners.SequenceEqual(providedMiners))
    return new ValidationResult { Message = "Miner list mismatch." };
```

In `RoundTerminateValidationProvider.ValidationForNextTerm()`:
```csharp
// After existing checks, validate against GetVictories
// This requires access to election contract state, may need context extension
```

**Additional Safeguards:**

1. Add assertion in `ProcessNextRound` checking miner count hasn't decreased
2. Add assertion in `ProcessNextTerm` comparing against `GenerateFirstRoundOfNextTerm` result
3. Add integration tests specifically covering miner list manipulation attempts

### Proof of Concept

**Initial State:**
- Current round N has 5 miners: [M1, M2, M3, M4, M5]
- Attacker is M1, currently the extra block producer
- Round number > 3 (to bypass initial round detection)

**Attack Sequence:**

1. **Attacker's Turn**: M1 is designated extra block producer for round N

2. **Malicious Round Creation**: Instead of calling the legitimate `GenerateNextRoundInformation` which would include all 5 miners, M1 crafts a custom `NextRoundInput` containing only:
   - `RoundNumber = N + 1`
   - `TermNumber = current term`
   - `RealTimeMinersInformation = { M1, M2 }` (only 2 miners)
   - All InValues set to null (passes validation)

3. **Submission**: M1 submits `NextRound(maliciousNextRoundInput)`

4. **Validation Passes**: 
   - Round number check: N+1 == N+1 ✓
   - InValues check: all null ✓
   - Miner list check: **NOT PERFORMED** ✓
   
5. **State Update**: `ProcessNextRound` stores the malicious round with only 2 miners

6. **Detection Bypass**: In subsequent rounds, `SolitaryMinerDetection` checks `currentRound.RealTimeMinersInformation.Count > 2`, which evaluates to `2 > 2 = false`, **skipping detection entirely**

7. **Solo Mining**: M1 continuously mines blocks without the solitary miner protection triggering, excluding M3, M4, M5 from consensus

**Expected Result**: Validation should reject the transaction with "Miner list mismatch"

**Actual Result**: Transaction succeeds, round N+1 has only 2 miners, solitary detection bypassed, M1 can monopolize block production

**Success Condition**: Query `GetCurrentRoundInformation()` returns a round with `RealTimeMinersInformation.Count == 2` instead of 5, and M1 can produce consecutive blocks without solitary miner detection triggering.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L70-70)
```csharp
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-46)
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

    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L19-27)
```csharp
    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```
