### Title
NextRound Transaction Can Bypass Validation to Corrupt Consensus State via Non-Hashed Fields

### Summary
The `ToRound()` method performs no validation when converting `NextRoundInput` to `Round`, and `AddRoundInformation()` directly stores the resulting Round without verification. A malicious miner can craft a NextRound transaction where the header contains valid Round data that passes validation, but the transaction's `NextRoundInput` contains corrupted `ActualMiningTimes`, `EncryptedPieces`, or `DecryptedPieces` fields. Since post-execution validation only compares Round hashes that exclude these fields, the corrupted data gets stored in consensus state, enabling manipulation of term transitions and disruption of block production scheduling.

### Finding Description

The vulnerability exists in the NextRound consensus transaction processing flow with multiple contributing factors:

**1. No Validation in ToRound() Conversion** [1](#0-0) 

The `ToRound()` method is a pure field copy operation with no validation of the resulting Round state.

**2. No Validation in AddRoundInformation() Storage** [2](#0-1) 

The `AddRoundInformation()` method directly stores the Round to state without any validation checks.

**3. Execution Path Through ProcessNextRound** [3](#0-2) 

At line 110, `ToRound()` is called to convert the transaction input, and at line 156, the unvalidated result is stored via `AddRoundInformation()`.

**4. Incomplete Pre-Execution Validation** [4](#0-3) 

The `RoundTerminateValidationProvider` only validates that RoundNumber increments correctly and that InValues are null. It does NOT validate that `ActualMiningTimes`, `EncryptedPieces`, or `DecryptedPieces` are empty for a new round.

**5. Hash Comparison Excludes Critical Fields** [5](#0-4) 

The `GetCheckableRound()` method explicitly clears `EncryptedPieces`, `DecryptedPieces`, and `ActualMiningTimes` before computing the hash. This means post-execution validation cannot detect manipulation of these fields. [6](#0-5) 

The `ValidateConsensusAfterExecution()` method compares Round hashes at lines 100-101, which excludes the manipulated fields.

**6. Critical Usage of ActualMiningTimes in Consensus Logic** [7](#0-6) 

The `NeedToChangeTerm()` method uses `ActualMiningTimes` to determine term transitions. Corrupted values enable premature or delayed term changes. [8](#0-7) 

Block production logic uses `ActualMiningTimes.Count` to limit tiny block production and determine mining behavior.

**7. Expected Clean State for NextRound** [9](#0-8) 

The legitimate `GenerateNextRoundInformation()` method creates new MinerInRound objects with only essential fields set (Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots). ActualMiningTimes, EncryptedPieces, and DecryptedPieces remain empty for a new round.

### Impact Explanation

**Consensus Integrity Compromise:**
- Corrupted `ActualMiningTimes` with fake timestamps allows a malicious miner to manipulate the `NeedToChangeTerm()` calculation, causing incorrect term transitions (premature term changes or preventing legitimate term changes)
- Disrupts the deterministic block production schedule by affecting tiny block production limits in consensus behavior determination
- Corrupted secret sharing data (`EncryptedPieces`/`DecryptedPieces`) can break the cryptographic randomness generation mechanism

**Protocol-Wide Impact:**
- Term transitions control miner set rotations and election rewards distribution - manipulation affects entire validator economics
- Incorrect block production scheduling can cause chain halts or excessive forking
- All nodes accept the corrupted Round data as canonical consensus state

**Severity Justification:**
This is a HIGH severity finding because it directly corrupts fundamental consensus state that controls chain liveness, validator rotation, and cryptographic randomness. The corrupted state persists across subsequent rounds and affects all consensus participants.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active miner in the current validator set (permissioned role but achievable through staking/election)
- Can generate and broadcast blocks with custom transaction content
- No additional cryptographic keys or special privileges beyond miner status required

**Attack Complexity:**
- Low complexity: simply craft a `NextRoundInput` protobuf message with manipulated non-hashed fields while keeping hashed fields correct
- The transaction can be generated using standard protobuf serialization tools
- No timing windows or race conditions required

**Feasibility Conditions:**
- Miner produces a block during their legitimate time slot (normal operation)
- Generates NextRound consensus transaction (periodic occurrence)
- Modifies the transaction's `NextRoundInput` before block broadcast

**Detection/Operational Constraints:**
- No log or event indicates field manipulation since validation passes
- Other nodes accept the block as valid through normal consensus
- Corruption only detectable through careful Round state inspection or when effects manifest (incorrect term changes, stuck block production)

**Probability Assessment:**
HIGH likelihood once a miner is compromised or malicious, as no technical barriers prevent exploitation and the attack is undetectable during validation.

### Recommendation

**1. Add Pre-Execution Validation for Non-Hashed Fields**

In `RoundTerminateValidationProvider.ValidationForNextRound()`, add checks after line 30:

```csharp
// Verify ActualMiningTimes is empty for all miners in next round
if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.ActualMiningTimes.Any()))
    return new ValidationResult { Message = "ActualMiningTimes must be empty for next round." };

// Verify EncryptedPieces is empty for all miners
if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.EncryptedPieces.Any()))
    return new ValidationResult { Message = "EncryptedPieces must be empty for next round." };

// Verify DecryptedPieces is empty for all miners  
if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.DecryptedPieces.Any()))
    return new ValidationResult { Message = "DecryptedPieces must be empty for next round." };
```

**2. Add Validation in ToRound() Method**

In `NextRoundInput.ToRound()`, add validation before returning:

```csharp
var round = new Round { /* field assignments */ };

// Validate clean state for new round
Assert(
    round.RealTimeMinersInformation.Values.All(m => 
        !m.ActualMiningTimes.Any() && 
        !m.EncryptedPieces.Any() && 
        !m.DecryptedPieces.Any()),
    "NextRoundInput contains invalid non-empty temporal or secret-sharing fields");

return round;
```

**3. Add Invariant Checks in AddRoundInformation()**

Add validation at the start of `AddRoundInformation()` method for NextRound scenarios.

**4. Test Cases to Add**

- Test NextRound transaction with non-empty ActualMiningTimes - should fail validation
- Test NextRound transaction with non-empty EncryptedPieces - should fail validation  
- Test NextRound transaction with non-empty DecryptedPieces - should fail validation
- Verify term transition calculation cannot be manipulated via corrupted ActualMiningTimes
- Verify tiny block limits remain correct with clean Round state

### Proof of Concept

**Required Initial State:**
- Active AEDPoS consensus chain with multiple miners
- Test miner is in current validator set and has a valid time slot
- Current round number > 1 (past genesis)

**Attack Transaction Steps:**

1. **Miner generates legitimate NextRound consensus data:**
   - Call `GetConsensusCommand()` → returns NextRound behavior
   - Call `GetConsensusExtraData()` → generates valid Round for block header

2. **Miner crafts malicious NextRoundInput:**
   - Serialize the header Round to create base NextRoundInput
   - Modify the serialized data to inject fake `ActualMiningTimes` (e.g., future timestamps to trigger premature term change)
   - Keep all hashed fields identical (RoundNumber, TermNumber, Orders, ExpectedMiningTimes, etc.)
   - Add random data to `EncryptedPieces` or `DecryptedPieces`

3. **Miner broadcasts block:**
   - Block header contains valid Round (passes ValidateConsensusBeforeExecution)
   - Block contains crafted NextRound transaction with corrupted NextRoundInput

4. **Network processes block:**
   - Pre-execution validation: ✓ Passes (validates header Round)
   - Transaction execution: `NextRound()` → `ProcessNextRound()` → `ToRound()` (no validation) → `AddRoundInformation()` (no validation)
   - Post-execution validation: ✓ Passes (hash comparison excludes corrupted fields)
   - Corrupted Round stored to `State.Rounds[nextRoundNumber]`

**Expected vs Actual Result:**

**Expected:** NextRound transaction rejected if containing non-empty ActualMiningTimes/EncryptedPieces/DecryptedPieces

**Actual:** Transaction accepted, corrupted Round stored in consensus state

**Success Condition:** 
Query `State.Rounds[roundNumber]` after execution shows non-empty `ActualMiningTimes` for miners who haven't mined yet, or subsequent `NeedToChangeTerm()` call returns incorrect result due to fake timestamps.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-80)
```csharp
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
