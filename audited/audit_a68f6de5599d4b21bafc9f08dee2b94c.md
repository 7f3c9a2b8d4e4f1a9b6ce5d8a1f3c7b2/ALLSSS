### Title
Unprotected .First() Call on Empty ActualMiningTimes in Round 1 TinyBlock Command Generation Causes Consensus Halt

### Summary
The `TinyBlockCommandStrategy.GetAEDPoSConsensusCommand()` method calls `.First()` on `MinerInRound.ActualMiningTimes` without checking if the collection is empty when `CurrentRound.RoundNumber == 1`. If Round 1 is initialized with `ExtraBlockProducerOfPreviousRound` set to a miner's public key (as observed in multiple test implementations), that miner will encounter an `InvalidOperationException` when requesting consensus commands before producing their first block, halting consensus initialization.

### Finding Description [1](#0-0) 

The vulnerable code path executes when:
1. A miner queries for a consensus command during Round 1
2. The consensus behavior provider determines `TinyBlock` behavior should be used
3. The miner has not yet produced any blocks (empty `ActualMiningTimes`)

For TinyBlock behavior to be selected in Round 1 with empty `ActualMiningTimes`: [2](#0-1) 

This path is taken when:
- `CurrentRound.ExtraBlockProducerOfPreviousRound` equals the miner's public key
- Current block time is before the round start time
- The miner hasn't produced any blocks yet (`OutValue == null`)
- `ActualMiningTimes.Count < maximumBlocksCount` (0 < 8)

While the production round generation code does not set `ExtraBlockProducerOfPreviousRound`: [3](#0-2) 

Multiple test implementations explicitly set this field for Round 1: [4](#0-3) [5](#0-4) 

The `ActualMiningTimes` field is a protobuf repeated field that starts empty and is only populated when blocks are produced: [6](#0-5) [7](#0-6) 

Other parts of the codebase implement proper defensive checks. `Round.IsTimeSlotPassed()` checks for empty collections before calling `.First()`: [8](#0-7) 

Similarly, `ProcessNextRound()` uses the safe `FirstOrDefault()` pattern: [9](#0-8) 

### Impact Explanation

If triggered, calling `.First()` on an empty collection throws an `InvalidOperationException`, causing the consensus command generation to fail. This prevents the affected miner from producing blocks during Round 1.

**Concrete harm:**
- Complete consensus halt during chain initialization if the first miner is affected
- The chain cannot progress past Round 1 until the issue is resolved
- All miners and users are blocked from transaction processing

**Affected parties:**
- Any chain initialized with Round 1 having `ExtraBlockProducerOfPreviousRound` set
- Side chains using test-based initialization patterns in production
- Development/staging environments using the test initialization code

**Severity justification:** While this depends on initialization configuration rather than attacker exploitation, the impact is CRITICAL because it completely halts consensus during the most critical phase (chain startup). The severity is HIGH because test code patterns that trigger this bug are widely present in the codebase.

### Likelihood Explanation

**Preconditions:**
- Round 1 must be initialized with `ExtraBlockProducerOfPreviousRound` field set to a valid miner's public key
- That miner must attempt to generate consensus commands before the round officially starts
- The miner has not yet produced any blocks (typical for chain initialization)

**Feasibility:**
- This is NOT directly attacker-exploitable since `FirstRound()` can only be called once: [10](#0-9) 

- However, the Round object is provided as input, and if initialization code follows test patterns, the vulnerability triggers
- Multiple test files demonstrate this exact initialization pattern exists in the codebase
- Custom chain deployments or side chains may inadvertently use test code patterns in production

**Probability:** MEDIUM
- Low in production main chain if proper initialization is used
- Medium-to-High in side chains, test networks, or custom deployments
- High in any environment where test initialization code is reused

**Detection:** The exception would be immediately visible during chain startup, making it easy to detect but requiring code fixes to resolve.

### Recommendation

**Immediate fix:** Add a defensive check before calling `.First()`:

```csharp
var currentTimeSlotStartTime = CurrentBlockTime < roundStartTime
    ? roundStartTime.AddMilliseconds(-MiningInterval)
    : CurrentRound.RoundNumber == 1
        ? MinerInRound.ActualMiningTimes.Count > 0 
            ? MinerInRound.ActualMiningTimes.First()
            : MinerInRound.ExpectedMiningTime  // Fallback to expected time
        : MinerInRound.ExpectedMiningTime;
```

Or use the safe `FirstOrDefault()` pattern:

```csharp
var currentTimeSlotStartTime = CurrentBlockTime < roundStartTime
    ? roundStartTime.AddMilliseconds(-MiningInterval)
    : CurrentRound.RoundNumber == 1
        ? MinerInRound.ActualMiningTimes.FirstOrDefault() ?? MinerInRound.ExpectedMiningTime
        : MinerInRound.ExpectedMiningTime;
```

**Additional measures:**
1. Add validation in `FirstRound()` to reject Round objects with `ExtraBlockProducerOfPreviousRound` set when `RoundNumber == 1`
2. Align test code with production code patterns for Round 1 generation
3. Add unit tests specifically covering TinyBlock behavior in Round 1 with empty `ActualMiningTimes`
4. Document that `ExtraBlockProducerOfPreviousRound` should not be set for the very first round

### Proof of Concept

**Required initial state:**
1. Chain not yet initialized (no previous rounds)
2. Round 1 object created with `ExtraBlockProducerOfPreviousRound` set to first miner's public key (using test pattern)

**Transaction steps:**
1. Call `FirstRound()` with a Round object where:
   - `RoundNumber = 1`
   - `ExtraBlockProducerOfPreviousRound = <first_miner_pubkey>`
   - Miners have empty `ActualMiningTimes` lists

2. First miner attempts to generate consensus command at time T where T < round start time

3. Consensus behavior provider evaluates conditions and returns `TinyBlock` behavior

4. `TinyBlockCommandStrategy.GetAEDPoSConsensusCommand()` is invoked

5. At line 36, `MinerInRound.ActualMiningTimes.First()` is called on empty collection

**Expected result:** Miner receives valid consensus command

**Actual result:** `InvalidOperationException: Sequence contains no elements` is thrown, halting consensus command generation

**Success condition:** Exception prevents the miner from producing blocks, blocking Round 1 completion and chain initialization.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L35-37)
```csharp
                : CurrentRound.RoundNumber == 1
                    ? MinerInRound.ActualMiningTimes.First()
                    : MinerInRound.ExpectedMiningTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-44)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval,
        Timestamp currentBlockTime, long currentRoundNumber = 0, long currentTermNumber = 0)
    {
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
        }

        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;

        return round;
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainRentFeeTestBase.cs (L198-198)
```csharp
        round.ExtraBlockProducerOfPreviousRound = sortedMiners[0];
```

**File:** test/AElf.Contracts.TestContract.Tests/TestContractTestBase.cs (L518-518)
```csharp
        round.ExtraBlockProducerOfPreviousRound = sortedMiners[0];
```

**File:** protobuf/aedpos_contract.proto (L292-292)
```text
    repeated google.protobuf.Timestamp actual_mining_times = 13;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L120-122)
```csharp
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L243-243)
```csharp
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L92-95)
```csharp
        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L74-77)
```csharp
    public override Empty FirstRound(Round input)
    {
        /* Basic checks. */
        Assert(State.CurrentRoundNumber.Value == 0, "Already initialized.");
```
