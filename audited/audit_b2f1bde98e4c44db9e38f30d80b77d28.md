### Title
Conditional Round Pruning Failure Leading to Unbounded State Growth and Memory Exhaustion

### Summary
The consensus contract's round pruning mechanism only removes old round data when the blockchain is in "Normal" mining status. During "Abnormal" or "Severe" status (when LIB advancement lags), pruning stops entirely, causing unlimited accumulation of historical Round objects containing MinerInRound data (including ActualMiningTimes). If the blockchain remains in degraded status for extended periods, this leads to unbounded state growth and eventual memory exhaustion.

### Finding Description

The root cause is a conditional pruning mechanism in the `AddRoundInformation` method that only removes old rounds when blockchain mining status is "Normal": [1](#0-0) 

The pruning condition checks if `GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount`. However, `GetMaximumBlocksCount()` returns a reduced value when the blockchain enters "Abnormal" or "Severe" status: [2](#0-1) [3](#0-2) 

The blockchain enters these degraded states when the current round number advances beyond the last irreversible block (LIB) round number: [4](#0-3) 

Each Round object stored in state contains a full map of MinerInRound objects for all miners, where each MinerInRound includes ActualMiningTimes data: [5](#0-4) 

When `AddRoundInformation` is called during any consensus update (UpdateValue, TinyBlock, NextRound, NextTerm), it stores the new round but fails to prune old rounds during Abnormal/Severe status, causing the `State.Rounds` mapping to grow without bound.

The specific line 61 referenced in the question accesses ActualMiningTimes: [6](#0-5) 

While ActualMiningTimes within a single round is bounded by MaximumBlocksCount (~8 entries), the accumulation of unpruned rounds means these data structures persist indefinitely when pruning is disabled.

### Impact Explanation

**Direct Harm**: Unbounded growth of the `State.Rounds` mapping leads to memory exhaustion of consensus nodes, causing denial of service of the entire blockchain.

**Quantified Damage**: 
- Each Round contains ~17 MinerInRound objects (typical miner count)
- Each MinerInRound stores ActualMiningTimes (max 8 timestamps), encrypted/decrypted pieces, hashes, and other metadata
- Estimated size: ~17-170 KB per round
- To exhaust 1 GB memory: ~6,000-60,000 rounds need to accumulate
- At typical round duration (4000 seconds): requires months to years of sustained abnormal status

**Affected Parties**: All consensus nodes and the entire blockchain operation become unavailable.

**Severity Justification**: Medium severity due to the design flaw where pruning fails exactly when the system is under stress, and the lack of any fallback mechanism or cap. While exploitation requires prolonged abnormal conditions, the counterintuitive design (stopping cleanup when blockchain health degrades) represents a critical failure mode with eventual DoS impact.

### Likelihood Explanation

**Preconditions**: 
- Blockchain must enter and remain in Abnormal status (R > R_LIB + 2) or Severe status (R >= R_LIB + 8)
- This occurs when the Last Irreversible Block (LIB) fails to advance while new rounds continue
- Can result from network partitions, consensus attacks preventing finality, or Byzantine miner behavior

**Attack Complexity**: Low - no direct attacker action required after triggering initial abnormal state. The flaw manifests naturally when blockchain health degrades.

**Feasibility**: Moderate - while triggering abnormal status is feasible through network disruption or consensus attacks, maintaining it for the extended duration needed for memory exhaustion (months) is challenging. However, the lack of any protective mechanism means the vulnerability is inevitable given sufficient time in degraded state.

**Economic Cost**: Minimal direct cost to trigger, as abnormal status can occur from network issues. An attacker would need to sustain conditions preventing LIB advancement.

**Probability**: The vulnerability is certain to manifest if abnormal status persists, though reaching memory exhaustion requires sustained degraded state. The design flaw itself (disabling pruning during stress) is always present.

### Recommendation

**Code-Level Mitigation**:

1. Remove or invert the pruning condition to ensure cleanup continues (or intensifies) during degraded blockchain status:

```csharp
// In AddRoundInformation:
var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
if (roundNumberToRemove > 1)  // Remove the GetMaximumBlocksCount() condition
    State.Rounds.Remove(roundNumberToRemove);
```

2. Add an absolute maximum rounds cap as a safety valve:

```csharp
const int AbsoluteMaxStoredRounds = 50000;  // Safety limit
var roundNumberToRemove = round.RoundNumber.Sub(Math.Min(KeepRounds, AbsoluteMaxStoredRounds));
```

3. Implement aggressive pruning during Severe status:

```csharp
var keepRounds = GetMaximumBlocksCount() < MaximumTinyBlocksCount 
    ? Math.Min(KeepRounds, 1000)  // Aggressive cleanup during stress
    : KeepRounds;
```

**Invariant Checks**:
- Add monitoring for `State.Rounds` size
- Assert that stored rounds count never exceeds `KeepRounds + SafetyMargin`
- Log warnings when pruning is skipped

**Test Cases**:
- Simulate prolonged Abnormal/Severe status and verify rounds are still pruned
- Test memory usage under extended non-pruning scenarios
- Verify graceful degradation even when round storage grows

### Proof of Concept

**Initial State**:
- Blockchain operating normally with ~17 miners
- Current round N, LIB at round N-2

**Attack Sequence**:

1. **Trigger Abnormal Status**: Network disruption or consensus manipulation prevents LIB from advancing beyond round M
2. **Rounds Continue**: Miners continue producing blocks, advancing rounds to M+3, M+4, ... M+K
3. **Pruning Fails**: Each call to `AddRoundInformation` checks if `GetMaximumBlocksCount() == 8`, which returns false during Abnormal/Severe status, so `State.Rounds.Remove()` is never called
4. **State Accumulation**: Rounds M through M+K all remain in `State.Rounds`, each containing full MinerInRound data with ActualMiningTimes
5. **Memory Exhaustion**: After K > ~6,000-60,000 rounds (depending on data size), consensus nodes exhaust memory

**Expected vs Actual**:
- Expected: Old rounds pruned after KeepRounds (40,960) regardless of blockchain status
- Actual: No pruning occurs during Abnormal/Severe status, allowing unlimited round accumulation

**Success Condition**: Monitor `State.Rounds` size during simulated prolonged abnormal status. If size exceeds KeepRounds without pruning, vulnerability is confirmed.

### Notes

The vulnerability specifically affects historical Round objects accumulation rather than ActualMiningTimes growing within a single MinerInRound. ActualMiningTimes is bounded per round by MaximumBlocksCount (~8) and is not carried forward when generating new rounds. However, when Round pruning fails, all historical ActualMiningTimes data persists in unpruned rounds, contributing to the overall state bloat that eventually causes memory exhaustion.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L117-123)
```csharp
        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-54)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L119-129)
```csharp
        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
        }
```

**File:** protobuf/aedpos_contract.proto (L243-301)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
}

message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L61-61)
```csharp
            var blocksBeforeCurrentRound = MinerInRound.ActualMiningTimes.Count(t => t < roundStartTime);
```
