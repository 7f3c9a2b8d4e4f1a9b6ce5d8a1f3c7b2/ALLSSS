### Title
Byzantine Minority Can Prevent Term Transitions by Coordinated Mining Abstention

### Summary
A minority of colluding miners (≥40% but <67%) can indefinitely prevent term transitions by refusing to mine during rounds that cross term boundaries. This causes `NeedToChangeTerm()` to return false, triggering `NextRound` instead of `NextTerm`, thereby maintaining the existing miners' monopoly and preventing newly elected miners from joining the consensus.

### Finding Description

The vulnerability exists in the term transition logic where `GetConsensusBehaviourToTerminateCurrentRound()` decides between `NextRound` and `NextTerm` behaviors. [1](#0-0) 

The decision relies on `NeedToChangeTerm()`, which requires at least `MinersCountOfConsent` (calculated as `(total_miners * 2 / 3) + 1`) miners to have `ActualMiningTimes` timestamps that cross the term boundary: [2](#0-1) [3](#0-2) 

**Root Cause**: The check counts only miners who have mined (`ActualMiningTimes.Any()`) in the current round. If fewer than `MinersCountOfConsent` miners participate after the term boundary crosses, the function returns false even though the time-based term period has elapsed.

**Critical Timing Issue**: When the extra block producer terminates the round, their mining time is added to the NEXT round, not the current round being evaluated: [4](#0-3) 

This means the extra block producer's participation doesn't count toward the `NeedToChangeTerm()` threshold for the current round.

**Attack Execution**: With 10 miners and `MinersCountOfConsent = 7`:
- If 4 miners refuse to mine (or only mine before the term boundary)
- Only 6 miners have timestamps crossing the boundary
- `6 < 7` causes `NeedToChangeTerm()` to return false
- `NextRound` is triggered instead of `NextTerm`
- Same miners continue; no new elections take effect

**Why Existing Protections Fail**: The evil miner detection threshold is 4,320 missed time slots (approximately 3 days): [5](#0-4) 

Colluding miners only need to abstain from one or a few strategic rounds at each term boundary, far below this threshold.

### Impact Explanation

**Governance Breakdown**: The primary impact is complete failure of the governance mechanism for miner rotation. When `NextTerm` should be triggered, it calls `GenerateFirstRoundOfNextTerm()` which retrieves newly elected miners from the Election Contract: [6](#0-5) [7](#0-6) 

Without term transitions, newly elected miners can never join the consensus, rendering the election system meaningless.

**Quantified Harm**:
- **Reward Misallocation**: Mining rewards continue flowing to incumbent miners instead of newly elected validators
- **Centralization**: A minority coalition (40%+) can maintain permanent control over consensus
- **Governance Capture**: Users' votes in elections become ineffective
- **Protocol Integrity**: Violates the fundamental AEDPoS guarantee that elections determine the validator set

**Severity Justification**: This is CRITICAL because it:
1. Breaks a core consensus invariant (miner rotation via elections)
2. Enables minority (<2/3) to override majority governance decisions
3. Can be sustained indefinitely with minimal cost
4. Affects all network participants

### Likelihood Explanation

**Attacker Capabilities**: Miners control their own nodes and can choose whether to produce blocks during any time slot. They can communicate off-chain to coordinate timing.

**Attack Complexity**: LOW
1. Monitor blockchain timestamp to identify when current round will cross the term boundary
2. Calculate: `(current_time - blockchain_start) / period_seconds` to determine term transition point
3. Coordinate 40%+ of miners to abstain from mining after the boundary
4. Repeat at each subsequent term boundary

**Feasibility Conditions**:
- No special privileges required beyond being an existing miner
- No on-chain transactions needed to execute the attack (only abstention)
- Time boundaries are predictable from the `PeriodSeconds` configuration
- Round timing is observable from block timestamps

**Detection Limitations**: While network observers can detect that miners are missing time slots, this appears as normal operational variance until the pattern repeats at every term boundary. By then, the attack has already succeeded.

**Economic Rationality**: Miners facing replacement (due to poor performance or lost votes) have strong economic incentive to collude:
- Continue earning mining rewards (initially ~12.5 tokens per block, halving periodically)
- Maintain validator status and associated reputation
- Avoid loss of invested infrastructure and operational setup

**Probability Assessment**: HIGH - This attack requires only:
- 40% collusion (achievable among miners facing replacement)
- Off-chain coordination (simple messaging)
- Passive action (not mining) rather than active attacks
- No risk of slashing beyond accumulating missed slots slowly

### Recommendation

**Immediate Mitigations**:

1. **Add Minimum Participation Check**: Before allowing `NextRound`, verify that a minimum threshold of miners participated:
```
if (miners_who_mined < minimum_participation_threshold) {
    return AElfConsensusBehaviour.NextTerm; // Force term change
}
```

2. **Implement Maximum Rounds Per Term**: Add state tracking of rounds within current term and force `NextTerm` after a maximum limit:
```
if (current_round - first_round_of_term > MAX_ROUNDS_PER_TERM) {
    return AElfConsensusBehaviour.NextTerm;
}
```

3. **Include Extra Block Producer in Term Check**: Modify `NeedToChangeTerm()` to consider the extra block producer's current mining time:
```
// Add extra block producer's timestamp to evaluation before checking threshold
var count = /* existing count */ + (IsTimeToChangeTerm(Context.CurrentBlockTime) ? 1 : 0);
return count >= MinersCountOfConsent;
```

4. **Lower Missed Slot Penalty Threshold**: Reduce the evil miner threshold from 4,320 slots to a smaller value that would catch this attack pattern within one term period.

**Long-term Solutions**:
- Implement sliding window for term changes that doesn't rely solely on single-round participation
- Add governance mechanism to force term transitions via on-chain proposal
- Enhance monitoring to detect coordinated non-participation patterns

**Test Cases**:
- Verify term change occurs when time boundary crossed even with minimum participation
- Test that maximum rounds per term limit is enforced
- Confirm evil miner detection triggers for strategic abstention patterns

### Proof of Concept

**Initial State**:
- 10 active miners in current term
- `MinersCountOfConsent = (10 * 2 / 3) + 1 = 7`
- `PeriodSeconds = 604800` (7 days)
- Current term number: 1
- Election has selected 5 new miners to replace 5 incumbent miners in next term
- Blockchain timestamp approaching 7-day boundary

**Attack Sequence**:

1. **T = Day 6.9**: Round N begins before term boundary
   - All 10 miners mine normally
   - Round continues across the 7-day boundary

2. **T = Day 7.0**: Term boundary crossed during round N
   - 6 non-colluding miners mine after boundary (their `ActualMiningTimes.Last()` crosses boundary)
   - 4 colluding miners (who would be replaced) refuse to mine after boundary
   - Their last `ActualMiningTimes` remain before the boundary

3. **T = Day 7.1**: Extra block producer (any of the 10) prepares to terminate round N
   - Calls `GetConsensusBehaviour()` → `GetConsensusBehaviourToTerminateCurrentRound()`
   - Evaluates `NeedToChangeTerm(start_timestamp, 1, 604800)`
   - Counts miners with `ActualMiningTimes` crossing boundary: **6**
   - Check: `6 < 7` → returns **false**
   - Returns `AElfConsensusBehaviour.NextRound` instead of `NextTerm`

4. **Result**: 
   - `ProcessNextRound()` is called, not `ProcessNextTerm()`
   - Same 10 miners continue in round N+1
   - Election results ignored; 5 newly elected miners cannot join
   - Term number remains 1; no miner list update occurs

5. **T = Day 14.0**: Attack repeats at next term boundary
   - Same 4 miners abstain during boundary crossing
   - Term transition fails again
   - Mining monopoly maintained indefinitely

**Expected vs Actual**:
- **Expected**: `NextTerm` triggered, miner list updated from election results
- **Actual**: `NextRound` triggered, same miners continue, elections nullified

**Success Condition**: Colluding miners successfully prevent term change and maintain their positions despite losing elections, demonstrating complete bypass of the governance mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-196)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-256)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }

        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;

        newRound.BlockchainAge = GetBlockchainAge();

        if (newRound.RealTimeMinersInformation.ContainsKey(senderPubkey))
            newRound.RealTimeMinersInformation[senderPubkey].ProducedBlocks = 1;
        else
            UpdateCandidateInformation(senderPubkey, 1, 0);

        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;

        return newRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-280)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
```
