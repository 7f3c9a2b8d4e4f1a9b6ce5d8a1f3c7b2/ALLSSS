# Audit Report

## Title
Byzantine Minority Can Prevent Term Transitions by Coordinated Mining Abstention

## Summary
A minority coalition of miners (≥40% but <67%) can indefinitely prevent term transitions in the AEDPoS consensus by strategically abstaining from mining during rounds that cross term boundaries. This causes the consensus to use `NextRound` instead of `NextTerm`, preventing newly elected miners from joining and breaking the governance-based miner rotation mechanism.

## Finding Description

The vulnerability exists in the term transition decision logic within the AEDPoS consensus contract. The decision between `NextRound` and `NextTerm` behavior relies on `NeedToChangeTerm()`, which counts how many miners have `ActualMiningTimes` timestamps that cross the term boundary. [1](#0-0) 

The method compares this count against `MinersCountOfConsent`, calculated as two-thirds plus one: [2](#0-1) [3](#0-2) 

**Root Cause**: The critical timing issue occurs because the extra block producer's `ActualMiningTime` is added to the NEXT round, not the current round being evaluated: [4](#0-3) 

When `GetConsensusBehaviourToTerminateCurrentRound()` evaluates `NeedToChangeTerm()`, it examines the current round state WITHOUT the extra block producer's contribution (whose timestamp gets added to the next round at lines 195-196).

**Attack Scenario**: With 10 miners where `MinersCountOfConsent = 7`:
1. Four miners (40%) coordinate to abstain from mining after the term boundary timestamp
2. Six honest miners continue mining normally
3. When the extra block producer requests consensus behavior, only 5 honest miners have already recorded `ActualMiningTimes` crossing the boundary
4. Since `5 < 7`, `NeedToChangeTerm()` returns false
5. The extra block producer uses `NextRound` instead of `NextTerm`
6. Same miners continue; newly elected miners never join

**Why Detection Fails**: The evil miner detection mechanism requires 4,320 missed time slots (approximately 3 days): [5](#0-4) 

Colluding miners only need to abstain strategically at each term boundary (e.g., missing a few rounds every 7 days), staying far below this detection threshold.

## Impact Explanation

This vulnerability breaks the fundamental governance mechanism that connects elections to validator rotation. When `NextTerm` is properly triggered, it calls `GenerateFirstRoundOfNextTerm()` which fetches newly elected miners from the Election Contract: [6](#0-5) [7](#0-6) 

Without term transitions, this entire mechanism is bypassed. The impact includes:

**Critical Governance Failure**:
- User votes in elections become meaningless
- Newly elected validators can never join consensus
- Incumbent miners maintain permanent control

**Economic Impact**:
- Mining rewards continue to incumbent miners instead of elected validators [8](#0-7) 

**Centralization Risk**:
- A minority coalition (≥40%) can override the majority's governance decisions
- Violates the core AEDPoS principle that 2/3+ consensus is required for safety

**Protocol Integrity**:
- Breaks the social contract between voters and the consensus mechanism
- Undermines trust in the governance system

## Likelihood Explanation

**HIGH Likelihood** - The attack is practical and economically rational:

**Technical Feasibility**:
- Miners control their own nodes and can choose when to produce blocks
- Term boundaries are predictable from the public `PeriodSeconds` configuration
- No special privileges or on-chain transactions required (passive attack via abstention)
- Off-chain coordination between miners is trivial (messaging, forums, etc.)

**Economic Incentives**:
- Miners facing replacement have strong motivation to collude
- Continued mining rewards (initially ~12.5 tokens per block)
- Preservation of validator status and reputation
- Protection of infrastructure investments

**Attack Sustainability**:
- Only requires strategic abstention at term boundaries (e.g., every 7 days)
- Far below the 4,320 time slot evil detection threshold
- Can be sustained indefinitely with minimal operational cost
- Appears as normal network variance until pattern recognition

**Threshold Analysis**:
- Only 40% collusion needed (achievable when multiple miners face replacement)
- Lower than the 67% Byzantine threshold typically assumed secure
- Example: With 10 miners, only 4 need to coordinate

## Recommendation

Modify the term transition logic to include the extra block producer's current mining timestamp in the evaluation. The fix should record the extra block producer's `ActualMiningTime` to the current round before evaluating `NeedToChangeTerm()`, or adjust the threshold calculation to account for the extra block producer who is about to mine.

**Proposed Fix**: In `ConsensusBehaviourProviderBase.GetConsensusBehaviour()`, when determining whether to terminate the round, temporarily add the current block time to the extra block producer's `ActualMiningTimes` in the current round before calling `GetConsensusBehaviourToTerminateCurrentRound()`. This ensures the term transition decision accounts for all miners who have or will mine in the current round.

Alternatively, adjust `MinersCountOfConsent` calculation when evaluating term transitions to be `(RealTimeMinersInformation.Count - 1) * 2 / 3 + 1` to exclude the extra block producer who hasn't recorded their time yet.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize a blockchain with 10 miners and a 7-day term period
2. Advance time past the first term boundary
3. Have 4 miners strategically abstain from mining after the boundary
4. Observe that when the 6th honest miner (acting as extra block producer) evaluates the consensus behavior, only 5 miners have recorded `ActualMiningTimes`
5. Verify that `NeedToChangeTerm()` returns false (5 < 7)
6. Confirm that `NextRound` is used instead of `NextTerm`
7. Validate that newly elected miners from the election contract are not included in the new round

The test would demonstrate that the same 10 miners continue indefinitely despite new validators being elected through the governance process.

## Notes

This vulnerability is particularly concerning because:

1. **It operates at the Byzantine threshold boundary**: While AEDPoS is designed to tolerate up to 1/3 Byzantine miners, this attack only requires ~40% coordination, which is below the traditional 51% or 67% thresholds.

2. **It's a passive attack**: Unlike active attacks that require malicious transactions or blocks, this attack simply involves miners choosing not to mine during specific time windows, making it difficult to attribute or penalize.

3. **It breaks protocol liveness without violating safety**: The blockchain continues to produce blocks and process transactions, but the governance mechanism is effectively frozen.

4. **Detection is challenging**: The abstention pattern only occurs at term boundaries (e.g., every 7 days), making it appear as normal network variance rather than coordinated attack behavior.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L7-7)
```csharp
    public const long InitialMiningRewardPerBlock = 12500000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-232)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
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
        };
        return victories.Pubkeys.Any();
    }
```
