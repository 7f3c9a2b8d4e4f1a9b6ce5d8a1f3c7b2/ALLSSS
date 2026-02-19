### Title
Side Chain Consensus Disruption Due to Unvalidated Zero maximumBlocksCount Parameter

### Summary
The `SideChainConsensusBehaviourProvider` constructor and `GetMaximumBlocksCount()` function lack validation to ensure `maximumBlocksCount` is at least 1. When the blockchain enters Abnormal status with zero miner overlap between the last two rounds, `maximumBlocksCount` can be set to 0, causing the base class to never return TinyBlock behavior and instead defaulting to NextRound, breaking side chain block production continuity through premature round transitions.

### Finding Description

The vulnerability exists in the consensus command generation flow for side chains:

**1. Unvalidated Constructor Parameter:**
The `SideChainConsensusBehaviourProvider` constructor accepts `maximumBlocksCount` without any validation and passes it directly to the base class. [1](#0-0) 

**2. Zero Value Can Be Computed:**
In `GetMaximumBlocksCount()`, when the blockchain is in Abnormal status, the calculation can return 0: [2](#0-1) 

The `factor` becomes 0 when `minersOfLastTwoRounds` (intersection of miners who mined in both previous rounds) equals 0. The `Ceiling` function then returns 0: [3](#0-2) 

**3. Broken TinyBlock Logic:**
With `maximumBlocksCount = 0`, the critical check in the base class becomes `ActualMiningTimes.Count < 0`, which is always false since count cannot be negative: [4](#0-3) 

The fallback check for extra block producers also fails: [5](#0-4) 

And in the new miner handling path: [6](#0-5) 

**4. Side Chain Defaults to NextRound:**
When TinyBlock is never returned, the code falls through to `GetConsensusBehaviourToTerminateCurrentRound()`, which for side chains always returns NextRound: [7](#0-6) 

### Impact Explanation

**Operational Impact on Side Chain Consensus:**
- Miners cannot produce tiny blocks during their designated time slots
- Every consensus command generation returns NextRound instead of TinyBlock
- Causes premature round transitions before miners can fill their time slots
- Breaks the intended consensus mechanism for block production continuity
- Disrupts normal side chain block production flow

**Affected Parties:**
- Side chain miners unable to produce blocks properly
- Side chain users experiencing disrupted block production
- Cross-chain operations may be delayed due to irregular block times

**Severity Justification (Medium):**
- Operational disruption to consensus continuity (not direct fund loss)
- Affects side chain stability and block production regularity
- No token theft or unauthorized governance changes
- Requires specific preconditions but has clear operational impact

### Likelihood Explanation

**Preconditions Required:**
1. Blockchain must be in Abnormal status (`libRoundNumber + 2 < currentRoundNumber < libRoundNumber + SevereStatusRoundsThreshold`)
2. Zero miner overlap between the last two rounds (`minersOfLastTwoRounds = 0`)

**Feasibility:**
- Abnormal status occurs when blockchain is already experiencing consensus issues (LIB falling behind)
- Zero miner overlap can occur when:
  - Different sets of miners participate in consecutive rounds
  - Network partitions cause inconsistent miner participation
  - Side chains with fewer miners have higher probability of non-overlapping sets
  - Malicious coordination to avoid mining in overlapping patterns

**Attack Complexity:**
- No active attack required; occurs naturally during network stress
- More likely on side chains with smaller miner sets
- Can be triggered by coordinated miner behavior during network issues

**Economic Rationality:**
- No direct attacker profit
- Could be used as part of broader DoS attack on side chain
- Low cost if miners simply avoid participation

**Detection:**
- Would be visible in consensus logs showing repeated NextRound behaviors
- Blockchain monitoring would detect abnormal round transition patterns

### Recommendation

**1. Add Input Validation:**
Add validation in `GetMaximumBlocksCount()` to ensure a minimum value of 1:

```csharp
private int GetMaximumBlocksCount()
{
    // ... existing calculation logic ...
    
    if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
    {
        var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
        var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
        var minersOfLastTwoRounds = previousRoundMinedMinerList
            .Intersect(previousPreviousRoundMinedMinerList).Count();
        var factor = minersOfLastTwoRounds.Mul(
            blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                (int)currentRoundNumber.Sub(libRoundNumber)));
        var count = Math.Max(1, Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
            Ceiling(factor, currentRound.RealTimeMinersInformation.Count)));
        Context.LogDebug(() => $"Maximum blocks count tune to {count}");
        return count;
    }
    
    // ... rest of logic ...
}
```

**2. Add Constructor Validation:**
Validate in the base class constructor:

```csharp
protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
    Timestamp currentBlockTime)
{
    Assert(maximumBlocksCount > 0, "Maximum blocks count must be positive");
    // ... rest of constructor ...
}
```

**3. Test Cases:**
- Test with `minersOfLastTwoRounds = 0` in Abnormal status
- Verify `maximumBlocksCount` is never less than 1
- Test side chain consensus behavior with edge case miner participation patterns
- Verify TinyBlock behavior is always available when in time slot

### Proof of Concept

**Initial State:**
- Side chain is operational with miner set {A, B, C, D, E}
- Current round R, LIB at round R-5 (Abnormal status: R-5 + 2 < R < R-5 + 8)
- Round R-2: Only miners {A, B, C} mined blocks
- Round R-1: Only miners {D, E} mined blocks (zero overlap)

**Execution Steps:**
1. Side chain enters Abnormal status as LIB falls behind
2. `GetMaximumBlocksCount()` is called during consensus command generation
3. Calculate `minersOfLastTwoRounds = {A,B,C}.Intersect({D,E}).Count() = 0`
4. Calculate `factor = 0 * (8 - (R - (R-5))) = 0`
5. Calculate `count = Math.Min(8, Ceiling(0, 5)) = Math.Min(8, 0) = 0`
6. Returns `maximumBlocksCount = 0`
7. Miner A tries to produce block during time slot
8. `ConsensusBehaviourProviderBase.GetConsensusBehaviour()` evaluates line 60: `ActualMiningTimes.Count < 0` → FALSE
9. Falls through to line 82: `GetConsensusBehaviourToTerminateCurrentRound()` → returns NextRound
10. Miner A cannot produce tiny blocks, immediately advances to next round

**Expected Result:**
Miner should be able to produce TinyBlock to fill time slot

**Actual Result:**
Miner gets NextRound behavior, causing premature round transition and breaking block production continuity

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L11-14)
```csharp
        public SideChainConsensusBehaviourProvider(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime) : base(currentRound, pubkey, maximumBlocksCount, currentBlockTime)
        {
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-55)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L81-85)
```csharp
    private static int Ceiling(int num1, int num2)
    {
        var flag = num1 % num2;
        return flag == 0 ? num1.Div(num2) : num1.Div(num2).Add(1);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
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
