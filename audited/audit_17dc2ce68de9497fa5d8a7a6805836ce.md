### Title
Missing Bounds Validation and Null Checks in GetMaximumBlocksCount() Allow Invalid Return Values and Runtime Exceptions

### Summary
The `GetMaximumBlocksCount()` function lacks critical safeguards in its Abnormal blockchain status path, allowing three distinct failure modes: (1) null reference exceptions when accessing uninitialized `MinedMinerListMap` entries, (2) division by zero when the miner count is zero, and (3) returning 0 which violates the documented minimum of 1. These failures can cause consensus disruption, halting block production or impairing tiny block generation during network degradation scenarios.

### Finding Description

The vulnerability exists in the Abnormal blockchain status calculation path. [1](#0-0) 

**Root Cause 1 - Null Reference Exception:**
Lines 44-45 directly access `.Pubkeys` on `MinedMinerListMap` entries without null checks. The `MinedMinerListMap` is populated only during round transitions [2](#0-1)  and entries are removed after 3 rounds. During early rounds (rounds 1-2) or if round transitions fail to record entries, accessing `State.MinedMinerListMap[currentRoundNumber.Sub(1)]` or `State.MinedMinerListMap[currentRoundNumber.Sub(2)]` will return null, causing a `NullReferenceException` when `.Pubkeys` is accessed.

**Root Cause 2 - Division by Zero:**
The `Ceiling` helper function performs division without checking if the denominator is zero. [3](#0-2)  If `currentRound.RealTimeMinersInformation.Count` is 0, line 52's call to `Ceiling(factor, currentRound.RealTimeMinersInformation.Count)` will throw a `DivideByZeroException`.

**Root Cause 3 - Invalid Zero Return Value:**
When `minersOfLastTwoRounds` is 0 (no common miners between the last two rounds), the `factor` becomes 0. `Ceiling(0, any_positive_count)` returns 0, and `Math.Min(8, 0)` returns 0, violating the documented minimum return value of 1. This occurs when miner sets change completely between rounds or during unreliable miner participation.

**Why Existing Protections Fail:**
The code has no null checks before accessing map entries, no division-by-zero guards in the `Ceiling` function, and no bounds validation on the final return value. The Abnormal status check logic [4](#0-3)  determines when this path executes but provides no safety against invalid state access.

**Execution Path:**
1. Blockchain enters Abnormal status when `libRoundNumber + 2 < currentRoundNumber < libRoundNumber + SevereStatusRoundsThreshold`
2. `GetMaximumBlocksCount()` is called via public method [5](#0-4)  or during consensus command generation [6](#0-5) 
3. Function attempts to read `MinedMinerListMap` entries that may be null or calculates with zero miners
4. Runtime exception occurs or invalid value (0) is returned

### Impact Explanation

**Operational Impact - Consensus Disruption:**

1. **Null Reference Exception Impact:** When the exception occurs, the calling transaction fails, preventing miners from obtaining consensus commands. This halts block production entirely until the blockchain state recovers, causing a complete consensus DoS. Affected parties include all network participants as no new blocks can be produced.

2. **Division by Zero Impact:** Similar to null reference, this causes immediate transaction failure and consensus command generation failure, halting block production. While `RealTimeMinersInformation.Count == 0` is unlikely in normal operation, corrupted state or initialization errors could trigger this.

3. **Zero Return Value Impact:** When `GetMaximumBlocksCount()` returns 0, miners cannot produce tiny blocks properly. In the consensus behavior provider [7](#0-6) , the check `if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)` becomes `if (count < 0)`, which is always false. This prevents the `TinyBlock` behavior, forcing miners to terminate rounds prematurely, severely reducing blockchain throughput during the Abnormal status period when the network most needs reliable block production.

**Severity Justification:** Medium severity is appropriate because while the impact is severe (consensus disruption), it requires specific preconditions (Abnormal blockchain status, missing state entries, or miner set changes) rather than being trivially exploitable at any time. However, these conditions occur naturally during network stress, making this a realistic operational threat.

### Likelihood Explanation

**Realistic Exploitability:**

**Preconditions:**
- **Abnormal Blockchain Status:** Occurs naturally when the current round number is 3-7 rounds ahead of the last irreversible block round. This indicates the network is failing to finalize blocks quickly enough, which happens during poor network connectivity, miner downtime, or network partitions.
- **Missing Map Entries:** Can occur during the first few rounds of blockchain operation before all entries are populated, or if state is corrupted/inconsistent.
- **Zero Common Miners:** Happens when miner sets change completely between rounds, which is realistic during election cycles or when miners go offline/come online.

**Attack Complexity:** No attack is required - these are natural failure modes that occur during legitimate network operation under stress. The blockchain automatically enters Abnormal status based on LIB progression, and the vulnerable code path executes automatically.

**Feasibility Conditions:**
- No special privileges required
- Executes through standard public ACS4 consensus interface methods
- No economic cost to trigger (happens organically)
- Detection is difficult as it appears as legitimate network degradation

**Probability:** Medium-High. Networks experiencing poor connectivity or high miner churn will trigger Abnormal status regularly. Early blockchain operation (first few rounds) has higher probability of null reference issues. Zero return values are probable during any significant miner set change in Abnormal status.

### Recommendation

**Immediate Mitigations:**

1. **Add Null Checks for MinedMinerListMap Access:**
```csharp
var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)];
var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)];

if (previousRoundMinedMinerList == null || previousPreviousRoundMinedMinerList == null)
{
    Context.LogDebug(() => "MinedMinerListMap entries not found, using default maximum blocks count");
    return AEDPoSContractConstants.MaximumTinyBlocksCount;
}

var minersOfLastTwoRounds = previousRoundMinedMinerList.Pubkeys
    .Intersect(previousPreviousRoundMinedMinerList.Pubkeys).Count();
```

2. **Add Division by Zero Guard in Ceiling Function:**
```csharp
private static int Ceiling(int num1, int num2)
{
    if (num2 <= 0) return 0; // or throw exception
    var flag = num1 % num2;
    return flag == 0 ? num1.Div(num2) : num1.Div(num2).Add(1);
}
```

3. **Validate Return Value Bounds:**
```csharp
var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
    Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
// Ensure minimum of 1 as documented
count = Math.Max(1, count);
Context.LogDebug(() => $"Maximum blocks count tune to {count}");
return count;
```

**Additional Safeguards:**
- Add explicit check for `currentRound.RealTimeMinersInformation.Count > 0` before performing calculations
- Consider returning a safe default (e.g., 1) instead of 0 when calculations fail
- Add defensive logging for all edge cases

**Test Cases to Prevent Regression:**
1. Test `GetMaximumBlocksCount()` during rounds 1-3 when `MinedMinerListMap` is sparsely populated
2. Test with completely disjoint miner sets between consecutive rounds
3. Test with mock corrupted state where `RealTimeMinersInformation` is empty
4. Test all three blockchain mining statuses (Normal, Abnormal, Severe) with edge case miner counts
5. Verify return value is always in range [1, 8]

### Proof of Concept

**Scenario 1 - Null Reference Exception:**

**Initial State:**
- Blockchain at round 3
- LIB at round 0 (early blockchain operation)
- `MinedMinerListMap` has no entries yet (round transitions haven't been processed properly)
- Current round number: 3, LIB round number: 0

**Execution Steps:**
1. Blockchain status evaluates to Abnormal: `0 + 2 < 3 < 0 + 8` ✓
2. Miner calls `GetConsensusCommand()` which invokes `GetMaximumBlocksCount()`
3. Code reaches line 44: `State.MinedMinerListMap[3 - 1].Pubkeys`
4. `State.MinedMinerListMap[2]` returns null (entry doesn't exist)
5. Accessing `.Pubkeys` on null throws `NullReferenceException`

**Expected Result:** Function should handle missing entries gracefully and return a safe default value.

**Actual Result:** Transaction fails with `NullReferenceException`, halting consensus command generation.

---

**Scenario 2 - Invalid Zero Return Value:**

**Initial State:**
- Blockchain at round 5
- LIB at round 2
- Previous round (4) had miners: {A, B, C}
- Previous-previous round (3) had miners: {D, E, F}
- No common miners between rounds 3 and 4

**Execution Steps:**
1. Blockchain status evaluates to Abnormal: `2 + 2 < 5 < 2 + 8` ✓
2. Miner calls `GetMaximumBlocksCount()`
3. `minersOfLastTwoRounds = {A,B,C}.Intersect({D,E,F}).Count() = 0`
4. `factor = 0 * (8 - (5 - 2)) = 0`
5. `Ceiling(0, 17) = 0`
6. `Math.Min(8, 0) = 0`
7. Function returns 0

**Expected Result:** Function should return minimum value of 1 as documented.

**Actual Result:** Function returns 0, causing miners to fail tiny block production checks, forcing premature round termination and reduced throughput.

---

**Success Condition for Exploit:** Transaction log shows `NullReferenceException` or debug log shows "Maximum blocks count tune to 0", and subsequent consensus behavior prevents tiny block production or causes consensus failure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L12-15)
```csharp
    public override Int32Value GetMaximumBlocksCount(Empty input)
    {
        return new Int32Value { Value = GetMaximumBlocksCount() };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L223-236)
```csharp
    private void RecordMinedMinerListOfCurrentRound()
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        State.MinedMinerListMap.Set(currentRound.RoundNumber, new MinerList
        {
            Pubkeys = { currentRound.GetMinedMiners().Select(m => ByteStringHelper.FromHexString(m.Pubkey)) }
        });

        // Remove information out of date.
        var removeTargetRoundNumber = currentRound.RoundNumber.Sub(3);
        if (removeTargetRoundNumber > 0 && State.MinedMinerListMap[removeTargetRoundNumber] != null)
            State.MinedMinerListMap.Remove(removeTargetRoundNumber);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L39-46)
```csharp
        var behaviour = IsMainChain
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```
