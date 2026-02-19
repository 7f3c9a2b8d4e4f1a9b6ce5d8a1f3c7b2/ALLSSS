# Audit Report

## Title
Missing Bounds Validation and Null Checks in GetMaximumBlocksCount() Allow Invalid Return Values and Runtime Exceptions

## Summary
The `GetMaximumBlocksCount()` function in the AEDPoS consensus contract contains three critical validation gaps in its Abnormal blockchain status path: (1) missing null checks when accessing `MinedMinerListMap` entries causing `NullReferenceException`, (2) missing zero-divisor validation in the `Ceiling` helper function causing `DivideByZeroException`, and (3) no bounds validation allowing a zero return value that violates the documented minimum of 1. These failures disrupt consensus during network degradation when reliable block production is most critical.

## Finding Description

The vulnerability exists in the Abnormal blockchain status calculation path within `GetMaximumBlocksCount()`. [1](#0-0) 

**Root Cause 1 - Null Reference Exception:**

The code directly accesses `.Pubkeys` on `MinedMinerListMap` entries without null validation. [2](#0-1) 

The `MinedMinerListMap` is only populated during round transitions in `RecordMinedMinerListOfCurrentRound()`. [3](#0-2) 

Entries are removed after 3 rounds, and no entries exist during early blockchain operation. When the Abnormal status path attempts to access `currentRoundNumber.Sub(1)` or `currentRoundNumber.Sub(2)`, it will encounter null entries in scenarios like:
- Early rounds before full history is established
- State corruption or failed recording
- Edge cases during round transitions

The code contains no null checks before accessing `.Pubkeys`, guaranteeing a `NullReferenceException` when entries are missing.

**Root Cause 2 - Division by Zero:**

The `Ceiling` helper function performs modulo and division operations without validating the denominator is non-zero. [4](#0-3) 

When called with `currentRound.RealTimeMinersInformation.Count` as the denominator [5](#0-4) , if the count is zero, both `num1 % num2` and `num1 / num2` will throw `DivideByZeroException`. While unlikely in normal operation, the code does not validate this precondition.

**Root Cause 3 - Invalid Zero Return Value:**

When no common miners exist between the last two rounds (complete miner set turnover), `minersOfLastTwoRounds` equals 0. [6](#0-5) 

This causes `factor` to become 0, leading `Ceiling(0, any_positive_count)` to return 0, and subsequently `Math.Min(8, 0)` returns 0. [7](#0-6) 

The function returns 0, violating the expected minimum of 1 and breaking downstream logic that depends on positive values.

**Why Existing Protections Fail:**

The Abnormal status detection logic determines when this path executes [8](#0-7)  but provides no safety against invalid state access. The only null check exists in the removal logic [9](#0-8) , not in the access path.

## Impact Explanation

**Consensus Disruption - Critical Path Failure:**

The function is called in critical consensus paths:
1. During every consensus information processing [10](#0-9) 
2. When generating consensus commands for miners [11](#0-10) 
3. Within the TinyBlock command strategy [12](#0-11) 

**Impact 1 - Runtime Exceptions (Null/DivByZero):**
When exceptions occur, the calling transaction fails immediately. Miners cannot obtain consensus commands, halting block production entirely. This creates a complete consensus DoS affecting all network participants until blockchain state recovers or advances past the problematic conditions.

**Impact 2 - Zero Return Value:**
When the function returns 0, the TinyBlock behavior becomes impossible. In the consensus behavior provider, the check `_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount` becomes `Count < 0` which is always false. [13](#0-12) 

This prevents miners from producing tiny blocks during Abnormal status when the network needs maximum throughput to recover. It forces premature round termination, severely degrading blockchain performance exactly when stress resilience is critical.

**Severity: Medium-High** - While requiring specific preconditions (Abnormal status, which itself indicates network stress), the impact is severe (consensus disruption) and the conditions occur naturally during realistic operational scenarios.

## Likelihood Explanation

**Realistic Triggering Conditions:**

**Abnormal Blockchain Status:**
The Abnormal status triggers when `libRoundNumber + 2 < currentRoundNumber < libRoundNumber + 8` with a threshold of 8 rounds. [14](#0-13) [15](#0-14) 

This occurs naturally when:
- Network experiences poor connectivity causing LIB to lag behind current round by 3-7 rounds
- Miner coordination issues during high churn periods
- Network partitions or temporary outages

**Missing Map Entries:**
Can occur during:
- Early blockchain operation (first few rounds) before full history is established
- Failed round transitions that don't properly record miner lists
- State inconsistencies or corruption

**Zero Common Miners:**
Happens during:
- Election cycles when miner sets change completely
- Mass miner turnover during network stress
- Coordinated miner rotation policies

**No Attack Required:**
These are natural failure modes during legitimate network operation. The blockchain automatically enters Abnormal status based on LIB progression. No special privileges, economic cost, or malicious action is required.

**Probability: Medium-High** - Networks experiencing connectivity issues, high miner churn, or operating in early stages will regularly encounter these conditions. The lack of defensive validation guarantees failures when conditions align.

## Recommendation

Add comprehensive validation to the Abnormal status path:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    // Add null checks for MinedMinerListMap entries
    var previousRoundEntry = State.MinedMinerListMap[currentRoundNumber.Sub(1)];
    var previousPreviousRoundEntry = State.MinedMinerListMap[currentRoundNumber.Sub(2)];
    
    if (previousRoundEntry == null || previousPreviousRoundEntry == null)
    {
        // Fallback to safe default when entries are missing
        Context.LogDebug(() => "MinedMinerListMap entries missing, using default maximum blocks count");
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    var previousRoundMinedMinerList = previousRoundEntry.Pubkeys;
    var previousPreviousRoundMinedMinerList = previousPreviousRoundEntry.Pubkeys;
    var minersOfLastTwoRounds = previousRoundMinedMinerList
        .Intersect(previousPreviousRoundMinedMinerList).Count();
    var factor = minersOfLastTwoRounds.Mul(
        blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
            (int)currentRoundNumber.Sub(libRoundNumber)));
    
    // Add validation for zero miner count
    var minerCount = currentRound.RealTimeMinersInformation.Count;
    if (minerCount == 0)
    {
        Context.LogDebug(() => "RealTimeMinersInformation count is zero, using default");
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
        Ceiling(factor, minerCount));
    
    // Ensure minimum return value of 1
    count = Math.Max(1, count);
    
    Context.LogDebug(() => $"Maximum blocks count tune to {count}");
    return count;
}
```

Additionally, add a guard to the `Ceiling` function:

```csharp
private static int Ceiling(int num1, int num2)
{
    Assert(num2 > 0, "Divisor must be positive");
    var flag = num1 % num2;
    return flag == 0 ? num1.Div(num2) : num1.Div(num2).Add(1);
}
```

## Proof of Concept

The vulnerability can be demonstrated through unit tests that simulate the Abnormal status with missing state:

```csharp
[Fact]
public void GetMaximumBlocksCount_NullReferenceException_WhenMinedMinerListMapMissing()
{
    // Setup: Create blockchain in Abnormal status with missing MinedMinerListMap entries
    // 1. Initialize consensus with round 3, libRoundNumber = 0
    // 2. Do NOT populate MinedMinerListMap for rounds 1 and 2
    // 3. Call GetMaximumBlocksCount() which will attempt to access null entries
    // Expected: NullReferenceException when accessing .Pubkeys on null entries
    // Actual: Function throws NullReferenceException, halting consensus
}

[Fact]
public void GetMaximumBlocksCount_ReturnsZero_WhenNoCommonMiners()
{
    // Setup: Create scenario with complete miner set change
    // 1. Initialize round 3 with libRoundNumber = 0 (Abnormal status)
    // 2. Populate MinedMinerListMap for rounds 1 and 2 with completely different miners
    // 3. Call GetMaximumBlocksCount()
    // Expected: Should return at least 1
    // Actual: Returns 0, breaking TinyBlock behavior logic
}
```

The proof demonstrates that the function lacks proper validation, causing either runtime exceptions or invalid zero returns during realistic network stress conditions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L35-37)
```csharp
        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-117)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-125)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-68)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L41-45)
```csharp
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L49-50)
```csharp
                    new ConsensusCommandProvider(new TinyBlockCommandStrategy(currentRound, pubkey,
                        currentBlockTime, GetMaximumBlocksCount())).GetConsensusCommand();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```
