# Audit Report

## Title
Null Reference Exception in GetMaximumBlocksCount() Causes Consensus DoS During Abnormal Blockchain Status

## Summary
The `GetMaximumBlocksCount()` function in the AEDPoS consensus contract accesses `MinedMinerListMap` entries without null validation, causing `NullReferenceException` when historical round data is missing. This creates a consensus deadlock during abnormal blockchain status when the Last Irreversible Block (LIB) lags behind, preventing the chain from recovering.

## Finding Description

The vulnerability exists in the abnormal status handling path where the code directly dereferences `MinedMinerListMap` entries without checking for null: [1](#0-0) 

The root cause stems from how `MappedState` handles missing keys. When a key doesn't exist in state storage, the indexer returns the result of deserializing null: [2](#0-1) 

The serialization helper returns `default(T)` for null input, which is `null` for reference types like `MinerList`: [3](#0-2) 

**Evidence of Developer Awareness:**

The codebase demonstrates that developers are aware `MinedMinerListMap` can return null, as evidenced by defensive null checking elsewhere in the same contract: [4](#0-3) 

**Triggering Conditions:**

The vulnerable code executes when `BlockchainMiningStatus.Abnormal` is detected, which occurs when the LIB round lags by 2+ rounds: [5](#0-4) [6](#0-5) 

**Execution Path:**

All consensus operations invoke `GetMaximumBlocksCount()` through the common processing pipeline: [7](#0-6) 

This affects all consensus transactions including `UpdateValue`, `NextRound`, `NextTerm`, and `TinyBlock`: [8](#0-7) 

The function is also called from the ACS4 consensus command interface: [9](#0-8) 

**Why Historical Data Can Be Missing:**

`MinedMinerListMap` is only populated during round transitions: [10](#0-9) 

This recording occurs in `ProcessNextRound` and `ProcessNextTerm`: [11](#0-10) [12](#0-11) 

The state definition confirms `MinedMinerListMap` is a mapped state that can have missing entries: [13](#0-12) 

## Impact Explanation

**Severity: High**

This vulnerability causes complete consensus system failure during abnormal blockchain status:

1. **Consensus DoS**: All consensus operations (`UpdateValue`, `NextRound`, `NextTerm`, `UpdateTinyBlockInformation`) throw `NullReferenceException` and fail to execute

2. **Chain Deadlock**: The blockchain cannot produce new blocks or process transactions when abnormal status is detected - precisely when recovery mechanisms are most needed

3. **No Recovery Path**: The exception prevents any consensus progress, creating a catch-22 where the chain enters abnormal status due to LIB lag but cannot execute the consensus operations needed to recover from that state

4. **Network-Wide Impact**: All miners are affected simultaneously, halting the entire network rather than impacting individual nodes

This breaks the fundamental security guarantee that the consensus mechanism can recover from temporary network issues and LIB lag.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability can be triggered in realistic operational scenarios:

**1. Contract Upgrade Scenario (Most Critical):**
- When the consensus contract is upgraded from a version without `MinedMinerListMap` tracking, all historical round data is missing
- Even at round 1000, accessing `MinedMinerListMap[999]` and `MinedMinerListMap[998]` returns null
- If the network experiences any LIB lag after upgrade, abnormal status triggers immediately
- Contract upgrades are standard blockchain maintenance operations

**2. Early Chain Operation:**
- During initial rounds after deployment, if LIB lag occurs before sufficient rounds have recorded their data
- Example: At round 4 with LIB at round 1, abnormal status triggers but historical data may be incomplete

**3. State Gaps from Failed Transitions:**
- If `NextRound` or `NextTerm` transactions fail or are skipped for any reason
- After blockchain rollbacks or state recovery operations
- Results in gaps in the `MinedMinerListMap` recording

**No Active Attack Required:**
- This is a latent vulnerability triggered by normal operational conditions
- LIB lag occurs naturally during network stress, validator downtime, or connectivity issues
- No malicious actor needed - the bug activates during the chain's attempt to handle stress

The combination of contract upgrades (common) and LIB lag (periodic during stress) makes this a realistic failure mode with significant probability of occurrence.

## Recommendation

Add null checks before accessing `MinedMinerListMap` entries in the abnormal status handling path:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)];
    var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)];
    
    // Add null checks
    if (previousRoundMinedMinerList == null || previousPreviousRoundMinedMinerList == null)
    {
        // Fallback: Return default maximum blocks count when historical data is missing
        Context.LogDebug(() => "MinedMinerListMap missing for recent rounds, using default maximum blocks count");
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    var minersOfLastTwoRounds = previousRoundMinedMinerList.Pubkeys
        .Intersect(previousPreviousRoundMinedMinerList.Pubkeys).Count();
    // ... rest of the calculation
}
```

This follows the same defensive pattern already used elsewhere in the codebase and ensures consensus operations can continue even when historical data is incomplete.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Initialize a consensus contract at a high round number (simulating post-upgrade state)
2. Configure the chain to enter abnormal status (set LIB to be 3 rounds behind current round)
3. Attempt to call any consensus operation (`UpdateValue`, `NextRound`, etc.)
4. Observe `NullReferenceException` when `GetMaximumBlocksCount()` attempts to access `MinedMinerListMap` entries that were never populated

The test would verify that:
- The abnormal status is correctly detected
- The code path reaches lines 44-45
- `MinedMinerListMap[currentRound-1]` returns null
- Accessing `.Pubkeys` throws `NullReferenceException`
- The consensus transaction fails completely

**Notes**

This vulnerability is particularly insidious because it creates a failure mode during exactly the conditions when the consensus mechanism needs to function correctly - when the chain is under stress and attempting to recover from LIB lag. The missing null checks, combined with the state initialization gaps that can occur during contract upgrades, create a realistic scenario for complete consensus failure with no recovery mechanism.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-125)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L26-36)
```csharp
    public TEntity this[TKey key]
    {
        get
        {
            if (!Cache.TryGetValue(key, out var valuePair))
            {
                valuePair = LoadKey(key);
                Cache[key] = valuePair;
            }

            return valuePair.IsDeleted ? SerializationHelper.Deserialize<TEntity>(null) : valuePair.Value;
```

**File:** src/AElf.Types/Helper/SerializationHelper.cs (L88-91)
```csharp
        public static T Deserialize<T>(byte[] bytes)
        {
            if (bytes == null)
                return default;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L35-52)
```csharp
        switch (input)
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
            case NextTermInput nextTermInput:
                randomNumber = nextTermInput.RandomNumber;
                ProcessNextTerm(nextTermInput);
                break;
            case UpdateValueInput updateValueInput:
                randomNumber = updateValueInput.RandomNumber;
                ProcessUpdateValue(updateValueInput);
                break;
            case TinyBlockInput tinyBlockInput:
                randomNumber = tinyBlockInput.RandomNumber;
                ProcessTinyBlock(tinyBlockInput);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-68)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-112)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-165)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L40-46)
```csharp
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L46-46)
```csharp
    public MappedState<long, MinerList> MinedMinerListMap { get; set; }
```
