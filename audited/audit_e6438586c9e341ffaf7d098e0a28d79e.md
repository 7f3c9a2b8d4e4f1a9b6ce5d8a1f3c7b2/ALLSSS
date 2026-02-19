### Title
Null Reference Exception in GetMaximumBlocksCount() Causes Consensus DoS During Abnormal Blockchain Status

### Summary
The `GetMaximumBlocksCount()` function accesses `MinedMinerListMap` entries without null checks, leading to a `NullReferenceException` when historical round data is missing. This exception prevents consensus operations during abnormal blockchain mining status, precisely when the chain is under stress and needs to recover from Last Irreversible Block (LIB) lag.

### Finding Description

**Exact Code Location:** [1](#0-0) 

The code directly accesses `.Pubkeys` on `MinedMinerListMap` entries without null checks:

**Root Cause:**
The `MappedState<TKey, TEntity>` indexer returns `SerializationHelper.Deserialize<TEntity>(null)` when a key doesn't exist in state: [2](#0-1) 

For protobuf message types like `MinerList`, deserialization of null returns `default(T)` which is null: [3](#0-2) 

When `State.MinedMinerListMap[currentRoundNumber.Sub(1)]` or `State.MinedMinerListMap[currentRoundNumber.Sub(2)]` returns null, accessing `.Pubkeys` throws `NullReferenceException`.

**Evidence of Known Issue:**
The codebase demonstrates defensive null checking in the same file for `MinedMinerListMap`: [4](#0-3) 

This proves developers are aware that `MinedMinerListMap` entries can be null, yet the protection is missing at lines 44-45.

**Triggering Condition:**
The vulnerable code path executes when `BlockchainMiningStatus.Abnormal` is detected: [5](#0-4) 

Abnormal status occurs when the LIB round number lags behind the current round number by 2+ rounds: [6](#0-5) 

**Execution Path:**
The function is invoked during all consensus operations: [7](#0-6) 

This affects `UpdateValue`, `NextRound`, `NextTerm`, and `TinyBlock` transactions: [8](#0-7) 

### Impact Explanation

**Operational Impact - Consensus DoS:**
- All consensus update operations (`UpdateValue`, `NextRound`, `NextTerm`, `UpdateTinyBlockInformation`) throw exceptions and fail
- Blocks cannot be produced or validated during abnormal blockchain status
- The chain cannot recover from LIB lag, creating a deadlock situation
- Affects entire network operation, not just individual miners

**Who is Affected:**
- All network participants: miners cannot produce blocks, users cannot submit transactions
- The entire blockchain halts during the most critical recovery period

**Severity Justification:**
This is **High severity** because:
1. It causes complete consensus failure during abnormal status (when the chain needs to recover)
2. No recovery mechanism exists - the exception prevents any consensus progress
3. Affects core protocol functionality, not peripheral features
4. Creates a catch-22: the chain enters abnormal status due to problems, but cannot exit because consensus operations fail

### Likelihood Explanation

**Feasible Preconditions:**
The `MinedMinerListMap` entries can be missing in several realistic scenarios:

1. **Contract Upgrade/Migration:** If the contract is upgraded from a version without `MinedMinerListMap`, historical round data won't exist even at high round numbers. The blockchain continues from round N, but `MinedMinerListMap[N-1]` and `MinedMinerListMap[N-2]` are null.

2. **Post-Deployment Initialization:** During initial deployment at a round where abnormal status can immediately trigger (e.g., if LIB is manually set or imported from another chain).

3. **State Inconsistency After Blockchain Issues:** After chain rollbacks, state corruption, or consensus failures that cause gaps in the `MinedMinerListMap` recording.

**Recording Logic:**
`MinedMinerListMap` is only populated when `NextRound` or `NextTerm` is called: [9](#0-8) 

Called from: [10](#0-9) [11](#0-10) 

If these transitions are skipped or fail, gaps appear in the historical data.

**Attack Complexity:**
No active attack needed - this is a latent vulnerability triggered by:
- Natural blockchain stress conditions (LIB lag)
- System operations (upgrades, migrations)
- Recovery from previous failures

**Probability:**
**Medium-High** - While the normal case maintains the required state, contract upgrades and blockchain stress events are not rare, making this a realistic failure mode.

### Recommendation

**Code-Level Mitigation:**
Add null checks before accessing `.Pubkeys` at lines 44-45:

```csharp
if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
{
    var previousRoundMinedMinerListEntry = State.MinedMinerListMap[currentRoundNumber.Sub(1)];
    var previousPreviousRoundMinedMinerListEntry = State.MinedMinerListMap[currentRoundNumber.Sub(2)];
    
    // Handle missing historical data gracefully
    if (previousRoundMinedMinerListEntry == null || previousPreviousRoundMinedMinerListEntry == null)
    {
        Context.LogDebug(() => "Missing historical miner list data, using default maximum blocks count");
        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
    
    var previousRoundMinedMinerList = previousRoundMinedMinerListEntry.Pubkeys;
    var previousPreviousRoundMinedMinerList = previousPreviousRoundMinedMinerListEntry.Pubkeys;
    
    var minersOfLastTwoRounds = previousRoundMinedMinerList
        .Intersect(previousPreviousRoundMinedMinerList).Count();
    // ... rest of the logic
}
```

**Invariant Checks to Add:**
1. Validate `MinedMinerListMap` entries exist before accessing in abnormal status
2. Add initialization logic to populate historical entries during contract upgrades
3. Add defensive logging when historical data is missing

**Test Cases to Prevent Regression:**
1. Test `GetMaximumBlocksCount()` with empty `MinedMinerListMap`
2. Test consensus operations immediately after contract deployment/upgrade
3. Test abnormal blockchain status with missing historical round data
4. Test state migration scenarios where `MinedMinerListMap` is partially populated

### Proof of Concept

**Required Initial State:**
1. Deploy or upgrade AEDPoS contract to a version with `MinedMinerListMap`
2. Start blockchain at round N where N ≥ 4
3. Do NOT populate `MinedMinerListMap` with historical data for rounds N-1, N-2
4. Set `ConfirmedIrreversibleBlockRoundNumber` to N-3 (triggering abnormal status condition)

**Transaction Steps:**
1. Any miner attempts to call `UpdateValue`, `NextRound`, `NextTerm`, or `UpdateTinyBlockInformation`
2. `ProcessConsensusInformation()` is invoked
3. `GetMaximumBlocksCount()` is called at line 68
4. Function reaches abnormal status branch at line 42
5. Line 44 accesses `State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys` where map entry is null
6. `NullReferenceException` is thrown

**Expected vs Actual Result:**
- **Expected:** Consensus operation completes, maximum blocks count is determined
- **Actual:** Transaction fails with `NullReferenceException`, preventing all consensus progress

**Success Condition:**
The vulnerability is confirmed if any consensus transaction fails with null reference exception when `MinedMinerListMap` entries for recent rounds are missing during abnormal blockchain status.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L42-43)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L44-47)
```csharp
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
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

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L26-37)
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
        }
```

**File:** src/AElf.Types/Helper/SerializationHelper.cs (L88-91)
```csharp
        public static T Deserialize<T>(byte[] bytes)
        {
            if (bytes == null)
                return default;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L35-53)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
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
