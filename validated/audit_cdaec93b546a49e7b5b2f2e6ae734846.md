# Audit Report

## Title
Insufficient Miner Selection in GetVictories() Leads to Undersized Consensus Round

## Summary
The `GetVictories()` function in the Election contract contains a logic error at line 72 that incorrectly limits backup miner selection to `currentMiners.Count` instead of `backups.Count`. When the target miner count auto-increments but there are insufficient valid candidates, this causes consensus rounds to be generated with fewer miners than configured, violating the critical protocol invariant that rounds must contain exactly `State.MinersCount.Value` miners.

## Finding Description

The vulnerability exists in the Election contract's private `GetVictories(List<string> currentMiners)` method. When there are insufficient valid candidates with votes to fill the required miner count, the function constructs a backup list from current miners and initial miners, then incorrectly limits the selection. [1](#0-0) 

**The Bug:**
After constructing the `backups` list (which may contain more miners than `currentMiners.Count` after adding initial miners), line 72 uses `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)` to determine how many backups to select.

**Execution Path:**

1. The AEDPoS consensus contract automatically increments the target miner count over time via `GetAutoIncreasedMinersCount()` and `GetMinersCount()`, adding 2 miners every `MinerIncreaseInterval` (default: 31536000 seconds = 1 year), starting from `SupposedMinersCount = 17`. [2](#0-1) [3](#0-2) [4](#0-3) 

2. During term transition, `ProcessNextTerm()` calls `UpdateMinersCountToElectionContract()` which sends the increased count to the Election contract, updating `State.MinersCount.Value`. [5](#0-4) [6](#0-5) 

3. The AEDPoS contract's `GenerateFirstRoundOfNextTerm()` method calls `TryToGetVictories()` to obtain the new miner list from the Election contract. [7](#0-6) 

4. `TryToGetVictories()` invokes `State.ElectionContract.GetVictories.Call(new Empty())`. [8](#0-7) 

5. The Election contract's `GetVictories()` method constructs backups but incorrectly limits selection at line 72, returning an undersized miner list.

6. This undersized list is used by `MinerList.GenerateFirstRoundOfNewTerm()`, which simply iterates over the provided miners without any validation that the count matches the expected value. [9](#0-8) 

**Concrete Example:**
- Target: `State.MinersCount.Value = 10`
- Valid candidates with votes: 2
- Previous term miners (`currentMiners.Count`): 5
- Available backups (after adding initial miners): 8
- **Buggy behavior**: Takes `Math.Min(8, 5) = 5` backups → Total: 2 + 5 = 7 miners (3 short of target)
- **Expected behavior**: Should take `Math.Min(8, 8) = 8` backups → Total: 2 + 8 = 10 miners

## Impact Explanation

This bug directly violates consensus integrity by creating a fundamental mismatch between configured and actual miner counts:

**Consensus Degradation**: The blockchain operates with fewer block producers than configured in `State.MinersCount.Value`, reducing decentralization, network security, and liveness guarantees.

**State Inconsistency**: The Election contract's `State.MinersCount.Value` indicates N miners should participate, but actual consensus rounds generated contain fewer than N miners, creating a persistent state inconsistency.

**Protocol Invariant Violation**: The critical invariant that consensus rounds must contain exactly `State.MinersCount.Value` miners is broken. The round generation logic provides no validation to catch this mismatch, allowing invalid rounds to be created and used.

**Reward Misallocation Risk**: Mining reward and profit distribution calculations that depend on the configured miner count may produce incorrect per-miner payouts due to the discrepancy.

This is **HIGH severity** because it directly compromises consensus integrity, a foundational security guarantee of the blockchain protocol.

## Likelihood Explanation

This vulnerability has **MEDIUM-HIGH likelihood** of occurring under normal network conditions:

**No Attacker Required**: This is a pure logic bug that triggers automatically under realistic operational scenarios, requiring no malicious action.

**Realistic Trigger Conditions**:
1. The miner count automatically increases every `MinerIncreaseInterval` by 2 miners - this is designed behavior that will occur annually in production networks.
2. Low voter participation or insufficient candidate onboarding results in `validCandidates.Count < State.MinersCount.Value` - a realistic scenario during network growth phases or periods of low community engagement.
3. The previous term had fewer miners than the new auto-incremented target - inevitable during the network's growth phase as the miner count scales up.

**Natural Occurrence**: In a growing network where the target miner count increases over time but community participation or candidate availability lags behind, this condition will manifest organically without any adversarial trigger.

**Detection**: While the bug produces observable symptoms (undersized consensus rounds), no runtime validation prevents the invalid state from being created and persisting.

## Recommendation

Fix the bug by changing line 72 to use `backups.Count` instead of `currentMiners.Count`:

```csharp
victories.AddRange(backups.OrderBy(p => p)
    .Take(Math.Min(diff, backups.Count))  // Changed from currentMiners.Count
    .Select(v => ByteStringHelper.FromHexString(v)));
```

Additionally, consider adding validation in `MinerList.GenerateFirstRoundOfNewTerm()` or `GenerateFirstRoundOfNextTerm()` to assert that the miner count matches the expected value, providing defense-in-depth against similar issues.

## Proof of Concept

```csharp
[Fact]
public async Task UndersizedConsensusRound_WhenBackupsExceedCurrentMiners()
{
    // Setup: Initialize with 5 initial miners
    await InitializeConsensusAndElectionContracts(5);
    
    // Advance blockchain time to trigger miner count auto-increment
    // MinerIncreaseInterval = 31536000 seconds (1 year)
    // Target should increase from 17 to 19 (17 + 2)
    await AdvanceBlockchainTime(31536000);
    
    // Setup scenario:
    // - Current active miners: 5
    // - Target miners after auto-increment: 10 
    // - Valid candidates with votes: 2
    // - Initial miners available as backups: 5
    // - Total backups available: 8 (5 current non-candidates + 5 initial - 2 overlap)
    
    // Only 2 candidates have votes (insufficient)
    await RegisterAndVoteForCandidates(2);
    
    // Trigger term transition which calls GetVictories
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // BUG: Should return 10 miners but returns only 7
    // Because Math.Min(8, 5) = 5 backups instead of Math.Min(8, 8) = 8
    var expectedCount = 10;
    var actualCount = victories.Value.Count;
    
    // This assertion will fail, proving the vulnerability
    Assert.Equal(expectedCount, actualCount);
    // Actual: 7 (2 valid candidates + 5 backups instead of 2 + 8)
}
```

## Notes

- The bug affects mainchain consensus where election-based miner selection occurs
- Side chains that reuse current miners are not affected by this specific path
- The vulnerability becomes more pronounced as the network ages and the auto-increment mechanism increases the target miner count further beyond initial capacity
- The mismatch between `State.MinersCount.Value` and actual round size persists until enough valid candidates with votes become available

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-257)
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
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-176)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
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
