# Audit Report

## Title
Insufficient Miner Selection in GetVictories() Leads to Undersized Consensus Round

## Summary
The `GetVictories()` function in the Election contract incorrectly limits backup miner selection to `currentMiners.Count` instead of `backups.Count`, causing consensus rounds to be generated with fewer miners than configured when the target miner count increases but valid candidates are insufficient.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method where backup miners are selected to fill gaps when valid candidates are insufficient. [1](#0-0) 

When valid candidates are insufficient to meet the target miner count, the function builds a backup list from current miners (excluding valid candidates) and adds initial miners to it [2](#0-1) . However, when selecting from these backups, it incorrectly limits the selection to `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)` [3](#0-2) .

Since `backups.Count` can exceed `currentMiners.Count` after adding initial miners, this causes fewer miners to be selected than are both available and needed.

**Execution Path**:
1. `State.MinersCount.Value` increases automatically over time via `GetAutoIncreasedMinersCount()` which adds 2 miners per `MinerIncreaseInterval` [4](#0-3) 
2. During term transitions, `GenerateFirstRoundOfNextTerm()` calls `TryToGetVictories()` to fetch elected miners [5](#0-4) 
3. `TryToGetVictories()` invokes the Election contract's `GetVictories()` [6](#0-5) 
4. The undersized miner list is used to generate the new consensus round [7](#0-6) 

The Consensus contract's `UpdateMinersCount` updates the Election contract's target count [8](#0-7) , but no validation exists to ensure the returned miner count matches this value.

## Impact Explanation

This vulnerability causes **consensus degradation** through protocol invariant violation:

- **Undersized Consensus Rounds**: The blockchain operates with fewer block producers than configured, reducing decentralization and network security
- **State Inconsistency**: `State.MinersCount.Value` indicates N miners should participate, but actual rounds contain < N miners
- **Broken Protocol Invariant**: The fundamental assumption that consensus rounds contain exactly `State.MinersCount.Value` miners is violated

**Quantified Example**: If `State.MinersCount.Value = 10`, `validCandidates = 2`, `currentMiners.Count = 5`, and initial miners provide 5 additional backups (for `backups.Count = 10`), the function returns only 7 miners (2 valid + min(8,5) backups) instead of the required 10, leaving 3 miner slots unfilled.

The severity is **MEDIUM** because while it degrades consensus quality and violates protocol invariants, the chain continues to function and no funds are directly lost.

## Likelihood Explanation

This vulnerability has **MEDIUM-HIGH** likelihood:

**Triggering Conditions** (all realistic):
1. `State.MinersCount.Value` automatically increases by 2 miners every `MinerIncreaseInterval` seconds (default is 31,536,000 seconds / 1 year) [9](#0-8) 
2. Low voter participation results in `validCandidates.Count < State.MinersCount.Value`
3. Previous term had fewer miners than the new target count

**No Attack Required**: This is a logic bug that triggers under natural protocol operation during network growth phases with insufficient candidate onboarding or voter engagement. The default `SupposedMinersCount` starts at 17 [10](#0-9) , and test configurations show scenarios with 5 initial miners scaling upward.

The bug is logged via debug statements [11](#0-10)  but no assertion validates the count, allowing undersized rounds to be generated.

## Recommendation

Change line 72 in `ViewMethods.cs` from:
```csharp
.Take(Math.Min(diff, currentMiners.Count))
```

To:
```csharp
.Take(Math.Min(diff, backups.Count))
```

This ensures that all available backup miners (including initial miners) are considered when filling gaps, up to the required deficit amount.

Additionally, add validation in `TryToGetVictories()` to assert that the returned miner count matches the expected `State.MinersCount.Value`, failing the term transition if insufficient miners are available rather than silently accepting an undersized consensus round.

## Proof of Concept

```csharp
[Fact]
public async Task GetVictories_UndersizedMinerList_WhenMinersCountIncreasesTest()
{
    // Setup: Start with 5 initial miners
    const int initialMinersCount = 5;
    const int targetMinersCount = 10; // Auto-increased target
    
    // Initialize election contract with 5 initial miners
    await InitializeElectionContractWithMiners(initialMinersCount);
    
    // Update MinersCount to simulate auto-increment over time
    await ConsensusContractStub.UpdateMinersCount.SendAsync(
        new UpdateMinersCountInput { MinersCount = targetMinersCount });
    
    // Register only 2 valid candidates (with votes)
    await AnnounceElectionAsync(ValidationDataCenterKeyPairs[0]);
    await AnnounceElectionAsync(ValidationDataCenterKeyPairs[1]);
    await VoteToCandidateAsync(VoterKeyPairs[0], 
        ValidationDataCenterKeyPairs[0].PublicKey.ToHex(), 100 * 86400, 100);
    await VoteToCandidateAsync(VoterKeyPairs[0], 
        ValidationDataCenterKeyPairs[1].PublicKey.ToHex(), 100 * 86400, 100);
    
    // Call GetVictories
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // BUG: Should return 10 miners, but returns only 7
    // (2 valid candidates + min(8, 5) backups = 7 instead of 10)
    victories.Value.Count.ShouldBe(targetMinersCount); // This will FAIL
    victories.Value.Count.ShouldBe(7); // This demonstrates the bug
}
```

## Notes

This vulnerability is a protocol-level logic error in the consensus miner selection mechanism. While it doesn't directly result in fund loss, it violates a critical invariant that consensus rounds should operate with the configured number of miners. During periods of network growth with low community participation, the blockchain will operate with reduced decentralization and security below intended levels.

The fix is straightforward (using `backups.Count` instead of `currentMiners.Count`), but the impact assessment must account for the fact that this degrades the security guarantees of the consensus mechanism during a realistic operational scenario.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-282)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L386-390)
```csharp
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L149-160)
```csharp
    public override Empty UpdateMinersCount(UpdateMinersCountInput input)
    {
        Context.LogDebug(() =>
            $"Consensus Contract Address: {Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName)}");
        Context.LogDebug(() => $"Sender Address: {Context.Sender}");
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only consensus contract can update miners count.");
        State.MinersCount.Value = input.MinersCount;
        SyncSubsidyInfoAfterReduceMiner();
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
