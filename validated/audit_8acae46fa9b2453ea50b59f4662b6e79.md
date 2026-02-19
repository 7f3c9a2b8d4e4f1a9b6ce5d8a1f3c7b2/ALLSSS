# Audit Report

## Title
Insufficient Miner Selection in GetVictories() Leads to Undersized Consensus Round

## Summary
The `GetVictories()` function in the Election contract incorrectly limits backup miner selection to `currentMiners.Count` instead of `backups.Count`, causing consensus rounds to be generated with fewer miners than configured when the target miner count increases but valid candidates are insufficient.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method [1](#0-0) . 

When valid candidates are insufficient to meet the target miner count, the function builds a backup list from current miners (excluding valid candidates) and adds initial miners to it [2](#0-1) . However, when selecting from these backups, it incorrectly limits the selection to `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)` [3](#0-2) .

Since `backups.Count` can exceed `currentMiners.Count` (after adding initial miners), this causes fewer miners to be selected than available and needed.

**Execution Path**:
1. `State.MinersCount.Value` increases automatically over time via `GetAutoIncreasedMinersCount()` which adds 2 miners per `MinerIncreaseInterval` [4](#0-3) 
2. During term transitions, `GenerateFirstRoundOfNextTerm()` calls `TryToGetVictories()` to fetch elected miners [5](#0-4) 
3. `TryToGetVictories()` invokes the Election contract's `GetVictories()` [6](#0-5) 
4. The undersized miner list is used to generate the new consensus round [7](#0-6) 

No validation exists to ensure the returned miner count matches `State.MinersCount.Value`.

## Impact Explanation

This vulnerability causes **consensus degradation** through protocol invariant violation:

- **Undersized Consensus Rounds**: The blockchain operates with fewer block producers than configured, reducing decentralization and network security
- **State Inconsistency**: `State.MinersCount.Value` indicates N miners should participate, but actual rounds contain < N miners
- **Broken Protocol Invariant**: The fundamental assumption that consensus rounds contain exactly `State.MinersCount.Value` miners is violated

**Quantified Example**: If `State.MinersCount.Value = 10`, `validCandidates = 2`, `currentMiners.Count = 5`, and initial miners provide 5 additional backups, the function returns only 7 miners (2 valid + min(8,5) backups) instead of the required 10, leaving 3 miner slots unfilled.

The severity is **MEDIUM** because while it degrades consensus quality and violates protocol invariants, the chain continues to function and no funds are directly lost.

## Likelihood Explanation

This vulnerability has **MEDIUM-HIGH** likelihood:

**Triggering Conditions** (all realistic):
1. `State.MinersCount.Value` automatically increases by 2 miners every `MinerIncreaseInterval` seconds [8](#0-7) 
2. Low voter participation results in `validCandidates.Count < State.MinersCount.Value`
3. Previous term had fewer miners than the new target count

**No Attack Required**: This is a logic bug that triggers under natural protocol operation during network growth phases with insufficient candidate onboarding or voter engagement. The default `SupposedMinersCount` starts at 17 [9](#0-8) , and test configurations show scenarios with 5 initial miners scaling upward.

The bug is logged but not prevented - debug statements show the incorrect count but no assertion validates it.

## Recommendation

Change line 72 in `contract/AElf.Contracts.Election/ViewMethods.cs` from:
```csharp
.Take(Math.Min(diff, currentMiners.Count))
```

To:
```csharp
.Take(Math.Min(diff, backups.Count))
```

This ensures all available backup miners are utilized up to the needed amount, rather than being artificially limited by the previous term's miner count.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set `MinersCount.Value` to 10
2. Create only 2 valid candidates (with votes)
3. Set current miners to 5
4. Provide 8+ initial miners as backups
5. Call `GetVictories()` and verify it returns only 7 miners instead of 10
6. Assert that `victories.Count < State.MinersCount.Value`, proving the invariant violation

The existing test `ElectionContract_GetVictories_ValidCandidatesNotEnough_Test` [10](#0-9)  validates the backup mechanism but doesn't catch this specific bug because it doesn't test scenarios where `backups.Count > currentMiners.Count`.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** test/AElf.Contracts.Election.Tests/GQL/ElectionTests.cs (L404-444)
```csharp
    public async Task<List<string>> ElectionContract_GetVictories_ValidCandidatesNotEnough_Test()
    {
        const int amount = 100;

        await NextRound(BootMinerKeyPair);

        foreach (var keyPair in ValidationDataCenterKeyPairs) await AnnounceElectionAsync(keyPair);

        var candidates = (await ElectionContractStub.GetCandidates.CallAsync(new Empty())).Value;
        foreach (var fullNodesKeyPair in ValidationDataCenterKeyPairs)
            candidates.ShouldContain(ByteString.CopyFrom(fullNodesKeyPair.PublicKey));

        var validCandidates = ValidationDataCenterKeyPairs
            .Take(EconomicContractsTestConstants.InitialCoreDataCenterCount - 1).ToList();
        foreach (var keyPair in validCandidates)
            await VoteToCandidateAsync(VoterKeyPairs[0], keyPair.PublicKey.ToHex(), 100 * 86400, amount);

        foreach (var votedFullNodeKeyPair in ValidationDataCenterKeyPairs.Take(EconomicContractsTestConstants
                     .InitialCoreDataCenterCount - 1))
        {
            var votes = await ElectionContractStub.GetCandidateVote.CallAsync(new StringValue
                { Value = votedFullNodeKeyPair.PublicKey.ToHex() });
            votes.ObtainedActiveVotedVotesAmount.ShouldBe(amount);
        }

        foreach (var votedFullNodeKeyPair in ValidationDataCenterKeyPairs.Skip(EconomicContractsTestConstants
                     .InitialCoreDataCenterCount - 1))
        {
            var votes = await ElectionContractStub.GetCandidateVote.CallAsync(new StringValue
                { Value = votedFullNodeKeyPair.PublicKey.ToHex() });
            votes.ObtainedActiveVotedVotesAmount.ShouldBe(0);
        }

        var victories = (await ElectionContractStub.GetVictories.CallAsync(new Empty())).Value
            .Select(p => p.ToHex()).ToList();

        // Victories should contain all valid candidates.
        foreach (var validCandidate in validCandidates) victories.ShouldContain(validCandidate.PublicKey.ToHex());

        return victories;
    }
```
