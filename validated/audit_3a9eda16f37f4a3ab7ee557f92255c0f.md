# Audit Report

## Title
Insufficient Miner Selection in GetVictories() Leads to Undersized Consensus Round

## Summary
The `GetVictories()` function in the Election contract incorrectly limits backup miner selection to `currentMiners.Count` instead of `backups.Count`, causing consensus rounds to be generated with fewer miners than configured when the target miner count increases but valid candidates are insufficient.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method. [1](#0-0) 

When valid candidates are insufficient to meet the target miner count, the function builds a backup list from current miners (excluding valid candidates) and adds initial miners to it. [2](#0-1) 

However, when selecting from these backups, it incorrectly limits the selection to `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)`. [3](#0-2) 

Since `backups.Count` can exceed `currentMiners.Count` after adding initial miners, this causes fewer miners to be selected than available and needed.

**Execution Path**:

1. `State.MinersCount.Value` increases automatically over time via `GetAutoIncreasedMinersCount()` which adds 2 miners per `MinerIncreaseInterval`. [4](#0-3) 

2. During term transitions, `GenerateFirstRoundOfNextTerm()` calls `TryToGetVictories()` to fetch elected miners. [5](#0-4) 

3. `TryToGetVictories()` invokes the Election contract's `GetVictories()`. [6](#0-5) 

4. The undersized miner list is used to generate the new consensus round. [7](#0-6) 

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

**No Attack Required**: This is a logic bug that triggers under natural protocol operation during network growth phases with insufficient candidate onboarding or voter engagement. The default `SupposedMinersCount` starts at 17. [9](#0-8) 

The bug is logged but not prevented - debug statements show the incorrect count but no assertion validates it.

## Recommendation

Change line 72 in `ViewMethods.cs` from:
```csharp
.Take(Math.Min(diff, currentMiners.Count))
```

To:
```csharp
.Take(Math.Min(diff, backups.Count))
```

This ensures all available backup miners are utilized when needed, maintaining the target miner count.

Additionally, add validation after the Election contract call to ensure the returned miner count matches expectations:
```csharp
Assert(victories.Pubkeys.Count == State.MinersCount.Value, 
    "Returned miner count does not match expected MinersCount");
```

## Proof of Concept

```csharp
[Fact]
public async Task GetVictories_UndersizedMinerList_WhenMinersCountIncreases()
{
    // Setup: Start with 5 initial miners
    // Update MinersCount to 10 (simulating auto-increase)
    await AEDPoSContractStub.SetMaximumMinersCount.SendAsync(new Int32Value { Value = 10 });
    
    // Only 2 candidates receive votes (valid candidates)
    var validCandidates = ValidationDataCenterKeyPairs.Take(2).ToList();
    foreach (var keyPair in validCandidates)
    {
        await AnnounceElectionAsync(keyPair);
        await VoteToCandidateAsync(VoterKeyPairs[0], keyPair.PublicKey.ToHex(), 100 * 86400, 100);
    }
    
    // Get victories - should return 10 but will return only 7
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // BUG: Returns 7 miners (2 valid + min(8, 5) backups) instead of 10
    victories.Value.Count.ShouldBe(10); // This will FAIL, actual count is 7
}
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
