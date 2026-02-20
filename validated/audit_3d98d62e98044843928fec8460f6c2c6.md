# Audit Report

## Title
Insufficient Miner Selection in GetVictories() Leads to Undersized Consensus Round

## Summary
The `GetVictories()` function in the Election contract contains a logic error at line 72 that incorrectly limits backup miner selection to `currentMiners.Count` instead of `backups.Count`. When the target miner count increases over time but there are insufficient valid candidates, this bug causes consensus rounds to be generated with fewer miners than configured, violating a critical protocol invariant.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method where backup miners are selected to fill gaps when there aren't enough valid candidates with votes. [1](#0-0) 

The bug occurs at line 72. When insufficient valid candidates exist, the code constructs a `backups` list from current miners (line 66) plus initial miners not already in the list (lines 67-69). However, line 72 uses `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)` when selecting from the backup pool.

**Execution Path:**

1. The AEDPoS consensus contract's miner count auto-increments over time via `GetAutoIncreasedMinersCount()`, adding 2 miners every `MinerIncreaseInterval` seconds: [2](#0-1) 

2. This increased count is communicated to the Election contract via `UpdateMinersCount()`: [3](#0-2) 

3. During term transition, `GenerateFirstRoundOfNextTerm()` calls `TryToGetVictories()`: [4](#0-3) 

4. `TryToGetVictories()` invokes the Election contract's `GetVictories()` method: [5](#0-4) 

5. The undersized miner list is used to generate the new consensus round via `GenerateFirstRoundOfNewTerm()`, which simply iterates over provided miners without validation: [6](#0-5) 

**Concrete Example:**
- Target: `State.MinersCount.Value = 10`
- Valid candidates with votes: 2
- Previous term miners (`currentMiners.Count`): 5
- Available backups after adding initial miners (`backups.Count`): 8
- **Current buggy behavior**: Takes `Math.Min(8, 5) = 5` backups → Total: 2 + 5 = 7 miners (3 short)
- **Expected behavior**: Should take `Math.Min(8, 8) = 8` backups → Total: 2 + 8 = 10 miners

## Impact Explanation

This bug directly violates consensus miner schedule integrity:

**Consensus Degradation**: The blockchain operates with fewer block producers than configured, reducing decentralization, network security, and liveness guarantees.

**State Inconsistency**: `State.MinersCount.Value` indicates N miners should participate, but actual consensus rounds contain < N miners, creating a mismatch between configuration and reality.

**Reward Misallocation Risk**: Mining reward and profit distribution calculations that rely on the configured miner count will be incorrect, potentially affecting per-miner payouts.

**Protocol Invariant Violation**: The critical invariant that consensus rounds must contain exactly `State.MinersCount.Value` miners is broken. No validation exists in `GenerateFirstRoundOfNewTerm()` to catch this mismatch.

This is **HIGH severity** because it directly compromises consensus integrity, a foundational protocol guarantee.

## Likelihood Explanation

This vulnerability has **MEDIUM-HIGH likelihood** of occurring naturally:

**No Attacker Required**: This is a logic bug that triggers under normal network conditions during term transitions.

**Realistic Trigger Conditions**:
1. The miner count automatically increases every `MinerIncreaseInterval` by 2 miners: [7](#0-6) 

2. Low voter participation or insufficient candidate onboarding results in `validCandidates.Count < State.MinersCount.Value` - a realistic scenario during network growth or periods of low engagement.

3. The previous term had fewer miners than the new auto-incremented target - inevitable during the growth phase.

**Natural Occurrence**: In a growing network where miner count targets increase but community participation lags, this condition will manifest without any adversarial behavior.

## Recommendation

Change line 72 in `ViewMethods.cs` to use `backups.Count` instead of `currentMiners.Count`:

```csharp
victories.AddRange(backups.OrderBy(p => p)
    .Take(Math.Min(diff, backups.Count))  // Fixed: use backups.Count
    .Select(v => ByteStringHelper.FromHexString(v)));
```

This ensures that all available backup miners are utilized when filling gaps, up to the number needed (`diff`).

## Proof of Concept

The vulnerability can be demonstrated by setting up a scenario where:
1. Initial miner count is configured (e.g., 17)
2. Auto-increment triggers to increase target to 19
3. Only 10 valid candidates exist with votes
4. Current term has 15 miners
5. Initial miners list contains 17 entries

In this scenario, `backups` will contain up to 17 miners (current + initial), but the bug will only take `Math.Min(9, 15) = 9` from the backup pool instead of utilizing all 9 needed, resulting in 10 + 9 = 19 miners as expected. However, if `currentMiners.Count` is smaller than `diff` (e.g., current term has only 5 miners), the bug manifests: `Math.Min(9, 5) = 5` taken instead of 9, resulting in only 15 total miners instead of 19.

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
