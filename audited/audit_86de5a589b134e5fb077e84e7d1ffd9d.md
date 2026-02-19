# Audit Report

## Title
Duplicate Miner Public Keys in Election Victories Cause Consensus Term Transition Failure

## Summary

The Election contract's `GetVictories` method contains a logic flaw that produces duplicate public keys when valid candidates are insufficient and initial miners are also valid candidates. This duplicate list causes the consensus contract's `GenerateFirstRoundOfNewTerm` method to throw an `ArgumentException` during dictionary creation, resulting in complete consensus term transition failure and blockchain DoS.

## Finding Description

The vulnerability exists in the interaction between two contracts during consensus term transitions.

**Root Cause - Election Contract:**

In the `GetVictories` method, when there are insufficient valid candidates (candidates with votes > 0), the code follows this logic: [1](#0-0) 

The critical flaw occurs at lines 67-69. When constructing the backup miner list, the code only checks if initial miners are already in the `backups` list (`!backups.Contains(k)`), but does NOT check if they are already in the `validCandidates` list. Since `backups` is created by excluding valid candidates (line 66: `currentMiners.Where(k => !validCandidates.Contains(k))`), an initial miner who is also a valid candidate will:
1. Already be in `victories` (added at line 65)
2. NOT be in `backups` (excluded at line 66)
3. Pass the check `!backups.Contains(k)` (line 69)
4. Get added to `backups` (line 68-69)
5. Get added to `victories` AGAIN (lines 71-74)

**Failure Point - Consensus Contract:**

When the consensus contract attempts to generate a new term round with this duplicated miner list: [2](#0-1) 

The `ToDictionary` call at lines 16-18 attempts to create a dictionary using `miner.ToHex()` as the key. When the same hex string appears twice in the `Pubkeys` collection, this throws `ArgumentException: "An item with the same key has already been added"`.

**Execution Path:**

The vulnerability is triggered during normal consensus term transition: [3](#0-2) [4](#0-3) 

The flow: `GetConsensusExtraDataForNextTerm` (line 209) → `GenerateFirstRoundOfNextTerm` (line 223) → `TryToGetVictories` (line 228) → Election contract's `GetVictories` (line 274) → returns duplicates → `victories.GenerateFirstRoundOfNewTerm` (line 231) → `ToDictionary` throws exception.

## Impact Explanation

This is a **HIGH severity** vulnerability because:

1. **Complete Consensus Failure**: The exception prevents any term transition from completing, effectively halting the blockchain's ability to rotate miners and progress to new consensus terms.

2. **Network-Wide Impact**: All nodes are affected as the blockchain cannot advance past the failed term transition. This freezes the election and governance system's core functionality.

3. **No Attack Required**: This occurs automatically during normal blockchain operation when the preconditions are met - no malicious actor is needed.

4. **Critical Timing**: Most likely to occur during the blockchain's early stages when transitioning from initial miners to elected miners, which is a critical period for network stability.

5. **Difficult Recovery**: Requires contract upgrade or manual intervention to resolve, as every subsequent term transition attempt will fail with the same exception.

## Likelihood Explanation

The likelihood is **HIGH** for the following reasons:

**Preconditions (All Realistic):**
1. Number of valid candidates < target miners count (common in early blockchain stages)
2. One or more initial miners announce as candidates (expected behavior for continuity)
3. Term transition is triggered (normal periodic operation)

**Probability Factors:**
- Initial miners naturally want to continue participating and will announce as candidates
- During blockchain launch, the election system starts with few candidates
- The first term transition from initial miners to elected miners is highly vulnerable
- No validation or deduplication logic exists to prevent this scenario

**Detection:**
The failure is immediate and deterministic. Once conditions are met, every term transition will fail until the bug is fixed.

## Recommendation

Add duplicate detection before returning the victories list. The fix should check if initial miners are already in the valid candidates list:

```csharp
if (State.InitialMiners.Value != null)
    backups.AddRange(
        State.InitialMiners.Value.Value.Select(k => k.ToHex())
            .Where(k => !backups.Contains(k) && !validCandidates.Contains(k)));
```

Alternatively, use `Distinct()` on the final victories list before returning:

```csharp
victories.AddRange(backups.OrderBy(p => p)
    .Take(Math.Min(diff, currentMiners.Count))
    .Select(v => ByteStringHelper.FromHexString(v)));
    
return victories.Distinct().ToList();
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

**Setup:**
1. Initialize blockchain with 5 initial miners
2. Set MinersCount to 5
3. Have initial miner #1 announce as candidate
4. Have initial miner #1 receive votes (becomes valid candidate)
5. Have only 3 other non-initial candidates announce and receive votes
6. Now there are 4 valid candidates (including initial miner #1) but need 5 miners
7. Trigger term transition

**Expected Result:** `ArgumentException` thrown during `GenerateFirstRoundOfNewTerm` when `ToDictionary` encounters duplicate initial miner #1 (appears once as valid candidate, once as backup initial miner).

**Vulnerable Code Flow:**
- `GetVictories` returns: [InitialMiner1, Candidate2, Candidate3, Candidate4, InitialMiner1]
- `ToDictionary` throws on second InitialMiner1 entry

This test would need to be implemented in the Election contract test suite by:
1. Configuring insufficient valid candidates
2. Ensuring at least one initial miner is a valid candidate
3. Calling `GetVictories` and passing result to consensus contract
4. Asserting the exception is thrown during dictionary creation

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
