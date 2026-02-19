# Audit Report

## Title
Insufficient Miner List Length in GetVictories() Due to Incorrect Backup Limit Calculation

## Summary
The `GetVictories()` function in the Election contract contains a critical logic error where it incorrectly limits the number of backup miners using `currentMiners.Count` instead of the actual `backups.Count`. This causes the function to return a miner list significantly shorter than the required `State.MinersCount.Value`, directly compromising consensus security by violating the fundamental invariant that the miner list must match the configured MinersCount.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method in the Election contract. [1](#0-0) 

When valid candidates are insufficient to fill all miner slots, the function attempts to fill the shortage using backup miners. The backups list is constructed by first taking current miners that aren't valid candidates, then adding initial miners that aren't already in the backups list. [2](#0-1) 

**Root Cause:** The critical bug occurs where the code limits the number of backups using `Math.Min(diff, currentMiners.Count)` instead of using the actual size of the `backups` collection. [3](#0-2) 

Since the `backups` list includes both filtered current miners AND initial miners, its size can significantly exceed `currentMiners.Count`. The incorrect limit means that even when sufficient backups are available, only a fraction are taken based on the obsolete `currentMiners.Count` value.

**Concrete Scenario:**
- Network has 17 InitialMiners set at genesis
- MinersCount is 17 (or increased to 17 through governance)
- Current term has only 5 active miners
- New term starts with only 3 candidates receiving votes
- `diff = 17 - 3 = 14` (need 14 more miners)
- `backups` = 5 current miners (none overlap with valid candidates) + 12 initial miners = 17 total
- Code executes: `backups.Take(Math.Min(14, 5))` → only takes 5 backups
- **Result:** 3 valid candidates + 5 backups = 8 miners instead of 17

**Why Existing Protections Fail:**
- The consensus contract calls `GetVictories()` and directly uses the returned list without any size validation. [4](#0-3) 
- The `GenerateFirstRoundOfNewTerm` method accepts any miner list size and creates a consensus round based on whatever count it receives. [5](#0-4) 
- No validation exists anywhere in the execution path to ensure the victories list matches MinersCount.

## Impact Explanation

**Critical Consensus Degradation:** The consensus mechanism fundamentally depends on having exactly `MinersCount` miners participating in each term. When fewer miners are selected, the entire security model is compromised:

1. **Quantified Security Loss:** If MinersCount = 17 but only 8 miners are selected, network security is reduced by more than 50%. An attacker controlling 5 miners (instead of needing 9) could now execute 51% attacks.

2. **Centralization Risk:** Block production power becomes concentrated among fewer participants, directly contradicting the decentralization goals of the consensus mechanism.

3. **Economic Unfairness:** Mining rewards intended for 17 miners are distributed among only 8 participants, creating unintended economic advantages and disincentivizing new miner participation.

4. **Governance Impact:** The governance system and reward distribution mechanisms operate under the assumption that MinersCount miners are active, leading to incorrect calculations and decisions.

**Who Is Affected:**
- The entire blockchain network suffers from weakened consensus security
- Honest miners lose mining slots and expected rewards
- Token holders face increased centralization and attack risk
- All stakeholders relying on the security guarantees of a 17-miner consensus

## Likelihood Explanation

**HIGH Likelihood - No Attacker Required**

This vulnerability is triggered through normal network operations without any malicious action:

1. **Governance Increases MinersCount:** Network scaling through governance-approved increases to MinersCount is standard practice. [6](#0-5) 

2. **Candidate Acquisition Lags:** During network growth phases, the rate at which new candidates announce and receive sufficient votes often lags behind MinersCount increases. This is especially common when MinersCount is increased significantly (e.g., from 5 to 17).

3. **Automatic Trigger:** The bug manifests automatically when the next term transition occurs and `GetVictories()` is called by the consensus contract, which happens as part of the normal consensus flow.

**Preconditions:**
- MinersCount has been increased through governance (realistic and expected)
- Insufficient new candidates have announced and received votes to fill all slots (common during growth)
- The pool of available miners (current + initial) exceeds currentMiners.Count but is used incorrectly (directly caused by the bug)

**Execution Complexity:** NONE - This is a passive logic bug that triggers automatically during term transitions.

## Recommendation

**Fix the backup limit calculation** to use the actual size of the backups collection:

Change line 72 from:
```csharp
.Take(Math.Min(diff, currentMiners.Count))
```

To:
```csharp
.Take(Math.Min(diff, backups.Count))
```

Or even simpler (since Take already handles counts gracefully):
```csharp
.Take(diff)
```

**Additional Recommended Safeguards:**
1. Add validation to ensure the returned victories list has exactly MinersCount elements when possible
2. Add explicit checks in the consensus contract before using the miner list
3. Consider adding a minimum threshold assertion that prevents consensus from proceeding if the miner list is significantly undersized

## Proof of Concept

The vulnerability can be demonstrated by examining the actual code execution path:

**Step 1:** MinersCount is set to 17 and InitialMiners contains 17 miners. [7](#0-6) 

**Step 2:** After some terms, currentMiners list has only 5 active miners (verified by checking current round miner count). [8](#0-7) 

**Step 3:** Only 3 candidates have votes, calculated by GetValidCandidates(). [9](#0-8) 

**Step 4:** The faulty logic executes:
- `diff = 17 - 3 = 14`
- `backups` starts with 5 current miners, then adds 12 initial miners → total 17
- But `backups.Take(Math.Min(14, 5))` only takes 5
- Final result: 3 + 5 = 8 miners returned

**Step 5:** Consensus contract accepts the undersized list without validation and generates a round with only 8 miners. [10](#0-9) 

This violates the consensus invariant that miner list size must equal MinersCount, resulting in degraded network security.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L47-49)
```csharp
        var currentMiners = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(k => k.ToHex()).ToList();
        return new PubkeyList { Value = { GetVictories(currentMiners) } };
```

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-95)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-242)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-28)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L33-38)
```csharp
        State.MinersCount.Value = input.MinerList.Count;
        State.InitialMiners.Value = new PubkeyList
        {
            // ReSharper disable once ConvertClosureToMethodGroup
            Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)) }
        };
```
