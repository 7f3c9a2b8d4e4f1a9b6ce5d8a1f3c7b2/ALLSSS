# Audit Report

## Title
Insufficient Miner List Length in GetVictories() Due to Incorrect Backup Limit Calculation

## Summary
The `GetVictories()` function in the Election contract contains a critical logic error where it incorrectly limits the number of backup miners using `currentMiners.Count` instead of the actual `backups.Count`. This causes the function to return a miner list significantly shorter than the required `State.MinersCount.Value`, directly compromising consensus security by violating the fundamental invariant that the miner list must match the configured MinersCount.

## Finding Description

The vulnerability exists in the private `GetVictories(List<string> currentMiners)` method in the Election contract. [1](#0-0) 

When valid candidates are insufficient to fill all miner slots, the function attempts to fill the shortage using backup miners. The backups list is constructed by first taking current miners that aren't valid candidates, then adding initial miners that aren't already in the backups list. [2](#0-1) 

**Root Cause:** The critical bug occurs at line 72 where the code limits the number of backups using `Math.Min(diff, currentMiners.Count)` instead of using the actual size of the `backups` collection. [3](#0-2) 

Since the `backups` list includes both filtered current miners AND initial miners, its size can significantly exceed `currentMiners.Count`. The incorrect limit means that even when sufficient backups are available, only a fraction are taken based on the obsolete `currentMiners.Count` value.

**Concrete Scenario:**
- Network has 17 InitialMiners set at genesis
- MinersCount is 17 (default SupposedMinersCount or increased through governance)
- Current term has only 5 active miners
- New term starts with only 3 candidates receiving votes
- `diff = 17 - 3 = 14` (need 14 more miners)
- `backups` = 5 current miners (none overlap with valid candidates) + 12 initial miners = 17 total
- Code executes: `backups.Take(Math.Min(14, 5))` → only takes 5 backups
- **Result:** 3 valid candidates + 5 backups = 8 miners instead of 17

**Why Existing Protections Fail:**
- The consensus contract calls `GetVictories()` through `TryToGetVictories` and directly uses the returned list without any size validation. [4](#0-3) 
- The `GenerateFirstRoundOfNewTerm` method in `GenerateFirstRoundOfNextTerm` accepts any miner list size and creates a consensus round based on whatever count it receives. [5](#0-4) 
- The `GenerateFirstRoundOfNewTerm` method in MinerList simply creates a Round with whatever miners are provided in the Pubkeys list. [6](#0-5) 
- No validation exists in the `ProcessNextTerm` method to ensure the victories list matches MinersCount. [7](#0-6) 

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

1. **Governance Increases MinersCount:** Network scaling through governance-approved increases to MinersCount is standard practice. The `SetMaximumMinersCount` method is controlled by Parliament governance and updates the MinersCount in the Election contract. [8](#0-7) 

2. **Default SupposedMinersCount:** The system is designed with a default SupposedMinersCount of 17 miners. [9](#0-8) 

3. **Candidate Acquisition Lags:** During network growth phases, the rate at which new candidates announce and receive sufficient votes often lags behind MinersCount increases. This is especially common when MinersCount is increased significantly (e.g., from 5 to 17).

4. **Automatic Trigger:** The bug manifests automatically when the next term transition occurs and `GetVictories()` is called by the consensus contract, which happens as part of the normal consensus flow.

**Preconditions:**
- MinersCount has been increased through governance (realistic and expected) OR is set to default value of 17
- Insufficient new candidates have announced and received votes to fill all slots (common during growth)
- The pool of available miners (current + initial) exceeds currentMiners.Count but is used incorrectly (directly caused by the bug)

**Execution Complexity:** NONE - This is a passive logic bug that triggers automatically during term transitions.

## Recommendation

Fix the backup selection logic to use the actual size of the backups collection instead of the obsolete currentMiners.Count:

**Change line 72 from:**
```csharp
.Take(Math.Min(diff, currentMiners.Count))
```

**To:**
```csharp
.Take(Math.Min(diff, backups.Count))
```

This ensures that when sufficient backups are available (from both current miners and initial miners), the full required number of miners (up to `diff`) will be selected to meet the MinersCount requirement.

Additionally, consider adding defensive validation in the consensus contract to assert that the returned victories list count equals MinersCount, to catch similar issues in the future.

## Proof of Concept

A test demonstrating this vulnerability would:
1. Initialize a chain with 17 initial miners
2. Set MinersCount to 17 through governance
3. Run several terms with only 5 active miners
4. Have only 3 candidates announce and receive votes for the next term
5. Trigger a term transition
6. Verify that GetVictories returns only 8 miners instead of 17
7. Confirm that the new consensus round operates with only 8 miners

The test would show that despite having 17 available miners (5 current + 12 from initial that aren't current), only 5 backups are selected due to the bug, resulting in a total of 8 miners (3 valid candidates + 5 backups) instead of the required 17.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-45)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
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
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
