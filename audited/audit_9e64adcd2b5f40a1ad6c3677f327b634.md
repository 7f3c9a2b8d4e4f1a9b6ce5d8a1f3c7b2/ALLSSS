### Title
Banned Initial Miners Can Re-Enter Miner Lists and Receive Rewards

### Summary
When an initial miner is banned through the evil node detection mechanism (`UpdateCandidateInformation` with `IsEvilNode=true`), they are not removed from the `State.InitialMiners` list. The `GetVictories` method, which selects miners for the next term, does not check the `BannedPubkeyMap` when adding initial miners as backup candidates. This allows banned initial miners to re-enter the active miner list and continue receiving mining rewards, completely bypassing the banning mechanism.

### Finding Description

**Root Cause:**

When an initial miner is marked as evil via `UpdateCandidateInformation`, the banned pubkey is added to `State.BannedPubkeyMap` and removed from `State.Candidates` and `State.CandidateInformationMap`, but is **not removed** from `State.InitialMiners`. [1](#0-0) 

The `GetVictories` method is called during term changes to determine the next term's miner list. When there are insufficient valid candidates (elected miners with votes), it fills the remaining slots with backup miners from the current miner list and initial miners. However, at lines 67-69, when adding initial miners to the backups list, **no check is performed against `State.BannedPubkeyMap`**: [2](#0-1) 

This contrasts sharply with the `GetMinerReplacementInformation` method, which correctly filters out banned initial miners when selecting alternatives for evil miners during the same term: [3](#0-2) 

**Execution Path:**

1. An initial miner is detected as evil and `RemoveEvilNode` or the consensus contract calls `UpdateCandidateInformation` with `IsEvilNode=true`
2. The miner is banned (added to `BannedPubkeyMap`) but remains in `State.InitialMiners`
3. At the next term change, the consensus contract calls `GetVictories` to determine the new miner list
4. If there are insufficient elected candidates, `GetVictories` adds initial miners as backups without checking if they're banned
5. The banned initial miner is included in the victories list returned to the consensus contract
6. The consensus contract generates the next round with this miner included
7. The Treasury contract distributes mining rewards to all miners in the round, including the banned initial miner [4](#0-3) [5](#0-4) 

### Impact Explanation

**Direct Harm:**
- Banned initial miners continue to participate in consensus and produce blocks despite being marked as malicious
- They receive proportional mining rewards based on blocks produced, misallocating treasury funds intended for legitimate miners
- The banning mechanism is completely ineffective for initial miners when there are insufficient elected candidates

**Quantified Damage:**
- Mining rewards are distributed via the Basic Reward scheme (10% of total treasury distribution) based on produced blocks
- A banned initial miner can receive rewards equal to `(their_produced_blocks / total_produced_blocks) * basic_reward_pool`
- With typical configurations of 17-21 initial miners, a single banned miner could receive 5-6% of the basic reward pool per term (7 days)

**Affected Parties:**
- Legitimate miners: receive reduced reward shares as the pool is divided among more participants including banned miners
- Token holders/voters: their voting mechanism is undermined as banned nodes they did not elect can still participate
- Protocol integrity: the consensus security model assumes banned nodes are excluded, not that they can re-enter

**Severity Justification:**
This is a HIGH severity issue because it:
1. Directly violates the consensus invariant that miner schedule integrity must be maintained
2. Causes continuous fund misallocation (rewards to malicious actors)
3. Undermines the entire node banning and governance mechanism
4. Has occurred in the codebase since the initial implementation of the banning feature

### Likelihood Explanation

**Attacker Capabilities:**
No attacker action is required. This is a protocol-level bug that occurs whenever:
1. An initial miner is banned via the evil node detection mechanism
2. There are insufficient elected candidates to fill all miner slots

**Attack Complexity:**
This is not an "attack" but rather an inevitable outcome of normal protocol operations given the bug. The conditions naturally occur when:
- The chain is still in early stages with low voter participation (insufficient elected candidates)
- An initial miner misbehaves and is detected by the consensus contract as evil
- A term change occurs after the banning

**Feasibility Conditions:**
Highly feasible because:
- The code path is triggered automatically during normal term changes
- No special permissions or preconditions are needed beyond the existence of a banned initial miner
- The bug has existed since deployment and would manifest in any chain configuration with banned initial miners and insufficient elected candidates

**Detection/Operational Constraints:**
- The bug is not easily detectable as banned miners would appear as normal miners in the active list
- Only by cross-referencing `BannedPubkeyMap` with active miner lists would the issue be discovered
- No events or logs specifically indicate this anomaly

**Probability:**
CERTAIN to occur if the preconditions are met (banned initial miner + insufficient candidates). This is not a probabilistic attack but a deterministic bug in the state management logic.

### Recommendation

**Immediate Fix:**

Add a banned pubkey check in the `GetVictories` method when adding initial miners as backups, matching the pattern used in `GetMinerReplacementInformation`:

In `contract/AElf.Contracts.Election/ViewMethods.cs` at line 68-69, modify:
```csharp
backups.AddRange(
    State.InitialMiners.Value.Value.Select(k => k.ToHex())
        .Where(k => !State.BannedPubkeyMap[k])  // ADD THIS CHECK
        .Where(k => !backups.Contains(k)));
```

**Additional Hardening:**

1. Modify `UpdateCandidateInformation` to also remove banned initial miners from `State.InitialMiners`:
```csharp
if (input.IsEvilNode)
{
    // ... existing code ...
    
    // Remove from InitialMiners if present
    var initialMiners = State.InitialMiners.Value;
    if (initialMiners.Value.Contains(ByteString.CopyFrom(publicKeyByte)))
    {
        initialMiners.Value.Remove(ByteString.CopyFrom(publicKeyByte));
        State.InitialMiners.Value = initialMiners;
    }
}
```

2. Add invariant check in consensus contract before generating new rounds to verify no banned miners are included

**Test Cases:**

1. Test that banned initial miner is filtered from GetVictories when insufficient candidates
2. Test that banned initial miner is removed from State.InitialMiners upon evil node detection
3. Test that banned initial miner does not receive rewards in subsequent terms
4. Test that GetMinerReplacementInformation and GetVictories have consistent banned checks

### Proof of Concept

**Initial State:**
1. Chain initialized with 17 initial miners in `State.InitialMiners`
2. Election contract initialized, currently only 10 elected candidates with sufficient votes
3. `State.MinersCount.Value = 17` (requires 17 miners per term)

**Exploit Sequence:**

**Step 1: Ban an initial miner**
- Transaction: Consensus contract detects evil behavior and calls `UpdateCandidateInformation(pubkey="INITIAL_MINER_X", IsEvilNode=true)`
- Result: 
  - `State.BannedPubkeyMap["INITIAL_MINER_X"] = true`
  - "INITIAL_MINER_X" removed from `State.Candidates`
  - "INITIAL_MINER_X" still in `State.InitialMiners` ❌

**Step 2: Term change triggers miner selection**
- Transaction: Extra block producer triggers `NextTerm` which calls `GenerateFirstRoundOfNextTerm`
- Call chain: `GenerateFirstRoundOfNextTerm` → `TryToGetVictories` → `GetVictories` (Election Contract)
- In `GetVictories`:
  - `validCandidates.Count = 10` (only 10 elected)
  - `State.MinersCount.Value = 17` (need 17)
  - `diff = 7` (need 7 more miners)
  - Code adds initial miners as backups WITHOUT checking `BannedPubkeyMap`
  - Result: "INITIAL_MINER_X" included in returned victories list ❌

**Step 3: Banned miner becomes active**
- The consensus contract generates Round with "INITIAL_MINER_X" in `RealTimeMinersInformation`
- "INITIAL_MINER_X" receives time slot and produces blocks
- Result: Banned miner participates in consensus ❌

**Step 4: Banned miner receives rewards**
- Transaction: Term ends, AEDPoS contract calls `Treasury.Release`
- `UpdateBasicMinerRewardWeights` iterates over `previousTermInformation.RealTimeMinersInformation` (includes "INITIAL_MINER_X")
- "INITIAL_MINER_X" is added as beneficiary with shares based on produced blocks
- Result: Banned miner receives mining rewards ❌

**Expected vs Actual:**

**Expected:** 
- Banned initial miner excluded from all miner lists
- Rewards distributed only to legitimate miners
- `GetVictories` returns 17 miners, none of which are banned

**Actual:**
- Banned initial miner included in victories list
- Banned miner produces blocks and receives rewards
- Banning mechanism bypassed for initial miners

**Success Condition:**
Query `State.BannedPubkeyMap["INITIAL_MINER_X"]` returns `true`, yet querying the current round's `RealTimeMinersInformation` includes "INITIAL_MINER_X" as an active miner receiving rewards.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-112)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
            var rankingList = State.DataCentersRankingList.Value;
            if (rankingList.DataCenters.ContainsKey(input.Pubkey))
            {
                rankingList.DataCenters[input.Pubkey] = 0;
                UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, input.Pubkey, true);
                State.DataCentersRankingList.Value = rankingList;
            }

            Context.LogDebug(() => $"Marked {input.Pubkey.Substring(0, 10)} as an evil node.");
            Context.Fire(new EvilMinerDetected { Pubkey = input.Pubkey });
            State.CandidateInformationMap.Remove(input.Pubkey);
            var candidates = State.Candidates.Value;
            candidates.Value.Remove(ByteString.CopyFrom(publicKeyByte));
            State.Candidates.Value = candidates;
            RemoveBeneficiary(input.Pubkey);
            return new Empty();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L67-69)
```csharp
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L777-822)
```csharp
    private void UpdateBasicMinerRewardWeights(IReadOnlyCollection<Round> previousTermInformation)
    {
        if (previousTermInformation.First().RealTimeMinersInformation != null)
            State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
            {
                SchemeId = State.BasicRewardHash.Value,
                Beneficiaries =
                {
                    GetAddressesFromCandidatePubkeys(previousTermInformation.First().RealTimeMinersInformation.Keys)
                }
            });

        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
                    }

                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
        });
    }
```
