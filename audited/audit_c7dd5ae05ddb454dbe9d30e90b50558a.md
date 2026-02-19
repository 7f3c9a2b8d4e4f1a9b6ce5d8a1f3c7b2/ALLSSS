### Title
Banned Miners Can Be Re-Selected As Block Producers Through Backup Selection Logic

### Summary
The `GetVictories` function's backup miner selection logic at lines 66-74 fails to check the banned status (`State.BannedPubkeyMap`) when selecting miners from the current miner list. This allows previously banned/evil miners who remain in the consensus contract's current miner list to be re-elected as block producers for the next term when there are insufficient valid candidates, completely bypassing the evil miner detection and banning mechanism.

### Finding Description

**Exact Code Location:** [1](#0-0) 

**Root Cause:**
When there aren't enough valid candidates to fill all miner positions (`diff > 0`), the backup selection logic creates a fallback list from current miners who are not in the valid candidates list: [2](#0-1) 

This line filters current miners only by checking if they're NOT in `validCandidates`, but **completely omits the banned status check** (`State.BannedPubkeyMap[k]`).

**Why currentMiners Can Contain Banned Miners:**
When a miner is marked as evil through `UpdateCandidateInformation` with `IsEvilNode=true`, the Election contract only sets the ban flag and removes them from the candidate list: [3](#0-2) 

However, this does NOT immediately remove the banned miner from the consensus contract's current round. The current miner list retrieved from the consensus contract reflects the active round's participants: [4](#0-3) [5](#0-4) 

Therefore, banned miners remain in `currentMiners` until the term/round transitions occur.

**Evidence of Inconsistency:**
The codebase demonstrates awareness of this requirement in `GetMinerReplacementInformation`, which explicitly filters out banned initial miners: [6](#0-5) 

The `GetEvilMinersPubkeys` function also shows that current miners can indeed be banned: [7](#0-6) 

### Impact Explanation

**Direct Consensus Integrity Violation:**
- Banned/evil miners who were detected and marked as malicious can be automatically re-selected as block producers for the next term
- This completely undermines the evil miner detection mechanism implemented throughout the consensus system
- Banned miners can continue producing blocks, earning rewards, and potentially causing further harm to the network

**Reward Misallocation:**
- Evil miners continue receiving block production rewards and mining subsidies despite being banned
- Honest alternative candidates are denied their rightful positions
- The Treasury and Profit distribution schemes continue rewarding malicious actors

**Security Compromise:**
- The consensus assumes banned miners are excluded from future rounds, but this assumption is violated
- A network with low candidate participation becomes vulnerable to persistent control by previously-identified malicious miners
- The evil miner replacement mechanism becomes ineffective if banned miners are immediately re-elected

**Affected Parties:**
- Network security (compromised consensus)
- Honest candidates (denied block production slots)
- Token holders (rewards distributed to evil miners)
- Overall protocol reputation

### Likelihood Explanation

**Feasible Preconditions:**
- Requires scenario where `State.MinersCount.Value > validCandidates.Count` (insufficient candidates with votes)
- This is realistic in networks with low candidate participation or during initial network stages
- At least one current miner must be banned via `UpdateCandidateInformation(IsEvilNode=true)` or `ReplaceCandidatePubkey`

**Attacker Capabilities:**
- No special privileges required beyond being a current miner who gets banned
- The banned miner remains passive - the vulnerability is triggered automatically during term transitions
- Detection by consensus contract already occurred (miner is marked as evil), but Election contract fails to honor this

**Execution Path:**
1. Consensus contract detects evil miner behavior and calls `UpdateCandidateInformation(IsEvilNode=true)` [8](#0-7) 

2. Miner is banned in Election contract but remains in current consensus round
3. At next term transition, consensus calls `GetVictories(Empty)` to determine next term's miners [9](#0-8) 

4. If insufficient valid candidates exist, backup selection executes without ban check
5. Banned miner is re-selected for next term

**Probability:**
- **High** in networks with low candidate participation (common in many blockchain networks)
- **Automatic** - no attacker action needed once initial ban occurs
- **Repeatable** - can occur at every term transition until candidate pool increases

### Recommendation

**Immediate Fix:**
Add banned status check to the backup selection logic in `GetVictories`:

```csharp
var backups = currentMiners
    .Where(k => !validCandidates.Contains(k) && !State.BannedPubkeyMap[k])
    .ToList();
```

**Additional Safeguards:**
1. Also add ban check when adding initial miners to backups:
```csharp
backups.AddRange(
    State.InitialMiners.Value.Value.Select(k => k.ToHex())
        .Where(k => !backups.Contains(k) && !State.BannedPubkeyMap[k]));
```

2. Add defensive assertion before returning victories:
```csharp
foreach (var victory in victories)
{
    Assert(!State.BannedPubkeyMap[victory.ToHex()], 
           "Banned miner detected in victory list");
}
```

**Regression Test Cases:**
1. Test scenario: insufficient candidates + current miner gets banned → verify banned miner excluded from next term
2. Test scenario: banned initial miner + insufficient candidates → verify banned initial miner not used as backup
3. Test scenario: multiple banned miners in current list + low candidates → verify all banned miners filtered

### Proof of Concept

**Initial State:**
- Network has `MinersCount = 17` required block producers
- Current term has 17 active miners: `[M1, M2, ..., M17]`
- Only 15 candidates have votes (valid candidates)
- Miner `M16` is detected as evil and banned via `UpdateCandidateInformation(IsEvilNode=true)`
- `State.BannedPubkeyMap["M16"] = true` is set
- `M16` remains in current consensus round's miner list

**Exploitation Steps:**
1. Term transition occurs
2. Consensus contract calls `State.ElectionContract.GetVictories.Call(new Empty())` [10](#0-9) 

3. `GetVictories` determines:
   - `validCandidates.Count = 15`
   - `State.MinersCount.Value = 17`
   - `diff = 17 - 15 = 2` (need 2 backups)

4. Backup selection executes:
   - `currentMiners = [M1, M2, ..., M17]` (includes banned M16)
   - `backups = currentMiners.Where(k => !validCandidates.Contains(k))` 
   - This includes `M16` and `M17` (both not in validCandidates)
   - **No ban check performed**

5. Result: `victories = [15 valid candidates] + [M16, M17]`

**Expected vs Actual:**
- **Expected:** M16 should be excluded, only M17 selected, possibly need one initial miner as backup
- **Actual:** M16 (banned) is included in next term's block producer list

**Success Condition:**
Banned miner M16 appears in the returned `PubkeyList` from `GetVictories` and will be assigned block production time slots in the next term, completely bypassing the ban.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L41-49)
```csharp
    public override PubkeyList GetVictories(Empty input)
    {
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L83-88)
```csharp
    public override Empty UpdateCandidateInformation(UpdateCandidateInformationInput input)
    {
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) ==
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
            "Only consensus contract can update candidate information.");
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L31-42)
```csharp
    public override MinerList GetCurrentMinerList(Empty input)
    {
        return TryToGetCurrentRoundInformation(out var round)
            ? new MinerList
            {
                Pubkeys =
                {
                    round.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k))
                }
            }
            : new MinerList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L274-274)
```csharp
        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
```
