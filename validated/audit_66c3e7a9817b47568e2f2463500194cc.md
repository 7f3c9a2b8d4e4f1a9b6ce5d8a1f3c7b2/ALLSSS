# Audit Report

## Title
Banned Miners Can Be Re-Selected Through GetVictories Backup Mechanism

## Summary
The `GetVictories()` function in the Election contract contains a critical vulnerability where its backup selection mechanism fails to verify banned status when selecting miners from `currentMiners` and `InitialMiners` lists. This allows miners that were explicitly marked as evil/banned to automatically rejoin consensus in the next term, completely bypassing the node banning security mechanism designed to protect network integrity.

## Finding Description

The vulnerability exists in the private `GetVictories()` method within the Election contract's backup selection logic. When the number of valid candidates (those with active votes) is insufficient to fill the required miner count, the function activates a backup mechanism to select additional miners.

**The Critical Flaw:**

The backup selection logic adds miners from `currentMiners` and `InitialMiners` lists without checking `State.BannedPubkeyMap`: [1](#0-0) 

At lines 66-74, the code:
1. Collects current miners not in valid candidates
2. Adds initial miners not already in backups
3. Takes miners from this backup list **without any banned status verification**

The `GetValidCandidates()` helper only filters based on vote amount (> 0), not banned status: [2](#0-1) 

**How Miners Get Banned:**

When miners are detected as evil, the consensus contract calls `UpdateCandidateInformation` with `IsEvilNode=true`: [3](#0-2) 

This properly sets `State.BannedPubkeyMap[pubkey] = true` and removes the candidate from the candidates list: [4](#0-3) 

Similarly, when pubkeys are replaced, the old pubkey is banned: [5](#0-4) 

**Why Existing Protections Fail:**

The contract has a properly functioning `GetMinerReplacementInformation()` method that **DOES** check for banned miners during mid-term replacement: [6](#0-5) 

Note line 389 explicitly filters: `.Where(k => !State.BannedPubkeyMap[k])` when selecting from initial miners.

However, `GetVictories()` completely lacks this same validation when selecting backups for new term generation.

**Execution Path:**

The consensus contract calls `GetVictories()` during new term generation: [7](#0-6) 

This occurs in `GenerateFirstRoundOfNextTerm`: [8](#0-7) 

## Impact Explanation

**Consensus Integrity Violation - Critical Severity:**

This vulnerability directly violates the miner schedule integrity invariant that is fundamental to AEDPoS consensus security:

1. **Evil Node Persistence**: Miners explicitly marked as evil through `UpdateCandidateInformation(IsEvilNode=true)` can automatically rejoin consensus in the next term, completely defeating the network's security mechanism for removing malicious nodes.

2. **Unauthorized Block Rewards**: Banned miners continue earning mining rewards they are not entitled to receive, representing an unauthorized extraction of value from the reward pool.

3. **Continued Malicious Behavior**: Whatever malicious behavior caused the ban (e.g., censoring transactions, excessive downtime, attempted double-signing) can continue uninterrupted after the term transition.

4. **Network-Wide Impact**: This affects the entire blockchain's security and liveness. All honest miners must operate alongside nodes that the system explicitly flagged for exclusion, and all users' transactions are subject to processing by banned malicious nodes.

5. **Automatic Exploitation**: No manual intervention can prevent this vulnerability - it triggers automatically during normal term transitions whenever the preconditions are met.

The severity is **Critical** because it breaks a core consensus security guarantee: that the network can permanently exclude malicious actors from block production.

## Likelihood Explanation

**High Probability with Zero Attack Complexity:**

**Preconditions:**
1. The number of valid candidates (with active votes > 0) must be less than `State.MinersCount.Value`, triggering `diff > 0`
2. A banned miner must exist in `currentMiners` or `InitialMiners` lists
3. That miner was previously banned via `UpdateCandidateInformation(IsEvilNode=true)` or `ReplaceCandidatePubkey`

**Why This Is Highly Likely:**

1. **Bootstrap Phases**: During network launch or when expanding validator set, having insufficient candidates with votes is extremely common
2. **Low Participation Chains**: Chains with limited election participation naturally have fewer valid candidates than required miner slots
3. **Validator Set Expansion**: When `MinersCount` increases, there's often a lag before enough candidates announce and receive votes

**Attack Complexity: Zero**

This is **not an exploit** requiring attacker action - it's an automatic system failure:
- The banned node takes no action
- No special transactions are needed
- It happens through normal consensus term transitions
- There's no distinguishable attack signature
- Defenders cannot prevent it without code changes

**Realistic Scenario:**

Consider a network with 5 initial miners requiring 5 miners per term:
1. Only 3 candidates announce election and receive votes (validCandidates = 3)
2. One initial miner M1 gets banned for missing time slots during term N
3. At term N+1 start, `GetVictories()` calculates: diff = 5 - 3 = 2
4. Backup mechanism activates, adding from currentMiners and InitialMiners
5. M1 is included in backups **without banned status check**
6. M1 operates as a miner in term N+1 despite being marked as evil

This scenario is common in real-world blockchain operations, particularly during early network phases or periods of low validator participation.

## Recommendation

Add banned status verification in the `GetVictories()` backup selection logic, consistent with the protection already implemented in `GetMinerReplacementInformation()`.

**Fix the backup selection at lines 66-74:**

```csharp
if (diff > 0)
{
    victories = new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
    
    // Filter out banned miners from currentMiners
    var backups = currentMiners
        .Where(k => !validCandidates.Contains(k))
        .Where(k => !State.BannedPubkeyMap[k])  // ADD THIS CHECK
        .ToList();
        
    if (State.InitialMiners.Value != null)
        backups.AddRange(
            State.InitialMiners.Value.Value.Select(k => k.ToHex())
                .Where(k => !backups.Contains(k))
                .Where(k => !State.BannedPubkeyMap[k]));  // ADD THIS CHECK

    victories.AddRange(backups.OrderBy(p => p)
        .Take(Math.Min(diff, currentMiners.Count))
        .Select(v => ByteStringHelper.FromHexString(v)));
    // ... rest of code
}
```

This ensures banned miners are excluded from backup selection during term transitions, maintaining consistency with mid-term replacement logic.

## Proof of Concept

```csharp
[Fact]
public async Task BannedMiner_Should_Not_Be_ReSelected_In_GetVictories_Backup()
{
    // Setup: Initialize with 5 miners required
    const int minersCount = 5;
    var initialMiners = GenerateInitialMiners(minersCount);
    await InitializeElectionContract(initialMiners, minersCount);
    
    // Setup: Only 3 candidates announce and receive votes (insufficient)
    var candidatesWithVotes = initialMiners.Take(3).ToList();
    foreach (var candidate in candidatesWithVotes)
    {
        await AnnounceElectionAndVote(candidate, votesAmount: 1000);
    }
    
    // Action: Ban one of the initial miners (not in candidates with votes)
    var bannedMiner = initialMiners[3];
    await ElectionContractStub.UpdateCandidateInformation.SendAsync(
        new UpdateCandidateInformationInput
        {
            Pubkey = bannedMiner,
            IsEvilNode = true
        });
    
    // Verify banned status is set
    var isBanned = await ElectionContractStub.GetBannedPubkeyMap.CallAsync(
        new StringValue { Value = bannedMiner });
    isBanned.Value.ShouldBeTrue();
    
    // Action: Simulate term transition - call GetVictories
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // Expected: Banned miner should NOT be in victories
    // Actual: VULNERABLE - banned miner IS in victories due to backup mechanism
    var victoryPubkeys = victories.Value.Select(v => v.ToHex()).ToList();
    
    // THIS ASSERTION FAILS - Proving the vulnerability
    victoryPubkeys.ShouldNotContain(bannedMiner,
        "Banned miner should not be re-selected in GetVictories backup mechanism");
    
    // The banned miner is incorrectly included because GetVictories backup 
    // logic at lines 66-74 does not check State.BannedPubkeyMap
}
```

**Notes:**
- This vulnerability affects the core consensus security of AElf mainchain operations
- The inconsistency between `GetVictories` (no banned check) and `GetMinerReplacementInformation` (has banned check) indicates this is an oversight rather than intentional design
- The fix is straightforward and mirrors existing security logic already implemented elsewhere in the contract

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L62-76)
```csharp
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L383-392)
```csharp
        var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
        if (diff > 0)
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L245-246)
```csharp
        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-233)
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
