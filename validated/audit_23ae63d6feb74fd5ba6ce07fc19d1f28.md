# Audit Report

## Title
Quit Candidates Can Bypass Election Restrictions and Become Consensus Validators via InitialMiners List

## Summary
The Election Contract's `GetVictories()` method fails to validate that pubkeys in the `InitialMiners` list are legitimate current candidates before selecting them as backup consensus validators. This allows a candidate who has quit the election to be moved into `InitialMiners` via `ReplaceCandidatePubkey()` and subsequently selected as a validator, bypassing the election process entirely.

## Finding Description

The vulnerability stems from insufficient validation in the authorization logic and backup validator selection process across multiple methods in the Election Contract.

**Root Cause 1: Overly Permissive Authorization Check**

The `IsCurrentCandidateOrInitialMiner()` function grants full privileges to any pubkey in `InitialMiners`, regardless of whether they are current candidates: [1](#0-0) 

This permissive check is used to authorize sensitive operations like `SetCandidateAdmin`: [2](#0-1) 

And critically, it's used in `ReplaceCandidatePubkey`: [3](#0-2) 

**Root Cause 2: QuitElection Doesn't Remove from InitialMiners**

When a candidate quits election, their `IsCurrentCandidate` flag is set to false and they are removed from the `Candidates` list: [4](#0-3) [5](#0-4) 

However, there is no logic to remove the pubkey from `InitialMiners` if present, creating a gap where quit candidates could remain in `InitialMiners` if they were previously added via replacement.

**Root Cause 3: ReplaceCandidatePubkey Allows Arbitrary Additions to InitialMiners**

The `ReplaceCandidatePubkey()` method allows an initial miner's admin to replace their pubkey with any pubkey, including quit candidates, and adds the new pubkey to `InitialMiners`: [6](#0-5) 

Critically, the method only bans the OLD pubkey, not the new one: [7](#0-6) 

There is no validation that the new pubkey:
- Has `IsCurrentCandidate = true`
- Is in the `Candidates` list
- Is legitimately entitled to be an initial miner

**Root Cause 4: GetVictories Lacks Validation for InitialMiners Backups**

The critical flaw is in `GetVictories()`, which uses `InitialMiners` as backups when there are insufficient valid candidates, but performs NO validation on these pubkeys: [8](#0-7) 

The `GetValidCandidates()` helper only checks candidates in the `Candidates` list with votes > 0: [9](#0-8) 

When backups are needed, `InitialMiners` are added directly without any validation that they are current candidates, have any votes, or are even in the election.

**Attack Execution Path:**

1. Attacker announces election with pubkey A (not an initial miner, publicly accessible):
   - A becomes a current candidate (`IsCurrentCandidate = true`)
   - A added to `Candidates` list
   - 100k ELF locked

2. Attacker calls `QuitElection()` with pubkey A:
   - `IsCurrentCandidate` set to `false`
   - A removed from `Candidates` list
   - 100k ELF returned to attacker

3. Initial miner B's admin (compromised or cooperating) calls `ReplaceCandidatePubkey(B → A)`:
   - Authorization check passes because B is in `InitialMiners`
   - B removed from `InitialMiners`, A added to `InitialMiners`
   - B is banned, but A is NOT banned
   - No validation that A is a current candidate

4. When consensus contract calls `GetVictories()` during term transition with insufficient valid candidates:
   - `GetValidCandidates()` returns candidates with votes > 0 (A is NOT included)
   - Insufficient candidates triggers backup logic
   - A (now in `InitialMiners`) is added to backups and selected as validator
   - No validation occurs on A's candidacy status

5. The consensus contract uses this result to generate the next term's miner list: [10](#0-9) [11](#0-10) 

**Why Existing Protections Fail:**

The prevention of initial miners announcing election only works one direction: [12](#0-11) 

This prevents initial miners from becoming candidates, but doesn't prevent quit candidates from entering `InitialMiners` through replacement.

## Impact Explanation

**Critical Consensus Integrity Violation:**
- A quit candidate who bypassed the election becomes a consensus validator
- They can produce blocks, participate in consensus decisions, and earn mining rewards
- This fundamentally violates the election-based validator selection mechanism where only candidates with community votes should become validators
- Token holders' votes are completely circumvented for validator selection

**High Authorization Bypass:**
- Quit candidates in `InitialMiners` retain admin management capabilities through `IsCurrentCandidateOrInitialMiner()` despite no longer being active candidates
- They can call `SetCandidateAdmin` and enable further `ReplaceCandidatePubkey` operations
- This creates a persistent, unaccountable validator position outside the election system
- The position can be perpetually maintained through cyclic replacements

**Protocol Governance Impact:**
- `InitialMiners` is designed for trusted bootstrap nodes that secure the network during launch
- Allowing arbitrary quit candidates to occupy these slots fundamentally undermines the bootstrap security model
- Legitimate candidates with actual votes are excluded from miner selection
- The attacker earns block production rewards without community approval or stake in the network's success

## Likelihood Explanation

**Attacker Capabilities Required:**
1. Ability to announce and quit election (publicly accessible - trivial)
2. Cooperation from or compromise of an initial miner's admin to authorize `ReplaceCandidatePubkey` (moderate barrier, but NOT a trusted role)
3. Period when valid candidates are insufficient (naturally occurring condition)

**Feasibility Assessment: Moderate**

The main barrier is obtaining initial miner admin cooperation. While initial miner admins are likely reputable entities controlling bootstrap infrastructure, they are NOT explicitly listed as "trusted roles" in the AElf threat model (unlike consensus system contracts or organization controllers). This makes the attack a matter of **mis-scoped privileges** rather than a trusted role compromise.

Initial miner admin cooperation could occur through:
- Key rotation scenarios where security procedures are lax
- Social engineering or economic incentives during periods of network stress
- Insider threats or compromised administrator accounts
- Legitimate disagreements about network governance

The insufficient candidates condition occurs naturally during:
- Network launch and early growth phases when participation is low
- Low participation periods during market downturns
- Following mass candidate withdrawal events
- Periods where validator economics are unfavorable

**Economic Rationality:**
- Benefits: Block production rewards, consensus influence, validator reputation
- Costs: 100k ELF deposit (fully recoverable after quit), cost of obtaining initial miner admin cooperation
- Attack becomes profitable if mining rewards over time exceed compromise costs

## Recommendation

**Fix 1: Validate NewPubkey in ReplaceCandidatePubkey**

Add validation that the new pubkey is either a current candidate or legitimately entitled to be in InitialMiners:

```csharp
public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
{
    Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
        "Pubkey is neither a current candidate nor an initial miner.");
    Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
        "Pubkey is in already banned.");
    
    // NEW: Validate new pubkey is a current candidate
    Assert(State.CandidateInformationMap[input.NewPubkey] != null && 
           State.CandidateInformationMap[input.NewPubkey].IsCurrentCandidate,
           "New pubkey must be a current candidate.");
    
    // ... rest of method
}
```

**Fix 2: Remove from InitialMiners in QuitElection**

Add logic to remove the pubkey from `InitialMiners` when quitting:

```csharp
public override Empty QuitElection(StringValue input)
{
    var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
    QuitElection(pubkeyBytes);
    
    // ... existing unlock and update logic ...
    
    // NEW: Remove from InitialMiners if present
    var initialMiners = State.InitialMiners.Value;
    var pubkeyByteString = ByteString.CopyFrom(pubkeyBytes);
    if (initialMiners != null && initialMiners.Value.Contains(pubkeyByteString))
    {
        initialMiners.Value.Remove(pubkeyByteString);
        State.InitialMiners.Value = initialMiners;
    }
    
    // ... rest of method
}
```

**Fix 3: Validate InitialMiners in GetVictories**

Add validation that InitialMiners are current candidates before using them as backups:

```csharp
private List<ByteString> GetVictories(List<string> currentMiners)
{
    var validCandidates = GetValidCandidates();
    
    // ... existing logic ...
    
    if (diff > 0)
    {
        victories = new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
        var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
        
        if (State.InitialMiners.Value != null)
        {
            // NEW: Only add InitialMiners that are current candidates
            var validInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !backups.Contains(k))
                .Where(k => State.CandidateInformationMap[k] != null && 
                           State.CandidateInformationMap[k].IsCurrentCandidate);
            backups.AddRange(validInitialMiners);
        }
        
        // ... rest of method
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated with the following test sequence:

```csharp
[Fact]
public async Task QuitCandidate_CanBecomeValidator_ViaInitialMinersReplacement()
{
    // Step 1: Attacker announces election with pubkey A
    var attackerKeyPair = CryptoHelper.GenerateKeyPair();
    var attackerPubkey = attackerKeyPair.PublicKey.ToHex();
    await ElectionContractStub.AnnounceElection.SendAsync(attackerAddress);
    
    // Verify A is a current candidate
    var candidateInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = attackerPubkey });
    candidateInfo.IsCurrentCandidate.ShouldBeTrue();
    
    // Step 2: Attacker quits election
    await ElectionContractStub.QuitElection.SendAsync(new StringValue { Value = attackerPubkey });
    
    // Verify A is no longer a current candidate
    candidateInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = attackerPubkey });
    candidateInfo.IsCurrentCandidate.ShouldBeFalse();
    
    // Step 3: Initial miner B's admin replaces B with A
    var initialMinerPubkey = InitialMiners[0];
    await ElectionContractStub.ReplaceCandidatePubkey.SendAsync(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = initialMinerPubkey,
        NewPubkey = attackerPubkey
    });
    
    // Step 4: GetVictories returns A as a validator when candidates insufficient
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // VULNERABILITY: Quit candidate A is selected as validator
    victories.Value.Select(v => v.ToHex()).ShouldContain(attackerPubkey);
}
```

This test proves that a quit candidate (with `IsCurrentCandidate = false`) can be selected as a consensus validator by being moved into the `InitialMiners` list through `ReplaceCandidatePubkey()`, completely bypassing the election process.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L21-22)
```csharp
        Assert(IsCurrentCandidateOrInitialMiner(input.Pubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L75-82)
```csharp
    private bool IsCurrentCandidateOrInitialMiner(string pubkey)
    {
        var isCurrentCandidate = State.CandidateInformationMap[pubkey] != null &&
                                 State.CandidateInformationMap[pubkey].IsCurrentCandidate;
        var isInitialMiner = State.InitialMiners.Value.Value.Contains(
            ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(pubkey)));
        return isCurrentCandidate || isInitialMiner;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L149-150)
```csharp
        Assert(!State.InitialMiners.Value.Value.Contains(pubkeyByteString),
            "Initial miner cannot announce election.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L252-253)
```csharp
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L298-298)
```csharp
        State.Candidates.Value.Value.Remove(publicKeyByteString);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L175-176)
```csharp
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L220-226)
```csharp
        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L246-246)
```csharp
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L60-76)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```
