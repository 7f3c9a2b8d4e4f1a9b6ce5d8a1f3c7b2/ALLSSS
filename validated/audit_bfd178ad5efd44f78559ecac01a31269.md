# Audit Report

## Title
Banned Candidates Persist in Election Snapshots Due to Incomplete Removal Logic

## Summary
The `GetPreviousTermSnapshotWithNewestPubkey()` function contains a critical logic flaw where banned candidates are not removed from election snapshots when their replacement pubkey already exists in the snapshot. This allows banned validators to be re-selected as consensus miners, directly bypassing the network's security ban mechanism and undermining consensus integrity.

## Finding Description

The vulnerability exists in the snapshot processing logic that handles banned candidates. When iterating through banned candidates, the code checks if the newest replacement pubkey already exists in the snapshot [1](#0-0) . If the replacement pubkey is already present, the code executes `continue` at line 154, which skips both the addition of the new pubkey (line 156) AND the removal of the banned candidate (line 157).

This creates a scenario where:

1. A banned candidate's pubkey remains in the election snapshot with full vote weight
2. The snapshot is consumed by the consensus contract to select alternative miners
3. No filtering for banned pubkeys occurs in the candidate selection logic

**Exploitation Path:**

The attack leverages legitimate contract operations in sequence:

- **Step 1**: Candidate B quits election via `QuitElection()`, which removes B from the candidates list [2](#0-1) 

- **Step 2**: Candidate A is marked as evil/banned through `UpdateCandidateInformation()`, which sets `State.BannedPubkeyMap[A] = true` [3](#0-2) 

- **Step 3**: A's admin replaces A's pubkey with B's pubkey via `ReplaceCandidatePubkey()`. This succeeds because the only check is whether the new pubkey is already in the candidates list [4](#0-3) , and since B quit, B is not in the list.

- **Step 4**: When `GetMinerReplacementInformation()` is called to find alternative miners, it retrieves the processed snapshot [5](#0-4) . If a historical snapshot contains both A and B, the banned candidate A remains in the processed snapshot due to the logic flaw.

- **Step 5**: The alternative selection logic filters out initial miners and current miners but **does not filter banned pubkeys** [6](#0-5) . Note that banned pubkey filtering only occurs for fallback initial miners [7](#0-6) , not for snapshot candidates.

- **Step 6**: The consensus contract directly uses the alternative candidate without additional validation, transferring the evil miner's time slot and order to the banned candidate [8](#0-7) 

- **Step 7**: During block production validation, `MiningPermissionValidationProvider` only checks if the sender is in the current round's miner list, with no banned pubkey validation [9](#0-8) 

This breaks the security invariant that banned validators cannot participate in consensus.

## Impact Explanation

**Critical Consensus Security Violation:**

The vulnerability directly undermines the network's ability to permanently exclude malicious or compromised validators. When a node is marked as evil, the intention is permanent exclusion from consensus participation. However, this bug allows banned candidates to:

- Retain their historical vote weight in election snapshots
- Be selected as replacement miners by the consensus contract
- Resume block production and consensus participation
- Potentially collect mining rewards

**Quantified Impact:**

- A banned candidate with high vote count from previous terms has selection priority based on vote ordering
- The consensus contract transfers the evil miner's consensus information (time slot, order, extra block producer status) directly to the banned candidate
- No additional validation checks occur at any stage once the alternative is selected

**Affected Parties:**

- **Network integrity**: Compromised or malicious nodes regain validator privileges
- **Honest validators**: Must operate alongside previously-banned nodes
- **Token holders**: Network security is degraded, putting staked value at risk

The severity is **High** because it directly compromises the consensus security model and the network's ability to enforce validator bans.

## Likelihood Explanation

**Realistic Attack Scenario:**

The vulnerability is exploitable through a sequence of legitimate contract operations:

1. **Historical Setup**: Multiple candidates participate in elections across several terms, building vote history
2. **Trigger Event**: One candidate quits election (normal operation)
3. **Ban Event**: Another candidate is detected as malicious and banned (security response)
4. **Exploitation**: The banned candidate's admin replaces the banned pubkey with the quit candidate's pubkey
5. **Automatic Execution**: During round transitions, the consensus contract queries historical snapshots and the banned candidate is automatically selected

**Feasibility Analysis:**

- All operations are accessible to candidate admins (unprivileged actors)
- No special permissions or timing windows required beyond normal admin control
- The bug triggers automatically during the consensus contract's routine snapshot processing
- Detection is difficult because pubkey replacement appears legitimate
- A sophisticated attacker controlling multiple candidate identities could orchestrate this

**Probability Assessment:**

Medium likelihood because:
- Requires coordination of specific events (quit + ban + replacement) 
- All events are normal operations that occur naturally in the protocol
- Once conditions are met, the vulnerability triggers automatically without additional attacker intervention
- The scenario becomes more likely in networks with frequent candidate turnover

The combination of High impact and Medium likelihood makes this a significant security concern requiring immediate remediation.

## Recommendation

Add banned pubkey filtering in the candidate selection logic within `GetMinerReplacementInformation()`. Specifically, after line 373 where current miners are filtered out, add an additional filter to exclude banned candidates:

```csharp
// In ViewMethods.cs, around line 374
var maybeNextCandidates = latestSnapshot.ElectionResult
    // Except initial miners.
    .Where(cs =>
        !State.InitialMiners.Value.Value.Contains(
            ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
    // Except current miners.
    .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
    // ADD THIS: Except banned pubkeys
    .Where(cs => !State.BannedPubkeyMap[cs.Key])
    .OrderByDescending(s => s.Value).ToList();
```

This ensures that even if a banned candidate remains in the snapshot due to the logic flaw, they will not be selected as an alternative miner.

**Alternative/Additional Fix:**

Fix the root cause in `GetPreviousTermSnapshotWithNewestPubkey()` by ensuring banned candidates are always removed from the snapshot, even when their replacement pubkey already exists:

```csharp
// In ViewMethods.cs, around line 149
foreach (var bannedCandidate in bannedCandidates)
{
    var newestPubkey = GetNewestPubkey(bannedCandidate);
    // Always remove the banned candidate first
    if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) 
        snapshot.ElectionResult.Remove(bannedCandidate);
    
    // Then add replacement if valid
    if (newestPubkey != null && newestPubkey != bannedCandidate &&
        !snapshot.ElectionResult.ContainsKey(newestPubkey))
    {
        var electionResult = snapshot.ElectionResult[bannedCandidate]; // This needs adjustment
        snapshot.ElectionResult.Add(newestPubkey, electionResult);
    }
}
```

Note: The second fix requires storing the vote count before removal.

## Proof of Concept

A proof of concept test would follow this sequence:

1. Initialize multiple candidates (A and B) in term T-1 with votes, creating a snapshot
2. In term T, have candidate B call `QuitElection()`
3. Mark candidate A as evil via consensus contract calling `UpdateCandidateInformation()` with `IsEvilNode = true`
4. As A's admin, call `ReplaceCandidatePubkey()` to replace A with B's pubkey
5. Trigger `GetMinerReplacementInformation()` and verify that A appears in the alternative candidates list
6. Verify that the consensus contract would accept A as a miner in the next round

The test would demonstrate that despite being banned, candidate A can be selected as an alternative miner and participate in consensus, violating the security invariant that banned nodes cannot produce blocks.

## Notes

This vulnerability represents a significant gap in the defense-in-depth strategy for consensus security. While the banned pubkey map is correctly maintained, the snapshot processing logic contains an edge case that allows banned candidates to persist. The lack of banned pubkey filtering in multiple validation points (snapshot selection, consensus alternative selection, and block production validation) allows this flaw to propagate through the entire consensus flow.

The vulnerability is particularly concerning because it can be triggered through normal protocol operations without requiring any privileged access, and detection is difficult since pubkey replacements are legitimate administrative operations.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L149-158)
```csharp
        foreach (var bannedCandidate in bannedCandidates)
        {
            var newestPubkey = GetNewestPubkey(bannedCandidate);
            // If newest pubkey not exists or same as old pubkey (which is banned), skip.
            if (newestPubkey == null || newestPubkey == bannedCandidate ||
                snapshot.ElectionResult.ContainsKey(newestPubkey)) continue;
            var electionResult = snapshot.ElectionResult[bannedCandidate];
            snapshot.ElectionResult.Add(newestPubkey, electionResult);
            if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) snapshot.ElectionResult.Remove(bannedCandidate);
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-363)
```csharp
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L368-377)
```csharp
            var maybeNextCandidates = latestSnapshot.ElectionResult
                // Except initial miners.
                .Where(cs =>
                    !State.InitialMiners.Value.Value.Contains(
                        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
                // Except current miners.
                .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
                .OrderByDescending(s => s.Value).ToList();
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L389-389)
```csharp
                .Where(k => !State.BannedPubkeyMap[k])
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L298-298)
```csharp
        State.Candidates.Value.Value.Remove(publicKeyByteString);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L96-96)
```csharp
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L191-191)
```csharp
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L313-338)
```csharp
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```
