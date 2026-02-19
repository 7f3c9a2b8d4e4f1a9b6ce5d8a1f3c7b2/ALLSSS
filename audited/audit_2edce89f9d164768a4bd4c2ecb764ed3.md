### Title
Banned Candidates Persist in Election Snapshots Due to Incomplete Removal Logic

### Summary
The `GetPreviousTermSnapshotWithNewestPubkey()` function fails to remove banned candidates from term snapshots when their newest replacement pubkey already exists in the snapshot. This allows banned candidates to remain in election results that are used by the consensus contract to select alternative miners, potentially enabling malicious or compromised nodes to be selected as validators.

### Finding Description

The vulnerability exists in the `GetPreviousTermSnapshotWithNewestPubkey()` function at lines 130-161. [1](#0-0) 

The root cause is in the banned candidate processing loop. When a banned candidate's newest pubkey is already present in the snapshot, the code executes `continue` to skip that candidate, but this prevents execution from reaching the removal logic at line 157. [2](#0-1) 

The specific problematic flow:
1. Line 151 retrieves the newest pubkey for a banned candidate
2. Line 153-154 checks if the newest pubkey already exists in the snapshot and skips if true
3. Line 156 adds the newest pubkey (only executed if the check passes)
4. Line 157 removes the banned candidate (only executed if the check passes)

**Why existing protections fail:** The check at line 154 `snapshot.ElectionResult.ContainsKey(newestPubkey)` is intended to prevent duplicate keys, but it has the unintended consequence of also preventing the removal of the banned candidate from the snapshot.

This processed snapshot is then consumed by `GetMinerReplacementInformation()` at line 363 [3](#0-2) , which uses it to select alternative candidates for miner replacement. Critically, the selection logic at lines 368-375 does NOT filter out banned pubkeys from the snapshot - it only excludes initial miners and current miners.

### Impact Explanation

**Consensus Integrity Compromise:**
- Banned candidates (marked as evil nodes or compromised) remain in election snapshots
- These banned candidates can be selected as replacement miners by the consensus contract
- The consensus contract calls `GetMinerReplacementInformation()` which relies on this flawed snapshot processing [4](#0-3) 

**Quantified Impact:**
- Banned candidates retain their full vote weight in the snapshot
- They can be selected as alternative miners with priority based on their vote count
- This bypasses the ban mechanism implemented in `UpdateCandidateInformation()` where evil nodes are banned [5](#0-4) 

**Who is affected:**
- The entire network's consensus mechanism
- All validators and token holders relying on honest miner selection
- Network security as malicious nodes could regain validator status

**Severity Justification:** Medium to High - While it requires specific preconditions, it directly undermines the consensus security model by allowing banned validators to be re-selected.

### Likelihood Explanation

**Attack Scenario:**
A realistic exploitation path exists:
1. Term N: Candidates A and B both participate with recorded votes
2. Snapshot is saved with both candidates' votes
3. Term N+1: Candidate B quits election (becomes non-candidate via `QuitElection()`) [6](#0-5) 
4. Term N+1: Candidate A (now malicious) is detected and banned
5. Term N+1: A's admin replaces A's pubkey with B's pubkey via `ReplaceCandidatePubkey()` - this is allowed because B is no longer a candidate [7](#0-6) 
6. Term N+2: When consensus needs replacement miners, it retrieves term N snapshot
7. The snapshot processing skips A because B already exists, leaving A (banned) in the results

**Feasibility:**
- Entry point: `GetMinerReplacementInformation()` is called by consensus contract (reachable)
- Preconditions: Requires a previous candidate to quit and a banned candidate to reuse that pubkey
- Execution: All steps are standard contract operations
- Detection: Difficult to detect as it appears as legitimate pubkey replacement

**Probability:** Medium - While it requires coordination of specific events, these are all normal operations that could occur naturally or be orchestrated by a malicious actor controlling multiple candidate identities.

### Recommendation

**Code-level fix:** Modify the banned candidate processing loop to always remove banned candidates from the snapshot, regardless of whether their replacement succeeds:

```csharp
foreach (var bannedCandidate in bannedCandidates)
{
    var newestPubkey = GetNewestPubkey(bannedCandidate);
    // Always remove the banned candidate first
    if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) 
        snapshot.ElectionResult.Remove(bannedCandidate);
    
    // Then try to add the newest pubkey if valid and not duplicate
    if (newestPubkey != null && newestPubkey != bannedCandidate &&
        !snapshot.ElectionResult.ContainsKey(newestPubkey))
    {
        var electionResult = snapshot.ElectionResult[bannedCandidate]; // Get before removal
        snapshot.ElectionResult.Add(newestPubkey, electionResult);
    }
}
```

**Alternative approach:** Add banned pubkey filtering in `GetMinerReplacementInformation()`:
```csharp
var maybeNextCandidates = latestSnapshot.ElectionResult
    .Where(cs => !State.BannedPubkeyMap[cs.Key]) // Add this check
    .Where(cs => !State.InitialMiners.Value.Value.Contains(...))
    .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
    .OrderByDescending(s => s.Value).ToList();
```

**Invariant checks to add:**
- Verify no banned pubkeys exist in processed snapshots
- Assert that all candidates in alternative candidate list are not banned
- Add unit tests covering pubkey replacement chains and quit-then-reuse scenarios

### Proof of Concept

**Initial State:**
- Term 1: Candidate A (pubkey "0xAAAA") has 1000 votes, Candidate B (pubkey "0xBBBB") has 500 votes
- Snapshot saved: {"0xAAAA": 1000, "0xBBBB": 500}

**Exploitation Steps:**
1. Term 2: Call `QuitElection("0xBBBB")` - B quits, no longer a candidate
2. Term 2: Consensus detects A as evil node, calls `UpdateCandidateInformation({Pubkey: "0xAAAA", IsEvilNode: true})`
   - A is marked as banned in `State.BannedPubkeyMap["0xAAAA"] = true`
3. Term 2: A's admin calls `ReplaceCandidatePubkey({OldPubkey: "0xAAAA", NewPubkey: "0xBBBB"})`
   - Succeeds because B is no longer a candidate
   - Maps A → B in replacement tracking
4. Term 3: Evil miner detected in current round, consensus calls `GetMinerReplacementInformation()`
5. Internally calls `GetPreviousTermSnapshotWithNewestPubkey()` on Term 1 snapshot
6. Processing:
   - `bannedCandidates = ["0xAAAA"]` (A is banned)
   - `GetNewestPubkey("0xAAAA")` returns "0xBBBB"
   - `snapshot.ElectionResult.ContainsKey("0xBBBB")` returns true
   - Executes `continue`, skips to next iteration
   - A is never removed from snapshot

**Expected vs Actual Result:**
- **Expected:** Snapshot = {"0xBBBB": 1000} (A removed, B inherits A's votes)
- **Actual:** Snapshot = {"0xAAAA": 1000, "0xBBBB": 500} (A remains despite being banned)

**Success Condition:** 
"0xAAAA" (banned candidate) appears in the `alternativeCandidates` list returned by `GetMinerReplacementInformation()`, allowing a banned node to be selected as a replacement miner.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L130-161)
```csharp
    private TermSnapshot GetPreviousTermSnapshotWithNewestPubkey()
    {
        var termNumber = State.CurrentTermNumber.Value.Sub(1);
        var snapshot = State.Snapshots[termNumber];
        if (snapshot == null) return null;
        var invalidCandidates = snapshot.ElectionResult.Where(r => r.Value <= 0).Select(r => r.Key).ToList();
        Context.LogDebug(() => $"Invalid candidates count: {invalidCandidates.Count}");
        foreach (var invalidCandidate in invalidCandidates)
        {
            Context.LogDebug(() => $"Invalid candidate detected: {invalidCandidate}");
            if (snapshot.ElectionResult.ContainsKey(invalidCandidate)) snapshot.ElectionResult.Remove(invalidCandidate);
        }

        if (!snapshot.ElectionResult.Any()) return snapshot;

        var bannedCandidates = snapshot.ElectionResult.Keys.Where(IsPubkeyBanned).ToList();
        Context.LogDebug(() => $"Banned candidates count: {bannedCandidates.Count}");
        if (!bannedCandidates.Any()) return snapshot;
        Context.LogDebug(() => "Getting snapshot and there's miner replaced during current term.");
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

        return snapshot;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-379)
```csharp
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
        // Check out election snapshot.
        if (latestSnapshot != null && latestSnapshot.ElectionResult.Any())
        {
            Context.LogDebug(() => $"Previous term snapshot:\n{latestSnapshot}");
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
            Context.LogDebug(() =>
                $"Found alternative miner from candidate list: {alternativeCandidates.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-257)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L229-280)
```csharp
    public override Empty QuitElection(StringValue input)
    {
        var pubkeyBytes = ByteArrayHelper.HexStringToByteArray(input.Value);
        QuitElection(pubkeyBytes);
        var pubkey = input.Value;

        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        Assert(Context.Sender == State.CandidateAdmins[initialPubkey], "Only admin can quit election.");
        var candidateInformation = State.CandidateInformationMap[pubkey];

        // Unlock candidate's native token.
        var lockId = candidateInformation.AnnouncementTransactionId;
        var lockVirtualAddress = Context.ConvertVirtualAddressToContractAddress(lockId);
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = lockVirtualAddress,
            To = State.CandidateSponsorMap[input.Value] ?? Address.FromPublicKey(pubkeyBytes),
            Symbol = Context.Variables.NativeSymbol,
            Amount = ElectionContractConstants.LockTokenForElection,
            Memo = "Quit election."
        });

        // Update candidate information.
        candidateInformation.IsCurrentCandidate = false;
        candidateInformation.AnnouncementTransactionId = Hash.Empty;
        State.CandidateInformationMap[pubkey] = candidateInformation;

        // Remove candidate public key from the Voting Item options.
        State.VoteContract.RemoveOption.Send(new RemoveOptionInput
        {
            VotingItemId = State.MinerElectionVotingItemId.Value,
            Option = pubkey
        });
        var dataCenterList = State.DataCentersRankingList.Value;
        if (dataCenterList.DataCenters.ContainsKey(pubkey))
        {
            dataCenterList.DataCenters[pubkey] = 0;
            UpdateDataCenterAfterMemberVoteAmountChanged(dataCenterList, pubkey, true);
            State.DataCentersRankingList.Value = dataCenterList;
        }

        var managedCandidatePubkey = State.ManagedCandidatePubkeysMap[Context.Sender];
        managedCandidatePubkey.Value.Remove(ByteString.CopyFrom(pubkeyBytes));
        if (managedCandidatePubkey.Value.Any())
            State.ManagedCandidatePubkeysMap[Context.Sender] = managedCandidatePubkey;
        else
            State.ManagedCandidatePubkeysMap.Remove(Context.Sender);

        State.CandidateSponsorMap.Remove(pubkey);

        return new Empty();
    }
```
