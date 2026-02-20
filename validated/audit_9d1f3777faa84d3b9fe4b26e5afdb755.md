# Audit Report

## Title
Miners Lose Term Credit When Replacing Pubkey Before Term End Due to Stale Round Data

## Summary
When a miner replaces their public key via `ReplaceCandidatePubkey`, the Election contract removes the old pubkey's `CandidateInformation` from state. However, the Consensus contract's stored round data retains references to the old pubkey. At term end, `TakeSnapshot` retrieves miners from stale round data and attempts to update their participation history, but fails due to an early return when the old pubkey's `CandidateInformation` is null, causing miners to permanently lose credit for terms where they actively produced blocks.

## Finding Description

This vulnerability arises from a data consistency issue between the Election and Consensus contracts during pubkey replacement.

**Root Cause:**

When `ReplaceCandidatePubkey` is executed, the Election contract transfers the candidate's information to the new pubkey and explicitly removes the old pubkey's entry: [1](#0-0) 

The method then notifies the Consensus contract via `RecordCandidateReplacement`, which only updates the **current** round's miner information: [2](#0-1) 

Previous rounds stored in `State.Rounds[roundNumber]` remain unchanged and continue referencing the old pubkey.

**Failure Point:**

At term end, the Consensus contract calls `TakeSnapshot` on the Election contract. This method retrieves the previous term's miners by calling `GetPreviousTermMinerPubkeyList`: [3](#0-2) 

The `GetPreviousTermMinerPubkeyList` method returns pubkeys directly from stored round data without any pubkey resolution: [4](#0-3) 

For each returned pubkey, the private `UpdateCandidateInformation` method is called, which has a critical early return when `candidateInformation` is null: [5](#0-4) 

Since the old pubkey's entry was removed during replacement, the method returns at line 485 without updating the `Terms` list (line 486) or `ContinualAppointmentCount` (lines 488-490).

**Why Existing Protections Fail:**

The codebase includes a `GetNewestPubkey` function specifically designed to resolve old pubkeys to their newest replacements: [6](#0-5) 

This function is correctly used in other contexts, such as when resolving vote records: [7](#0-6) 

A dedicated method `GetPreviousTermSnapshotWithNewestPubkey` even applies this mapping for snapshot queries: [8](#0-7) 

However, `TakeSnapshot` does not call `GetNewestPubkey` before updating candidate information, causing it to use stale pubkeys.

## Impact Explanation

**Direct Impact:**

Miners who replace their public keys lose historical participation credit. The `Terms` field, documented as "The number of terms that the candidate is elected", becomes incomplete: [9](#0-8) 

Similarly, `ContinualAppointmentCount` tracking breaks, preventing accurate measurement of consecutive term participation.

**Severity:**

This is a **High** severity issue because:
- It violates the fundamental election system invariant that miners receive credit for active participation
- Historical participation records are critical for DPoS transparency and voter decision-making
- The `CandidateInformation` structure is designed to maintain complete participation history for accountability
- Any future logic depending on the `Terms` list for rewards, eligibility, or reputation would disadvantage affected miners
- Voters and off-chain systems lose access to accurate miner performance data

## Likelihood Explanation

**Trigger Conditions:**
1. A miner calls `ReplaceCandidatePubkey` (requires only candidate admin privileges)
2. The term ends while the new pubkey is active
3. The Consensus contract automatically calls `TakeSnapshot`

**Probability:**

This issue has **High** likelihood because:
- `ReplaceCandidatePubkey` is a legitimate operational feature for key rotation
- Key rotation is a common security practice for operational reasons (compromised keys, hardware failures, organizational changes)
- The vulnerability triggers deterministically without user awareness
- No warnings inform users that pubkey replacement causes term credit loss
- Every term end after replacement reliably triggers the bug

The "attacker" is actually any legitimate user exercising the pubkey replacement feature - no malicious intent required.

## Recommendation

Modify the `TakeSnapshot` method to resolve old pubkeys to their newest versions before updating candidate information:

```csharp
foreach (var pubkey in previousTermMinerList)
{
    // Resolve to newest pubkey before updating
    var newestPubkey = GetNewestPubkey(pubkey);
    UpdateCandidateInformation(newestPubkey, input.TermNumber, previousTermMinerList);
}
```

Alternatively, modify `GetPreviousTermMinerPubkeyList` in the Consensus contract to automatically resolve pubkeys using the Election contract's `GetNewestPubkey` method before returning the list.

## Proof of Concept

```csharp
// Test: Miner loses term credit after pubkey replacement
[Fact]
public async Task MinerLosesTermCreditAfterPubkeyReplacement()
{
    // Setup: Initialize term 1 with a miner
    var oldPubkey = "old_pubkey_hex";
    var newPubkey = "new_pubkey_hex";
    
    // Step 1: Miner is active in term 1
    var candidateInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = oldPubkey });
    Assert.Empty(candidateInfo.Terms);
    
    // Step 2: Replace pubkey during term
    await ElectionContractStub.ReplaceCandidatePubkey.SendAsync(
        new ReplaceCandidatePubkeyInput { OldPubkey = oldPubkey, NewPubkey = newPubkey });
    
    // Step 3: Term ends, TakeSnapshot is called
    await ConsensusContractStub.NextTerm.SendAsync(new NextTermInput { /* ... */ });
    
    // Step 4: Verify old pubkey has no CandidateInformation
    var oldInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = oldPubkey });
    Assert.Null(oldInfo.Pubkey); // Removed during replacement
    
    // Step 5: Verify new pubkey's Terms list is INCOMPLETE (bug)
    var newInfo = await ElectionContractStub.GetCandidateInformation.CallAsync(
        new StringValue { Value = newPubkey });
    Assert.DoesNotContain(1L, newInfo.Terms); // Term 1 credit LOST
    
    // Expected: newInfo.Terms should contain term 1
    // Actual: newInfo.Terms is empty - miner lost credit
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L237-243)
```csharp
        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L331-357)
```csharp
    public override StringValue GetNewestPubkey(StringValue input)
    {
        return new StringValue { Value = GetNewestPubkey(input.Value) };
    }

    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
    }

    private string GetNewestPubkey(string pubkey)
    {
        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        return State.InitialToNewestPubkeyMap[initialPubkey] ?? initialPubkey;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L430-434)
```csharp
        var previousTermMinerList =
            State.AEDPoSContract.GetPreviousTermMinerPubkeyList.Call(new Empty()).Pubkeys.ToList();

        foreach (var pubkey in previousTermMinerList)
            UpdateCandidateInformation(pubkey, input.TermNumber, previousTermMinerList);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L481-492)
```csharp
    private void UpdateCandidateInformation(string pubkey, long lastTermNumber,
        List<string> previousMiners)
    {
        var candidateInformation = State.CandidateInformationMap[pubkey];
        if (candidateInformation == null) return;
        candidateInformation.Terms.Add(lastTermNumber);
        var victories = GetVictories(previousMiners);
        candidateInformation.ContinualAppointmentCount = victories.Contains(ByteStringHelper.FromHexString(pubkey))
            ? candidateInformation.ContinualAppointmentCount.Add(1)
            : 0;
        State.CandidateInformationMap[pubkey] = candidateInformation;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-147)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L464-473)
```csharp
    public override PubkeyList GetPreviousTermMinerPubkeyList(Empty input)
    {
        var lastRoundNumber = State.FirstRoundNumberOfEachTerm[State.CurrentTermNumber.Value].Sub(1);
        var lastRound = State.Rounds[lastRoundNumber];
        if (lastRound == null || lastRound.RoundId == 0) return new PubkeyList();
        return new PubkeyList
        {
            Pubkeys = { lastRound.RealTimeMinersInformation.Keys }
        };
    }
```

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L337-354)
```csharp
    private ElectionVotingRecord TransferVotingRecordToElectionVotingRecord(VotingRecord votingRecord, Hash voteId)
    {
        var lockSeconds = State.LockTimeMap[voteId];
        return new ElectionVotingRecord
        {
            Voter = votingRecord.Voter,
            Candidate = GetNewestPubkey(votingRecord.Option),
            Amount = votingRecord.Amount,
            TermNumber = votingRecord.SnapshotNumber,
            VoteId = voteId,
            LockTime = lockSeconds,
            VoteTimestamp = votingRecord.VoteTimestamp,
            WithdrawTimestamp = votingRecord.WithdrawTimestamp,
            UnlockTimestamp = votingRecord.VoteTimestamp.AddSeconds(lockSeconds),
            IsWithdrawn = votingRecord.IsWithdrawn,
            Weight = GetVotesWeight(votingRecord.Amount, lockSeconds),
            IsChangeTarget = votingRecord.IsChangeTarget
        };
```

**File:** protobuf/election_contract.proto (L365-380)
```text
message CandidateInformation {
    // Candidate’s public key.
    string pubkey = 1;
    // The number of terms that the candidate is elected.
    repeated int64 terms = 2;
    // The number of blocks the candidate has produced.
    int64 produced_blocks = 3;
    // The time slot for which the candidate failed to produce blocks.
    int64 missed_time_slots = 4;
    // The count of continual appointment.
    int64 continual_appointment_count = 5;
    // The transaction id when the candidate announced.
    aelf.Hash announcement_transaction_id = 6;
    // Indicate whether the candidate can be elected in the current term.
    bool is_current_candidate = 7;
}
```
