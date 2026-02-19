### Title
LockTimeMap Entries Not Removed After Withdrawal Causing Storage Bloat and Vote ID Reuse Denial of Service

### Summary
The Election contract's `LockTimeMap` state variable is set when votes are created but never removed when votes are withdrawn. This causes unbounded storage accumulation and prevents users from reusing custom vote tokens after withdrawal, as the existence check incorrectly treats withdrawn votes as still active.

### Finding Description

The vulnerability exists in the vote creation and withdrawal flow:

**Vote Creation** - When a user creates a vote, the lock time is stored in `LockTimeMap`: [1](#0-0) 

The contract checks if `LockTimeMap[voteId] == 0` to determine if a vote already exists (line 433), then sets the lock time (line 434).

**Vote Withdrawal** - When a vote is withdrawn, the `LockTimeMap` entry is read for validation but never removed: [2](#0-1) 

The withdrawal process validates the lock time has passed (lines 634-636) and removes `WeightsAlreadyFixedMap` entry (line 668), but critically does NOT remove the `LockTimeMap` entry.

**Vote ID Generation** - Users can provide custom tokens to generate deterministic vote IDs: [3](#0-2) 

When a token is provided, the same token will always generate the same vote ID (line 405).

**Token Field Documentation**: [4](#0-3) 

The token field (line 298) is documented as "Used to generate vote id", confirming this is an intended feature.

**No Removal Code Exists** - A comprehensive grep search of the codebase confirms no code removes `LockTimeMap` entries.

### Impact Explanation

**1. Storage Bloat**: Every vote creates a permanent `LockTimeMap` entry that is never cleaned up. Over time, as users vote and withdraw repeatedly, the map accumulates unbounded entries consuming contract storage indefinitely.

**2. Vote ID Reuse Denial of Service**: Users who provide custom tokens for deterministic vote ID generation cannot reuse those tokens after withdrawal. When they attempt to vote again with the same token:
- The same vote ID is generated
- The check at line 433 finds `LockTimeMap[voteId] != 0` (still contains the old lock time)
- Transaction reverts with "Vote already exists" even though the previous vote was withdrawn
- User is permanently blocked from using that token

**3. Incorrect State Representation**: The contract uses `LockTimeMap` as an existence check, but this incorrectly treats withdrawn votes (which have `IsWithdrawn = true` in the Vote contract) as still "existing". The proper check should verify if an active vote exists in the underlying Vote contract.

**Who is Affected**: All users who utilize the custom token feature for deterministic vote IDs (for operational tracking, accounting, or automation purposes) are permanently blocked from reusing their tokens after withdrawal.

### Likelihood Explanation

**Attacker Capabilities Required**: None - this affects normal users exercising legitimate functionality. Any user can:
1. Access the public `Vote` method
2. Provide a custom token (documented feature, used in tests)
3. Withdraw after lock period expires
4. Attempt to vote again with the same token

**Attack Complexity**: Trivial - the issue occurs naturally through normal usage: [5](#0-4) 

Tests demonstrate using custom tokens (line 247: `Token = HashHelper.ComputeFrom("token A")`), confirming this is expected functionality.

**Feasibility Conditions**: 
- No special permissions required
- Execution steps are straightforward contract calls
- Economic cost is only standard transaction fees
- Issue occurs deterministically on every withdrawal when using custom tokens

**Detection**: The storage bloat occurs silently. The DoS is discovered only when users attempt to reuse tokens post-withdrawal.

### Recommendation

**Immediate Fix**: Remove the `LockTimeMap` entry during withdrawal:

In `ElectionContract_Elector.cs` `Withdraw` method, add after line 668:
```csharp
State.LockTimeMap.Remove(input);
```

**Better Existence Check**: Replace the `LockTimeMap` check with a proper vote existence check that queries the Vote contract:
```csharp
var existingVote = State.VoteContract.GetVotingRecord.Call(voteId);
Assert(existingVote == null || existingVote.IsWithdrawn, "Active vote already exists with this ID.");
```

**State Cleanup**: The `LockTimeMap` should only track active votes:
- Set entry when vote is created (line 434)
- Remove entry when vote is withdrawn (new line after 668)
- Remove entry when vote target is changed (after line 48 in `ChangeVotingOption`)

**Test Case**: Add regression test verifying vote ID reuse after withdrawal:
1. Vote with custom token X
2. Withdraw after lock period
3. Vote again with same custom token X
4. Verify success and new vote is created

### Proof of Concept

**Initial State**: User Alice has sufficient ELF tokens, election contract is initialized with candidates.

**Transaction Sequence**:

1. **First Vote** - Alice votes with custom token:
```
ElectionContract.Vote({
    CandidatePubkey: "candidate_pubkey",
    Amount: 1000,
    EndTimestamp: now + 100 days,
    Token: Hash("alice_deterministic_token")
})
```
Result: Success. `voteId = GenerateId(contract, Hash("alice_deterministic_token"))`, `LockTimeMap[voteId] = 8640000` (100 days in seconds).

2. **Time Advance** - Wait 101 days.

3. **Withdrawal** - Alice withdraws her vote:
```
ElectionContract.Withdraw(voteId)
```
Result: Success. Vote marked as withdrawn, tokens unlocked, BUT `LockTimeMap[voteId]` still equals `8640000`.

4. **Second Vote Attempt** - Alice tries to vote again with same token:
```
ElectionContract.Vote({
    CandidatePubkey: "candidate_pubkey",
    Amount: 2000,
    EndTimestamp: now + 200 days,
    Token: Hash("alice_deterministic_token")  // Same token
})
```

**Expected Result**: Success - new vote created with new lock time.

**Actual Result**: Transaction reverts with assertion failure "Vote already exists" at line 433 because `LockTimeMap[voteId]` is non-zero (8640000), even though the previous vote was fully withdrawn.

**Success Condition**: Alice is permanently unable to use `Hash("alice_deterministic_token")` for any future votes, demonstrating the permanent DoS condition.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L402-412)
```csharp
    private Hash GenerateVoteId(VoteMinerInput voteMinerInput)
    {
        if (voteMinerInput.Token != null)
            return Context.GenerateId(Context.Self, voteMinerInput.Token);

        var candidateVotesCount =
            State.CandidateVotes[voteMinerInput.CandidatePubkey]?.ObtainedActiveVotedVotesAmount ?? 0;
        return Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(voteMinerInput.CandidatePubkey.GetBytes(),
                candidateVotesCount.ToBytes(false)));
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L421-434)
```csharp
    public override Hash Vote(VoteMinerInput input)
    {
        // Check candidate information map instead of candidates. 
        var targetInformation = State.CandidateInformationMap[input.CandidatePubkey];
        AssertValidCandidateInformation(targetInformation);

        var electorPubkey = Context.RecoverPublicKey();

        var lockSeconds = (input.EndTimestamp - Context.CurrentBlockTime).Seconds;
        AssertValidLockSeconds(lockSeconds);

        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L629-679)
```csharp
    public override Empty Withdraw(Hash input)
    {
        var votingRecord = State.VoteContract.GetVotingRecord.Call(input);

        var actualLockedTime = Context.CurrentBlockTime.Seconds.Sub(votingRecord.VoteTimestamp.Seconds);
        var claimedLockDays = State.LockTimeMap[input];
        Assert(actualLockedTime >= claimedLockDays,
            $"Still need {claimedLockDays.Sub(actualLockedTime).Div(86400)} days to unlock your token.");

        var voterPublicKey = Context.RecoverPublicKey();

        var voterVotes = GetElectorVote(voterPublicKey);

        Assert(voterVotes != null, $"Voter {Context.Sender.ToBase58()} never votes before");

        voterVotes.ActiveVotingRecordIds.Remove(input);
        voterVotes.WithdrawnVotingRecordIds.Add(input);
        voterVotes.ActiveVotedVotesAmount = voterVotes.ActiveVotedVotesAmount.Sub(votingRecord.Amount);

        State.ElectorVotes[Context.Sender.ToBase58()] = voterVotes;

        // Update Candidate's Votes information.
        var newestPubkey = GetNewestPubkey(votingRecord.Option);
        var candidateVotes = State.CandidateVotes[newestPubkey];

        Assert(candidateVotes != null, $"Newest pubkey {newestPubkey} is invalid. Old pubkey is {votingRecord.Option}");

        candidateVotes.ObtainedActiveVotingRecordIds.Remove(input);
        candidateVotes.ObtainedWithdrawnVotingRecordIds.Add(input);
        candidateVotes.ObtainedActiveVotedVotesAmount =
            candidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
        State.CandidateVotes[newestPubkey] = candidateVotes;

        UnlockTokensOfVoter(input, votingRecord.Amount);
        RetrieveTokensFromVoter(votingRecord.Amount);
        WithdrawTokensOfVoter(input);
        if (!State.WeightsAlreadyFixedMap[input])
        {
            RemoveBeneficiaryOfVoter();
            State.WeightsAlreadyFixedMap.Remove(input);
        }

        var rankingList = State.DataCentersRankingList.Value;
        if (!rankingList.DataCenters.ContainsKey(newestPubkey)) return new Empty();
        rankingList.DataCenters[newestPubkey] =
            rankingList.DataCenters[newestPubkey].Sub(votingRecord.Amount);
        UpdateDataCenterAfterMemberVoteAmountChanged(rankingList, newestPubkey);
        State.DataCentersRankingList.Value = rankingList;

        return new Empty();
    }
```

**File:** protobuf/election_contract.proto (L290-299)
```text
message VoteMinerInput {
    // The candidate public key.
    string candidate_pubkey = 1;
    // The amount token to vote.
    int64 amount = 2;
    // The end timestamp of this vote.
    google.protobuf.Timestamp end_timestamp = 3;
    // Used to generate vote id.
    aelf.Hash token = 4;
}
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L242-249)
```csharp
        var voteRet = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
        {
            CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
            Amount = amount,
            EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime),
            Token = HashHelper.ComputeFrom("token A")
        });
        voteRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
```
