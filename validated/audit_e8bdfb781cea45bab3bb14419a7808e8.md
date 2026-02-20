# Audit Report

## Title
LockTimeMap Entries Not Removed After Withdrawal Causing Storage Bloat and Vote ID Reuse Denial of Service

## Summary
The Election contract's `Vote` method uses `LockTimeMap` as both a data store and an existence indicator, but the `Withdraw` method fails to remove entries from this map. This causes permanent denial of service for users utilizing custom tokens to generate deterministic vote IDs, as they cannot reuse those tokens after withdrawal. Additionally, this leads to unbounded storage accumulation over the chain's lifetime.

## Finding Description

The vulnerability stems from improper lifecycle management of the `LockTimeMap` state variable, which maps vote IDs to lock durations.

**Vote Creation Flow**: The `Vote` method generates a vote ID and checks if `LockTimeMap[voteId] == 0` to determine if a vote already exists. [1](#0-0)  If the value is zero (the default for uninitialized map entries), the vote is considered non-existent and creation proceeds. The lock time is then stored at this key. [2](#0-1) 

**Vote ID Generation**: When users provide a custom token in `VoteMinerInput`, the `GenerateVoteId` method produces a deterministic vote ID using `Context.GenerateId(Context.Self, voteMinerInput.Token)`. [3](#0-2)  This means the same token always generates the same vote ID for the same sender. This is documented as an intended feature in the protobuf definition. [4](#0-3) 

**Vote Withdrawal Flow**: The `Withdraw` method reads from `LockTimeMap` to validate that the lock period has expired [5](#0-4) , but crucially never removes the entry. While it removes the `WeightsAlreadyFixedMap` entry [6](#0-5) , the `LockTimeMap` entry persists indefinitely throughout the entire withdrawal process. [7](#0-6) 

**State Mismatch**: The underlying Vote contract correctly tracks withdrawn votes by setting `IsWithdrawn = true` in the voting record [8](#0-7) , but the Election contract's `LockTimeMap` does not reflect this state change, creating a semantic inconsistency.

**Attack Scenario**:
1. User votes using custom token "X", generating `voteId = GenerateId(Self, "X")`
2. `LockTimeMap[voteId]` is set to 100 days (8,640,000 seconds)
3. After 100 days, user successfully withdraws
4. `LockTimeMap[voteId]` still contains 8,640,000 (not removed)
5. User attempts to vote again with token "X"
6. Same `voteId` is generated deterministically
7. Check `LockTimeMap[voteId] == 0` fails (value is 8,640,000)
8. Transaction reverts with "Vote already exists"
9. User is permanently blocked from reusing token "X"

## Impact Explanation

**Primary Impact - Denial of Service**: Users who utilize custom tokens for deterministic vote ID generation are permanently prevented from reusing those tokens after withdrawal. This breaks the intended functionality where users should be able to vote again after their lock period expires. The custom token feature is explicitly documented and tested [9](#0-8) , confirming this as a legitimate and intended use case, not an edge case.

**Secondary Impact - Storage Bloat**: Every vote creates a permanent `LockTimeMap` entry that is never cleaned up. The map is defined as `MappedState<Hash, long>` [10](#0-9) , and with continuous voting activity over the chain's lifetime, this leads to unbounded storage growth.

**Tertiary Impact - Incorrect State Representation**: The contract misuses `LockTimeMap` as an existence indicator, creating a semantic mismatch. Withdrawn votes (which have `IsWithdrawn = true` in the Vote contract) incorrectly appear as "existing" in the Election contract's logic.

## Likelihood Explanation

This issue has **HIGH** likelihood of occurrence:

**No Special Privileges Required**: The vulnerability affects the public `Vote` method accessible to all users. No governance approval, special roles, or elevated permissions are needed.

**Expected Usage Pattern**: Custom tokens are an explicitly documented feature. The proto definition includes the field with the comment "Used to generate vote id", and the test suite demonstrates this functionality, confirming it as intended behavior.

**Deterministic Occurrence**: Every withdrawal when using custom tokens results in the inability to reuse that token. The issue triggers automatically through normal contract usage without requiring special conditions, timing, or external dependencies.

**Detection Difficulty**: Users discover the problem only when attempting to reuse a token after withdrawal. The storage bloat occurs silently without any visible errors or warnings.

## Recommendation

Implement proper cleanup of `LockTimeMap` entries during withdrawal. Add the following line after the lock time validation in the `Withdraw` method:

```csharp
State.LockTimeMap.Remove(input);
```

This should be placed after line 636 where the lock time is validated but before the method continues. Alternatively, if historical lock time data is required, implement a separate existence check mechanism (similar to `WeightsAlreadyFixedMap`) that is properly cleaned up on withdrawal, decoupling the data storage concern from the existence check concern.

## Proof of Concept

```csharp
[Fact]
public async Task LockTimeMap_NotRemoved_After_Withdrawal_DoS_Test()
{
    // Setup: Announce candidate and prepare voter
    const long voteAmount = 100;
    const int lockTimeInDays = 100;
    var candidatesKeyPairs = await ElectionContract_AnnounceElection_Test();
    var candidateKeyPair = candidatesKeyPairs[0];
    var customToken = HashHelper.ComputeFrom("my_custom_token");
    
    // Step 1: Vote with custom token
    var voteRet = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = voteAmount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTimeInDays * 86400),
        Token = customToken
    });
    voteRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var voteId = Hash.Parser.ParseFrom(voteRet.TransactionResult.ReturnValue);
    
    // Step 2: Wait for lock period to expire and withdraw
    BlockTimeProvider.SetBlockTime(TimestampHelper.GetUtcNow().AddSeconds((lockTimeInDays + 1) * 86400));
    var withdrawRet = await ElectionContractStub.Withdraw.SendAsync(voteId);
    withdrawRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Attempt to vote again with same custom token - THIS SHOULD SUCCEED BUT FAILS
    var secondVoteRet = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = voteAmount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTimeInDays * 86400),
        Token = customToken // Same custom token
    });
    
    // BUG: Transaction reverts with "Vote already exists" even though we withdrew
    // Expected: TransactionResultStatus.Mined
    // Actual: TransactionResultStatus.Failed with error "Vote already exists."
    secondVoteRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    secondVoteRet.TransactionResult.Error.ShouldContain("Vote already exists");
}
```

## Notes

The root cause is that `LockTimeMap` serves dual purposes: (1) storing lock duration data for validation, and (2) acting as an existence indicator. When a vote is withdrawn, the data remains for potential historical queries, but this prevents the existence check from working correctly for vote ID reuse. The fix requires either removing the entry (if historical data isn't needed) or introducing a separate, properly-maintained existence tracking mechanism.

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L404-405)
```csharp
        if (voteMinerInput.Token != null)
            return Context.GenerateId(Context.Self, voteMinerInput.Token);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L433-433)
```csharp
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L434-434)
```csharp
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

**File:** protobuf/election_contract.proto (L297-298)
```text
    // Used to generate vote id.
    aelf.Hash token = 4;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L203-203)
```csharp
        votingRecord.IsWithdrawn = true;
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L236-250)
```csharp
    public async Task ElectionContract_Vote_With_Token_Test()
    {
        var amount = 100;
        const int lockTime = 100 * 60 * 60 * 24;
        var candidatesKeyPairs = await ElectionContract_AnnounceElection_Test();
        var candidateKeyPair = candidatesKeyPairs[0];
        var voteRet = await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
        {
            CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
            Amount = amount,
            EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime),
            Token = HashHelper.ComputeFrom("token A")
        });
        voteRet.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L38-38)
```csharp
    public MappedState<Hash, long> LockTimeMap { get; set; }
```
