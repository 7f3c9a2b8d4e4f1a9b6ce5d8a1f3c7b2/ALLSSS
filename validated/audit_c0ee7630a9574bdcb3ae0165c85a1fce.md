# Audit Report

## Title
Vote ID Collision Causing Permanent Denial of Service for Specific Candidate Vote Counts

## Summary
The Election contract's vote ID generation mechanism creates deterministic IDs based on a candidate's current active vote count. When votes are withdrawn, the `LockTimeMap` entries are never cleaned up, causing vote count values to become permanently "poisoned." Future votes generating the same ID will fail the collision check, resulting in a permanent denial of service for legitimate voters.

## Finding Description

The vulnerability exists in the interaction between three critical functions in the Election contract:

**Vote ID Generation Logic:**
When the optional `Token` field is not provided (standard usage pattern), the `GenerateVoteId()` function generates vote IDs deterministically by hashing the contract address, candidate's public key, and the candidate's **current** `ObtainedActiveVotedVotesAmount`. [1](#0-0) 

The protobuf definition shows `Token` is an optional field [2](#0-1) , and test helpers confirm it is typically not provided in standard usage [3](#0-2) .

**Vote Creation Check:**
The `Vote()` function generates a vote ID and asserts that no vote with this ID already exists by checking `State.LockTimeMap[voteId] == 0`. If the check passes, it stores the lock time in the map. [4](#0-3) 

**Missing Cleanup in Withdrawal:**
The `Withdraw()` function decreases the candidate's `ObtainedActiveVotedVotesAmount`, allowing the vote count to return to previous values. [5](#0-4) 

However, during withdrawal, while `WeightsAlreadyFixedMap` is explicitly cleaned up, the `LockTimeMap` entry is never removed. [6](#0-5) 

**Root Cause:**
The vote ID generation depends on a mutable value (`ObtainedActiveVotedVotesAmount`) that can decrease through withdrawals and cycle back to previous values. However, the collision-detection map (`LockTimeMap`) persists indefinitely, creating vote ID collisions across different time periods.

**Attack Scenario:**
1. Candidate starts with `ObtainedActiveVotedVotesAmount = 0`
2. Alice votes 100 tokens → generates `voteId` based on count=0, stores in `LockTimeMap`
3. Candidate now has 100 active votes
4. Lock period expires, Alice withdraws → candidate returns to 0 active votes
5. `LockTimeMap[voteId]` still contains the old lock time (never removed)
6. Bob attempts to vote for the same candidate with any amount when count=0
7. System generates the same `voteId` (deterministic based on count=0)
8. Vote fails at assertion: "Vote already exists."

## Impact Explanation

**Denial of Service Impact:**
- Legitimate users are permanently blocked from voting for a candidate whenever the candidate's active vote count returns to a previously-used value
- An attacker can deliberately "poison" sequential vote count values (0, 1, 2, ..., N) by creating and withdrawing small votes at each count level
- The capital cost is minimal since tokens are returned after withdrawal (only gas fees incurred)
- Once poisoned, these vote count values remain unusable forever since `LockTimeMap` entries are never cleared

**Affected Components:**
- All future voters attempting to vote when candidate vote counts match poisoned values
- The candidates themselves, who cannot receive new votes at certain vote count thresholds
- The election system's integrity, as vote distribution becomes artificially constrained

**Severity Justification:**
This is a HIGH severity issue because it breaks a core function of the Election contract. The voting mechanism is fundamental to AElf's governance system, and preventing legitimate users from voting constitutes a critical operational failure that undermines the democratic process and consensus mechanism.

## Likelihood Explanation

**Natural Occurrence:**
This vulnerability will manifest naturally through normal operations without malicious actors. As users vote and withdraw over time, vote counts naturally fluctuate. When a candidate's vote count decreases (through withdrawals) and later returns to a previous value (through new votes), the collision will occur automatically.

**Attacker Capabilities Required:**
- Access to the public `Vote()` function (no privileges needed)
- Minimal token amount (even 1 token per count value)
- Patience to wait for minimum lock periods to expire

**Attack Complexity:**
LOW - The attack sequence is straightforward:
1. Vote for a candidate with minimal amounts at sequential vote count values (0, 1, 2, ...)
2. Wait for minimum lock periods to expire
3. Withdraw all votes
4. All those count values are now permanently unusable by any future voter

**Economic Rationality:**
- Attack cost is near zero: tokens are fully returned after withdrawal
- Only transaction gas fees are consumed
- High impact (DoS of voting) relative to minimal cost makes this highly exploitable
- Count value 0 is especially critical as it's the starting state for all candidates

**Probability Assessment:**
HIGH - The vulnerability will trigger naturally through legitimate usage patterns as the system matures and users regularly vote and withdraw.

## Recommendation

The issue can be fixed by removing the `LockTimeMap` entry during vote withdrawal, similar to how `WeightsAlreadyFixedMap` is already being cleaned up.

Add the following line in the `Withdraw()` function after the lock time validation:

```csharp
State.LockTimeMap.Remove(input);
```

This should be added immediately after line 636 (after the lock time assertion) or alongside the `WeightsAlreadyFixedMap.Remove(input)` call at line 668.

Alternatively, consider redesigning the vote ID generation to include additional entropy (such as voter address or timestamp) to prevent collisions when vote counts cycle, though this would be a more significant change.

## Proof of Concept

```csharp
[Fact]
public async Task Vote_ID_Collision_DoS_Test()
{
    // Setup: Announce a candidate
    var candidateKeyPair = ValidationDataCenterKeyPairs[0];
    await ElectionContractStub.AnnounceElection.SendAsync(
        Address.FromPublicKey(candidateKeyPair.PublicKey));
    
    const int lockTime = 90 * 60 * 60 * 24; // 90 days (minimum)
    var amount = 100;
    
    // Step 1: Alice votes when candidate has 0 votes
    var aliceKeyPair = VoterKeyPairs[0];
    var aliceStub = GetElectionContractTester(aliceKeyPair);
    var voteResult1 = await aliceStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = amount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
        // Note: No Token field provided (standard usage)
    });
    voteResult1.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var voteId1 = voteResult1.Output;
    
    // Step 2: Wait for lock period to expire
    BlockTimeProvider.SetBlockTime(StartTimestamp.AddSeconds(lockTime + 1));
    
    // Step 3: Alice withdraws, returning candidate vote count to 0
    var withdrawResult = await aliceStub.Withdraw.SendAsync(voteId1);
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify candidate vote count is back to 0
    var candidateVotes = await ElectionContractStub.GetCandidateVote.CallAsync(
        new StringValue { Value = candidateKeyPair.PublicKey.ToHex() });
    candidateVotes.ObtainedActiveVotedVotesAmount.ShouldBe(0);
    
    // Step 4: Bob tries to vote when candidate has 0 votes (same as Alice's initial state)
    var bobKeyPair = VoterKeyPairs[1];
    var bobStub = GetElectionContractTester(bobKeyPair);
    var voteResult2 = await bobStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
        Amount = amount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
        // Note: No Token field provided (standard usage)
    });
    
    // VULNERABILITY: Bob's vote fails due to vote ID collision
    // The assertion "Vote already exists" is triggered
    voteResult2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    voteResult2.TransactionResult.Error.ShouldContain("Vote already exists");
}
```

## Notes

The vulnerability is confirmed through code analysis showing that `LockTimeMap` entries are never removed anywhere in the codebase. The grep search for "LockTimeMap.Remove" returns zero results, proving this cleanup operation does not exist. This creates a permanent state pollution where historical vote IDs can block future legitimate votes when vote counts cycle back to previous values.

The issue is particularly severe for vote count value 0, which is the initial state for all new candidates and will be frequently revisited as the first voter withdraws their vote. This makes the vulnerability highly likely to trigger in normal operations without any malicious intent.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L432-434)
```csharp
        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L656-660)
```csharp
        candidateVotes.ObtainedActiveVotingRecordIds.Remove(input);
        candidateVotes.ObtainedWithdrawnVotingRecordIds.Add(input);
        candidateVotes.ObtainedActiveVotedVotesAmount =
            candidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
        State.CandidateVotes[newestPubkey] = candidateVotes;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L665-669)
```csharp
        if (!State.WeightsAlreadyFixedMap[input])
        {
            RemoveBeneficiaryOfVoter();
            State.WeightsAlreadyFixedMap.Remove(input);
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

**File:** test/AElf.Contracts.Election.Tests/ElectionContractTestHelpers.cs (L92-104)
```csharp
    private async Task<TransactionResult> VoteToCandidateAsync(ECKeyPair voterKeyPair, string candidatePublicKey,
        long lockTime, long amount)
    {
        var electionStub = GetElectionContractTester(voterKeyPair);
        var voteResult = (await electionStub.Vote.SendAsync(new VoteMinerInput
        {
            CandidatePubkey = candidatePublicKey,
            Amount = amount,
            EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
        })).TransactionResult;

        return voteResult;
    }
```
