### Title
VotersCount Inflation Through Multiple Votes from Same Voter

### Summary
The `UpdateVotingResult` function unconditionally increments `VotersCount` by 1 for every vote without checking if the voter has already been counted. When the same voter votes multiple times with different VoteIds, VotersCount incorrectly inflates beyond the actual number of unique voters. This creates an accounting inconsistency where VotersCount can remain non-zero even after all votes are withdrawn.

### Finding Description
The vulnerability exists in the `UpdateVotingResult` function at line 178: [1](#0-0) 

Every time a vote is cast, this line unconditionally increments VotersCount by 1, regardless of whether the voter has already cast votes for the same voting item.

The asymmetric logic becomes apparent when comparing with the withdrawal mechanism. In the `Withdraw` function, VotersCount only decrements when a voter has no remaining active votes: [2](#0-1) 

This creates an imbalance:
- **Vote**: Always increments VotersCount (+1 per vote)
- **Withdraw**: Only decrements when last vote is removed (-1 when all votes withdrawn)

The field name and documentation indicate it should track unique voters. The proto definition describes it as "The total number of voters": [3](#0-2) 

However, the implementation tracks total votes, not unique voters. The `Vote` function calls `UpdateVotingResult` for every vote: [4](#0-3) 

### Impact Explanation
**Direct Impact:**
- VotersCount becomes permanently inflated when voters cast multiple votes
- After all votes are withdrawn, VotersCount remains at a non-zero value instead of 0
- This violates the semantic contract that "voters_count" represents the number of unique participants

**Affected Systems:**
The Election contract exposes this inflated value through `GetVotersCount`: [5](#0-4) 

This could impact:
1. Governance metrics and dashboards displaying incorrect participation statistics
2. Any quorum calculations that might rely on voter counts
3. Transparency and audit trails showing inflated participation numbers

**Exploitation Example:**
- Voter A casts 2 votes: VotersCount = 2 (should be 1)
- Voter A withdraws first vote: VotersCount = 2 (correct, still has 1 active)
- Voter A withdraws second vote: VotersCount = 1 (should be 0)

Result: VotersCount = 1 with zero active votes.

### Likelihood Explanation
**Attacker Capabilities:**
Any voter can trigger this vulnerability simply by voting multiple times for the same voting item. This is a normal, permitted operation in the system. The Election contract's `Vote` method allows voters to vote for multiple candidates, with each vote being a separate transaction: [6](#0-5) 

**Execution Practicality:**
The vulnerability is triggered automatically through normal voting operations:
1. Call `Vote` with first option → VotersCount increments
2. Call `Vote` with second option → VotersCount increments again (bug)
3. Both votes are from the same voter but counted as 2 different voters

**Feasibility:**
Test evidence confirms this behavior is reproducible. The test explicitly validates this inflation: [7](#0-6) 

The test shows user1 voting twice and expects VotersCount = 2, not 1.

Additional evidence from multi-voter scenarios: [8](#0-7) 

With 2 users each voting twice, VotersCount = 4, not 2 unique voters.

**Detection Probability:** Low - The bug is embedded in normal voting flow and tests codify the incorrect behavior as expected.

### Recommendation
**Code-Level Mitigation:**
Modify `UpdateVotingResult` to only increment VotersCount when the voter has no prior active votes for this voting item:

```csharp
private void UpdateVotingResult(VotingItem votingItem, string option, long amount)
{
    var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
    var votingResult = State.VotingResults[votingResultHash];
    if (!votingResult.Results.ContainsKey(option)) votingResult.Results.Add(option, 0);

    var currentVotes = votingResult.Results[option];
    votingResult.Results[option] = currentVotes.Add(amount);
    
    // Only increment VotersCount if this is the voter's first active vote
    var votedItems = State.VotedItemsMap[Context.Sender] ?? new VotedItems();
    var voterItemIndex = votingItem.VotingItemId.ToHex();
    bool isFirstVote = !votedItems.VotedItemVoteIds.ContainsKey(voterItemIndex) || 
                       !votedItems.VotedItemVoteIds[voterItemIndex].ActiveVotes.Any();
    
    if (isFirstVote)
    {
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
    }
    
    votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
    State.VotingResults[votingResultHash] = votingResult;
}
```

Note: The check must occur in `UpdateVotingResult` before `UpdateVotedItems` is called, or access the voter address passed from the calling context.

**Invariant Check:**
Add assertion: After all votes for a voting item are withdrawn, VotersCount for that item must equal 0.

**Test Cases:**
1. Test same voter voting multiple times, verify VotersCount increments only once
2. Test same voter withdrawing all votes, verify VotersCount returns to 0
3. Test cross-snapshot voting behavior with VotersCount inheritance

### Proof of Concept
**Initial State:**
- Voting item registered with 3 options
- Single voter with sufficient token balance

**Transaction Sequence:**
1. Voter calls `Vote(VotingItemId, Option1, Amount1)` → VotersCount = 1 ✓
2. Voter calls `Vote(VotingItemId, Option2, Amount2)` → VotersCount = 2 ✗ (should remain 1)
3. Check: Query `GetLatestVotingResult` → VotersCount shows 2
4. Voter calls `Withdraw(VoteId1)` → VotersCount = 2 (voter still has VoteId2 active)
5. Voter calls `Withdraw(VoteId2)` → VotersCount = 1 ✗ (should be 0)
6. Check: Query `GetLatestVotingResult` → VotersCount shows 1 despite zero active votes

**Expected Result:** VotersCount = 0 after all withdrawals

**Actual Result:** VotersCount = 1 after all withdrawals

**Success Condition:** The vulnerability is confirmed when VotersCount > 0 while the voter has zero active votes remaining.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L178-178)
```csharp
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L217-218)
```csharp
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);
```

**File:** protobuf/vote_contract.proto (L169-170)
```text
    // The total number of voters.
    int64 voters_count = 4;
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L224-230)
```csharp
    public override Int64Value GetVotersCount(Empty input)
    {
        return new Int64Value
        {
            Value = State.VoteContract.GetLatestVotingResult.Call(State.MinerElectionVotingItemId.Value).VotersCount
        };
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L421-467)
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

        UpdateElectorInformation(electorPubkey, input.Amount, voteId);

        var candidateVotesAmount = UpdateCandidateInformation(input.CandidatePubkey, input.Amount, voteId);

        LockTokensOfVoter(input.Amount, voteId);
        TransferTokensToVoter(input.Amount);
        CallVoteContractVote(input.Amount, input.CandidatePubkey, voteId);
        AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), lockSeconds, voteId);

        var rankingList = State.DataCentersRankingList.Value;
        if (rankingList.DataCenters.ContainsKey(input.CandidatePubkey))
        {
            rankingList.DataCenters[input.CandidatePubkey] =
                rankingList.DataCenters[input.CandidatePubkey].Add(input.Amount);
            State.DataCentersRankingList.Value = rankingList;
        }
        else
        {
            if (rankingList.DataCenters.Count < GetValidationDataCenterCount())
            {
                State.DataCentersRankingList.Value.DataCenters.Add(input.CandidatePubkey,
                    candidateVotesAmount);
                AddBeneficiary(input.CandidatePubkey);
            }
            else
            {
                TryToBecomeAValidationDataCenter(input, candidateVotesAmount, rankingList);
            }
        }

        return voteId;
    }
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L613-616)
```csharp
        await Vote(voteUser1, votingItem.VotingItemId, votingItem.Options.First(), 100L);
        await Vote(voteUser1, votingItem.VotingItemId, votingItem.Options.First(), 200L);
        var votingResult = await GetLatestVotingResult(votingItem.VotingItemId);
        votingResult.VotersCount.ShouldBe(2);
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L619-622)
```csharp
        await Vote(voteUser2, votingItem.VotingItemId, votingItem.Options.Last(), 100L);
        await Vote(voteUser2, votingItem.VotingItemId, votingItem.Options.Last(), 200L);
        votingResult = await GetLatestVotingResult(votingItem.VotingItemId);
        votingResult.VotersCount.ShouldBe(4);
```
