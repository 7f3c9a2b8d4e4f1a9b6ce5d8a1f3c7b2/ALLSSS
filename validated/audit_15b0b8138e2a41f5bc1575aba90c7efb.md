# Audit Report

## Title
VoteId Reuse Vulnerability in Delegated Voting Enables Vote Inflation and State Inconsistency

## Summary
The Vote contract's `Vote()` function lacks validation to prevent reusing the same `VoteId` in delegated voting mode (IsLockToken=false). This allows sponsors to call `Vote()` multiple times with identical VoteId values, causing each call to increment voting results while only storing the final record, creating inconsistent state between VotingRecords and VotingResults.

## Finding Description

The vulnerability exists in the vote processing logic where VoteId uniqueness is not enforced for delegated voting scenarios.

In the `Vote()` function, when processing votes for delegated voting items (IsLockToken=false), the validation logic only checks that the sponsor is the caller and that VoteId is non-null. [1](#0-0) 

The voting record is stored by directly assigning to the state mapping, which overwrites any existing record with the same VoteId without first checking for existence. [2](#0-1) 

Subsequently, `UpdateVotingResult()` unconditionally adds the vote amount to the results, increments the voters count, and adds to the total votes amount - regardless of whether this VoteId was previously counted. [3](#0-2) 

For delegated voting items, no tokens are locked since the locking logic only executes when IsLockToken is true. [4](#0-3) 

This creates a state inconsistency where:
- Multiple calls with the same VoteId add to VotingResults multiple times
- Only the final VotingRecord is stored
- VotingResults.VotesAmount > actual sum of VotingRecord amounts
- Withdrawal operations cannot properly clean up the inflated vote counts

## Impact Explanation

**Integrity Violation**: The fundamental invariant that VotingResults should match the sum of VotingRecords is violated. This breaks the trustworthiness of voting data stored in the contract.

**Vote Inflation**: A sponsor can inflate vote counts arbitrarily without any token backing. For example, calling Vote(VoteId="X", Amount=1000, Option="A") followed by Vote(VoteId="X", Amount=2000, Option="B") results in total votes of 3000 but only one record with amount 2000.

**Broken Withdrawal**: The Withdraw function will only subtract the final recorded amount, leaving phantom votes in the results that can never be withdrawn. [5](#0-4) 

**Impact on Calling Contracts**: Any legitimate contract using delegated voting that has a bug causing VoteId reuse would suffer from vote inflation. While well-designed contracts like the Election contract protect against this by validating VoteId uniqueness themselves, the lack of validation in the Vote contract creates a footgun for contract developers.

## Likelihood Explanation

**High Exploitability**: The Register() function is public, allowing any actor to create a voting item with IsLockToken=false and become the sponsor. [6](#0-5) 

The sponsor then has complete control over VoteId and Amount parameters when calling Vote() for their delegated voting item. No special privileges or complex state manipulation is required - just sequential transactions reusing the same VoteId.

**No Economic Cost**: Since IsLockToken=false means no tokens are locked, there is no economic barrier to exploitation.

**Detection Difficulty**: The inflated vote counts appear legitimate in the VotingResult state. Only forensic comparison of VotingRecords against VotingResults would reveal the discrepancy.

However, the primary impact is limited to voting items created by the attacker themselves, unless external systems rely on these results or legitimate contracts have bugs that cause VoteId reuse.

## Recommendation

Add VoteId uniqueness validation in the `AssertValidVoteInput()` function for delegated voting mode:

```csharp
if (!votingItem.IsLockToken)
{
    Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
    Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
    Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
    // Add uniqueness check
    Assert(State.VotingRecords[input.VoteId] == null, "VoteId already exists.");
}
```

This ensures that each VoteId can only be used once, maintaining the integrity invariant between VotingRecords and VotingResults.

## Proof of Concept

```csharp
[Fact]
public async Task VoteId_Reuse_Inflates_Vote_Counts()
{
    // Register a delegated voting item (IsLockToken=false)
    var votingItem = await RegisterVotingItemAsync(10, 3, false, DefaultSender, 10);
    
    var voteId = HashHelper.ComputeFrom("test-vote-id");
    
    // First vote with VoteId
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        VoteId = voteId,
        Voter = Accounts[1].Address,
        Amount = 1000,
        Option = votingItem.Options[0]
    });
    
    // Second vote with SAME VoteId but different amount/option
    await VoteContractStub.Vote.SendAsync(new VoteInput
    {
        VotingItemId = votingItem.VotingItemId,
        VoteId = voteId,
        Voter = Accounts[2].Address,
        Amount = 2000,
        Option = votingItem.Options[1]
    });
    
    // Check results - should show inflated counts
    var result = await VoteContractStub.GetVotingResult.CallAsync(new GetVotingResultInput
    {
        VotingItemId = votingItem.VotingItemId,
        SnapshotNumber = 1
    });
    
    // Results show 3000 total votes
    result.VotesAmount.ShouldBe(3000);
    result.Results[votingItem.Options[0]].ShouldBe(1000);
    result.Results[votingItem.Options[1]].ShouldBe(2000);
    result.VotersCount.ShouldBe(2);
    
    // But only one record exists
    var record = await VoteContractStub.GetVotingRecord.CallAsync(voteId);
    record.Amount.ShouldBe(2000); // Only last amount stored
    record.Voter.ShouldBe(Accounts[2].Address); // Only last voter stored
}
```

## Notes

The vulnerability is confirmed to exist in the Vote contract's core logic. While the Election contract (which uses delegated voting) protects against this by validating VoteId uniqueness before calling Vote, this does not eliminate the vulnerability in the Vote contract itself. The lack of validation creates a dangerous API that can lead to state inconsistency and broken withdrawal operations. Any contract using delegated voting must implement their own VoteId uniqueness checks, which violates the principle of defensive programming and places unnecessary burden on calling contracts.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-39)
```csharp
    public override Empty Register(VotingRegisterInput input)
    {
        var votingItemId = AssertValidNewVotingItem(input);

        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        // Accepted currency is in white list means this token symbol supports voting.
        var isInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
        {
            Symbol = input.AcceptedCurrency,
            Address = Context.Self
        }).Value;
        Assert(isInWhiteList, "Claimed accepted token is not available for voting.");

        // Initialize voting event.
        var votingItem = new VotingItem
        {
            Sponsor = Context.Sender,
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L122-130)
```csharp
        if (votingItem.IsLockToken)
            // Lock voted token.
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L169-181)
```csharp
    private void UpdateVotingResult(VotingItem votingItem, string option, long amount)
    {
        // Update VotingResult based on this voting behaviour.
        var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
        var votingResult = State.VotingResults[votingResultHash];
        if (!votingResult.Results.ContainsKey(option)) votingResult.Results.Add(option, 0);

        var currentVotes = votingResult.Results[option];
        votingResult.Results[option] = currentVotes.Add(amount);
        votingResult.VotersCount = votingResult.VotersCount.Add(1);
        votingResult.VotesAmount = votingResult.VotesAmount.Add(amount);
        State.VotingResults[votingResultHash] = votingResult;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L215-216)
```csharp
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-389)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
```
