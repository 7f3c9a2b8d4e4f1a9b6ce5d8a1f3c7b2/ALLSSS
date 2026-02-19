### Title
Delegated Voting Allows Unlimited Vote Manipulation Without Token Backing

### Summary
The Vote contract's delegated voting mechanism (IsLockToken=false) allows any sponsor to register a voting item and repeatedly vote with arbitrary amounts for any addresses without locking or validating token balances. This violates the fundamental security invariant that votes should represent actual locked tokens, enabling costless manipulation of voting results that could mislead external contracts or dApps consuming Vote contract data.

### Finding Description

The vulnerability exists in the Vote contract's `Vote()` method and related validation logic: [1](#0-0) 

When a voting item has `IsLockToken=false` (delegated voting mode), the contract skips token locking entirely. The validation logic only checks that the sender is the sponsor: [2](#0-1) 

No access control exists on the `Register()` method, allowing anyone to create a delegated voting item: [3](#0-2) 

The vote amounts are directly added to voting results without any balance validation: [4](#0-3) [5](#0-4) 

The design documentation acknowledges that delegated voting "should lock in higher level contract" but provides no enforcement: [6](#0-5) 

### Impact Explanation

**Concrete Impact:**
- An attacker can create voting items with artificially inflated vote counts (millions/billions of votes) without owning any tokens
- Each malicious vote record appears legitimate when queried via `GetVotingResult()` or `GetVotingRecord()`
- External contracts, dApps, or governance systems that query arbitrary voting items could make decisions based on fake vote data
- While the Election contract is protected (it uses its own voting item ID and properly locks tokens), the Vote contract is public infrastructure potentially used by other systems

**Who is Affected:**
- Any external smart contracts or dApps that use the Vote contract for governance decisions
- Off-chain systems that query Vote contract results for decision-making
- Users who trust voting results from unknown voting items

**Severity Justification:**
This is HIGH severity because:
1. It violates the critical invariant: "Token Supply & Fees: lock/unlock correctness"
2. The exploit is trivial and costless (no tokens required)
3. The Vote contract is a system contract serving as public voting infrastructure
4. Vote manipulation undermines trust in any governance system using this contract

### Likelihood Explanation

**Attack Complexity:** Trivial - requires only two transactions:
1. Call `Register()` with `IsLockToken=false`
2. Call `Vote()` repeatedly with arbitrary amounts

**Attacker Capabilities:** 
- No special permissions needed
- No token holdings required  
- No economic cost to exploit

**Feasibility:**
- Entry point is publicly accessible (`Register()` and `Vote()` are public methods)
- No authorization checks prevent malicious voting item creation
- Test code demonstrates this pattern works: [7](#0-6) 

**Detection Difficulty:**
- Malicious voting items are indistinguishable from legitimate ones when queried
- No on-chain mechanism exists to verify sponsor legitimacy or token backing

### Recommendation

**Immediate Mitigation:**
Add access control to delegated voting creation. Implement a whitelist of trusted sponsors allowed to create `IsLockToken=false` voting items:

```
// Add to VoteContractState.cs
internal BoolState TrustedSponsors { get; set; }

// Modify Register() in VoteContract.cs after line 34
if (!input.IsLockToken)
{
    Assert(State.TrustedSponsors[Context.Sender], 
           "Only whitelisted contracts can create delegated voting items.");
}
```

**Long-term Solution:**
1. Implement a registration system where trusted system contracts (Election, governance contracts) are whitelisted during initialization
2. Add a view method to verify if a voting item's sponsor is trusted
3. Add metadata to VotingItem indicating sponsor trust status for external consumers to validate

**Invariant Checks:**
- Enforce that only authorized addresses can create delegated voting items
- Add view methods for external contracts to verify voting item legitimacy before trusting results

**Test Cases:**
- Test that unauthorized addresses cannot create delegated voting items
- Test that whitelisted sponsors can create delegated voting items
- Test that fake voting items don't affect legitimate voting items

### Proof of Concept

**Initial State:**
- Attacker has any address (no special permissions)
- Attacker has 0 tokens

**Attack Steps:**

1. **Attacker calls Register() with IsLockToken=false:**
```
Input: VotingRegisterInput {
    IsLockToken = false,
    AcceptedCurrency = "ELF",
    Options = ["Option1", "Option2"],
    StartTimestamp = now,
    EndTimestamp = future
}
Result: Creates voting item, attacker becomes sponsor
```

2. **Attacker repeatedly calls Vote() with arbitrary amounts:**
```
For i = 1 to 1000:
    Input: VoteInput {
        VotingItemId = malicious_voting_item_id,
        Voter = random_address[i],
        Amount = 1_000_000,  // 1 million votes per call
        Option = "Option1",
        VoteId = generate_unique_hash(i)
    }
    Result: Vote recorded, no tokens locked or checked
```

3. **Query voting results:**
```
Call GetVotingResult(malicious_voting_item_id, 1)
Result: Shows Option1 with 1 billion votes, 1000 voters
       All without any token backing
```

**Expected vs Actual Result:**
- **Expected:** Votes should require locked tokens or at minimum balance verification
- **Actual:** Unlimited fake votes can be created costlessly, appearing legitimate in queries

**Success Condition:**
Attacker successfully creates a voting item with billions of votes without locking any tokens, and these results are indistinguishable from legitimate votes when queried by external systems.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L20-82)
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
            VotingItemId = votingItemId,
            AcceptedCurrency = input.AcceptedCurrency,
            IsLockToken = input.IsLockToken,
            TotalSnapshotNumber = input.TotalSnapshotNumber,
            CurrentSnapshotNumber = 1,
            CurrentSnapshotStartTimestamp = input.StartTimestamp,
            StartTimestamp = input.StartTimestamp,
            EndTimestamp = input.EndTimestamp,
            RegisterTimestamp = Context.CurrentBlockTime,
            Options = { input.Options },
            IsQuadratic = input.IsQuadratic,
            TicketCost = input.TicketCost
        };

        State.VotingItems[votingItemId] = votingItem;

        // Initialize first voting going information of registered voting event.
        var votingResultHash = GetVotingResultHash(votingItemId, 1);
        State.VotingResults[votingResultHash] = new VotingResult
        {
            VotingItemId = votingItemId,
            SnapshotNumber = 1,
            SnapshotStartTimestamp = input.StartTimestamp
        };

        Context.Fire(new VotingItemRegistered
        {
            Sponsor = votingItem.Sponsor,
            VotingItemId = votingItemId,
            AcceptedCurrency = votingItem.AcceptedCurrency,
            IsLockToken = votingItem.IsLockToken,
            TotalSnapshotNumber = votingItem.TotalSnapshotNumber,
            CurrentSnapshotNumber = votingItem.CurrentSnapshotNumber,
            CurrentSnapshotStartTimestamp = votingItem.StartTimestamp,
            StartTimestamp = votingItem.StartTimestamp,
            EndTimestamp = votingItem.EndTimestamp,
            RegisterTimestamp = votingItem.RegisterTimestamp,
            IsQuadratic = votingItem.IsQuadratic,
            TicketCost = votingItem.TicketCost
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L119-119)
```csharp
        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-389)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
```

**File:** contract/AElf.Contracts.Vote/README.md (L77-78)
```markdown
- This method will only lock token if voting event isn't delegated. Delegated voting event should lock in higher level
  contract, like `Election Contract`.
```

**File:** test/AElf.Contracts.Vote.Tests/BVT/BasicTests.cs (L218-228)
```csharp
            var registerItem = await RegisterVotingItemAsync(100, 3, false, DefaultSender, 1);
            var withdrawUser = Accounts[2];
            var voteId = HashHelper.ComputeFrom("hash");
            await VoteContractStub.Vote.SendAsync(new VoteInput
            {
                VotingItemId = registerItem.VotingItemId,
                Voter = withdrawUser.Address,
                VoteId = voteId,
                Option = registerItem.Options[1],
                Amount = 100
            });
```
