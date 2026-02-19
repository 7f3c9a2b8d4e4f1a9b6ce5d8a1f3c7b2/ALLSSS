### Title
VoteId Collision Across VotingItems Causes Vote Accounting Corruption in ChangeVotingOption

### Summary
The `ChangeVotingOption` function retrieves a `VotingRecord` by `VoteId` without validating that it belongs to the `MinerElectionVotingItemId`. Since `VoteId` is a global key across all VotingItems and anyone can create a VotingItem with `IsLockToken=false` to overwrite arbitrary VoteIds, an attacker can cause severe vote accounting corruption where votes are double-counted or incorrectly transferred between candidates.

### Finding Description

**Root Cause:**

The Vote contract stores `VotingRecords` using `VoteId` as a global key without scoping by `VotingItemId`. [1](#0-0) 

When voting with `IsLockToken=false`, the Vote contract allows the sponsor to provide arbitrary `VoteId` and `Voter` values. [2](#0-1) 

The Vote function directly overwrites any existing `VotingRecord` with the same `VoteId`, regardless of which `VotingItemId` it belongs to. [3](#0-2) 

The Election contract's `MinerElectionVotingItemId` is registered with `IsLockToken=false`. [4](#0-3) 

**Missing Validation:**

The `ChangeVotingOption` function retrieves the `VotingRecord` by `VoteId` but does NOT validate that `votingRecord.VotingItemId` equals `State.MinerElectionVotingItemId.Value`. [5](#0-4) 

The function then uses `votingRecord.Option` to determine which candidate's votes to decrement, trusting that this Option represents an Election candidate. [6](#0-5) 

**Attack Execution Path:**

1. Attacker creates a malicious VotingItem with `IsLockToken=false` and includes a valid Election candidate's public key as an option
2. Attacker calls `VoteContract.Vote` directly, providing a victim's existing Election `VoteId`, the victim's address as `Voter`, and the malicious VotingItem's ID, with a valid candidate as the `Option`
3. This overwrites the victim's `VotingRecord` to point to the attacker's VotingItem
4. When the victim calls `ChangeVotingOption`, it reads the corrupted `VotingRecord` and incorrectly decrements vote counts from the wrong candidate (the one in the attacker's record) while the original candidate retains the votes

### Impact Explanation

**Direct Consensus/Governance Impact:**

The attack corrupts the vote accounting system used for miner election, violating the critical invariant that "votes should be accurately tracked and transferred". 

Specifically:
- **Original Candidate A**: Retains victim's votes even after the victim changed to Candidate B (votes never removed from `CandidateVotes[A].ObtainedActiveVotingRecordIds` and vote counts)
- **Attacker's Chosen Candidate C**: Loses votes they never received (incorrectly decremented) [7](#0-6) 
- **New Candidate B**: Gains votes (correctly incremented)
- **Net Effect**: Votes are double-counted (A and B both count the same votes), and C's vote count is manipulated downward

This directly affects consensus miner selection, as miner lists are determined by vote counts. An attacker can artificially inflate their candidate's votes or suppress competitor candidates' votes.

**Who is Affected:**
- All Election voters whose votes can be tampered with
- Honest candidates whose vote counts are manipulated
- The entire consensus system's integrity

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Create a VotingItem (public function, anyone can do this) [8](#0-7) 
2. Know victim VoteIds (publicly queryable from blockchain state)
3. Call `VoteContract.Vote` as the sponsor with chosen VoteId/Voter values

**Attack Complexity:** Low
- Single transaction to register malicious VotingItem
- Single transaction to overwrite victim's VotingRecord
- No race condition needed (large time window between victim's initial vote and their call to `ChangeVotingOption`)

**Feasibility Conditions:**
- Victim must have an active vote in the Election contract
- Victim must eventually call `ChangeVotingOption` (common operation for vote management)
- Attacker needs minimal transaction fees to register VotingItem and call Vote

**Detection Constraints:**
- Attack executes silently without error
- Victim's `ChangeVotingOption` transaction succeeds normally
- Vote corruption only detectable through careful state comparison

**Probability:** HIGH - All preconditions are easily achievable, no trusted role compromise needed, and attack cost is negligible compared to potential governance impact.

### Recommendation

**Immediate Fix:**

Add validation in `ChangeVotingOption` to ensure the retrieved `VotingRecord` belongs to the Election's VotingItem:

```csharp
var votingRecord = State.VoteContract.GetVotingRecord.Call(input.VoteId);
Assert(votingRecord.VotingItemId == State.MinerElectionVotingItemId.Value, 
    "Vote does not belong to Election voting item.");
Assert(Context.Sender == votingRecord.Voter, "No permission to change current vote's option.");
```

**Systemic Fix:**

Modify the Vote contract to prevent VoteId reuse across different VotingItems:

1. Add validation in `Vote` function to check if `VoteId` already exists and belongs to a different `VotingItemId`
2. Scope VoteIds by VotingItemId (e.g., use composite key: `Hash.Combine(VotingItemId, VoteId)`)
3. Add explicit checks in all functions that retrieve VotingRecords to validate VotingItemId consistency

**Test Cases:**

1. Test that `ChangeVotingOption` fails when VotingRecord's VotingItemId doesn't match Election's VotingItemId
2. Test that Vote contract rejects attempts to reuse a VoteId across different VotingItems
3. Verify vote accounting integrity after malicious VotingItem attempts to overwrite VoteIds

### Proof of Concept

**Initial State:**
1. Alice votes 1000 tokens for Candidate A in Election contract, receives VoteId `X`
2. Election state: `CandidateVotes[A].ObtainedActiveVotingRecordIds = [X]`, vote amount = 1000
3. Vote contract: `VotingRecords[X] = {VotingItemId: MinerElectionVotingItemId, Option: "A", Amount: 1000, Voter: Alice}`

**Attack Steps:**
1. Attacker calls `VoteContract.Register` to create malicious VotingItem with `IsLockToken=false`, options including valid candidate "C"
2. Attacker calls `VoteContract.Vote` with:
   - `VoteId = X` (Alice's VoteId)
   - `VotingItemId = AttackerVotingItemId`
   - `Voter = Alice`
   - `Option = "C"`
   - `Amount = 1000`
3. This overwrites: `VotingRecords[X] = {VotingItemId: AttackerVotingItemId, Option: "C", ...}`

**Victim Transaction:**
4. Alice calls `ElectionContract.ChangeVotingOption(VoteId: X, CandidatePubkey: "B")`
5. Function retrieves corrupted VotingRecord with Option="C"
6. Decrements Candidate C's votes by 1000 (C never had these votes)
7. Increments Candidate B's votes by 1000
8. Never removes votes from Candidate A

**Result:**
- **Expected:** A loses 1000 votes, B gains 1000 votes (net zero)
- **Actual:** A keeps 1000 votes, B gains 1000 votes, C loses 1000 votes (net +1000 vote inflation for A+B, -1000 for C)
- **Success Condition:** Query `CandidateVotes[A]`, `CandidateVotes[B]`, and `CandidateVotes[C]` to observe corrupted vote counts violating conservation of total votes

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContractState.cs (L16-19)
```csharp
    /// <summary>
    ///     VoteId -> VotingRecord
    /// </summary>
    public MappedState<Hash, VotingRecord> VotingRecords { get; set; }
```

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L384-388)
```csharp
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L60-68)
```csharp
        var votingRegisterInput = new VotingRegisterInput
        {
            IsLockToken = false,
            AcceptedCurrency = Context.Variables.NativeSymbol,
            TotalSnapshotNumber = long.MaxValue,
            StartTimestamp = TimestampHelper.MinValue,
            EndTimestamp = TimestampHelper.MaxValue
        };
        State.VoteContract.Register.Send(votingRegisterInput);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L27-28)
```csharp
        var votingRecord = State.VoteContract.GetVotingRecord.Call(input.VoteId);
        Assert(Context.Sender == votingRecord.Voter, "No permission to change current vote's option.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L63-70)
```csharp
        var oldVoteOptionPublicKey = GetNewestPubkey(votingRecord.Option);
        var oldCandidateVotes = State.CandidateVotes[oldVoteOptionPublicKey];
        oldCandidateVotes.ObtainedActiveVotingRecordIds.Remove(input.VoteId);
        oldCandidateVotes.ObtainedActiveVotedVotesAmount =
            oldCandidateVotes.ObtainedActiveVotedVotesAmount.Sub(votingRecord.Amount);
        oldCandidateVotes.AllObtainedVotedVotesAmount =
            oldCandidateVotes.AllObtainedVotedVotesAmount.Sub(votingRecord.Amount);
        State.CandidateVotes[oldVoteOptionPublicKey] = oldCandidateVotes;
```
