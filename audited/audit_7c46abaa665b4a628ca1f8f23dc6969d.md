### Title
VoteId Collision Across Different Voting Items Causes Vote Record Corruption and Token Lock Issues

### Summary
The VoteId generation mechanism in the Vote contract does not include the VotingItemId in its hash computation, only using the VotesAmount value. When two votes from the same origin transaction target different voting items that have identical VotesAmount values, they generate the same VoteId, causing the second vote to overwrite the first vote's record. This leads to permanent token locks and vote accounting corruption.

### Finding Description

**Root Cause:** [1](#0-0) 

The VoteId is generated using only `votingResult.VotesAmount.ToBytes(false)` as the distinguishing parameter. The underlying `Context.GenerateId` implementation concatenates: [2](#0-1) 

This produces: `Hash(OriginTransactionId + ContractAddress + VotesAmount)`. Critically, **VotingItemId is not included** in this computation.

**Vulnerability Path:**
For `IsLockToken = true` voting items, the VoteId generation occurs here: [3](#0-2) 

When a contract makes multiple inline votes within a single transaction, all inline calls share the same `OriginTransactionId`: [4](#0-3) 

**Why Existing Protections Fail:**
The vote record storage has no collision detection: [5](#0-4) 

The code directly overwrites any existing record with the same VoteId, and there's no assertion checking for duplicate VoteIds.

### Impact Explanation

**Direct Consequences:**

1. **Permanent Token Lock**: When the first vote locks tokens with a specific LockId (the VoteId), but the record is overwritten by the second vote pointing to a different voting item, the first vote's tokens become unwithdrawable: [6](#0-5) 

2. **Vote Accounting Corruption**: The Withdraw function uses the VotingRecord to determine which voting item to update: [7](#0-6) 

Since the record points to the wrong voting item, withdrawal subtracts votes from the wrong item's tally, corrupting vote counts across multiple voting items.

3. **Token Unlock Mismatch**: The unlock will use the corrupted record's amount, potentially unlocking incorrect token amounts.

**Affected Parties:**
- Any voter (including contracts) participating in `IsLockToken = true` voting items
- Voting item sponsors who rely on accurate vote tallies
- Token holders whose funds become permanently locked

**Severity Justification:**
CRITICAL - Direct fund loss through permanent token locks, complete breakdown of vote record integrity, and exploitable by any attacker who can create voting items or time their votes to match VotesAmount values.

### Likelihood Explanation

**Attacker Capabilities Required:**
1. Deploy a malicious contract that makes multiple inline calls to `Vote()`
2. Either create two voting items with `IsLockToken = true`, or target existing items
3. Time the attack when both target voting items have matching VotesAmount values

**Attack Complexity:**
LOW to MEDIUM:
- If attacker creates both voting items: Can initialize them to start with VotesAmount = 0, then vote once on each to reach identical amounts
- If targeting existing items: Must monitor VotesAmount values and execute when they match
- No special privileges required - anyone can register voting items and vote

**Feasibility Conditions:**
- Contract execution model supports inline transactions: CONFIRMED [8](#0-7) 

- Contracts can call Vote on `IsLockToken = true` items: CONFIRMED (no restriction at lines 390-398)
- State updates between inline transactions are sequential: CONFIRMED, but VoteId generation happens BEFORE state updates, so matching VotesAmount is possible

**Detection Constraints:**
- Attack leaves evidence in transaction traces (multiple Vote events with same VoteId)
- However, on-chain validation would not prevent the attack before execution
- No automatic detection mechanism exists in the contract

**Economic Rationality:**
Attacker can grief victims by locking their tokens permanently, or manipulate vote outcomes by corrupting tallies. Attack cost is minimal (gas fees + small voting amounts).

### Recommendation

**Primary Fix - Include VotingItemId in VoteId Generation:**

Modify line 397 to include the VotingItemId in the VoteId computation:

```csharp
input.VoteId = Context.GenerateId(Context.Self, 
    ByteArrayHelper.ConcatArrays(
        votingItem.VotingItemId.ToBytes(),
        votingResult.VotesAmount.ToBytes(false)
    ));
```

This ensures VoteIds are unique per voting item, preventing cross-item collisions.

**Secondary Fix - Add Duplicate VoteId Check:**

Before line 117, add validation:
```csharp
Assert(State.VotingRecords[input.VoteId] == null, "Vote ID already exists.");
```

This provides defense-in-depth against any VoteId collision scenarios.

**Test Cases to Add:**
1. Test voting on two different voting items with identical VotesAmount from same transaction
2. Test inline voting from contracts on `IsLockToken = true` items
3. Test withdrawal after VoteId collision to verify correct behavior
4. Negative test confirming duplicate VoteId rejection

### Proof of Concept

**Required Initial State:**
1. Two voting items A and B exist with `IsLockToken = true`
2. Both items configured with `AcceptedCurrency = "ELF"`, valid options, and active voting period
3. Item A has `VotesAmount = 0` (initial state)
4. Item B has `VotesAmount = 0` (initial state)
5. Attacker deploys a malicious contract with sufficient ELF tokens

**Transaction Steps:**

**Step 1:** Attacker's contract method executes a single transaction containing two inline votes:
- `State.VoteContract.Vote.Send(new VoteInput { VotingItemId = A, Amount = 100, Option = "OptionA" })`
- `State.VoteContract.Vote.Send(new VoteInput { VotingItemId = B, Amount = 200, Option = "OptionB" })`

**Step 2:** First inline vote executes:
- Reads `VotingResults[A].VotesAmount = 0`
- Generates `VoteId = Hash(OriginTxId + VoteContractAddress + "0")`
- Stores `VotingRecords[VoteId] = {VotingItemId: A, Amount: 100, Voter: AttackerContract}`
- Locks 100 ELF with `LockId = VoteId`
- Updates `VotingResults[A].VotesAmount = 100`

**Step 3:** Second inline vote executes:
- Reads `VotingResults[B].VotesAmount = 0`
- Generates `VoteId = Hash(OriginTxId + VoteContractAddress + "0")` **(IDENTICAL!)**
- **OVERWRITES** `VotingRecords[VoteId] = {VotingItemId: B, Amount: 200, Voter: AttackerContract}`
- Locks 200 ELF with `LockId = VoteId`
- Updates `VotingResults[B].VotesAmount = 200`

**Expected vs Actual Result:**

**Expected:** 
- Two distinct VoteIds created
- Both votes independently recorded and withdrawable
- Total 300 ELF locked under two different LockIds

**Actual:**
- Single VoteId created for both votes
- First vote's record lost, overwritten by second vote
- 100 ELF locked under LockId for item A (unrecorded)
- 200 ELF locked under LockId for item B (recorded)
- `VotingRecords[VoteId]` points to item B only

**Success Condition:**
Query `State.VotingRecords[VoteId]` returns a record with `VotingItemId = B` and `Amount = 200`, while 300 total ELF tokens are locked with the same LockId. Attempting to withdraw will only unlock 200 ELF (per the corrupted record), leaving 100 ELF permanently locked.

### Citations

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

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L191-231)
```csharp
    public override Empty Withdraw(WithdrawInput input)
    {
        var votingRecord = State.VotingRecords[input.VoteId];
        if (votingRecord == null) throw new AssertionException("Voting record not found.");
        var votingItem = State.VotingItems[votingRecord.VotingItemId];

        if (votingItem.IsLockToken)
            Assert(votingRecord.Voter == Context.Sender, "No permission to withdraw votes of others.");
        else
            Assert(votingItem.Sponsor == Context.Sender, "No permission to withdraw votes of others.");

        // Update VotingRecord.
        votingRecord.IsWithdrawn = true;
        votingRecord.WithdrawTimestamp = Context.CurrentBlockTime;
        State.VotingRecords[input.VoteId] = votingRecord;

        var votingResultHash = GetVotingResultHash(votingRecord.VotingItemId, votingRecord.SnapshotNumber);

        var votedItems = State.VotedItemsMap[votingRecord.Voter];
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].ActiveVotes.Remove(input.VoteId);
        votedItems.VotedItemVoteIds[votingItem.VotingItemId.ToHex()].WithdrawnVotes.Add(input.VoteId);
        State.VotedItemsMap[votingRecord.Voter] = votedItems;

        var votingResult = State.VotingResults[votingResultHash];
        votingResult.Results[votingRecord.Option] =
            votingResult.Results[votingRecord.Option].Sub(votingRecord.Amount);
        if (!votedItems.VotedItemVoteIds[votingRecord.VotingItemId.ToHex()].ActiveVotes.Any())
            votingResult.VotersCount = votingResult.VotersCount.Sub(1);

        votingResult.VotesAmount = votingResult.VotesAmount.Sub(votingRecord.Amount);

        State.VotingResults[votingResultHash] = votingResult;

        if (votingItem.IsLockToken)
            State.TokenContract.Unlock.Send(new UnlockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                Amount = votingRecord.Amount,
                LockId = input.VoteId
            });
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L390-398)
```csharp
        else
        {
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L139-146)
```csharp
    public Hash GenerateId(Address contractAddress, IEnumerable<byte> bytes)
    {
        var contactedBytes = OriginTransactionId.Value.Concat(contractAddress.Value);
        var enumerable = bytes as byte[] ?? bytes?.ToArray();
        if (enumerable != null)
            contactedBytes = contactedBytes.Concat(enumerable);
        return HashHelper.ComputeFrom(contactedBytes.ToArray());
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L216-247)
```csharp
    private async Task ExecuteInlineTransactions(int depth, Timestamp currentBlockTime,
        ITransactionContext txContext, TieredStateCache internalStateCache,
        IChainContext internalChainContext,
        Hash originTransactionId,
        CancellationToken cancellationToken)
    {
        var trace = txContext.Trace;
        internalStateCache.Update(txContext.Trace.GetStateSets());
        foreach (var inlineTx in txContext.Trace.InlineTransactions)
        {
            var singleTxExecutingDto = new SingleTransactionExecutingDto
            {
                Depth = depth + 1,
                ChainContext = internalChainContext,
                Transaction = inlineTx,
                CurrentBlockTime = currentBlockTime,
                Origin = txContext.Origin,
                OriginTransactionId = originTransactionId
            };

            var inlineTrace = await ExecuteOneAsync(singleTxExecutingDto, cancellationToken);

            if (inlineTrace == null)
                break;
            trace.InlineTraces.Add(inlineTrace);
            if (!inlineTrace.IsSuccessful())
                // Already failed, no need to execute remaining inline transactions
                break;

            internalStateCache.Update(inlineTrace.GetStateSets());
        }
    }
```
