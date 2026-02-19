### Title
VoteId Collision Leading to Permanent Token Lock and Vote Record Corruption

### Summary
The VoteContract generates VoteId using only `OriginTransactionId`, contract address, and `VotesAmount` counter, without including the specific `VotingItemId`. When multiple votes on different voting items occur within the same transaction and those items have identical `VotesAmount` values, they generate the same VoteId. This causes the second vote to overwrite the first vote's record while both locks accumulate tokens in the same virtual address, resulting in permanent token lock and corrupted voting state.

### Finding Description

**Root Cause:**

The VoteId generation logic is located in the `AssertValidVoteInput` method: [1](#0-0) 

The VoteId is computed using `Context.GenerateId`, which concatenates: [2](#0-1) 

This generates: `Hash(OriginTransactionId + VoteContractAddress + votingResult.VotesAmount)`

**Critical Flaw:** The VoteId does NOT include the `VotingItemId`. Each voting item maintains its own independent `VotesAmount` counter. When two different voting items have the same `VotesAmount` value at the moment of voting, and both votes occur in the same transaction (thus sharing the same `OriginTransactionId`), they produce identical VoteIds.

**Why Protections Fail:**

1. **No Collision Detection:** The Vote method directly overwrites VotingRecords without checking for existing entries: [3](#0-2) 

Unlike the Election contract which has explicit collision protection: [4](#0-3) 

2. **Shared OriginTransactionId:** All inline calls within a transaction share the same OriginTransactionId, as confirmed by the transaction context architecture. Multiple `Send` calls from a contract execute as inline transactions with the same origin.

3. **Lock Accumulation:** The token contract's Lock mechanism computes a virtual address using: [5](#0-4) 

When the same LockId is used twice, tokens accumulate in the same virtual address without error, but only one VotingRecord survives.

**Execution Path:**

1. Transaction initiates with unique `OriginTransactionId`
2. First Vote call: reads VotingItem A's `VotesAmount = X`, generates `VoteId = Hash(TxId + Contract + X)`, locks tokens
3. Second Vote call: reads VotingItem B's `VotesAmount = X`, generates identical `VoteId = Hash(TxId + Contract + X)`, locks more tokens to same virtual address
4. Second vote overwrites first vote's `State.VotingRecords[VoteId]`
5. Withdrawal can only access surviving record, leaving first vote's tokens permanently locked

### Impact Explanation

**Direct Fund Loss:**
- Tokens from the overwritten vote become permanently locked in the virtual address
- The surviving VotingRecord only tracks the second vote's amount
- Unlock can only withdraw based on the surviving record: [6](#0-5) 

**Example Scenario:**
- Vote 1: 100 tokens on Item A (VotesAmount = 0) → VoteId = Hash(Tx + Contract + 0)
- Vote 2: 200 tokens on Item B (VotesAmount = 0) → VoteId = Hash(Tx + Contract + 0)
- Virtual address receives 300 tokens total
- Only VotingRecord for Item B (200 tokens) exists
- Withdrawal unlocks 200 tokens
- **100 tokens permanently locked**

**Vote Record Corruption:**
- The first vote's record is completely lost
- Voting results for Item A become incorrect
- `VotedItems` tracking inconsistencies between Item A and Item B
- The VotedItemsMap is updated for both items: [7](#0-6) 
But only one VotingRecord exists, causing state inconsistency.

**Affected Parties:**
- Voters lose locked tokens permanently
- Voting items have corrupted vote tallies
- Vote sponsors receive incorrect results
- Protocol integrity compromised

**Severity: HIGH**
- Direct financial loss (permanent token lock)
- No recovery mechanism exists
- Corrupts core voting functionality
- Exploitable with reasonable preconditions

### Likelihood Explanation

**Attacker Capabilities:**
- Ability to create or monitor voting items to find those with matching VotesAmount
- Ability to deploy a malicious contract or use existing multi-call mechanisms
- Standard user permissions (no privileged access required)

**Attack Complexity: LOW**
1. Identify/create two voting items with `IsLockToken = true` that have identical `VotesAmount` values (e.g., both newly registered with `VotesAmount = 0`)
2. Deploy a simple contract that makes two `VoteContract.Vote.Send()` calls in sequence
3. Execute transaction calling both votes
4. Collision occurs automatically due to shared OriginTransactionId and matching VotesAmount

**Feasibility Conditions:**
- **Common scenario:** Newly registered voting items all start with `VotesAmount = 0`, making collisions trivial to trigger
- **Contracts can make multiple external calls:** AElf supports inline transactions via `SendInline`, allowing multiple Vote calls in one transaction
- **No voting item restrictions:** Any user can vote on multiple items if they hold the accepted currency

**Detection Constraints:**
- Collision is transparent to blockchain observers
- Only appears as normal voting activity
- Overwritten records leave no trace
- Locked tokens appear legitimate until withdrawal fails

**Probability: MEDIUM-HIGH**
- Preconditions are easily achievable (matching VotesAmount is common)
- Attack is technically straightforward
- Economic cost is minimal (standard voting transaction)
- Can occur accidentally with legitimate multi-voting contracts

### Recommendation

**Immediate Fix:**
Add VotingItemId to VoteId generation to ensure uniqueness across voting items:

```csharp
// In AssertValidVoteInput method, line 397:
input.VoteId = Context.GenerateId(Context.Self, 
    ByteArrayHelper.ConcatArrays(
        votingItem.VotingItemId.Value,
        votingResult.VotesAmount.ToBytes(false)
    ));
```

**Add Collision Prevention:**
Add explicit collision check before storing VotingRecord:

```csharp
// In Vote method, before line 117:
Assert(State.VotingRecords[input.VoteId] == null, "Vote ID already exists.");
```

**Additional Invariant Checks:**
1. Verify VotingRecord.VotingItemId matches expected item during withdrawal
2. Track total locked amount per user per voting item separately
3. Add event emission for VoteId generation to aid in debugging

**Test Cases:**
1. Test voting on two different items with same VotesAmount in one transaction
2. Test withdrawal after collision scenario
3. Test locked balance reconciliation between VotingRecords and token locks
4. Test VoteId uniqueness across different voting items

### Proof of Concept

**Required Initial State:**
- Two voting items registered (Item A and Item B) with `IsLockToken = true`
- Both items have `VotesAmount = 0` (newly created) or any identical value
- Attacker has sufficient tokens of the accepted currency
- Attacker deploys a malicious contract

**Attack Transaction Steps:**

1. **Malicious Contract Code:**
```csharp
public void ExploitVoteCollision() {
    // Both votes in same transaction = same OriginTransactionId
    State.VoteContract.Vote.Send(new VoteInput {
        VotingItemId = ItemA_Id,  // VotesAmount = 0
        Amount = 100,
        Option = "OptionX"
    });
    
    State.VoteContract.Vote.Send(new VoteInput {
        VotingItemId = ItemB_Id,  // VotesAmount = 0 (same as ItemA)
        Amount = 200,
        Option = "OptionY"
    });
}
```

2. **Execute transaction calling `ExploitVoteCollision()`**

**Expected Result (Vulnerable Code):**
- First vote: VoteId = Hash(TxId + VoteContract + 0), locks 100 tokens
- Second vote: VoteId = Hash(TxId + VoteContract + 0) (SAME), locks 200 tokens
- `State.VotingRecords[VoteId]` = {ItemB, amount=200} (ItemA record overwritten)
- Virtual address contains 300 tokens
- Withdrawal unlocks only 200 tokens
- **100 tokens permanently locked**

**Success Condition:**
- Query `State.VotingRecords[VoteId]` shows only Item B vote
- Token lock virtual address balance = 300 tokens
- Withdrawal of VoteId returns only 200 tokens
- 100 tokens unrecoverable

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L117-117)
```csharp
        State.VotingRecords[input.VoteId] = votingRecord;
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L146-161)
```csharp
    private void UpdateVotedItems(Hash voteId, Address voter, VotingItem votingItem)
    {
        var votedItems = State.VotedItemsMap[voter] ?? new VotedItems();
        var voterItemIndex = votingItem.VotingItemId.ToHex();
        if (votedItems.VotedItemVoteIds.ContainsKey(voterItemIndex))
            votedItems.VotedItemVoteIds[voterItemIndex].ActiveVotes.Add(voteId);
        else
            votedItems.VotedItemVoteIds[voterItemIndex] =
                new VotedIds
                {
                    ActiveVotes = { voteId }
                };

        votedItems.VotedItemVoteIds[voterItemIndex].WithdrawnVotes.Remove(voteId);
        State.VotedItemsMap[voter] = votedItems;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L224-231)
```csharp
        if (votingItem.IsLockToken)
            State.TokenContract.Unlock.Send(new UnlockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                Amount = votingRecord.Amount,
                LockId = input.VoteId
            });
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L397-397)
```csharp
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L433-433)
```csharp
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-212)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```
