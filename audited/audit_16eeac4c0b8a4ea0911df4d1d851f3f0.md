### Title
Recast Function Permanently Disabled After Token Transfer Due to Overly Restrictive Balance Requirement

### Summary
The `Recast` function contains a flawed permission model that prevents legitimate minters from updating their NFT metadata after transferring any tokens. The function requires minters to hold ALL tokens (`nftInfo.Quantity == Balance`) at line 262, which conflicts with the minter authorization check at line 260 and renders the feature unusable in normal NFT operations where tokens are transferred or when multiple minters exist for the same token ID.

### Finding Description

The `Recast` function is designed to allow authorized minters to update NFT metadata (uri, alias, metadata fields). However, it implements two contradictory permission checks: [1](#0-0) 

**Root Cause:**
Line 260 correctly checks if the caller is in the minter list (authorization-based check). However, line 262 additionally requires that `nftInfo.Quantity == State.BalanceMap[tokenHash][Context.Sender]`, meaning the caller must hold ALL minted tokens. This second check conflates authorization with ownership, making the authorization check at line 260 meaningless.

**Why Protections Fail:**

The vulnerability manifests in two scenarios:

1. **Single Minter Token Transfer**: When a minter mints an NFT and transfers even one token to another address, their balance decreases while `nftInfo.Quantity` remains unchanged (total minted amount). The equality check at line 262 will fail permanently. [2](#0-1) 

The `DoTransfer` function updates balances but does not affect `nftInfo.Quantity`, which represents the total minted amount stored during minting: [3](#0-2) 

2. **Multiple Minters with IsTokenIdReuse**: When a protocol has `IsTokenIdReuse=true` (allowing the same token ID to be minted multiple times), multiple minters can mint the same token ID, each incrementing the total quantity: [4](#0-3) 

In this case, `nftInfo.Quantity` represents the sum of all minting operations, and no single minter will ever hold all tokens in their balance, making Recast impossible for anyone. [5](#0-4) 

### Impact Explanation

**Operational Impact - Feature DoS:**
- Legitimate minters permanently lose the ability to update (recast) their NFT metadata after any token transfer
- For protocols with `IsTokenIdReuse=true`, the Recast feature is completely broken by design from the moment a second minter participates
- The Recast functionality becomes unusable in the primary use case of NFTs: trading and transferring ownership

**Affected Parties:**
- NFT minters who need to update metadata, correct errors, or evolve their NFT properties
- NFT protocols that rely on IsTokenIdReuse for creating editions or collections
- End users who expect NFT metadata to be updateable by authorized parties

**Severity Justification - Medium:**
- No direct fund loss or theft occurs
- Feature is completely disabled in normal operations
- Breaks expected functionality and user experience
- Affects all NFT protocols using this contract
- No workaround exists without contract upgrade

### Likelihood Explanation

**Likelihood: Very High**

**Feasible Preconditions:**
- No attack needed - occurs during normal NFT operations
- NFT transfers are the fundamental use case for NFTs
- Multiple minters per token ID is an explicitly supported feature (`IsTokenIdReuse=true`)

**Reachable Entry Point:**
The `Recast` function is a public method accessible to any address: [6](#0-5) 

**Execution Practicality:**
- Scenario 1 (Single Minter): Occurs immediately after first transfer - 100% reproducible
- Scenario 2 (Multiple Minters): Occurs automatically when second minter mints - 100% reproducible
- No complex setup, special timing, or race conditions required

**Detection:**
- Easily discovered by any minter attempting to recast after transferring tokens
- Visible in transaction logs with "Do not support recast." assertion failure

### Recommendation

**Code-Level Mitigation:**

Remove or modify the balance requirement at line 262. The minter authorization check at line 260 is sufficient for access control. Recommended fix:

```solidity
public override Empty Recast(RecastInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
    Assert(minterList.Value.Contains(Context.Sender), "No permission.");
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    Assert(nftInfo.Quantity != 0, "NFT does not exist or is fully burned.");
    // Remove the balance check: Assert(nftInfo.Quantity == State.BalanceMap[tokenHash][Context.Sender])
    
    // Alternative: Check if sender is in nftInfo.Minters list for stricter control
    // Assert(nftInfo.Minters.Contains(Context.Sender), "Must be original minter of this specific NFT.");
    
    // ... rest of function
}
```

**Invariant Checks to Add:**
- Verify that authorization checks do not conflate ownership with permission
- Ensure minter authorization is based on protocol-level or NFT-level minter lists, not token balance
- Add checks to ensure `nftInfo.Minters` list is properly maintained if used for authorization

**Test Cases to Prevent Regression:**
1. Test Recast after single minter transfers tokens to another address
2. Test Recast with multiple minters when `IsTokenIdReuse=true`
3. Test Recast when minter holds partial balance
4. Test Recast when minter holds zero balance but is still in minter list
5. Test Recast denial for non-minters regardless of balance

### Proof of Concept

**Scenario 1: Single Minter Transfer**

Initial State:
- NFT Protocol "ART123" exists with minter Alice in MinterListMap
- No NFTs minted yet

Transaction Steps:
1. Alice calls `Mint(symbol="ART123", tokenId=1, quantity=10, owner=Alice)`
   - Expected: Success, `nftInfo.Quantity = 10`, `State.BalanceMap[tokenHash][Alice] = 10`
   
2. Alice calls `Transfer(symbol="ART123", tokenId=1, to=Bob, amount=3)`
   - Expected: Success, `State.BalanceMap[tokenHash][Alice] = 7`, `State.BalanceMap[tokenHash][Bob] = 3`
   - `nftInfo.Quantity` remains `10` (unchanged)

3. Alice calls `Recast(symbol="ART123", tokenId=1, metadata=newMetadata)`
   - Line 260: `Assert(minterList.Value.Contains(Alice))` → **PASSES** (Alice is minter)
   - Line 262: `Assert(10 == 7)` → **FAILS**
   - Expected: Transaction reverts with "Do not support recast."
   - Actual: Transaction reverts (vulnerability confirmed)

**Success Condition for Exploit:** Alice (legitimate minter) is denied Recast access after normal token transfer, confirming the vulnerability.

**Scenario 2: Multiple Minters with IsTokenIdReuse**

Initial State:
- NFT Protocol "COLL456" exists with `IsTokenIdReuse=true`
- Minters Alice and Bob in MinterListMap

Transaction Steps:
1. Alice calls `Mint(symbol="COLL456", tokenId=1, quantity=5)`
   - Expected: Success, `nftInfo.Quantity = 5`, `State.BalanceMap[tokenHash][Alice] = 5`

2. Bob calls `Mint(symbol="COLL456", tokenId=1, quantity=5)` (same token ID)
   - Expected: Success (IsTokenIdReuse=true allows this)
   - Result: `nftInfo.Quantity = 10`, `State.BalanceMap[tokenHash][Bob] = 5`
   - `nftInfo.Minters = [Alice, Bob]`

3. Alice calls `Recast(symbol="COLL456", tokenId=1, metadata=newMetadata)`
   - Line 260: **PASSES** (Alice is minter)
   - Line 262: `Assert(10 == 5)` → **FAILS**

4. Bob calls `Recast(symbol="COLL456", tokenId=1, metadata=newMetadata)`
   - Line 260: **PASSES** (Bob is minter)
   - Line 262: `Assert(10 == 5)` → **FAILS**

**Success Condition for Exploit:** Neither legitimate minter can recast, even without any transfers, confirming the design flaw for IsTokenIdReuse protocols.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L46-55)
```csharp
    private void DoTransfer(Hash tokenHash, Address from, Address to, long amount)
    {
        if (amount < 0) throw new AssertionException("Invalid transfer amount.");

        if (amount == 0) return;

        Assert(State.BalanceMap[tokenHash][from] >= amount, "Insufficient balance.");
        State.BalanceMap[tokenHash][from] = State.BalanceMap[tokenHash][from].Sub(amount);
        State.BalanceMap[tokenHash][to] = State.BalanceMap[tokenHash][to].Add(amount);
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L256-256)
```csharp
    public override Empty Recast(RecastInput input)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L259-263)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(minterList.Value.Contains(Context.Sender), "No permission.");
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        Assert(nftInfo.Quantity != 0 && nftInfo.Quantity == State.BalanceMap[tokenHash][Context.Sender],
            "Do not support recast.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L423-424)
```csharp
                Minters = { Context.Sender },
                Quantity = quantity,
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L433-437)
```csharp
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L48-48)
```csharp
            IsTokenIdReuse = input.IsTokenIdReuse,
```
