### Title
Permission Inconsistency Between NFT Mint, Burn, and Recast Operations Due to Different Minter List Resolution Methods

### Summary
The NFT contract uses two different methods to resolve the minter list: `PerformMint` automatically includes the token issuer via `GetMinterList()`, while `Burn` and `Recast` operations directly check the stored minter list. This creates a permission inconsistency where a protocol creator who removes themselves from the minter list can still mint NFTs but cannot burn or recast them, violating the expected uniform permission model.

### Finding Description

The root cause lies in the inconsistent minter list resolution across different operations:

**During Protocol Creation:**
The token issuer is set to the creator address [1](#0-0) , and this creator is added to the initial minter list [2](#0-1) .

**During Mint Operations:**
The `PerformMint` method calls a private `GetMinterList(TokenInfo)` helper [3](#0-2)  which automatically adds the token issuer to the minter list if not already present [4](#0-3) . This ensures the issuer always has mint permissions regardless of the stored minter list state.

**During Burn Operations:**
The `Burn` method directly retrieves the stored minter list from state [5](#0-4)  without automatically including the issuer, checking only the explicit stored list.

**During Recast Operations:**
The `Recast` method similarly retrieves the stored minter list directly [6](#0-5)  and checks only explicit membership.

**Exploitation Path:**
The creator can remove themselves from the stored minter list via `RemoveMinters` [7](#0-6) , which validates that the caller is the protocol creator [8](#0-7) . After this removal:
- The creator can still **mint** new NFTs (issuer automatically re-added by `GetMinterList`)
- The creator **cannot burn** their own NFTs (stored list checked directly)
- The creator **cannot recast** NFT metadata (stored list checked directly)

### Impact Explanation

**Operational Inconsistency:**
Protocol creators lose expected uniform control over their NFT collections. If a creator removes themselves from the minter list (intentionally believing they're relinquishing all minting-related privileges, or accidentally), they retain mint capabilities but lose burn and recast capabilities.

**Affected Parties:**
- Protocol creators who manage their own minter lists
- NFT ecosystem participants who expect consistent permission semantics
- Integration layers that assume uniform permission models

**Severity Justification (Medium):**
- No direct fund theft or value extraction
- Creates operational confusion and unexpected behavior
- Violates authorization invariant: "NFT uniqueness and ownership checks" should apply uniformly across operations
- Can lead to inability to clean up or modify NFT metadata when needed
- Undermines trust in permission management if creators cannot reliably control their privileges

### Likelihood Explanation

**Attacker Capabilities:**
No malicious attacker needed - this affects legitimate protocol creators managing their permissions.

**Attack Complexity:**
Low - requires only a single call to `RemoveMinters` with the creator's own address, which is an explicitly permitted operation.

**Feasibility Conditions:**
- Creator must remove themselves from the minter list (allowed by design)
- Creator attempts to burn or recast after removal
- No external dependencies or special state requirements

**Probability Reasoning:**
Medium likelihood because:
- Creators have legitimate reasons to modify minter lists
- The inconsistency is not documented, leading to unexpected behavior
- A creator might remove themselves believing it removes all minting-related privileges
- The private `GetMinterList()` method's behavior is hidden from external callers

### Recommendation

**Code-Level Mitigation:**
Standardize minter list resolution across all operations by using the same `GetMinterList(TokenInfo)` method consistently:

1. Modify the `Burn` method to use `GetMinterList()` instead of directly accessing `State.MinterListMap`:
```csharp
var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput { Symbol = input.Symbol });
var minterList = GetMinterList(tokenInfo);
```

2. Modify the `Recast` method similarly to use `GetMinterList()`:
```csharp
var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput { Symbol = input.Symbol });
var minterList = GetMinterList(tokenInfo);
```

**Alternative Approach:**
If the design intent is that creators can fully relinquish privileges, then remove the automatic issuer inclusion from `GetMinterList()` and require explicit minter list membership for all operations including mint.

**Invariant Checks:**
- Add assertion that minter list resolution method is consistent across mint/burn/recast
- Add integration tests verifying permission behavior after RemoveMinters is called by the creator

**Test Cases:**
1. Test creator removes self from minter list, attempts mint → should pass or fail consistently
2. Test creator removes self from minter list, attempts burn → should match mint behavior
3. Test creator removes self from minter list, attempts recast → should match mint behavior

### Proof of Concept

**Initial State:**
- NFT protocol created with Creator = Address A
- Token issuer set to Address A (automatically)
- Minter list contains Address A (automatically added)

**Transaction Steps:**
1. Creator (Address A) calls `Create()` to establish NFT protocol "SYMBOL-1"
   - Result: Address A is issuer and in minter list

2. Creator (Address A) calls `Mint(symbol="SYMBOL-1", tokenId=1, owner=A)`
   - Expected: Success (A is in minter list)
   - Actual: ✓ Success

3. Creator (Address A) calls `RemoveMinters(symbol="SYMBOL-1", minterList=[A])`
   - Expected: Success (A is the creator)
   - Actual: ✓ Success
   - State: Stored minter list is now empty

4. Creator (Address A) calls `Mint(symbol="SYMBOL-1", tokenId=2, owner=A)`
   - Expected: Either success or failure (should be consistent with step 5-6)
   - Actual: ✓ Success (issuer automatically re-added by `GetMinterList()`)

5. Creator (Address A) calls `Burn(symbol="SYMBOL-1", tokenId=1, amount=1)`
   - Expected: Should match mint behavior (success if mint succeeds)
   - Actual: ✗ **Failure** - "No permission." (stored list checked directly, A not present)

6. Creator (Address A) calls `Recast(symbol="SYMBOL-1", tokenId=2, metadata={...})`
   - Expected: Should match mint behavior (success if mint succeeds)
   - Actual: ✗ **Failure** - "No permission." (stored list checked directly, A not present)

**Success Condition:**
Demonstrates that after removing themselves from the minter list, the creator can mint (step 4 succeeds) but cannot burn (step 5 fails) or recast (step 6 fails), proving the permission inconsistency.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L27-27)
```csharp
            Issuer = creator,
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L89-93)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L259-260)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(minterList.Value.Contains(Context.Sender), "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L355-373)
```csharp
    public override Empty RemoveMinters(RemoveMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
        var minterList = State.MinterListMap[protocolInfo.Symbol];

        foreach (var minter in input.MinterList.Value)
            if (minterList.Value.Contains(minter))
                minterList.Value.Remove(minter);

        State.MinterListMap[input.Symbol] = minterList;

        Context.Fire(new MinterListRemoved
        {
            Symbol = input.Symbol,
            MinterList = input.MinterList
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L375-381)
```csharp
    private MinterList GetMinterList(TokenInfo tokenInfo)
    {
        var minterList = State.MinterListMap[tokenInfo.Symbol] ?? new MinterList();
        if (!minterList.Value.Contains(tokenInfo.Issuer)) minterList.Value.Add(tokenInfo.Issuer);

        return minterList;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
