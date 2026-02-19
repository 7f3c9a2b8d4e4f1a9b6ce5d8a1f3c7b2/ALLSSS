### Title
Token Supply Not Persisted After Burn - Balance-Supply Accounting Mismatch

### Summary
The `Burn()` function successfully reduces user balances via `ModifyBalance()` but fails to persist the corresponding supply reduction because it never calls `SetTokenInfo()` after modifying `tokenInfo.Supply`. This creates a permanent accounting mismatch where total supply exceeds the sum of all balances, breaking the fundamental token invariant.

### Finding Description
The vulnerability exists in the private `Burn()` method where the execution flow is: [1](#0-0) 

The issue occurs because:
1. `ModifyBalance(address, symbol, -amount)` directly updates `State.Balances[address][symbol]` which triggers state persistence [2](#0-1) 

2. `tokenInfo.Supply = tokenInfo.Supply.Sub(amount)` only modifies the in-memory object
3. No call to `SetTokenInfo(tokenInfo)` is made to persist the supply change back to state

In AElf's state management system, modifications to protobuf object properties do not automatically persist - an explicit assignment to `State.TokenInfos[symbol]` (via `SetTokenInfo`) is required: [3](#0-2) 

This pattern is correctly followed in other supply-modifying operations:
- `Issue()` calls `SetTokenInfo(tokenInfo)` after modifying supply [4](#0-3) 

- `CrossChainReceiveToken()` calls `SetTokenInfo(tokenInfo)` after modifying supply [5](#0-4) 

The AElf `MappedState` implementation requires explicit setter invocation to cache state changes for persistence: [6](#0-5) 

### Impact Explanation
**Direct Fund Impact - Token Inflation:**
- Every burn operation reduces individual balances but leaves total supply unchanged
- Over time: `tokenInfo.Supply > Sum(all balances)`
- This breaks the critical invariant that supply should equal the sum of all outstanding balances
- Economic models relying on accurate supply metrics (staking rewards, inflation calculations, cross-chain balance reconciliation) become corrupted
- The protocol appears to have more tokens in supply than actually exist, creating phantom inflation

**Affected Parties:**
- All token holders (burned tokens don't reduce circulating supply)
- DeFi protocols using supply for calculations
- Cross-chain bridges relying on supply verification
- Governance systems with supply-weighted voting

**Severity Justification:**
High severity due to permanent corruption of token accounting, affecting core protocol invariants without recovery mechanism.

### Likelihood Explanation
**Reachable Entry Point:**
The public `Burn(BurnInput)` method is directly callable by any token holder for burnable tokens: [7](#0-6) 

**Attacker Capabilities:**
- No special privileges required
- Any user holding burnable tokens can trigger the vulnerability
- Occurs with every legitimate burn operation

**Execution Practicality:**
- 100% reproducible on every burn transaction
- No race conditions or timing dependencies
- Automatically triggered through normal protocol usage

**Economic Rationality:**
- Users burning tokens for legitimate reasons unknowingly corrupt accounting
- No additional cost beyond normal burn transaction fees
- Effect accumulates with protocol usage

**Detection Constraints:**
- Not easily detectable without comparing on-chain supply to calculated balance sum
- Appears as legitimate burn in events, masking the persistence failure
- Silent failure with no error or revert

### Recommendation
**Code-Level Fix:**
Add `SetTokenInfo(tokenInfo)` call after modifying supply in the `Burn()` function:

```csharp
private Empty Burn(Address address, string symbol, long amount)
{
    var tokenInfo = AssertValidToken(symbol, amount);
    Assert(tokenInfo.IsBurnable, "The token is not burnable.");
    ModifyBalance(address, symbol, -amount);
    tokenInfo.Supply = tokenInfo.Supply.Sub(amount);
    SetTokenInfo(tokenInfo);  // ADD THIS LINE
    
    Context.Fire(new Burned
    {
        Burner = address,
        Symbol = symbol,
        Amount = amount
    });
    return new Empty();
}
```

**Invariant Check:**
Add assertion to verify supply consistency after burn operations in test suites.

**Regression Prevention:**
- Add unit tests verifying `GetTokenInfo(symbol).Supply` decreases after burn
- Add integration tests comparing supply to sum of balances after burn sequences
- Add state validation in cross-chain token verification

### Proof of Concept
**Initial State:**
- Token "TEST" exists with `Supply = 1000`, user Alice has `Balance = 100`

**Transaction Steps:**
1. Alice calls `Burn(BurnInput { Symbol = "TEST", Amount = 50 })`
2. `ModifyBalance` executes successfully, Alice's balance becomes 50
3. `tokenInfo.Supply` is modified to 950 in memory
4. No `SetTokenInfo` call occurs
5. Transaction completes successfully

**Expected Result:**
- Alice balance: 50 ✓
- Token supply: 950 ✓

**Actual Result:**
- Alice balance: 50 ✓ (persisted via `ModifyBalance`)
- Token supply: 1000 ✗ (not persisted, `SetTokenInfo` never called)

**Success Condition:**
Query `GetTokenInfo("TEST").Supply` returns 1000 instead of expected 950, while `GetBalance(Alice, "TEST")` correctly returns 50, demonstrating the accounting mismatch.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L163-168)
```csharp
        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(input.To, input.Symbol, input.Amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L318-321)
```csharp
    public override Empty Burn(BurnInput input)
    {
        return Burn(Context.Sender, input.Symbol, input.Amount);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L323-337)
```csharp
    private Empty Burn(Address address, string symbol, long amount)
    {
        var tokenInfo = AssertValidToken(symbol, amount);
        Assert(tokenInfo.IsBurnable, "The token is not burnable.");
        ModifyBalance(address, symbol, -amount);
        tokenInfo.Supply = tokenInfo.Supply.Sub(amount);

        Context.Fire(new Burned
        {
            Burner = address,
            Symbol = symbol,
            Amount = amount
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L620-623)
```csharp
        tokenInfo.Supply = tokenInfo.Supply.Add(amount);
        Assert(tokenInfo.Supply <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(receivingAddress, tokenInfo.Symbol, amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L418-422)
```csharp
    private void SetTokenInfo(TokenInfo tokenInfo)
    {
        var symbol = tokenInfo.Symbol;
        State.TokenInfos[symbol] = tokenInfo;
    }
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L38-48)
```csharp
        set
        {
            if (!Cache.TryGetValue(key, out var valuePair))
            {
                valuePair = LoadKey(key);
                Cache[key] = valuePair;
            }

            valuePair.IsDeleted = false;
            valuePair.Value = value;
        }
```
