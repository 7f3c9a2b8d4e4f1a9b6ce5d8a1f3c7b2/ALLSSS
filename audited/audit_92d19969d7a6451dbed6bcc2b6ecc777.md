### Title
Symbol Alias Normalization Inconsistency in ModifyBalance Causes Token Supply Accounting Errors

### Summary
The `ModifyBalance` function reads balance using normalized symbols (via `GetActualTokenSymbol`) but writes balance using raw input symbols without normalization. When token aliases exist and functions like `Issue`, `Burn`, or `Lock` are called with alias symbols instead of actual symbols, balances are written to incorrect storage keys, breaking the critical invariant that total supply must equal the sum of all balances.

### Finding Description

The root cause is an inconsistency in how `ModifyBalance` handles symbol parameters: [1](#0-0) 

The function reads balance via `GetBalance(address, symbol)` which normalizes symbols: [2](#0-1) [3](#0-2) 

However, `ModifyBalance` writes the updated balance to `State.Balances[address][symbol]` using the raw symbol parameter without calling `GetActualTokenSymbol`.

Tokens can have aliases via the `SetSymbolAlias` function: [4](#0-3) 

**Vulnerable entry points that pass raw symbols to ModifyBalance:**

1. **Issue function** - uses raw `input.Symbol`: [5](#0-4) 

2. **Burn function** - uses raw `symbol` parameter: [6](#0-5) 

3. **Lock function** - uses raw `input.Symbol` via `DoTransfer`: [7](#0-6) [8](#0-7) 

**Why existing protections fail:**

While `Transfer` and `TransferFrom` properly normalize symbols before calling `ModifyBalance`: [9](#0-8) [10](#0-9) 

The `Issue`, `Burn`, and `Lock` functions do not perform this normalization before passing symbols to `ModifyBalance` or `DoTransfer`.

### Impact Explanation

**Direct Fund Impact - Token Supply Inflation/Deflation:**

The most severe attack vector is via `Burn`:
1. Attacker has 100 tokens of "TOKEN-1" (actual symbol)
2. Alias "ALIAS-1" exists mapping to "TOKEN-1"
3. Attacker calls `Burn(symbol: "ALIAS-1", amount: 100)`
4. Balance is read from `State.Balances[attacker]["TOKEN-1"]` (100 tokens)
5. Balance is written to `State.Balances[attacker]["ALIAS-1"]` (0 tokens)
6. Supply is reduced by 100
7. Attacker still has 100 accessible tokens at `State.Balances[attacker]["TOKEN-1"]`

Result: Total supply is reduced while the attacker maintains full token access, breaking the fundamental invariant `sum(all_balances) == total_supply`.

**Secondary Impacts:**
- **Issue with alias**: Tokens are minted to supply but stored under wrong key, becoming inaccessible (DoS)
- **Lock with alias**: Locked tokens become stranded in virtual address under wrong key, preventing unlock
- **Economic manipulation**: Supply-based calculations for governance, rewards, or pricing become incorrect
- **Treasury/Profit accounting**: Distribution calculations relying on supply metrics produce wrong results

### Likelihood Explanation

**Reachable Entry Point:** ✓ Public functions `Issue`, `Burn`, and `Lock` are directly callable.

**Feasible Preconditions:** 
- Token must have an alias set via `SetSymbolAlias` (requires NFT collection owner/issuer authorization)
- For `Burn`: User must have burnable tokens
- For `Issue`: Caller must be authorized issuer
- For `Lock`: Caller must have lock whitelist permission

**Execution Practicality:** ✓ Attack requires only:
1. A token with an alias (legitimately created by collection owner)
2. Calling public functions with the alias symbol instead of actual symbol
3. No special privileges beyond normal token operations

**Economic Rationality:** ✓ 
- `Burn` attack is zero-cost (user burns tokens while keeping them)
- Can manipulate token metrics for potential price/governance manipulation
- Realistic for any NFT collection with aliases

**Detection:** Difficult to detect as transactions appear normal; only state inspection reveals balance key mismatches.

### Recommendation

**Immediate Fix:** Normalize all symbol parameters before passing to `ModifyBalance`:

1. **In Issue function** (line 168), change:
```csharp
ModifyBalance(input.To, input.Symbol, input.Amount);
```
To:
```csharp
ModifyBalance(input.To, tokenInfo.Symbol, input.Amount);
```

2. **In private Burn function** (line 327), use the actual symbol from tokenInfo instead of the parameter.

3. **In Lock function** (line 212), normalize before calling DoTransfer:
```csharp
var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
DoTransfer(input.Address, virtualAddress, tokenInfo.Symbol, input.Amount, input.Usage);
```

**Defensive Fix:** Add normalization directly in `ModifyBalance`:
```csharp
private void ModifyBalance(Address address, string symbol, long addAmount)
{
    var actualSymbol = GetActualTokenSymbol(symbol);
    var before = GetBalance(address, actualSymbol);
    if (addAmount < 0 && before < -addAmount)
        Assert(false, $"{address}. Insufficient balance...");
    var target = before.Add(addAmount);
    State.Balances[address][actualSymbol] = target;
}
```

**Invariant Checks:**
- Add assertion: `sum(GetBalance for all addresses) == tokenInfo.Supply` in test suites
- Validate balance storage keys match actual symbols, not aliases

### Proof of Concept

**Initial State:**
- Token "NFT-1" exists with Supply = 1000, IsBurnable = true
- Alias "SHORT-1" created for "NFT-1" via SetSymbolAlias
- User A has State.Balances[A]["NFT-1"] = 100

**Attack Steps:**

1. User A calls `Burn(BurnInput { Symbol: "SHORT-1", Amount: 100 })`

2. Execution in Burn:
   - `AssertValidToken("SHORT-1", 100)` resolves to "NFT-1" TokenInfo ✓
   - `ModifyBalance(A, "SHORT-1", -100)`:
     - `GetBalance(A, "SHORT-1")` reads `State.Balances[A]["NFT-1"]` = 100 ✓
     - Validation passes ✓
     - Writes `State.Balances[A]["SHORT-1"]` = 0
   - `tokenInfo.Supply` reduced to 900

3. User A calls `Transfer(TransferInput { To: B, Symbol: "NFT-1", Amount: 100 })`
   - Transfer normalizes to "NFT-1"
   - `ModifyBalance(A, "NFT-1", -100)`:
     - Reads `State.Balances[A]["NFT-1"]` = 100 ✓
     - Writes `State.Balances[A]["NFT-1"]` = 0
   - `ModifyBalance(B, "NFT-1", 100)`:
     - Writes `State.Balances[B]["NFT-1"]` = 100

**Expected Result:**
- User A should have 0 tokens after burning 100
- Supply should be 900
- User B should have 100 tokens
- Sum of balances should equal supply

**Actual Result:**
- User A successfully burned AND transferred 100 tokens (double-spent)
- State.Balances[A]["NFT-1"] = 0
- State.Balances[A]["SHORT-1"] = 0 (ghost balance)
- State.Balances[B]["NFT-1"] = 100
- Total Supply = 900
- Sum of accessible balances = 100
- **Invariant broken: 100 ≠ 900**

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L166-172)
```csharp
    private long GetBalance(Address address, string symbol)
    {
        AssertValidInputAddress(address);
        var actualSymbol = GetActualTokenSymbol(symbol);
        Assert(!string.IsNullOrWhiteSpace(actualSymbol), "Invalid symbol.");
        return State.Balances[address][actualSymbol];
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L286-294)
```csharp
    private string GetActualTokenSymbol(string aliasOrSymbol)
    {
        if (State.TokenInfos[aliasOrSymbol] == null)
        {
            return State.SymbolAliasMap[aliasOrSymbol] ?? aliasOrSymbol;
        }

        return aliasOrSymbol;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L168-168)
```csharp
        ModifyBalance(input.To, input.Symbol, input.Amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L182-183)
```csharp
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransfer(Context.Sender, input.To, tokenInfo.Symbol, input.Amount, input.Memo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L212-212)
```csharp
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L256-257)
```csharp
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransferFrom(input.From, input.To, Context.Sender, tokenInfo.Symbol, input.Amount, input.Memo);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L318-328)
```csharp
    public override Empty Burn(BurnInput input)
    {
        return Burn(Context.Sender, input.Symbol, input.Amount);
    }

    private Empty Burn(Address address, string symbol, long amount)
    {
        var tokenInfo = AssertValidToken(symbol, amount);
        Assert(tokenInfo.IsBurnable, "The token is not burnable.");
        ModifyBalance(address, symbol, -amount);
        tokenInfo.Supply = tokenInfo.Supply.Sub(amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L768-768)
```csharp
        State.SymbolAliasMap[input.Alias] = input.Symbol;
```
