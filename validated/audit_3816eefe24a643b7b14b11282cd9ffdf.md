# Audit Report

## Title
Symbol Alias Normalization Inconsistency in ModifyBalance Causes Token Supply Accounting Errors

## Summary
The `ModifyBalance` function contains a critical asymmetry: it reads balances using normalized symbols but writes balances using raw input symbols without normalization. When `Issue`, `Burn`, or `Lock` functions are called with token aliases instead of actual symbols, balances are written to incorrect storage keys, breaking the fundamental invariant that total supply must equal the sum of all balances.

## Finding Description

The root cause lies in `ModifyBalance`'s inconsistent symbol handling. The function reads the current balance by calling `GetBalance`, which internally normalizes the symbol parameter. [1](#0-0) 

The `GetBalance` function calls `GetActualTokenSymbol` to resolve aliases to their actual token symbols. [2](#0-1) 

The normalization mechanism is implemented in `GetActualTokenSymbol`, which looks up aliases in the `SymbolAliasMap`. [3](#0-2) 

However, `ModifyBalance` then writes the updated balance directly to `State.Balances[address][symbol]` using the raw symbol parameter without any normalization (line 124 in the ModifyBalance function above).

Token aliases are created via `SetSymbolAlias`, which maps an alias to an actual NFT item symbol and stores it in `State.SymbolAliasMap`. [4](#0-3) [5](#0-4) 

**Vulnerable Entry Points:**

1. **Issue function** - The function calls `AssertValidToken` which normalizes the symbol, but then passes raw `input.Symbol` directly to `ModifyBalance` instead of using the normalized `tokenInfo.Symbol`. [6](#0-5) 

2. **Burn function** - Similarly passes raw `symbol` parameter directly to `ModifyBalance` without using the normalized symbol from `tokenInfo`. [7](#0-6) 

3. **Lock function** - Passes raw `input.Symbol` to `DoTransfer`, which subsequently calls `ModifyBalance` without normalization. [8](#0-7) 

**Why Existing Protections Fail:**

While `Transfer` and `TransferFrom` properly normalize symbols by calling `AssertValidToken` and using the returned `tokenInfo.Symbol`:
- Transfer uses normalized symbol: [9](#0-8) 
- TransferFrom uses normalized symbol: [10](#0-9) 

The vulnerable functions (`Issue`, `Burn`, `Lock`) call `AssertValidToken` but then discard its returned normalized symbol, passing the raw input symbol to `ModifyBalance`.

The `GetTokenInfo` helper function used by `AssertValidToken` does resolve aliases. [11](#0-10) 

## Impact Explanation

**Critical Supply Accounting Violation:**

The most severe impact occurs with `Burn`:
1. User has 100 tokens of "TOKEN-1" stored at `State.Balances[user]["TOKEN-1"]`
2. Alias "ALIAS-1" maps to "TOKEN-1" via `State.SymbolAliasMap`
3. User calls `Burn(symbol: "ALIAS-1", amount: 100)`
4. `ModifyBalance` reads balance from `State.Balances[user]["TOKEN-1"]` (100 tokens) via the normalized path in `GetBalance`
5. `ModifyBalance` writes 0 to `State.Balances[user]["ALIAS-1"]` (wrong storage key!)
6. Token supply is reduced by 100
7. User retains 100 tokens at `State.Balances[user]["TOKEN-1"]` (unchanged)

**Result:** The protocol's fundamental invariant `sum(all_balances) == total_supply` is violated. The supply is reduced while the user maintains full access to their tokens.

**Additional Impacts:**

- **Issue with alias**: Newly minted tokens become permanently inaccessible as they're stored under the wrong storage key, causing a denial of service for issued tokens
- **Lock with alias**: Locked tokens are stored in the virtual address under the wrong key, making them unrecoverable via `Unlock`, resulting in permanent fund lock
- **Economic manipulation**: Any supply-based calculations for governance weights, reward distributions, or price discovery become incorrect
- **Treasury/Profit accounting**: Distribution mechanisms relying on accurate supply metrics produce wrong results

## Likelihood Explanation

**Highly Likely to Occur:**

- **Reachable Entry Points**: `Issue`, `Burn`, and `Lock` are public functions directly callable by any user meeting standard authorization requirements
- **Feasible Preconditions**: 
  - Token aliases are legitimate features set by NFT collection owners/issuers via `SetSymbolAlias` (authorized by design)
  - `Burn` only requires user to own burnable tokens
  - `Issue` requires issuer authorization (standard)
  - `Lock` requires lock whitelist permission (standard)
- **Zero Attack Cost**: The `Burn` attack costs nothing - user "burns" tokens while keeping them
- **No Special Privileges**: Beyond normal token operations, no elevated permissions needed
- **User Error Likely**: Even without malicious intent, legitimate users calling these functions with aliases will trigger the bug
- **Detection Difficulty**: Transactions appear normal; only deep state inspection reveals the storage key mismatch

The feature is actively used and tested, as confirmed by the existence of comprehensive alias tests. [12](#0-11) 

## Recommendation

Modify the vulnerable functions to use the normalized symbol from `AssertValidToken`:

**For Issue:**
```csharp
public override Empty Issue(IssueInput input)
{
    // ... existing validation ...
    var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
    // ... existing checks ...
    
    tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
    tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);
    Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
    SetTokenInfo(tokenInfo);
    
    // FIX: Use tokenInfo.Symbol instead of input.Symbol
    ModifyBalance(input.To, tokenInfo.Symbol, input.Amount);
    
    Context.Fire(new Issued
    {
        Symbol = tokenInfo.Symbol,  // Also update event
        Amount = input.Amount,
        To = input.To,
        Memo = input.Memo
    });
    return new Empty();
}
```

**For Burn:**
```csharp
private Empty Burn(Address address, string symbol, long amount)
{
    var tokenInfo = AssertValidToken(symbol, amount);
    Assert(tokenInfo.IsBurnable, "The token is not burnable.");
    
    // FIX: Use tokenInfo.Symbol instead of raw symbol
    ModifyBalance(address, tokenInfo.Symbol, -amount);
    tokenInfo.Supply = tokenInfo.Supply.Sub(amount);

    Context.Fire(new Burned
    {
        Burner = address,
        Symbol = tokenInfo.Symbol,  // Also update event
        Amount = amount
    });
    return new Empty();
}
```

**For Lock:**
```csharp
public override Empty Lock(LockInput input)
{
    Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
    AssertValidInputAddress(input.Address);
    AssertSystemContractOrLockWhiteListAddress(input.Symbol);
    
    Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
        "Lock behaviour should be initialed by origin address.");

    var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
    if (allowance >= input.Amount)
        State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
    
    // FIX: Get normalized symbol
    var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
    
    var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
        .Concat(input.LockId.Value).ToArray());
    var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
    
    // FIX: Use tokenInfo.Symbol instead of input.Symbol
    DoTransfer(input.Address, virtualAddress, tokenInfo.Symbol, input.Amount, input.Usage);
    DealWithExternalInfoDuringLocking(new TransferFromInput
    {
        From = input.Address,
        To = virtualAddress,
        Symbol = tokenInfo.Symbol,  // Also update here
        Amount = input.Amount,
        Memo = input.Usage
    });
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BurnWithAlias_SupplyAccountingCorruption_Test()
{
    // Setup: Create NFT collection and item with alias
    var symbols = await CreateNftCollectionAndNft();
    var nftSymbol = symbols[1]; // e.g., "TP-31175"
    
    // Set alias "TP" for the NFT item
    await TokenContractStub.SetSymbolAlias.SendAsync(new SetSymbolAliasInput
    {
        Symbol = nftSymbol,
        Alias = "TP"
    });
    
    // Issue tokens to user
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = nftSymbol,
        Amount = 100,
        To = DefaultAddress
    });
    
    // Verify initial state
    var initialBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultAddress,
        Symbol = nftSymbol
    });
    initialBalance.Balance.ShouldBe(100);
    
    var initialTokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
    {
        Symbol = nftSymbol
    });
    var initialSupply = initialTokenInfo.Supply;
    initialSupply.ShouldBe(100);
    
    // EXPLOIT: Burn using alias instead of actual symbol
    await TokenContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = "TP",  // Using alias!
        Amount = 100
    });
    
    // VULNERABILITY DEMONSTRATED:
    // 1. Balance at actual symbol key is UNCHANGED
    var balanceAtActualKey = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultAddress,
        Symbol = nftSymbol  // Query with actual symbol
    });
    balanceAtActualKey.Balance.ShouldBe(100);  // Still 100! Should be 0.
    
    // 2. Supply was reduced
    var finalTokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
    {
        Symbol = nftSymbol
    });
    finalTokenInfo.Supply.ShouldBe(0);  // Supply reduced to 0
    
    // INVARIANT VIOLATION: sum(balances) > supply
    // User has 100 tokens but supply is 0
    // This breaks the fundamental protocol invariant
}
```

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L405-416)
```csharp
    private TokenInfo GetTokenInfo(string symbolOrAlias)
    {
        var tokenInfo = State.TokenInfos[symbolOrAlias];
        if (tokenInfo != null) return tokenInfo;
        var actualTokenSymbol = State.SymbolAliasMap[symbolOrAlias];
        if (!string.IsNullOrEmpty(actualTokenSymbol))
        {
            tokenInfo = State.TokenInfos[actualTokenSymbol];
        }

        return tokenInfo;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L154-178)
```csharp
    public override Empty Issue(IssueInput input)
    {
        Assert(input.To != null, "To address not filled.");
        AssertValidMemo(input.Memo);
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
        Assert(tokenInfo.Issuer == Context.Sender || Context.Sender == Context.GetZeroSmartContractAddress(),
            $"Sender is not allowed to issue token {input.Symbol}.");

        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(input.To, input.Symbol, input.Amount);

        Context.Fire(new Issued
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = input.To,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L180-193)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransfer(Context.Sender, input.To, tokenInfo.Symbol, input.Amount, input.Memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = tokenInfo.Symbol,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-222)
```csharp
    public override Empty Lock(LockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");

        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
        AssertValidToken(input.Symbol, input.Amount);
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
        DealWithExternalInfoDuringLocking(new TransferFromInput
        {
            From = input.Address,
            To = virtualAddress,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L254-259)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransferFrom(input.From, input.To, Context.Sender, tokenInfo.Symbol, input.Amount, input.Memo);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L318-337)
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

        Context.Fire(new Burned
        {
            Burner = address,
            Symbol = symbol,
            Amount = amount
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L738-779)
```csharp
    public override Empty SetSymbolAlias(SetSymbolAliasInput input)
    {
        // Alias setting can only work for NFT Item for now.
        // And the setting exists on the TokenInfo of the NFT Collection.

        // Can only happen on Main Chain.
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "Symbol alias setting only works on MainChain.");

        var collectionSymbol = GetNftCollectionSymbol(input.Symbol, true);

        // For now, token alias can only be set once.
        Assert(State.SymbolAliasMap[input.Alias] == null, $"Token alias {input.Alias} already exists.");

        CheckTokenAlias(input.Alias, collectionSymbol);

        var collectionTokenInfo = GetTokenInfo(collectionSymbol);
        if (collectionTokenInfo == null)
        {
            throw new AssertionException($"NFT Collection {collectionSymbol} not found.");
        }

        Assert(collectionTokenInfo.Owner == Context.Sender || collectionTokenInfo.Issuer == Context.Sender,
            "No permission.");

        collectionTokenInfo.ExternalInfo.Value[TokenContractConstants.TokenAliasExternalInfoKey]
            = $"{{\"{input.Symbol}\":\"{input.Alias}\"}}";

        SetTokenInfo(collectionTokenInfo);

        State.SymbolAliasMap[input.Alias] = input.Symbol;

        Context.LogDebug(() => $"Token alias added: {input.Symbol} -> {input.Alias}");

        Context.Fire(new SymbolAliasAdded
        {
            Symbol = input.Symbol,
            Alias = input.Alias
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L78-79)
```csharp
    // Alias -> Actual Symbol
    public MappedState<string, string> SymbolAliasMap { get; set; }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenAliasTests.cs (L165-201)
```csharp
    public async Task TransferViaAlias_Test()
    {
        await CreateTokenWithAlias_Test();

        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "TP-31175",
            Amount = 1,
            To = DefaultAddress
        });

        {
            var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = DefaultAddress,
                Symbol = "TP"
            });
            balance.Balance.ShouldBe(1);
        }

        await TokenContractStub.Transfer.SendAsync(new TransferInput
        {
            // Transfer via alias.
            Symbol = "TP",
            Amount = 1,
            To = User1Address
        });

        {
            var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = User1Address,
                Symbol = "TP"
            });
            balance.Balance.ShouldBe(1);
        }
    }
```
