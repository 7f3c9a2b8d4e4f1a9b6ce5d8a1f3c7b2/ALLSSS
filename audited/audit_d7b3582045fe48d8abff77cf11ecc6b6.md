# Audit Report

## Title
NFT Alias Symbol Resolution Bypass Causes Undeclared State Path Access in Parallel Execution

## Summary
The ACS2 state path provider declares resource paths using input symbols without resolving NFT aliases, while execution resolves aliases before accessing state. This mismatch causes transactions using NFT aliases to access undeclared state paths (balances, allowances, and NFT collection paths), breaking parallel execution safety guarantees and enabling race conditions.

## Finding Description

The vulnerability exists in the interaction between the ACS2 resource path declaration system and NFT alias resolution. 

**Root Cause:**

The `GetResourceInfo` method for `TransferFrom` declares resource paths using the input symbol directly without alias resolution. [1](#0-0) 

When an NFT alias is used (e.g., "TP" for "TP-31175"), the `AddPathForAllowance` method calls `GetSymbolType` on the unresolved alias. [2](#0-1) 

Since NFT aliases lack hyphens (validated by design), `GetSymbolType` incorrectly identifies the alias as `SymbolType.Token` instead of `SymbolType.Nft`. [3](#0-2) 

This causes `AddPathForAllowance` to skip declaring the NFT collection allowance path (e.g., "TP-*"), which is only added for NFT and NftCollection types.

**Execution Flow Mismatch:**

During actual execution, the `TransferFrom` method resolves the alias to the actual NFT symbol before state access. [4](#0-3) 

The resolution occurs through `GetTokenInfo`, which checks `State.SymbolAliasMap` to convert aliases to actual symbols. [5](#0-4) 

The resolved symbol (e.g., "TP-31175") is then passed to `DoTransferFrom`, which accesses the NFT collection allowance path that was never declared. [6](#0-5) 

Specifically, `GetAllowance` calls `GetNftCollectionAllSymbolAllowance` which accesses `State.Allowances[from][spender]["TP-*"]` - an undeclared path. [7](#0-6) 

**Alias Validation Confirms the Issue:**

The `CheckTokenAlias` method validates that aliases must equal the collection prefix (without hyphen), confirming that aliases never contain hyphens by design. [8](#0-7) 

This is a supported feature with test coverage demonstrating `TransferFrom` works with aliases. [9](#0-8) 

## Impact Explanation

**Concrete Path Mismatch:**

For NFT "TP-31175" with alias "TP":
- **Declared paths**: `Allowances[from][spender]["TP"]`, `Allowances[from][spender]["*"]`, `Balances[from]["TP"]`, `Balances[to]["TP"]`
- **Accessed paths**: `Allowances[from][spender]["TP-31175"]`, `Allowances[from][spender]["TP-*"]`, `Allowances[from][spender]["*"]`, `Balances[from]["TP-31175"]`, `Balances[to]["TP-31175"]`

Only the global allowance path "*" overlaps. All NFT-specific and collection paths are undeclared.

**Critical Impacts:**

1. **Parallel Execution Violations**: Transactions write to undeclared state paths, violating ACS2 guarantees. The parallel execution system relies on accurate resource path declarations to determine which transactions can execute concurrently. Undeclared path access breaks this fundamental assumption.

2. **Race Conditions**: Two transactions using aliases for different NFTs in the same collection (e.g., "ALIAS1"→"ABC-1" and "ALIAS2"→"ABC-2") won't declare the shared collection allowance path "ABC-*". The system may allow parallel execution when these transactions actually conflict on the same collection-level allowance state.

3. **State Corruption Risk**: Concurrent writes to the same undeclared allowance or balance paths can cause lost updates, inconsistent state, or transaction failures in parallel execution environments.

**Affected Parties**: All users of NFTs with aliases, NFT collection owners, and the parallel execution system's integrity.

## Likelihood Explanation

**Attacker Capabilities:**
- NFT collection owners/issuers can set aliases via the public `SetSymbolAlias` method (requires only NFT ownership, not special privileges)
- Any user can invoke `TransferFrom` with an alias after receiving approval

**Attack Complexity**: Low - simply use an alias in a transaction parameter.

**Feasibility Conditions:**
- Aliases are a documented, supported feature as evidenced by dedicated test coverage
- The vulnerability triggers automatically for any transaction using an alias, requiring no special exploitation technique
- No economic barriers beyond normal transaction fees

**Probability**: HIGH - This occurs for 100% of transactions using NFT aliases, which is a legitimate and encouraged use case supported by the protocol.

## Recommendation

Resolve aliases in `GetResourceInfo` before declaring resource paths. Modify the `AddPathForAllowance` method to call alias resolution:

```csharp
private void AddPathForAllowance(ResourceInfo resourceInfo, string from, string spender, string symbol)
{
    // Resolve alias to actual symbol for correct path declaration
    var actualSymbol = GetActualTokenSymbol(symbol);
    
    resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender, actualSymbol));
    resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender,
        GetAllSymbolIdentifier()));
    var symbolType = GetSymbolType(actualSymbol); // Use resolved symbol for type determination
    if (symbolType == SymbolType.Nft || symbolType == SymbolType.NftCollection)
    {
        resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender,
            GetNftCollectionAllSymbolIdentifier(actualSymbol)));
    }
}
```

Similarly, resolve aliases for balance paths in the `TransferFrom` case of `GetResourceInfo`:

```csharp
case nameof(TransferFrom):
{
    var args = TransferFromInput.Parser.ParseFrom(txn.Params);
    var actualSymbol = GetActualTokenSymbol(args.Symbol); // Resolve alias
    var resourceInfo = new ResourceInfo
    {
        WritePaths =
        {
            GetPath(nameof(TokenContractState.Balances), args.From.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.Balances), args.To.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.LockWhiteLists), actualSymbol, txn.From.ToString())
        },
        // ... rest of implementation
    };
    AddPathForAllowance(resourceInfo, args.From.ToString(), txn.From.ToString(), args.Symbol);
    // ... rest of implementation
}
```

## Proof of Concept

The existing test `ApproveAndTransferFromViaAlias_Test` demonstrates the issue, though it doesn't explicitly verify parallel execution paths. A PoC would:

1. Create NFT "TP-31175" with alias "TP"
2. Issue the NFT to an address
3. Approve a spender using alias "TP"
4. Call `TransferFrom` with alias "TP"
5. Verify via `GetResourceInfo` that declared paths use "TP" while execution accesses "TP-31175" and "TP-*" paths
6. Demonstrate parallel execution allows two transactions with different aliases from the same collection to execute concurrently despite conflicting on collection allowance state

The vulnerability is confirmed by code analysis showing the path declaration uses unresolved aliases while execution uses resolved symbols, creating the mismatch that breaks parallel execution guarantees.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L40-64)
```csharp
            case nameof(TransferFrom):
            {
                var args = TransferFromInput.Parser.ParseFrom(txn.Params);
                var resourceInfo = new ResourceInfo
                {
                    WritePaths =
                    {
                        GetPath(nameof(TokenContractState.Balances), args.From.ToString(), args.Symbol),
                        GetPath(nameof(TokenContractState.Balances), args.To.ToString(), args.Symbol),
                        GetPath(nameof(TokenContractState.LockWhiteLists), args.Symbol, txn.From.ToString())
                    },
                    ReadPaths =
                    {
                        GetPath(nameof(TokenContractState.TokenInfos), args.Symbol),
                        GetPath(nameof(TokenContractState.ChainPrimaryTokenSymbol)),
                        GetPath(nameof(TokenContractState.TransactionFeeFreeAllowancesSymbolList))
                    }
                };
                AddPathForAllowance(resourceInfo, args.From.ToString(), txn.From.ToString(), args.Symbol);
                AddPathForTransactionFee(resourceInfo, txn.From.ToString(), txn.MethodName);
                AddPathForDelegatees(resourceInfo, txn.From, txn.To, txn.MethodName);
                AddPathForTransactionFeeFreeAllowance(resourceInfo, txn.From);

                return resourceInfo;
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L71-82)
```csharp
    private void AddPathForAllowance(ResourceInfo resourceInfo, string from, string spender, string symbol)
    {
        resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender, symbol));
        resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender,
            GetAllSymbolIdentifier()));
        var symbolType = GetSymbolType(symbol);
        if (symbolType == SymbolType.Nft || symbolType == SymbolType.NftCollection)
        {
            resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.Allowances), from, spender,
                GetNftCollectionAllSymbolIdentifier(symbol)));
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFTHelper.cs (L7-14)
```csharp
    private SymbolType GetSymbolType(string symbol)
    {
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(words[0].Length > 0 && IsValidCreateSymbol(words[0]), "Invalid Symbol input");
        if (words.Length == 1) return SymbolType.Token;
        Assert(words.Length == 2 && words[1].Length > 0 && IsValidItemId(words[1]), "Invalid NFT Symbol input");
        return words[1] == TokenContractConstants.CollectionSymbolSuffix ? SymbolType.NftCollection : SymbolType.Nft;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L840-852)
```csharp
    private void CheckTokenAlias(string alias, string collectionSymbol)
    {
        if (collectionSymbol == null)
        {
            throw new AssertionException("Token alias can only be set for NFT Item.");
        }

        // Current Rule: Alias must be the seed name.
        var parts = collectionSymbol.Split(TokenContractConstants.NFTSymbolSeparator);
        Assert(parts.Length == 2, $"Incorrect collection symbol: {collectionSymbol}.");
        Assert(parts.Last() == TokenContractConstants.CollectionSymbolSuffix, "Incorrect collection symbol suffix.");
        Assert(alias == parts.First(), $"Alias for an item of {collectionSymbol} cannot be {alias}.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L69-95)
```csharp
    private void DoTransferFrom(Address from, Address to, Address spender, string symbol, long amount, string memo)
    {
        AssertValidInputAddress(from);
        AssertValidInputAddress(to);
        
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L125-130)
```csharp
    private long GetNftCollectionAllSymbolAllowance(Address from, Address spender, string sourceSymbol,
        out string allowanceSymbol)
    {
        allowanceSymbol = GetNftCollectionAllSymbolIdentifier(sourceSymbol);
        return State.Allowances[from][spender][allowanceSymbol];
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenAliasTests.cs (L204-238)
```csharp
    public async Task ApproveAndTransferFromViaAlias_Test()
    {
        await CreateTokenWithAlias_Test();

        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "TP-31175",
            Amount = 1,
            To = DefaultAddress
        });

        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Symbol = "TP",
            Amount = 1,
            Spender = User1Address
        });

        await TokenContractStubUser.TransferFrom.SendAsync(new TransferFromInput
        {
            Symbol = "TP",
            Amount = 1,
            From = DefaultAddress,
            To = User2Address,
        });

        {
            var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = User2Address,
                Symbol = "TP"
            });
            balance.Balance.ShouldBe(1);
        }
    }
```
