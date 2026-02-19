### Title
Token Alias Resolution Causes Undeclared NFT Collection Allowance Path Access in Parallel Execution

### Summary
When `TransferFrom` is called with an NFT collection alias (e.g., "TP" for "TP-0"), the `GetResourceInfo` method uses `GetSymbolType` to classify the alias as a regular token and fails to declare the NFT collection allowance path (e.g., "TP-*"). However, during execution, the alias is resolved to the actual NFT collection symbol, causing `GetAllowance` to read/write the undeclared "TP-*" allowance path. This creates parallel execution conflicts and missing state locks.

### Finding Description

The vulnerability stems from a mismatch between state path declaration and actual execution:

**State Path Declaration Phase:**
In `GetResourceInfo` for `TransferFrom`, the method receives the raw symbol from transaction parameters without alias resolution: [1](#0-0) 

The `AddPathForAllowance` function calls `GetSymbolType` to determine whether to add the NFT collection allowance path: [2](#0-1) 

For an alias like "TP", `GetSymbolType` classifies it as a `Token` because it contains no '-' separator: [3](#0-2) 

Since the symbol type is `Token` (not `Nft` or `NftCollection`), lines 77-81 are skipped, and the NFT collection allowance path (e.g., "TP-*") is NOT added to `WritePaths`.

**Execution Phase:**
During `TransferFrom` execution, the alias is resolved to the actual symbol: [4](#0-3) 

The `AssertValidToken` method uses `GetTokenInfo` which resolves aliases: [5](#0-4) 

Now `DoTransferFrom` is called with `tokenInfo.Symbol` (the actual symbol like "TP-31175" or "TP-0"), and `GetAllowance` is invoked: [6](#0-5) 

For the actual symbol "TP-31175", `GetSymbolType` returns `Nft` (or `NftCollection` for "TP-0"), triggering line 110 which reads the NFT collection allowance path "TP-*": [7](#0-6) 

If the allowance is consumed, line 94 writes to this undeclared path: [8](#0-7) 

The token alias feature is officially supported, as confirmed by system tests: [9](#0-8) 

Alias configuration shows that aliases map to collection prefixes: [10](#0-9) 

### Impact Explanation

**Operational Impact - Parallel Execution Integrity Violation:**

1. **Race Conditions**: Two `TransferFrom` transactions using aliases that resolve to the same NFT collection can be executed in parallel because their declared state paths don't overlap. However, both actually access the same undeclared NFT collection allowance path (e.g., "TP-*"), causing race conditions.

2. **Missing State Locks**: AElf's parallel execution engine relies on declared state paths to determine transaction conflicts. Undeclared paths bypass the locking mechanism, allowing concurrent modifications to the same allowance state.

3. **State Corruption**: Without proper locking, the allowance deduction at line 94 can be lost or double-counted:
   - Transaction A reads allowance = 100 for "TP-*"
   - Transaction B reads allowance = 100 for "TP-*" (concurrent)
   - Transaction A deducts 50, writes 50
   - Transaction B deducts 30, writes 70
   - Final state: 70 (should be 20)

4. **Balance Path Mismatch**: Secondary issue - `GetResourceInfo` declares balance paths for the alias "TP", but execution accesses paths for the actual symbol "TP-31175", creating additional undeclared state access.

**Who is Affected**: All users relying on NFT collection allowances when using token aliases. This includes DApps, marketplaces, and multi-signature wallets that approve NFT collection transfers.

### Likelihood Explanation

**Likelihood: HIGH**

1. **Reachable Entry Point**: `TransferFrom` is a public method callable by any user: [4](#0-3) 

2. **Feasible Preconditions**: 
   - NFT collections with aliases are created through standard `Create` operations with alias configuration
   - Users approve spenders using collection-level allowances (symbol suffix "-*")
   - No special permissions required

3. **Execution Practicality**:
   - Aliases are a documented feature, not an edge case
   - Test suite confirms `TransferFrom` works with aliases
   - Natural usage pattern: users prefer short aliases over long NFT symbols

4. **Economic Rationality**: 
   - No cost to exploit beyond normal transaction fees
   - Attacker can deliberately create parallel conflicting transactions
   - No detection mechanism for undeclared state access

5. **Operational Reality**: The parallel execution engine in AElf depends on accurate state path declaration. This is a core assumption that gets violated, not a minor edge case.

### Recommendation

**Immediate Fix:**

Modify `GetResourceInfo` to resolve aliases before determining symbol types:

```csharp
case nameof(TransferFrom):
{
    var args = TransferFromInput.Parser.ParseFrom(txn.Params);
    
    // NEW: Resolve alias to actual symbol for path generation
    var actualSymbol = GetActualTokenSymbol(args.Symbol);
    
    var resourceInfo = new ResourceInfo
    {
        WritePaths =
        {
            GetPath(nameof(TokenContractState.Balances), args.From.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.Balances), args.To.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.LockWhiteLists), actualSymbol, txn.From.ToString())
        },
        ReadPaths =
        {
            GetPath(nameof(TokenContractState.TokenInfos), args.Symbol), // Keep original for lookup
            GetPath(nameof(TokenContractState.SymbolAliasMap), args.Symbol), // Add alias map read
            GetPath(nameof(TokenContractState.ChainPrimaryTokenSymbol)),
            GetPath(nameof(TokenContractState.TransactionFeeFreeAllowancesSymbolList))
        }
    };
    AddPathForAllowance(resourceInfo, args.From.ToString(), txn.From.ToString(), actualSymbol);
    // ... rest unchanged
}
```

**Additional Safeguards:**

1. Add integration test that verifies state path declarations match actual execution for alias-based operations
2. Implement runtime assertion that compares declared vs. accessed state paths in test environment
3. Document that all state path generation must use resolved symbols, not aliases

**Test Case to Prevent Regression:**

```csharp
[Fact]
public async Task TransferFrom_WithAlias_DeclaresCorrectStatePaths()
{
    // Setup: Create NFT collection "TEST-0" with alias "TEST"
    // Approve using collection-level allowance "TEST-*"
    // TransferFrom using alias "TEST"
    // Assert: GetResourceInfo declares path for "TEST-*"
}
```

### Proof of Concept

**Initial State:**
1. NFT Collection "COLL-0" created with alias "COLL"
2. Individual NFT "COLL-1" minted to Alice
3. Alice approves Bob for all NFTs in collection: `Approve(spender=Bob, symbol="COLL-*", amount=999999)`
4. State: `Allowances[Alice][Bob]["COLL-*"] = 999999`

**Exploit Sequence:**

**Transaction A (uses alias):**
```
TransferFrom(from=Alice, to=Charlie, symbol="COLL", amount=1)
```
- GetResourceInfo: classifies "COLL" as Token, doesn't declare "COLL-*" path
- Execution: resolves to "COLL-1", reads/writes "COLL-*" allowance
- Declared paths: Alice/COLL, Charlie/COLL
- Actual accessed: Alice/COLL-1, Charlie/COLL-1, Allowances[Alice][Bob]["COLL-*"]

**Transaction B (concurrent, uses alias):**
```
TransferFrom(from=Alice, to=David, symbol="COLL", amount=1) 
```
- Same path declarations as Transaction A
- No declared path overlap → executed in parallel

**Expected Result:**
- Allowances[Alice][Bob]["COLL-*"] should be 999997 (999999 - 1 - 1)

**Actual Result:**
- Due to race condition on undeclared "COLL-*" path, final value could be 999998 (one deduction lost)
- Parallel execution allows both transactions to read initial value 999999, both deduct 1, one write overwrites the other

**Success Condition:**
The vulnerability is confirmed if:
1. GetResourceInfo for "COLL" doesn't include "COLL-*" in WritePaths (verified at line 76-81)
2. Execution actually accesses "COLL-*" (verified at line 110, 129, 94)
3. Test demonstrates allowance deduction is incorrect when transactions run in parallel

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L42-58)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L826-838)
```csharp
    private void SetTokenAlias(TokenInfo tokenInfo)
    {
        var (symbol, alias) = ExtractAliasSetting(tokenInfo);
        State.SymbolAliasMap[alias] = symbol;

        CheckTokenAlias(alias, tokenInfo.Symbol);

        Context.Fire(new SymbolAliasAdded
        {
            Symbol = symbol,
            Alias = alias
        });
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L89-95)
```csharp
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L97-116)
```csharp
    private long GetAllowance(Address from, Address spender, string sourceSymbol, long amount,
        out string allowanceSymbol)
    {
        allowanceSymbol = sourceSymbol;
        var allowance = State.Allowances[from][spender][sourceSymbol];
        if (allowance >= amount) return allowance;
        var tokenType = GetSymbolType(sourceSymbol);
        if (tokenType == SymbolType.Token)
        {
            allowance = GetAllSymbolAllowance(from, spender, out allowanceSymbol);
        }
        else
        {
            allowance = GetNftCollectionAllSymbolAllowance(from, spender, sourceSymbol, out allowanceSymbol);
            if (allowance >= amount) return allowance;
            allowance = GetAllSymbolAllowance(from, spender, out allowanceSymbol);
        }

        return allowance;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L125-136)
```csharp
    private long GetNftCollectionAllSymbolAllowance(Address from, Address spender, string sourceSymbol,
        out string allowanceSymbol)
    {
        allowanceSymbol = GetNftCollectionAllSymbolIdentifier(sourceSymbol);
        return State.Allowances[from][spender][allowanceSymbol];
    }

    private string GetNftCollectionAllSymbolIdentifier(string sourceSymbol)
    {
        // "AAA-*"
        return $"{sourceSymbol.Split(TokenContractConstants.NFTSymbolSeparator)[0]}-{TokenContractConstants.AllSymbolIdentifier}";
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
