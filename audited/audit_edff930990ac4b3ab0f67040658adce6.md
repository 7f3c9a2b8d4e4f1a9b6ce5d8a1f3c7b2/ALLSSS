### Title
Token Alias Resolution Mismatch in ACS2 Resource Path Declaration Enables Parallel Execution Race Conditions

### Summary
The `TransferFrom` method's ACS2 resource path provider declares state paths using the raw input symbol (which may be an alias), but the actual execution modifies state using the resolved actual symbol. This mismatch allows conflicting transactions to be incorrectly classified as non-conflicting, enabling parallel execution race conditions that can lead to double-spending of token allowances and incorrect balance updates for NFT tokens with aliases.

### Finding Description

The vulnerability exists in the interaction between the ACS2 resource path declaration and the actual state modifications during `TransferFrom` execution:

**Path Declaration Phase:**
In [1](#0-0) , when `GetResourceInfo` is called for `TransferFrom`, it declares resource paths using `args.Symbol` directly from the transaction input without resolving aliases.

Specifically at [2](#0-1) , `AddPathForAllowance` is called with the unresolved symbol.

The `AddPathForAllowance` method at [3](#0-2)  then declares write paths for `Allowances[from][spender][symbol]` using this unresolved symbol. Additionally, it calls `GetSymbolType` on the alias, which incorrectly classifies NFT aliases (like "TP") as `SymbolType.Token` instead of `SymbolType.Nft`, causing it to skip adding the NFT collection allowance path (`PREFIX-*`).

**Actual Execution Phase:**
During actual execution at [4](#0-3) , `TransferFrom` calls `AssertValidToken` which resolves aliases through [5](#0-4) , returning the actual symbol (e.g., "TP-31175" instead of alias "TP").

The resolved symbol is then passed to `DoTransferFrom` at [6](#0-5) , which:
1. Modifies balance state using the actual symbol via `DoTransfer`
2. Modifies allowance state at line 94 using the actual symbol or collection wildcards

The `GetAllowance` method at [7](#0-6)  checks NFT collection allowances for the actual symbol prefix, not the alias prefix.

**Root Cause:**
The ACS2 path provider uses the raw input symbol without alias resolution, while execution uses the resolved symbol. For NFT tokens, this also causes `GetSymbolType` at [8](#0-7)  to misclassify the token type, omitting critical NFT collection allowance paths.

### Impact Explanation

**Direct Fund Impact:**
- **Allowance Double-Spending**: Two parallel `TransferFrom` transactions using different representations (alias "TP" vs actual "TP-31175") of the same NFT token will declare non-conflicting paths but modify the same allowance state. Both can read the same allowance value, pass validation, and each deduct from it, effectively spending the allowance twice.
- **Balance Race Conditions**: Similarly, balance updates for `Balances[from]["TP-31175"]` and `Balances[to]["TP-31175"]` are undeclared when using aliases, allowing parallel transactions to corrupt balance state.

**Affected Assets:**
All NFT tokens with aliases are vulnerable. As demonstrated in [9](#0-8) , aliases are actively supported and tested functionality specifically for NFT items.

**Severity Justification:**
- Violates the critical invariant: "allowance/approval enforcement" from Token Supply & Fees
- Enables unauthorized token transfers beyond approved amounts
- Affects NFT assets which often have high individual value
- No way for token owners to prevent this attack once they've approved an allowance

### Likelihood Explanation

**Reachable Entry Point:**
The `TransferFrom` method is a standard public entry point available to any user with approved allowances.

**Feasible Preconditions:**
1. NFT token must have an alias set (supported feature per [10](#0-9) )
2. Token owner has approved an allowance to a spender
3. Spender submits two `TransferFrom` transactions: one using the alias, one using the actual symbol
4. AElf's parallel execution scheduler processes both transactions in the same block

**Execution Practicality:**
- Aliases are documented functionality specifically for NFT items
- Test coverage exists at [9](#0-8)  demonstrating `TransferFrom` with aliases works
- No special privileges required—any approved spender can exploit this
- The parallel execution system will see the transactions as non-conflicting due to different declared paths

**Economic Rationality:**
- Attack cost: transaction fees for two `TransferFrom` calls
- Attack benefit: ability to transfer tokens beyond approved allowance
- For high-value NFTs, this is economically attractive

**Detection Constraints:**
The race condition is non-deterministic—success depends on parallel scheduling. However, an attacker can retry until successful, and the mismatch is deterministic once parallel execution occurs.

### Recommendation

**Code-Level Mitigation:**

1. **Resolve aliases in ACS2 path provider**: Modify [1](#0-0)  to resolve aliases before declaring paths:

```csharp
case nameof(TransferFrom):
{
    var args = TransferFromInput.Parser.ParseFrom(txn.Params);
    // Add: Resolve alias to actual symbol
    var actualSymbol = GetActualTokenSymbol(args.Symbol);
    var resourceInfo = new ResourceInfo
    {
        WritePaths =
        {
            GetPath(nameof(TokenContractState.Balances), args.From.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.Balances), args.To.ToString(), actualSymbol),
            GetPath(nameof(TokenContractState.LockWhiteLists), actualSymbol, txn.From.ToString())
        },
        // ... rest of paths
    };
    AddPathForAllowance(resourceInfo, args.From.ToString(), txn.From.ToString(), actualSymbol);
    // ... rest of method
}
```

2. **Apply same fix to `Transfer` method**: The same issue exists at [11](#0-10) 

3. **Add GetActualTokenSymbol helper**: Make [12](#0-11)  accessible to the state path provider or duplicate the logic.

**Invariant Checks:**
- Add assertions that declared ACS2 paths match actual state modifications
- Include alias resolution in ACS2 test coverage

**Test Cases:**
Add parallel execution test for `TransferFrom` with aliases:
```csharp
[Fact]
public async Task ACS2_GetResourceInfo_TransferFrom_WithAlias_Conflict_Test()
{
    // Create NFT with alias
    // Verify that TransferFrom with alias and TransferFrom with actual symbol
    // declare IDENTICAL resource paths (should conflict)
}
```

### Proof of Concept

**Initial State:**
1. NFT collection "TP-0" exists with NFT item "TP-31175" that has alias "TP" (per [13](#0-12) )
2. Token owner (Alice) has balance of 1 NFT token "TP-31175"
3. Alice approves spender (Bob) for allowance of 1 token using either alias or actual symbol (stored as [14](#0-13)  `Allowances[Alice][Bob]["TP-31175"] = 1`)

**Attack Sequence:**
1. Bob submits Transaction A: `TransferFrom(from: Alice, to: Charlie, symbol: "TP", amount: 1)`
   - Declared paths: `Allowances[Alice][Bob]["TP"]`, `Balances[Alice]["TP"]`, `Balances[Charlie]["TP"]`
   
2. Bob submits Transaction B: `TransferFrom(from: Alice, to: David, symbol: "TP-31175", amount: 1)`
   - Declared paths: `Allowances[Alice][Bob]["TP-31175"]`, `Balances[Alice]["TP-31175"]`, `Balances[David]["TP-31175"]`

3. AElF parallel execution scheduler sees non-conflicting paths and executes both transactions in parallel

**Expected Result:**
One transaction should succeed (transferring 1 token), the other should fail with insufficient allowance.

**Actual Result:**
Both transactions can succeed because:
- Both read `Allowances[Alice][Bob]["TP-31175"] = 1` before either writes
- Both pass allowance check (`1 >= 1`)
- Both execute transfer and deduct allowance
- Final state: `Allowances[Alice][Bob]["TP-31175"] = -1` or `0` (depending on write order)
- Charlie receives 1 token, David receives 1 token (2 tokens total from 1 token balance and 1 token allowance)

**Success Condition:**
Bob successfully transfers 2 tokens despite only having allowance for 1, demonstrating the allowance double-spend vulnerability.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L15-38)
```csharp
            case nameof(Transfer):
            {
                var args = TransferInput.Parser.ParseFrom(txn.Params);
                var resourceInfo = new ResourceInfo
                {
                    WritePaths =
                    {
                        GetPath(nameof(TokenContractState.Balances), txn.From.ToString(), args.Symbol),
                        GetPath(nameof(TokenContractState.Balances), args.To.ToString(), args.Symbol)
                    },
                    ReadPaths =
                    {
                        GetPath(nameof(TokenContractState.TokenInfos), args.Symbol),
                        GetPath(nameof(TokenContractState.ChainPrimaryTokenSymbol)),
                        GetPath(nameof(TokenContractState.TransactionFeeFreeAllowancesSymbolList))
                    }
                };

                AddPathForTransactionFee(resourceInfo, txn.From.ToString(), txn.MethodName);
                AddPathForDelegatees(resourceInfo, txn.From, txn.To, txn.MethodName);
                AddPathForTransactionFeeFreeAllowance(resourceInfo, txn.From);

                return resourceInfo;
            }
```

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L254-259)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransferFrom(input.From, input.To, Context.Sender, tokenInfo.Symbol, input.Amount, input.Memo);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L270-281)
```csharp
    private void Approve(Address spender, string symbol, long amount)
    {
        var actualSymbol = GetActualTokenSymbol(symbol);
        State.Allowances[Context.Sender][spender][actualSymbol] = amount;
        Context.Fire(new Approved
        {
            Owner = Context.Sender,
            Spender = spender,
            Symbol = actualSymbol,
            Amount = amount
        });
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

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenAliasTests.cs (L358-378)
```csharp
    private TokenInfo NftCollection1155WithAliasInfo => new()
    {
        Symbol = "TP-",
        TokenName = "Trump Digital Trading Cards #1155",
        TotalSupply = TotalSupply,
        Decimals = 0,
        Issuer = DefaultAddress,
        IssueChainId = _chainId,
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                {
                    NftCollectionMetaFields.ImageUrlKey,
                    "https://i.seadn.io/gcs/files/0f5cdfaaf687de2ebb5834b129a5bef3.png?auto=format&w=3840"
                },
                { NftCollectionMetaFields.NftType, NftType },
                { TokenAliasExternalInfoKey, "{\"TP-31175\":\"TP\"}" }
            }
        }
    };
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
