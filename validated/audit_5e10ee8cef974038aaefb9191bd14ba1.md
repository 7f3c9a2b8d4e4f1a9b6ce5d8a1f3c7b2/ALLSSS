# Audit Report

## Title
State-Dependent Resource Path Declarations Violate ACS2 Parallel Execution Guarantees in Transaction Fee Free Allowances

## Summary
The `AddPathForTransactionFeeFreeAllowance()` function in the MultiToken contract's ACS2 implementation dynamically determines resource paths by reading `TransactionFeeFreeAllowancesSymbolList` state at path extraction time. When this configuration state changes between resource info caching and transaction execution, the cached resource paths become stale, causing transactions to access undeclared state paths and violating ACS2 parallel execution guarantees.

## Finding Description

The ACS2 standard requires contracts to declare all state paths they will access via the `GetResourceInfo` method to enable safe parallel execution. The MultiToken contract violates this principle through state-dependent path generation in its transaction fee free allowance implementation.

**Root Cause - Dynamic Path Generation:**

The `AddPathForTransactionFeeFreeAllowance` function reads the current value of `State.TransactionFeeFreeAllowancesSymbolList.Value?.Symbols` to determine which allowance state paths to declare. [1](#0-0)  When this list is null or contains only certain symbols, only those corresponding paths are added to the resource info. If the list is null, NO allowance paths are declared at all.

**Resource Info Caching Without State Validation:**

When transactions enter the transaction pool, the `ResourceExtractionService` extracts and caches their resource information. [2](#0-1)  This cache is reused during execution grouping if the contract code hash matches, with NO validation that configuration state remains unchanged. [3](#0-2) 

**Configuration Changes Invalidate Cached Paths:**

Governance can modify the symbol list through `ConfigTransactionFeeFreeAllowances`, which adds new symbols to `TransactionFeeFreeAllowancesSymbolList` without triggering cache invalidation for pending transactions. [4](#0-3) 

**Undeclared State Access During Execution:**

During fee charging, `SetOrRefreshTransactionFeeFreeAllowances` writes to `TransactionFeeFreeAllowancesLastRefreshTimes` and `TransactionFeeFreeAllowances` state for ALL symbols in the CURRENT list, including symbols that were not present when resource info was cached. [5](#0-4) 

Similarly, `CalculateTransactionFeeFreeAllowances` reads from these state paths based on the current symbol list. [6](#0-5) 

## Impact Explanation

**ACS2 Guarantee Violation:**

This vulnerability fundamentally breaks the ACS2 contract that the parallel execution system depends on. The parallel execution system uses declared resource paths to group transactions that can safely execute concurrently. [7](#0-6)  When transactions access undeclared paths, the conflict detection mechanism cannot properly identify conflicting state accesses.

**Race Condition Potential:**

Multiple Transfer transactions with stale cached paths (declaring no or incomplete allowance paths) can be incorrectly grouped for parallel execution. When they execute concurrently after a governance configuration change, they all access the same undeclared allowance state paths without proper conflict detection, creating potential race conditions on concurrent state writes.

**State Integrity Risk:**

While the refresh-based allowance model (which uses full overwrite semantics) mitigates the worst data corruption scenarios, the violation of parallel execution guarantees can still lead to unpredictable behavior when the system attempts to enforce consistency constraints on undeclared paths.

**Affected Transactions:**

Any Transfer or TransferFrom transaction that remains in the transaction pool during a governance configuration change to `TransactionFeeFreeAllowancesSymbolList` will execute with stale resource path declarations. [8](#0-7) 

## Likelihood Explanation

**High Probability of Occurrence:**

This vulnerability triggers through normal blockchain operations without requiring any attacker capabilities:

1. Users submit Transfer/TransferFrom transactions during periods when the symbol list contains certain symbols
2. Transactions enter the pool and resource info is cached with paths corresponding to the current symbol list
3. Governance executes `ConfigTransactionFeeFreeAllowances` to add new symbols (requires Parliament controller authority, but is a legitimate operational activity)
4. Original transactions remain in pool and eventually execute with stale cached resource info

**Realistic Preconditions:**

- Transactions routinely wait in pools for multiple blocks due to fee markets, network conditions, or miner selection strategies
- Governance configuration changes for fee allowances are expected operational activities for managing protocol economics
- No special coordination or attack required - the vulnerability window exists naturally

**No Mitigation Mechanism:**

The resource cache invalidation system only validates contract code hash changes, block acceptance, or transaction expiry. [9](#0-8)  There is NO mechanism to invalidate cache entries when configuration state like `TransactionFeeFreeAllowancesSymbolList` changes.

## Recommendation

Implement one of the following solutions:

**Option 1: Static Path Declaration**

Modify `AddPathForTransactionFeeFreeAllowance` to declare paths for all possible symbols that could be configured, rather than reading the current configuration state. This ensures resource info remains valid regardless of configuration changes.

**Option 2: Configuration Version Tracking**

Add a configuration version counter to `TransactionFeeFreeAllowancesSymbolList` that increments on every configuration change. Include this version in the cached resource info and invalidate the cache when the version changes.

**Option 3: Cache Invalidation on Configuration Change**

Modify `ConfigTransactionFeeFreeAllowances` to publish an event that triggers cache invalidation for all pending transactions in the transaction pool.

**Recommended Implementation: Option 2**

Add a version field to track configuration changes and invalidate stale cache entries:

```csharp
// In TokenContractState_ChargeFee.cs
public SingletonState<long> TransactionFeeFreeAllowancesConfigVersion { get; set; }

// In TokenContract_Fees.cs ConfigTransactionFeeFreeAllowances method
State.TransactionFeeFreeAllowancesConfigVersion.Value = 
    (State.TransactionFeeFreeAllowancesConfigVersion.Value ?? 0) + 1;

// In ResourceExtractionService.cs, store version with cache
// and validate it matches current version before reusing
```

## Proof of Concept

```csharp
[Fact]
public async Task ACS2_StaleResourceCache_AfterConfigChange_Test()
{
    // Setup: Configure initial fee allowance with SymbolA only
    await TokenContractStub.ConfigTransactionFeeFreeAllowances.SendAsync(
        new ConfigTransactionFeeFreeAllowancesInput
        {
            Value = {
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "SYMBOLA",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value = { new TransactionFeeFreeAllowance { Symbol = "ELF", Amount = 1_00000000 } }
                    },
                    RefreshSeconds = 600,
                    Threshold = 1_00000000
                }
            }
        });

    // Create transaction T1 and get its resource info (will cache paths for SymbolA only)
    var txn1 = GenerateTokenTransaction(Accounts[0].Address, nameof(TokenContractStub.Transfer),
        new TransferInput { Amount = 100, Symbol = "ELF", To = Accounts[1].Address });
    var resourceInfo1 = await Acs2BaseStub.GetResourceInfo.CallAsync(txn1);
    
    // Verify initial resource info contains SymbolA paths
    var symbolAPath = "TransactionFeeFreeAllowances." + Accounts[0].Address.ToBase58() + ".SYMBOLA";
    resourceInfo1.WritePaths.Any(p => p.Path.Parts.Contains(symbolAPath)).ShouldBeTrue();

    // Governance adds SymbolB to configuration (cache NOT invalidated)
    await TokenContractStub.ConfigTransactionFeeFreeAllowances.SendAsync(
        new ConfigTransactionFeeFreeAllowancesInput
        {
            Value = {
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "SYMBOLB",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value = { new TransactionFeeFreeAllowance { Symbol = "ELF", Amount = 2_00000000 } }
                    },
                    RefreshSeconds = 600,
                    Threshold = 1_00000000
                }
            }
        });

    // T1 executes with stale cache - will access SymbolB paths NOT in cached resource info
    // During execution, SetOrRefreshTransactionFeeFreeAllowances will write to SymbolB state
    // But T1's cached ResourceInfo never declared these paths
    
    // Verify the vulnerability: cached resource info is stale
    var currentSymbolList = await TokenContractStub.GetTransactionFeeFreeAllowancesConfig.CallAsync(new Empty());
    currentSymbolList.Value.Count.ShouldBe(2); // Now has both SymbolA and SymbolB
    
    // But cached resourceInfo1 only has paths for SymbolA, not SymbolB
    var symbolBPath = "TransactionFeeFreeAllowances." + Accounts[0].Address.ToBase58() + ".SYMBOLB";
    resourceInfo1.WritePaths.Any(p => p.Path.Parts.Contains(symbolBPath)).ShouldBeFalse();
    
    // This proves that T1 will access undeclared paths (SymbolB) during execution
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L11-69)
```csharp
    public override ResourceInfo GetResourceInfo(Transaction txn)
    {
        switch (txn.MethodName)
        {
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

            default:
                return new ResourceInfo { NonParallelizable = true };
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L148-167)
```csharp
    private void AddPathForTransactionFeeFreeAllowance(ResourceInfo resourceInfo, Address from)
    {
        var symbols = State.TransactionFeeFreeAllowancesSymbolList.Value?.Symbols;
        if (symbols != null)
        {
            foreach (var symbol in symbols)
            {
                resourceInfo.WritePaths.Add(GetPath(nameof(TokenContractState.TransactionFeeFreeAllowances),
                    from.ToBase58(), symbol));
                resourceInfo.WritePaths.Add(GetPath(
                    nameof(TokenContractState.TransactionFeeFreeAllowancesLastRefreshTimes), from.ToBase58(), symbol));

                var path = GetPath(nameof(TokenContractState.TransactionFeeFreeAllowancesConfigMap), symbol);
                if (!resourceInfo.ReadPaths.Contains(path))
                {
                    resourceInfo.ReadPaths.Add(path);
                }
            }
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ResourceExtractionService.cs (L101-110)
```csharp
        if (_resourceCache.TryGetValue(transaction.GetHash(), out var resourceCache))
            if (contractResourceInfoCache.TryGetValue(transaction.To, out var contractResourceInfo))
                if (resourceCache.ResourceInfo.ContractHash == contractResourceInfo.CodeHash &&
                    resourceCache.ResourceInfo.IsNonparallelContractCode ==
                    contractResourceInfo.IsNonparallelContractCode)
                    return new TransactionWithResourceInfo
                    {
                        Transaction = transaction,
                        TransactionResourceInfo = resourceCache.ResourceInfo
                    };
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ResourceExtractionService.cs (L218-227)
```csharp
    public async Task HandleTransactionAcceptedEvent(TransactionAcceptedEvent eventData)
    {
        var chainContext = await GetChainContextAsync();
        var transaction = eventData.Transaction;

        var resourceInfo = await GetResourcesForOneAsync(chainContext, transaction, CancellationToken.None);
        _resourceCache.TryAdd(transaction.GetHash(),
            new TransactionResourceCache(resourceInfo, transaction.To,
                eventData.Transaction.GetExpiryBlockNumber()));
    }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ResourceExtractionService.cs (L229-258)
```csharp
    public async Task HandleNewIrreversibleBlockFoundAsync(NewIrreversibleBlockFoundEvent eventData)
    {
        try
        {
            ClearResourceCache(_resourceCache
                //.AsParallel()
                .Where(c => c.Value.ResourceUsedBlockHeight <= eventData.BlockHeight)
                .Select(c => c.Key).Distinct().ToList());
        }
        catch (InvalidOperationException e)
        {
            Logger.LogError(e, "Unexpected case occured when clear resource info.");
        }

        await Task.CompletedTask;
    }

    public async Task HandleBlockAcceptedAsync(BlockAcceptedEvent eventData)
    {
        ClearResourceCache(eventData.Block.TransactionIds);

        await Task.CompletedTask;
    }

    private void ClearResourceCache(IEnumerable<Hash> transactions)
    {
        foreach (var transactionId in transactions) _resourceCache.TryRemove(transactionId, out _);

        Logger.LogDebug($"Resource cache size after cleanup: {_resourceCache.Count}");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L302-320)
```csharp
    private void SetOrRefreshTransactionFeeFreeAllowances(Address address)
    {
        var config = State.TransactionFeeFreeAllowancesSymbolList.Value;
        if (config == null) return;

        foreach (var symbol in config.Symbols)
        {
            if (State.Balances[address][symbol] <
                State.TransactionFeeFreeAllowancesConfigMap[symbol].Threshold) continue;
            var lastRefreshTime = State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol];

            if (lastRefreshTime != null && State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds >
                (Context.CurrentBlockTime - lastRefreshTime).Seconds) continue;

            State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol] = Context.CurrentBlockTime;
            State.TransactionFeeFreeAllowances[address][symbol] =
                State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone();
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1224-1266)
```csharp
    public override Empty ConfigTransactionFeeFreeAllowances(ConfigTransactionFeeFreeAllowancesInput input)
    {
        AssertSenderAddressWith(GetDefaultParliamentController().OwnerAddress);
        Assert(input.Value != null && input.Value.Count > 0, "Invalid input");

        State.TransactionFeeFreeAllowancesSymbolList.Value ??= new TransactionFeeFreeAllowancesSymbolList
        {
            Symbols = { new RepeatedField<string>() }
        };

        foreach (var allowances in input.Value!)
        {
            ValidateToken(allowances.Symbol);
            Assert(
                allowances.TransactionFeeFreeAllowances?.Value != null &&
                allowances.TransactionFeeFreeAllowances.Value.Count > 0,
                "Invalid input allowances");
            Assert(allowances.Threshold >= 0, "Invalid input threshold");
            Assert(allowances.RefreshSeconds >= 0, "Invalid input refresh seconds");

            var config = new TransactionFeeFreeAllowanceConfig
            {
                Symbol = allowances.Symbol,
                Threshold = allowances.Threshold,
                RefreshSeconds = allowances.RefreshSeconds,
                FreeAllowances = new TransactionFeeFreeAllowanceMap()
            };

            foreach (var allowance in allowances.TransactionFeeFreeAllowances!.Value!)
            {
                config.FreeAllowances.Map.TryAdd(allowance.Symbol, allowance);
            }

            State.TransactionFeeFreeAllowancesConfigMap[allowances.Symbol] = config;

            if (!State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols.Contains(allowances.Symbol))
            {
                State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols.Add(allowances.Symbol);
            }
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1313-1356)
```csharp
    private TransactionFeeFreeAllowancesMap CalculateTransactionFeeFreeAllowances(Address input)
    {
        var freeAllowanceMap = State.TransactionFeeFreeAllowances[input];

        var freeAllowancesConfig = State.TransactionFeeFreeAllowancesSymbolList.Value;
        if (freeAllowancesConfig == null)
        {
            return new TransactionFeeFreeAllowancesMap();
        }

        var transactionFeeFreeAllowancesMap = new TransactionFeeFreeAllowancesMap();

        foreach (var symbol in freeAllowancesConfig.Symbols)
        {
            var balance = State.Balances[input][symbol];
            if (balance < State.TransactionFeeFreeAllowancesConfigMap[symbol].Threshold) continue;

            var lastRefreshTime = State.TransactionFeeFreeAllowancesLastRefreshTimes[input][symbol];

            var freeAllowances = freeAllowanceMap[symbol];

            if (freeAllowances == null)
            {
                transactionFeeFreeAllowancesMap.Map.Add(symbol,
                    State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone());
                continue;
            }

            if (lastRefreshTime == null)
            {
                transactionFeeFreeAllowancesMap.Map.Add(symbol, freeAllowances);
            }
            else
            {
                transactionFeeFreeAllowancesMap.Map[symbol] =
                    (Context.CurrentBlockTime - lastRefreshTime).Seconds >
                    State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds
                        ? State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone()
                        : freeAllowances;
            }
        }

        return transactionFeeFreeAllowancesMap;
    }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/TransactionGrouper.cs (L115-174)
```csharp
    private List<List<Transaction>> GroupParallelizables(List<TransactionWithResourceInfo> txsWithResources)
    {
        var resourceUnionSet = new Dictionary<int, UnionFindNode>();
        var transactionResourceHandle = new Dictionary<Transaction, int>();
        var groups = new List<List<Transaction>>();
        var readOnlyPaths = txsWithResources.GetReadOnlyPaths();
        foreach (var txWithResource in txsWithResources)
        {
            UnionFindNode first = null;
            var transaction = txWithResource.Transaction;
            var transactionResourceInfo = txWithResource.TransactionResourceInfo;

            // Add resources to disjoint-set, later each resource will be connected to a node id, which will be our group id
            foreach (var resource in transactionResourceInfo.WritePaths.Concat(transactionResourceInfo.ReadPaths)
                         .Where(p => !readOnlyPaths.Contains(p))
                         .Select(p => p.GetHashCode()))
            {
                if (!resourceUnionSet.TryGetValue(resource, out var node))
                {
                    node = new UnionFindNode();
                    resourceUnionSet.Add(resource, node);
                }

                if (first == null)
                {
                    first = node;
                    transactionResourceHandle.Add(transaction, resource);
                }
                else
                {
                    node.Union(first);
                }
            }
        }

        var grouped = new Dictionary<int, List<Transaction>>();

        foreach (var txWithResource in txsWithResources)
        {
            var transaction = txWithResource.Transaction;
            if (!transactionResourceHandle.TryGetValue(transaction, out var firstResource))
                continue;

            // Node Id will be our group id
            var gId = resourceUnionSet[firstResource].Find().NodeId;

            if (!grouped.TryGetValue(gId, out var gTransactions))
            {
                gTransactions = new List<Transaction>();
                grouped.Add(gId, gTransactions);
            }

            // Add transaction to its group
            gTransactions.Add(transaction);
        }

        groups.AddRange(grouped.Values);

        return groups;
    }
```
