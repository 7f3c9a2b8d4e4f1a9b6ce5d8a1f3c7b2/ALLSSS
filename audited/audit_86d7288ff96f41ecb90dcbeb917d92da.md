### Title
Stale Resource Path Declarations Due to State-Dependent Path Generation in Transaction Fee Free Allowances

### Summary
The `AddPathForTransactionFeeFreeAllowance()` function dynamically determines resource paths based on `TransactionFeeFreeAllowancesSymbolList` state at path extraction time. When resource information is cached during transaction pool acceptance but the symbol list changes before execution, transactions access allowance state paths that were never declared in their cached `GetResourceInfo` results, violating ACS2 parallel execution guarantees and potentially causing race conditions. [1](#0-0) 

### Finding Description

The vulnerability exists in the interaction between ACS2 resource path caching and state-dependent path declarations:

**Root Cause:**
When a transaction enters the transaction pool, `HandleTransactionAcceptedEvent` extracts and caches its resource information by calling `GetResourceInfo`. [2](#0-1) 

The `AddPathForTransactionFeeFreeAllowance` function reads `State.TransactionFeeFreeAllowancesSymbolList.Value?.Symbols` to determine which allowance state paths to declare. If this is null or contains symbols [A], only those paths are added. If symbols is null, NO allowance paths are declared. [1](#0-0) 

**Cache Reuse Without State Validation:**
When grouping transactions for execution, cached resource info is reused if the contract code hash matches, with NO validation that state-dependent path declarations remain valid. [3](#0-2) 

**Undeclared State Access During Execution:**
During fee charging, if the symbol list now contains symbols not present during caching, execution accesses state paths that were never declared:

- `SetOrRefreshTransactionFeeFreeAllowances` WRITES to `State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol]` and `State.TransactionFeeFreeAllowances[address][symbol]` [4](#0-3) 

- `CalculateTransactionFeeFreeAllowances` READS from these states [5](#0-4) 

### Impact Explanation

**Violation of ACS2 Guarantees:**
The ACS2 standard exists to enable safe parallel execution by ensuring all state accesses are declared upfront. This vulnerability breaks that fundamental guarantee, as transactions execute with stale resource path declarations that don't match their actual state accesses.

**Race Condition Potential:**
Multiple Transfer transactions with stale cached paths (declaring no allowance paths) can be grouped for parallel execution. If they execute concurrently after `ConfigTransactionFeeFreeAllowances` adds new symbols, they all access the same undeclared allowance state paths without conflict detection, creating race conditions on:
- `TransactionFeeFreeAllowancesLastRefreshTimes` writes
- `TransactionFeeFreeAllowances` reads and writes

**Affected Users:**
Any user whose Transfer/TransferFrom transactions remain in the pool during governance configuration changes affecting `TransactionFeeFreeAllowancesSymbolList`.

**Severity Justification:**
While the refresh-based allowance model (periodic overwrites rather than incremental deductions) may mitigate data corruption in this specific case, the vulnerability fundamentally breaks the ACS2 contract that the parallel execution system depends on, creating unpredictable behavior and potential execution failures.

### Likelihood Explanation

**Attacker Capabilities:**
No special attacker capabilities required. This occurs naturally during normal blockchain operation:
1. User submits transaction during period when symbol list is null or contains minimal symbols
2. Transaction enters pool, resource info cached with corresponding paths
3. Governance executes `ConfigTransactionFeeFreeAllowances` (requires Parliament controller, but is legitimate governance activity)
4. Original transaction mines with stale cache [6](#0-5) 

**Probability:**
HIGH - Transactions routinely wait in pools for multiple blocks due to fee markets, network conditions, or miner selection. Governance configuration changes for fee allowances are expected operational activities. The combination occurs naturally without requiring attacker coordination.

**Detection Constraints:**
The system has no mechanism to invalidate resource cache when state-dependent path declarations change. Cache invalidation only occurs based on contract code hash changes or block acceptance, not configuration state changes. [7](#0-6) 

### Recommendation

**Immediate Fix:**
Add the symbol list itself as a cache invalidation key. When extracting resources, include the current `TransactionFeeFreeAllowancesSymbolList` hash in the cache validation:

```csharp
// In ResourceExtractionService cache validation
if (resourceCache.ResourceInfo.ContractHash == contractResourceInfo.CodeHash &&
    resourceCache.ResourceInfo.IsNonparallelContractCode == contractResourceInfo.IsNonparallelContractCode &&
    resourceCache.ConfigStateHash == GetCurrentConfigStateHash()) // NEW CHECK
```

**Alternative Fix:**
Mark Transfer/TransferFrom as NonParallelizable when allowances are configured, or always declare maximum possible allowance paths regardless of current symbol list state.

**Invariant to Add:**
Assert that all state paths accessed during execution were declared in `GetResourceInfo` for that transaction.

**Test Cases:**
1. Submit Transfer transaction when symbols list is null
2. Execute `ConfigTransactionFeeFreeAllowances` to add symbols
3. Mine the original transaction
4. Verify resource paths match actual accesses or transaction is re-grouped

### Proof of Concept

**Initial State:**
- `TransactionFeeFreeAllowancesSymbolList.Value` = null or []
- User submits Transfer(to: Bob, amount: 100, symbol: USDT)

**Step 1 - Transaction Pool Acceptance:**
- `HandleTransactionAcceptedEvent` called
- `GetResourceInfo` executes, `AddPathForTransactionFeeFreeAllowance` sees null symbols
- Cached resource info: WritePaths = [Balances], NO allowance paths [8](#0-7) 

**Step 2 - Governance Configuration:**
- Parliament executes `ConfigTransactionFeeFreeAllowances` 
- Adds "ELF" to symbol list with threshold=1000, allowances=100 ELF per hour [6](#0-5) 

**Step 3 - Transaction Execution:**
- Original Transfer transaction selected for block
- `GetResourcesForOneWithCacheAsync` returns STALE cached info (no allowance paths)
- Grouped for parallel execution with other transfers [3](#0-2) 

**Step 4 - Undeclared Access:**
- `ChargeTransactionFees` executes
- Calls `SetOrRefreshTransactionFeeFreeAllowances` which reads symbols = ["ELF"]
- WRITES to `State.TransactionFeeFreeAllowancesLastRefreshTimes[user]["ELF"]` - **UNDECLARED**
- WRITES to `State.TransactionFeeFreeAllowances[user]["ELF"]` - **UNDECLARED** [4](#0-3) 

**Expected Result:**
Transaction should declare all allowance paths it will access.

**Actual Result:**
Transaction accesses allowance state paths that were never declared in its cached `ResourceInfo`, violating ACS2 guarantees.

**Success Condition:**
Multiple transactions exhibiting this behavior grouped in parallel access the same undeclared allowance state, demonstrating the race condition potential.

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

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ResourceExtractionService.cs (L155-158)
```csharp
            if (_resourceCache.TryGetValue(transaction.GetHash(), out var resourceCache) &&
                executive.ContractHash == resourceCache.ResourceInfo.ContractHash &&
                resourceCache.ResourceInfo.IsNonparallelContractCode == false)
                return resourceCache.ResourceInfo;
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
