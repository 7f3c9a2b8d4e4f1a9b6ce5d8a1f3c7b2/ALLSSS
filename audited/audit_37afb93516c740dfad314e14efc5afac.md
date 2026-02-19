# Audit Report

## Title
State-Dependent Resource Path Declarations Violate ACS2 Parallel Execution Guarantees in Transaction Fee Free Allowances

## Summary
The `AddPathForTransactionFeeFreeAllowance()` function in the MultiToken contract's ACS2 implementation dynamically determines resource paths by reading `TransactionFeeFreeAllowancesSymbolList` state at path extraction time. When this configuration state changes between resource info caching and transaction execution, the cached resource paths become stale, causing transactions to access undeclared state paths and violating ACS2 parallel execution guarantees. [1](#0-0) 

## Finding Description

The ACS2 standard requires contracts to declare all state paths they will access via the `GetResourceInfo` method to enable safe parallel execution. The MultiToken contract violates this principle through state-dependent path generation in its transaction fee free allowance implementation.

**Root Cause - Dynamic Path Generation:**
The `AddPathForTransactionFeeFreeAllowance` function reads the current value of `State.TransactionFeeFreeAllowancesSymbolList.Value?.Symbols` to determine which allowance state paths to declare. When this list is null or contains symbols [A], only those corresponding paths are added to the resource info. If the list is null, NO allowance paths are declared at all. [2](#0-1) 

**Resource Info Caching Without State Validation:**
When transactions enter the transaction pool, the runtime extracts and caches their resource information. This cache is reused during execution grouping if the contract code hash matches, with NO validation that configuration state remains unchanged. [3](#0-2) 

**Configuration Changes Invalidate Cached Paths:**
Governance can modify the symbol list through `ConfigTransactionFeeFreeAllowances`, which adds new symbols to `TransactionFeeFreeAllowancesSymbolList` without triggering cache invalidation for pending transactions. [4](#0-3) 

**Undeclared State Access During Execution:**
During fee charging, `SetOrRefreshTransactionFeeFreeAllowances` writes to `TransactionFeeFreeAllowancesLastRefreshTimes` and `TransactionFeeFreeAllowances` state for ALL symbols in the CURRENT list, including symbols that were not present when resource info was cached. [5](#0-4) 

Similarly, `CalculateTransactionFeeFreeAllowances` reads from these state paths based on the current symbol list. [6](#0-5) 

## Impact Explanation

**ACS2 Guarantee Violation:**
This vulnerability fundamentally breaks the ACS2 contract that the parallel execution system depends on. The standard exists specifically to ensure all state accesses are declared upfront, enabling the system to safely group non-conflicting transactions for parallel execution. By allowing stale resource path declarations, the system loses this guarantee.

**Race Condition Potential:**
Multiple Transfer transactions with stale cached paths (declaring no or incomplete allowance paths) can be incorrectly grouped for parallel execution. When they execute concurrently after a governance configuration change, they all access the same undeclared allowance state paths without proper conflict detection, creating potential race conditions on concurrent state writes.

**State Integrity Risk:**
While the refresh-based allowance model (which uses full overwrite semantics rather than incremental deductions) mitigates the worst data corruption scenarios, the violation of parallel execution guarantees can still lead to unpredictable behavior and potential execution failures when the system attempts to enforce consistency constraints on undeclared paths.

**Affected Transactions:**
Any Transfer or TransferFrom transaction that remains in the transaction pool during a governance configuration change to `TransactionFeeFreeAllowancesSymbolList` will execute with stale resource path declarations.

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
The resource cache invalidation system only validates contract code hash changes, block acceptance, or transaction expiry. There is NO mechanism to invalidate cache entries when configuration state like `TransactionFeeFreeAllowancesSymbolList` changes. [7](#0-6) 

## Recommendation

**Fix the Design Flaw:**
The `GetResourceInfo` implementation should NOT read dynamic configuration state to determine resource paths. Instead, it should either:

1. **Declare all possible allowance paths statically** - Include paths for all symbols that COULD have allowances configured, based on system-wide token list or a maximum set
2. **Mark fee charging operations as non-parallelizable** - Set `NonParallelizable = true` for transactions that access dynamic allowance configurations
3. **Implement configuration-aware cache invalidation** - Extend the resource cache invalidation mechanism to detect configuration state changes and invalidate affected cached entries

The recommended approach is option 1: modify `AddPathForTransactionFeeFreeAllowance` to declare paths for a statically-determined set of symbols rather than reading dynamic state:

```csharp
private void AddPathForTransactionFeeFreeAllowance(ResourceInfo resourceInfo, Address from)
{
    // Option A: Declare paths for all registered tokens
    // Option B: Declare paths for a configured maximum set
    // Option C: Read symbol list but include it in cache validation
    
    // Current vulnerable implementation should be replaced
}
```

Additionally, consider emitting an event when `TransactionFeeFreeAllowancesSymbolList` changes that could trigger cache invalidation for affected transactions.

## Proof of Concept

Due to the complexity of reproducing the exact timing conditions and the infrastructure requirements (transaction pool, parallel execution grouping, governance actions), a complete runnable test would require significant framework setup. However, the vulnerability can be demonstrated through the following sequence:

```csharp
[Fact]
public async Task StaleResourcePaths_ViolateACS2Guarantees()
{
    // 1. Submit Transfer transaction when symbol list contains only ["ELF"]
    var transferTx = await TokenContract.Transfer.SendAsync(new TransferInput 
    { 
        To = RecipientAddress, 
        Symbol = "ELF", 
        Amount = 100 
    });
    
    // At this point, GetResourceInfo would declare paths only for "ELF" allowances
    
    // 2. Governance adds new symbol "USDT" to TransactionFeeFreeAllowancesSymbolList
    await TokenContract.ConfigTransactionFeeFreeAllowances.SendAsync(new ConfigTransactionFeeFreeAllowancesInput
    {
        Value = 
        {
            new ConfigTransactionFeeFreeAllowance
            {
                Symbol = "USDT",
                TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances { /* config */ },
                Threshold = 1000,
                RefreshSeconds = 86400
            }
        }
    });
    
    // 3. When the original Transfer transaction executes, it will access
    // TransactionFeeFreeAllowances[sender]["USDT"] and 
    // TransactionFeeFreeAllowancesLastRefreshTimes[sender]["USDT"]
    // But these paths were never declared in the cached GetResourceInfo result
    
    // This violates ACS2 parallel execution guarantees
}
```

The vulnerability is confirmed by examining the code paths showing that resource info caching uses only contract code hash validation, not configuration state validation.

## Notes

This vulnerability represents a design flaw in the contract's ACS2 implementation rather than a traditional exploit. While the practical impact is partially mitigated by the refresh-based allowance model's overwrite semantics, it still constitutes a violation of fundamental parallel execution guarantees that could lead to unpredictable system behavior and potential state integrity issues under concurrent execution scenarios.

### Citations

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

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ResourceExtractionService.cs (L246-251)
```csharp
    public async Task HandleBlockAcceptedAsync(BlockAcceptedEvent eventData)
    {
        ClearResourceCache(eventData.Block.TransactionIds);

        await Task.CompletedTask;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1313-1332)
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
```
