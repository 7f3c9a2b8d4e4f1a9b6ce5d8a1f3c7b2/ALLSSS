### Title
Stale Resource Path Cache Causes Transaction Failures When Delegation State Changes

### Summary
The resource extraction cache in the parallel execution system validates only contract code changes but not delegation state changes. When a transaction is cached with no delegatees and later delegatees are added while the transaction remains in the pool, the stale cached resource paths cause incorrect parallel execution grouping, leading to legitimate transaction failures with "Parallel conflict" errors.

### Finding Description

**Root Cause Location:** [1](#0-0) 

When `AddPathForDelegatees()` is called during resource info extraction, if `GetDelegateeList()` returns an empty list for first-level delegatees, the function returns early at line 118, never processing second-level delegation paths (lines 119-131). [2](#0-1) 

The resource cache validation only checks `ContractHash` match (line 103), not whether delegation state has changed. Cached `TransactionResourceInfo` persists across blocks until the transaction is included or expires. [3](#0-2) 

Cache entries persist with `ResourceUsedBlockHeight` set to transaction expiry (up to 512 blocks per `ReferenceBlockValidPeriod`).

**Exploitation Path:**

1. Transaction T1 (Transfer) enters pool at height N with no delegatees
2. `GetResourceInfo` called, `AddPathForDelegatees` returns early, cache stores ResourceInfo without delegatee balance paths
3. At height N+1, `SetTransactionFeeDelegations` adds first-level delegatee Bob (who has second-level delegatee Charlie)
4. At height N+2, T1 is grouped for block production
5. Cache hit returns stale info without Bob/Charlie balance paths [4](#0-3) 

6. Transaction grouper incorrectly determines T1 doesn't conflict with transactions accessing Bob/Charlie balances
7. During parallel execution, T1 charges fees from Bob/Charlie via delegation mechanism [5](#0-4) 

8. Conflict detected post-execution when actual state accesses don't match predicted paths [6](#0-5) 

9. Transaction marked as failed with "Parallel conflict" status [7](#0-6) 

### Impact Explanation

**Operational Impact:**
- Legitimate user transactions fail unnecessarily with "Parallel conflict" error
- Users must resubmit transactions, causing poor user experience
- Performance degradation from wasted execution and retry overhead
- No fund loss or authorization bypass (conflict detection prevents state corruption)

**Affected Users:**
- Any user whose transaction remains in pool while delegation relationships change
- Particularly affects high-value transactions with longer confirmation times
- Users in active delegation scenarios (transaction fee delegation feature)

**Severity Justification:**
Low-Medium severity due to operational disruption without financial loss. Reactive mitigation exists via conflict detection and cache clearing, but initial transaction attempt still fails.

### Likelihood Explanation

**Feasibility:**
- Transactions naturally remain in pool for multiple blocks (normal behavior, up to 512 blocks per transaction expiry rules)
- Delegation state changes are legitimate operations via `SetTransactionFeeDelegations` and `SetTransactionFeeDelegateInfos` public methods
- No special attacker capabilities required - occurs through normal protocol usage
- Medium likelihood in systems with active delegation usage

**Attack Complexity:**
- Low complexity - no sophisticated attack required
- Timing window is generous (512 blocks = ~1 hour on many chains)
- Can occur accidentally during normal operations, not just malicious scenarios

**Detection Constraints:**
- Post-execution conflict detection exists but is reactive [8](#0-7) 

- Cache cleared after first failure, subsequent retry succeeds [9](#0-8) 

### Recommendation

**Code-Level Mitigation:**

1. **Add delegation state to cache validation**: Extend `TransactionResourceCache` to include a hash of delegation state at cache time. Invalidate cache if delegation state hash changes.

2. **Alternative: Add chain height to cache key**: Include `chainContext.BlockHeight` in cache validation at ResourceExtractionService.cs lines 101-110. Invalidate cache if current height exceeds cached height.

3. **Proactive cache invalidation**: When `SetTransactionFeeDelegations` or `SetTransactionFeeDelegateInfos` executes, publish an event that triggers cache invalidation for affected delegator addresses' pending transactions.

**Invariant Checks:**
- Assert resource path completeness: After execution, verify actual accessed paths were subset of predicted paths
- Add monitoring: Log cache hits with stale delegation state for visibility

**Test Cases:**
- Test scenario: Cache transaction with no delegatees, add delegatees in next block, verify cache invalidated or correctly includes new paths
- Test multi-level delegation cache invalidation across block heights
- Test transaction retry success rate after conflict detection clears cache

### Proof of Concept

**Initial State (Height N):**
- Alice has no transaction fee delegatees
- Transaction T1 = Transfer(from: Alice, to: Bob, amount: 100, symbol: "ELF") created with RefBlockNumber = N

**Step 1 - T1 Enters Pool:**
- T1 submitted to transaction pool
- `HandleTransactionAcceptedEvent` triggered
- `GetResourceInfo` called for T1
- `AddPathForDelegatees(resourceInfo, Alice, Bob, "Transfer")` executed
- `GetDelegateeList(Alice, Bob, "Transfer")` returns empty list
- Function returns early at line 118 without adding delegatee paths
- Cache: `_resourceCache[T1.Hash] = TransactionResourceCache(ResourceInfo without delegatee paths, TokenContract, N+512)`

**Step 2 - Height N+1 Block Mined:**
- Transaction T2 calls `SetTransactionFeeDelegations(delegatorAddress: Alice, delegations: {Charlie: 1000 ELF})`
- Charlie is now Alice's first-level delegatee
- Charlie has his own delegatee David (second-level)
- T1 remains in pool (not yet included in block)
- T1's cache NOT cleared (only T2's cache cleared via `HandleBlockAcceptedAsync`)

**Step 3 - Height N+2 Block Production:**
- Miner prepares block including T1 and T3 (where T3 accesses Charlie's balance)
- `LocalParallelTransactionExecutingService.ExecuteAsync` called
- `_grouper.GroupAsync(chainContext: Height N+1, transactions: [T1, T3])` executed
- For T1: `GetResourcesForOneWithCacheAsync` finds cache hit
- Contract hash matches, returns cached ResourceInfo (missing Charlie's balance path)
- For T3: Fresh computation includes Charlie's balance path
- Grouper sees no overlap, groups T1 and T3 as parallelizable

**Step 4 - Parallel Execution Conflict:**
- T1 executes: `ChargeTransactionFees` attempts to charge from Charlie via delegation
- T3 executes: Accesses Charlie's balance simultaneously
- Both transactions access Charlie's balance (State.Balances[Charlie]["ELF"])
- `MergeResults` detects `existingKeys.Overlaps(groupedExecutionReturnSets.AllKeys)` = true
- T1 or T3 added to `conflictingSets`

**Expected vs Actual Result:**
- **Expected**: T1 should have declared Charlie's balance in resource paths, preventing parallel grouping with T3
- **Actual**: T1's stale cache caused incorrect grouping, leading to transaction failure with status "Parallel conflict"

**Success Condition**: T1 fails on first attempt, cache cleared, retry succeeds with fresh delegation state.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS2_StatePathsProvider.cs (L113-132)
```csharp
    private void AddPathForDelegatees(ResourceInfo resourceInfo, Address from, Address to, string methodName)
    {
        var delegateeList = new List<string>();
        //get and add first-level delegatee list
        delegateeList.AddRange(GetDelegateeList(from, to, methodName));
        if (delegateeList.Count <= 0) return;
        var secondDelegateeList = new List<string>();
        //get and add second-level delegatee list
        foreach (var delegateeAddress in delegateeList.Select(a => Address.FromBase58(a)))
        {
            //delegatee of the first-level delegate is delegator of the second-level delegate
            secondDelegateeList.AddRange(GetDelegateeList(delegateeAddress, to, methodName));
        }
        delegateeList.AddRange(secondDelegateeList);
        foreach (var delegatee in delegateeList.Distinct())
        {
            AddPathForTransactionFee(resourceInfo, delegatee, methodName);
            AddPathForTransactionFeeFreeAllowance(resourceInfo, Address.FromBase58(delegatee));
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

**File:** src/AElf.Kernel.SmartContract.Parallel/Application/LocalParallelTransactionExecutingService.cs (L46-46)
```csharp
        var groupedTransactions = await _grouper.GroupAsync(chainContext, transactions);
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Application/LocalParallelTransactionExecutingService.cs (L145-158)
```csharp
    private void ProcessConflictingSets(List<ExecutionReturnSet> conflictingSets)
    {
        foreach (var conflictingSet in conflictingSets)
        {
            var result = new TransactionResult
            {
                TransactionId = conflictingSet.TransactionId,
                Status = TransactionResultStatus.Conflict,
                Error = "Parallel conflict"
            };
            conflictingSet.Status = result.Status;
            conflictingSet.TransactionResult = result;
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Application/LocalParallelTransactionExecutingService.cs (L200-208)
```csharp
            if (!existingKeys.Overlaps(groupedExecutionReturnSets.AllKeys))
            {
                returnSets.AddRange(groupedExecutionReturnSets.ReturnSets);
                foreach (var key in groupedExecutionReturnSets.AllKeys) existingKeys.Add(key);
            }
            else
            {
                conflictingSets.AddRange(groupedExecutionReturnSets.ReturnSets);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L100-116)
```csharp
            var transactionFeeDelegatees =
                State.TransactionFeeDelegateInfoMap[fromAddress][input.ContractAddress][input.MethodName] ??
                State.TransactionFeeDelegateesMap[fromAddress];
            if (transactionFeeDelegatees != null)
            {
                var delegateeAddress = transactionFeeDelegatees.Delegatees;
                foreach (var (delegatee, _) in delegateeAddress)
                {
                    chargingResult = ChargeFromDelegations(input, ref fromAddress, ref bill, ref allowanceBill, fee,
                        isSizeFeeFree, Address.FromBase58(delegatee));
                    if (chargingResult)
                    {
                        break;
                    }
                }
            }
        }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ConflictingTransactionIdentificationService.cs (L27-34)
```csharp
    public async Task<List<TransactionWithResourceInfo>> IdentifyConflictingTransactionsAsync(
        IChainContext chainContext,
        List<ExecutionReturnSet> returnSets, List<ExecutionReturnSet> conflictingSets)
    {
        var possibleConflicting = FindPossibleConflictingReturnSets(returnSets, conflictingSets);
        var wrongTxnWithResources = await FindContractOfWrongResourcesAsync(chainContext, possibleConflicting);
        return wrongTxnWithResources;
    }
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Application/ConflictingTransactionsFoundInParallelGroupsEventHandler.cs (L51-51)
```csharp
        _resourceExtractionService.ClearConflictingTransactionsResourceCache(wrongTransactionIds);
```
