### Title
Missing Cross-Contract State Paths in Transfer/TransferFrom ACS2 Declaration Enables Parallel Execution Conflicts

### Summary
The Token contract's `Transfer` and `TransferFrom` methods can invoke cross-contract callbacks via `Context.SendInline` when tokens have transfer callbacks configured in their `ExternalInfo`. However, the `GetResourceInfo` ACS2 implementation does not declare these cross-contract state modifications in `WritePaths`, violating the ACS2 parallel execution specification. This causes incorrect transaction grouping, leading to execution conflicts and transaction failures.

### Finding Description

**Location:** [1](#0-0) [2](#0-1) 

**Root Cause:**

The `Transfer` method internally calls `DealWithExternalInfoDuringTransfer`: [3](#0-2) 

Similarly, `TransferFrom` calls `DoTransferFrom` which also invokes `DealWithExternalInfoDuringTransfer`: [4](#0-3) 

The `DealWithExternalInfoDuringTransfer` method executes cross-contract calls when a token has the `TransferCallbackExternalInfoKey` configured: [5](#0-4) 

This `Context.SendInline` call creates an inline transaction to the callback contract that can modify arbitrary state in that contract. However, the `GetResourceInfo` implementation only declares state paths within the Token contract itself (balances, allowances, etc.) and does not account for state modifications that may occur in callback contracts.

**Why Protections Fail:**

The ACS2 specification requires all state paths to be declared before execution for correct parallel grouping: [6](#0-5) 

The parallel execution system relies on these declared paths to group transactions: [7](#0-6) 

When paths are not declared, conflicts are only detected post-execution during the merge phase: [8](#0-7) 

Conflicting transactions are marked as CONFLICT and fail: [9](#0-8) 

### Impact Explanation

**Harm:**
1. **Transaction Failures**: Valid `Transfer`/`TransferFrom` transactions can fail with `TransactionResultStatus.CONFLICT` when their undeclared callback state paths overlap with other transactions
2. **Throughput Degradation**: Wasted computational resources executing transactions that are later marked as conflicting, reducing system throughput
3. **DoS Vector**: An attacker can create tokens with callbacks specifically designed to conflict with many transactions, causing widespread transaction failures and system degradation

**Who is Affected:**
- Users transferring tokens that have transfer callbacks configured
- System-wide throughput and performance when multiple such transfers occur in parallel
- The parallel execution mechanism's correctness and efficiency

**Severity Justification:**
While there is no direct fund theft, this violates a critical protocol invariant (ACS2 state path declaration) and can cause operational DoS. The ACS2 documentation explicitly states transactions will be "canceled and labeled to 'can not be grouped' when the StatePath mismatchs the method," which is exactly what occurs here.

### Likelihood Explanation

**Attacker Capabilities:**
- Any user can create a token with arbitrary `ExternalInfo` including `TransferCallbackExternalInfoKey` [10](#0-9) 

**Attack Complexity:**
1. Create a token with `TransferCallbackExternalInfoKey` configured to point to a contract with state modifications
2. Deploy or use an existing callback contract that modifies specific state paths
3. Trigger multiple transfers of this token in the same block that would be grouped for parallel execution
4. The parallel execution system incorrectly groups them (missing state paths)
5. Transactions conflict during execution and fail

**Feasibility Conditions:**
- Token creation cost must be acceptable for attacker
- Callback feature must be enabled (code shows it is implemented but rarely used in tests)
- Multiple transfers must occur in same block for parallel execution

**Probability:**
MEDIUM - The feature exists and is functional, but appears to be rarely used in practice based on lack of test coverage. However, an attacker could deliberately exploit this for targeted DoS.

### Recommendation

**Code-Level Mitigation:**

1. **Option A - Disable Parallel Execution for Callback Tokens**: In `GetResourceInfo`, check if the token has any callback keys configured and return `NonParallelizable = true`:

```csharp
// In TokenContract_ACS2_StatePathsProvider.cs, Transfer case
var tokenInfo = State.TokenInfos[args.Symbol];
if (tokenInfo?.ExternalInfo?.Value?.ContainsKey(TokenContractConstants.TransferCallbackExternalInfoKey) == true)
{
    return new ResourceInfo { NonParallelizable = true };
}
```

2. **Option B - Declare Callback Contract Paths**: Extract the callback contract address from `ExternalInfo` and add its entire address space to `WritePaths` (conservative approach):

```csharp
// Add to WritePaths
var callbackAddress = GetCallbackAddress(args.Symbol);
if (callbackAddress != null)
{
    resourceInfo.WritePaths.Add(new ScopedStatePath 
    { 
        Address = callbackAddress,
        Path = new StatePath { Parts = { "*" } } // Entire contract
    });
}
```

3. **Option C - Restrict Callback Feature**: Remove or restrict the callback feature entirely if it's not actively used, eliminating the issue.

**Invariant Checks:**
- Add validation that tokens with callbacks cannot use parallel execution
- Add tests that verify conflict detection for tokens with callbacks
- Document the limitation in ACS2 implementation

**Test Cases:**
- Create token with transfer callback that modifies state
- Submit multiple parallel transfers of this token
- Verify either: transactions are marked non-parallelizable upfront, OR conflicts are detected but this is documented behavior
- Add regression tests for parallel execution with callback tokens

### Proof of Concept

**Initial State:**
1. Deploy a callback contract `CallbackContract` with a state variable `Counter`
2. Callback contract has method `OnTransfer(TransferFromInput input)` that increments `Counter`

**Attack Steps:**

1. Create token `CALLBACK` with `ExternalInfo` containing:
```json
{
  "aelf_transfer_callback": "{\"ContractAddress\":\"<CallbackContract>\",\"MethodName\":\"OnTransfer\"}"
}
```

2. Issue `CALLBACK` tokens to addresses A, B, C

3. In the same block, submit three transactions:
   - A transfers 100 CALLBACK to D
   - B transfers 100 CALLBACK to E  
   - C transfers 100 CALLBACK to F

**Expected vs Actual:**

**Expected (if paths were declared correctly):**
- Transactions recognized as non-parallelizable due to shared callback state
- All three execute sequentially
- All succeed

**Actual (current implementation):**
- ACS2 `GetResourceInfo` declares only Token contract state paths
- Parallel execution system groups all three for parallel execution (no overlap in Token state)
- All three execute in parallel, each calling `CallbackContract.OnTransfer`
- All three attempt to modify `CallbackContract.Counter` simultaneously
- Post-execution conflict detection identifies overlapping state writes
- Two or all three transactions marked with `TransactionResultStatus.CONFLICT`
- Valid transfers fail despite correct inputs and sufficient balances

**Success Condition:**
Conflicting transactions receive CONFLICT status, demonstrating that the missing state path declarations cause operational failures.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L337-350)
```csharp
    private void DealWithExternalInfoDuringTransfer(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TransferCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.TransferCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```

**File:** docs-sphinx/reference/acs/acs2.rst (L422-454)
```text
Usage
-----

AElf uses the key-value database to store data. For the data generated
during the contract execution, a mechanism called **State Path** is used
to determine the key of the data.

For example ``Token contract`` defines a property,

.. code:: c#

    public MappedState<Address, string, long> Balances { get; set; }

it can be used to access, modify balance.

Assuming that the address of the ``Token contract`` is
**Nmjj7noTpMqZ522j76SDsFLhiKkThv1u3d4TxqJMD8v89tWmE**. If you want to
know the balance of the address
**2EM5uV6bSJh6xJfZTUa1pZpYsYcCUAdPvZvFUJzMDJEx3rbioz**, you can directly
use this key to access redis / ssdb to get its value.

.. code:: text

   Nmjj7noTpMqZ522j76SDsFLhiKkThv1u3d4TxqJMD8v89tWmE/Balances/2EM5uV6bSJh6xJfZTUa1pZpYsYcCUAdPvZvFUJzMDJEx3rbioz/ELF

On AElf, the implementation of parallel transaction execution is also
based on the key , developers need to provide a method may access to the
``StatePath``, then the corresponding transactions will be properly
grouped before executing: if the two methods do not access the same
StatePath, then you can safely place them in different groups.

Attention: The transaction will be canceled and labeled to “can not be
groupped” when the StatePath mismatchs the method.
```

**File:** src/AElf.Kernel.SmartContract.Parallel/Domain/ExecutiveExtensions.cs (L12-39)
```csharp
    public static async Task<TransactionResourceInfo> GetTransactionResourceInfoAsync(this IExecutive executive,
        ITransactionContext transactionContext, Hash txId)
    {
        await executive.ApplyAsync(transactionContext);
        if (!transactionContext.Trace.IsSuccessful()) return NotParallelizable(txId, executive.ContractHash);

        try
        {
            var resourceInfo = ResourceInfo.Parser.ParseFrom(transactionContext.Trace.ReturnValue);
            return new TransactionResourceInfo
            {
                TransactionId = txId,
                WritePaths =
                {
                    resourceInfo.WritePaths
                },
                ReadPaths = { resourceInfo.ReadPaths },
                ParallelType = resourceInfo.NonParallelizable
                    ? ParallelType.NonParallelizable
                    : ParallelType.Parallelizable,
                ContractHash = executive.ContractHash
            };
        }
        catch (Exception)
        {
            return NotParallelizable(txId, executive.ContractHash);
        }
    }
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

**File:** src/AElf.Kernel.SmartContract.Parallel/Application/LocalParallelTransactionExecutingService.cs (L189-209)
```csharp
    private List<ExecutionReturnSet> MergeResults(
        GroupedExecutionReturnSets[] groupedExecutionReturnSetsArray,
        out List<ExecutionReturnSet> conflictingSets)
    {
        var returnSets = new List<ExecutionReturnSet>();
        conflictingSets = new List<ExecutionReturnSet>();
        var existingKeys = new HashSet<string>();
        var readOnlyKeys = GetReadOnlyKeys(groupedExecutionReturnSetsArray);
        foreach (var groupedExecutionReturnSets in groupedExecutionReturnSetsArray)
        {
            groupedExecutionReturnSets.AllKeys.ExceptWith(readOnlyKeys);
            if (!existingKeys.Overlaps(groupedExecutionReturnSets.AllKeys))
            {
                returnSets.AddRange(groupedExecutionReturnSets.ReturnSets);
                foreach (var key in groupedExecutionReturnSets.AllKeys) existingKeys.Add(key);
            }
            else
            {
                conflictingSets.AddRange(groupedExecutionReturnSets.ReturnSets);
            }
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L13-13)
```csharp
    public const string TransferCallbackExternalInfoKey = "aelf_transfer_callback";
```
