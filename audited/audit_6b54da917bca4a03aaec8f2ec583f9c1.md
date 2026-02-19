### Title
Unbounded Storage DoS via Unlimited Contract-Method Delegation Pairs Per Delegator

### Summary
The `SetTransactionFeeDelegateInfos` function enforces a limit of 24 delegatees per individual (contract, method) combination but lacks any global limit on the total number of different (contract, method) pairs a single delegator can create. An attacker can exploit this by repeatedly calling the function with different contract-method combinations, causing unbounded state storage growth that bloats the blockchain state and degrades network performance.

### Finding Description

The vulnerability exists in the `SetTransactionFeeDelegateInfos` function where delegation information is stored in a three-level nested map structure. [1](#0-0) 

The function accepts a list of `DelegateInfo` objects, each specifying a different (contract, method) pair: [2](#0-1) 

For each contract-method combination in the input list, the function only validates that the number of delegatees does not exceed `DELEGATEE_MAX_COUNT` (24): [3](#0-2) [4](#0-3) 

However, there is **no validation** on:
1. The total number of different (contract, method) pairs a delegator can have across all their delegation entries
2. The size of `input.DelegateInfoList` in a single transaction call [5](#0-4) 

The loop processes each delegation info and writes to a unique state key per (contract, method) combination: [6](#0-5) 

While AElf enforces a 128KB limit per individual state write and a 5MB transaction size limit, these constraints do not prevent the attack. An attacker can:
- Submit multiple transactions, each adding new (contract, method) pairs
- OR submit a single large transaction with many different pairs (limited only by 5MB transaction size)
- Accumulate unlimited total storage across all their delegation entries

### Impact Explanation

**Operational Impact - Storage DoS:**
- An attacker controlling a delegator address can create an **unbounded number** of (contract, method) delegation entries
- Each entry can contain up to 24 delegatees with multiple token delegations, approaching the 128KB per-entry limit
- Total storage per delegator = `number_of_contract_method_pairs × ~128KB` (potentially unlimited)
- This bloated state must be stored, synchronized, and maintained by **all network nodes**
- State database size grows disproportionately, degrading query performance and synchronization time
- While individual state writes during fee charging only access specific (contract, method) combinations, the aggregate storage burden affects the entire network

**Severity Justification:**
This is a HIGH severity vulnerability because:
1. It allows **unbounded state growth** without corresponding functional benefit
2. The attack affects **network-wide resources** (all nodes' storage and sync performance)
3. The attacker pays only standard transaction fees but can create persistent, compounding damage
4. No governance or administrative action can retroactively remove malicious entries without coordinated cleanup operations

### Likelihood Explanation

**Attacker Capabilities:**
- Any user can call `SetTransactionFeeDelegateInfos` for their own address as delegator
- No special permissions, governance approval, or trusted role required
- Function is publicly accessible with only basic input validation [7](#0-6) 

**Attack Complexity:**
- **Low complexity**: Simple repeated invocations with different (contract, method) pairs
- Can be scripted and automated easily
- No timing requirements or race conditions

**Economic Feasibility:**
- Attacker pays standard transaction fees per call
- Cost scales linearly with number of entries created
- For a motivated attacker seeking to degrade network performance, the cost-to-damage ratio is favorable
- The damage (permanent state bloat affecting all nodes) persists indefinitely while the attacker pays only once

**Execution Practicality:**
- Attack requires no coordination or dependencies
- Can be executed gradually over time or in bursts
- Multiple (contract, method) pairs can be created per transaction, accelerating the attack

**Detection Constraints:**
- Difficult to distinguish malicious behavior from legitimate high-usage patterns
- No alerting mechanism for excessive delegation entry creation by a single delegator

### Recommendation

**1. Add Global Limit Per Delegator:**
Introduce a constant defining the maximum number of (contract, method) pairs per delegator:

```csharp
public const int MAX_DELEGATE_INFO_ENTRIES_PER_DELEGATOR = 100; // or appropriate value
```

**2. Enforce Global Limit in SetTransactionFeeDelegateInfos:**
Before processing the input list, count existing entries and validate the total:

```csharp
// Count total existing (contract, method) pairs for this delegator
var existingPairsCount = GetTotalDelegateInfoCount(delegatorAddress);
var newPairsCount = input.DelegateInfoList.Count(info => 
    !ExistsDelegateInfo(delegatorAddress, info.ContractAddress, info.MethodName));
    
Assert(existingPairsCount + newPairsCount <= MAX_DELEGATE_INFO_ENTRIES_PER_DELEGATOR,
    "Total delegation entries per delegator exceeds maximum limit");
```

**3. Add Input Size Validation:**
Limit the size of `DelegateInfoList` in a single call:

```csharp
Assert(input.DelegateInfoList.Count <= MAX_DELEGATE_INFOS_PER_CALL,
    "Too many delegate infos in single transaction");
```

**4. Add Helper Method:**
```csharp
private int GetTotalDelegateInfoCount(Address delegatorAddress)
{
    // Iterate through all contract addresses and methods to count existing entries
    // This should be optimized with a separate counter state variable to avoid expensive iteration
}
```

**5. Test Cases to Add:**
- Test that a delegator cannot exceed the global limit across multiple calls
- Test that attempting to add entries beyond the limit fails gracefully
- Test that removing entries allows adding new ones within the limit
- Test boundary conditions (exactly at limit, one over limit)

### Proof of Concept

**Initial State:**
- Attacker controls delegator address `A`
- Multiple contract addresses exist in the system (or attacker can use any valid address)
- Native token and other tokens are initialized

**Attack Sequence:**

**Step 1:** Create first batch of delegation entries
```csharp
// Call SetTransactionFeeDelegateInfos with 100 different (contract, method) pairs
var delegateInfoList = new List<DelegateInfo>();
for (int i = 0; i < 100; i++) {
    delegateInfoList.Add(new DelegateInfo {
        ContractAddress = contractAddress,
        MethodName = $"Method{i}",
        Delegations = { ["ELF"] = 1000 },
        IsUnlimitedDelegate = false
    });
}
await TokenContract.SetTransactionFeeDelegateInfos(new SetTransactionFeeDelegateInfosInput {
    DelegatorAddress = A,
    DelegateInfoList = delegateInfoList
});
```

**Step 2:** Repeat with different contract addresses or method names
```csharp
// Second batch with different contracts
for (int i = 0; i < 100; i++) {
    delegateInfoList.Add(new DelegateInfo {
        ContractAddress = anotherContractAddress,
        MethodName = $"Method{i}",
        Delegations = { ["ELF"] = 1000 },
        IsUnlimitedDelegate = false
    });
}
// Call succeeds - no limit checked
```

**Step 3:** Continue until state is significantly bloated
- Repeat Steps 1-2 with variations (different contracts, different methods)
- Each successful call adds more storage under `State.TransactionFeeDelegateInfoMap[A]`

**Expected Result:** 
Transaction should fail when global limit is exceeded

**Actual Result:**
- All transactions succeed
- Storage grows unbounded
- State at `TransactionFeeDelegateInfoMap[A]` contains thousands of entries
- Network nodes must store and synchronize all this data
- Query operations on delegation state become slower

**Success Condition:**
Attacker successfully creates >1000 unique (contract, method) delegation entries under a single delegator address, demonstrating unbounded storage growth with only per-entry limits enforced.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L66-69)
```csharp
    /// <summary>
    /// delegator address -> contract address -> method name -> delegatee info
    /// </summary>
    public MappedState<Address, Address, string, TransactionFeeDelegatees> TransactionFeeDelegateInfoMap { get; set; }
```

**File:** protobuf/token_contract_impl.proto (L399-412)
```text
message SetTransactionFeeDelegateInfosInput{
    // the delegator address
    aelf.Address delegator_address = 1;
    //delegate info list (support batch)
    repeated DelegateInfo delegate_info_list = 2;
}
message DelegateInfo{
    //symbol->amount
    map<string, int64> delegations = 1;
    aelf.Address contract_address = 2;
    string method_name = 3;
    //Whether to pay transaction fee continuously
    bool isUnlimitedDelegate = 4;
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L198-201)
```csharp
    public override Empty SetTransactionFeeDelegateInfos(SetTransactionFeeDelegateInfosInput input)
    {
        Assert(input.DelegatorAddress != null && input.DelegateInfoList.Count > 0,
            "Delegator address and delegate info cannot be null.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L206-246)
```csharp
        foreach (var delegateInfo in input.DelegateInfoList)
        {
            //If isUnlimitedDelegate is false,delegate info list should > 0.
            Assert(delegateInfo.IsUnlimitedDelegate || delegateInfo.Delegations.Count > 0,
                "Delegation cannot be null.");
            Assert(delegateInfo.ContractAddress != null && !string.IsNullOrEmpty(delegateInfo.MethodName),
                "Invalid contract address and method name.");

            var existDelegateeInfoList =
                State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateInfo.ContractAddress]
                    [delegateInfo.MethodName] ?? new TransactionFeeDelegatees();
            var delegateeAddress = Context.Sender.ToBase58();
            var existDelegateeList = existDelegateeInfoList.Delegatees;
            //If the transaction contains delegatee,update delegate info.
            if (existDelegateeList.TryGetValue(delegateeAddress, out var value))
            {
                toUpdateTransactionList.Value.Add(UpdateDelegateInfo(value, delegateInfo));
            } //else,add new delegate info.
            else
            {
                Assert(existDelegateeList.Count < TokenContractConstants.DELEGATEE_MAX_COUNT,
                    "The quantity of delegatee has reached its limit");
                existDelegateeList.Add(delegateeAddress, new TransactionFeeDelegations());
                var transactionFeeDelegations = existDelegateeList[delegateeAddress];
                toAddTransactionList.Value.Add(AddDelegateInfo(transactionFeeDelegations, delegateInfo));
            }

            if (existDelegateeInfoList.Delegatees[delegateeAddress].Delegations.Count == 0 &&
                !existDelegateeInfoList.Delegatees[delegateeAddress].IsUnlimitedDelegate)
            {
                existDelegateeInfoList.Delegatees.Remove(delegateeAddress);
                toCancelTransactionList.Value.Add(new DelegateTransaction
                {
                    ContractAddress = delegateInfo.ContractAddress,
                    MethodName = delegateInfo.MethodName
                });
            }

            State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateInfo.ContractAddress]
                [delegateInfo.MethodName] = existDelegateeInfoList;
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L18-18)
```csharp
    public const int DELEGATEE_MAX_COUNT = 24;
```
