# Audit Report

## Title
Unbounded Storage DoS via Unlimited Contract-Method Delegation Pairs Per Delegator

## Summary
The `SetTransactionFeeDelegateInfos` function in the MultiToken contract lacks a global limit on the total number of different (contract, method) delegation pairs a single delegator can create. While it enforces a limit of 24 delegatees per individual pair, an attacker can create unlimited unique pairs across multiple transactions, leading to unbounded blockchain state growth that degrades network-wide storage and synchronization performance.

## Finding Description

The vulnerability exists in the transaction fee delegation mechanism where state is stored in a three-level nested map structure [1](#0-0) . This maps `delegator_address -> contract_address -> method_name -> TransactionFeeDelegatees`.

The `SetTransactionFeeDelegateInfos` function accepts a list of `DelegateInfo` objects, where each object specifies a unique (contract, method) combination [2](#0-1) . The function is defined as a public method [3](#0-2) .

For each contract-method pair, the function retrieves or creates delegation information and validates that the number of delegatees does not exceed `DELEGATEE_MAX_COUNT` [4](#0-3) . This constant is defined as 24 [5](#0-4) .

**Critical Gap:** The function only validates that `input.DelegateInfoList.Count > 0` [6](#0-5) , but places **no upper bound** on the list size or on the cumulative number of unique (contract, method) pairs a delegator can accumulate across all invocations.

The state write operation creates a unique persistent entry for each (delegator, contract, method) triple [7](#0-6) . An attacker can:
1. Call the function repeatedly with their own address as `delegatorAddress`
2. Each call specifies different (contract, method) combinations
3. Accumulate thousands or millions of state entries over time
4. Each entry persists indefinitely in the blockchain state

The function performs only basic input validation [8](#0-7)  without authorization checks, making it publicly accessible to any address.

## Impact Explanation

**Network-Wide Storage DoS:**
- Each unique (delegator, contract, method) combination creates a permanent state entry that must be stored, indexed, and synchronized by all network nodes
- An attacker can create an unbounded number of such entries by varying contract addresses or method names
- State database bloat degrades node performance: slower queries, longer sync times for new nodes, increased disk I/O
- No cleanup mechanism exists; entries persist indefinitely

**Why HIGH Severity:**
1. **Unbounded Growth:** No mechanism caps total entries per delegator
2. **Network-Wide Impact:** Every full node bears the storage burden permanently
3. **Asymmetric Cost:** Attacker pays standard transaction fees once; network bears permanent storage costs forever
4. **Difficult Remediation:** No built-in cleanup mechanism; would require coordinated governance action and potentially breaking state changes

The existence of `DELEGATEE_MAX_COUNT = 24` demonstrates the codebase's awareness of limiting similar vectors, making the absence of a per-delegator pair limit appear to be an oversight rather than intentional design.

## Likelihood Explanation

**High Likelihood - All Conditions Met:**

1. **No Access Barriers:** The function is publicly accessible with no privileged access control beyond basic address format validation

2. **Low Attack Complexity:** 
   - Simple scripted loop calling `SetTransactionFeeDelegateInfos` with different (contract, method) combinations
   - The function loops through all provided delegate info items without upper bound checking [9](#0-8) 
   - No timing dependencies or race conditions
   - Can be executed gradually to evade detection

3. **Economic Feasibility:**
   - Attacker pays only standard transaction fees
   - Cost scales linearly with entries created
   - For motivated attackers (competitors, malicious actors), cost-to-damage ratio is favorable
   - Permanent damage persists long after attacker's one-time payment

4. **Detection Difficulty:**
   - Hard to distinguish malicious activity from legitimate usage patterns
   - No alerting for excessive delegation pair creation
   - By the time unusual patterns are detected, significant state bloat may already exist

## Recommendation

Introduce a global constant `MAX_DELEGATION_PAIRS_PER_DELEGATOR` (e.g., 100 or 200) and enforce it in `SetTransactionFeeDelegateInfos`:

```csharp
public override Empty SetTransactionFeeDelegateInfos(SetTransactionFeeDelegateInfosInput input)
{
    Assert(input.DelegatorAddress != null && input.DelegateInfoList.Count > 0,
        "Delegator address and delegate info cannot be null.");
    
    // Add upper bound check on input list size
    Assert(input.DelegateInfoList.Count <= TokenContractConstants.MAX_DELEGATE_INFO_BATCH_SIZE,
        "Delegate info list exceeds maximum batch size.");
    
    var delegatorAddress = input.DelegatorAddress;
    
    // Count existing pairs for this delegator
    var existingPairsCount = CountExistingDelegationPairs(delegatorAddress);
    var newUniquePairsCount = CountNewUniquePairs(input.DelegateInfoList, delegatorAddress);
    
    Assert(existingPairsCount + newUniquePairsCount <= TokenContractConstants.MAX_DELEGATION_PAIRS_PER_DELEGATOR,
        "Total delegation pairs would exceed maximum allowed per delegator.");
    
    // ... rest of existing logic
}
```

Additionally, add helper methods to track and validate the total pair count, and define appropriate constants in `TokenContractConstants.cs`.

## Proof of Concept

```csharp
[Fact]
public async Task UnboundedStorageDoS_ViaDelegationPairs()
{
    // Attacker creates unlimited delegation pairs
    var attackerAddress = SampleAddress.AddressList[0];
    
    // Create 1000 unique (contract, method) pairs (limited only by tx throughput)
    for (int i = 0; i < 1000; i++)
    {
        var input = new SetTransactionFeeDelegateInfosInput
        {
            DelegatorAddress = attackerAddress,
            DelegateInfoList = 
            {
                new DelegateInfo
                {
                    ContractAddress = GenerateRandomAddress(i),
                    MethodName = $"Method{i}",
                    IsUnlimitedDelegate = true
                }
            }
        };
        
        // Each call succeeds and creates a new state entry
        var result = await TokenContractStub.SetTransactionFeeDelegateInfos.SendAsync(input);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
    
    // All 1000 pairs are persisted in state - no limit enforced
    // Network must store, index, and sync all entries permanently
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState.cs (L69-69)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L198-198)
```csharp
    public override Empty SetTransactionFeeDelegateInfos(SetTransactionFeeDelegateInfosInput input)
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L200-201)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```
