### Title
Empty Method-Specific Delegation Blocks Fallback to Global Delegatees Causing Transaction Fee Payment DoS

### Summary
The `TryToChargeTransactionFee` function uses the `??` null-coalescing operator to fallback from method-specific delegations to global delegations. However, when a method-specific `TransactionFeeDelegatees` entry exists but has an empty `Delegatees` map, the `??` operator does not trigger the fallback because the object itself is non-null. This causes users to permanently lose access to their global delegatees for specific contract methods, resulting in transaction failures even when valid global delegation exists.

### Finding Description

The vulnerability exists in the delegation lookup logic at lines 100-102: [1](#0-0) 

The code uses the `??` operator which only checks for null references, not for empty collections. In protobuf/C#, a `TransactionFeeDelegatees` object with an empty `Delegatees` dictionary is not null—it's a valid object with `Count == 0`.

**Root Cause 1 - Incomplete Cleanup in SetTransactionFeeDelegateInfos:**

When updating method-specific delegations, the code removes individual delegatees when their delegations are exhausted but fails to remove the entire `TransactionFeeDelegatees` object when all delegatees are removed: [2](#0-1) 

At line 236, individual delegatees are removed from the map, but at lines 244-245, the potentially-empty `TransactionFeeDelegatees` object is saved back to state without checking if `Delegatees.Count == 0`.

**Root Cause 2 - No Cleanup in ModifyDelegation:**

When delegations are consumed during fee charging, amounts are decremented but no cleanup occurs: [3](#0-2) 

The code decrements delegation amounts (lines 222, 233) but never removes entries when they reach zero, never removes delegatees when all their delegations are exhausted, and never removes the `TransactionFeeDelegatees` object when it becomes empty.

**Root Cause 3 - No Cleanup in RemoveTransactionFeeDelegateInfo:**

Even explicit removal operations fail to clean up empty objects: [4](#0-3) 

Line 383 removes the delegatee, but lines 385-386 save the object back without checking if the `Delegatees` map is now empty.

**Execution Path:**

When attempting to charge fees with an empty method-specific entry, the code path is: [5](#0-4) 

At line 103, `transactionFeeDelegatees` is non-null (but empty), so the condition passes. At lines 105-106, the foreach loop over `Delegatees` executes zero iterations since the map is empty. No fees are charged, `chargingResult` remains false, and the transaction fails.

The same issue exists in the `ChargeFromDelegations` function: [6](#0-5) 

Although this uses `?.Delegatees`, if the method-specific entry exists with an empty `Delegatees` map, it returns an empty (non-null) map, and the `??` operator doesn't trigger.

### Impact Explanation

**Operational Impact - DoS of Transaction Fee Payment:**

Users who set up method-specific delegations for certain contract methods will permanently lose the ability to use their global delegatees as a fallback for those methods once the method-specific delegations are consumed or removed. This occurs because:

1. User sets both global delegatees (via `SetTransactionFeeDelegations`) and method-specific delegatees (via `SetTransactionFeeDelegateInfos`) for Contract X, Method Y
2. Method-specific delegations get naturally consumed through transaction fee charging
3. An empty `TransactionFeeDelegatees` object persists in state for that contract-method combination
4. All future transactions to Contract X, Method Y cannot use the global delegatees
5. Transactions fail with "Transaction fee not enough" even though valid global delegatees exist

**Who is Affected:**

- Any user who sets method-specific delegations will be affected when those delegations are exhausted
- Delegatees lose the ability to pay fees on behalf of delegators for specific methods
- This impacts normal users relying on fee delegation for transaction convenience

**Severity Justification:**

Medium severity because:
- It's a denial-of-service condition, not direct fund theft
- Users retain the ability to pay their own fees directly
- Only affects specific contract-method combinations, not all transactions
- Requires user to explicitly call removal functions to recover, adding operational friction
- Violates the expected fallback behavior designed into the system

### Likelihood Explanation

**High Likelihood:**

The vulnerability triggers through normal system usage without requiring any attacker:

1. **Reachable Entry Point:** Users call public methods `SetTransactionFeeDelegateInfos` to set method-specific delegations and then execute transactions that consume those delegations
2. **Feasible Preconditions:** Only requires a user to have both global and method-specific delegations configured, which is a legitimate use case
3. **Execution Practicality:** Delegations are naturally consumed during normal transaction execution via the `ChargeTransactionFees` flow
4. **No Special Capabilities Required:** No attacker needed—the bug triggers through intended functionality
5. **High Probability:** Any user with method-specific delegations will eventually hit this as delegations are consumed

The delegation consumption happens automatically during fee charging: [7](#0-6) 

Line 202-203 calls `ModifyDelegation` which decrements amounts without cleanup, leading to the empty state over time.

**Detection/Operational Constraints:**

Users may not immediately notice the issue until their method-specific delegations are fully exhausted, at which point transactions start failing unexpectedly.

### Recommendation

**1. Add Cleanup Logic in SetTransactionFeeDelegateInfos:**

After removing a delegatee at line 236, check if the `Delegatees` map is empty and remove the entire entry:

```csharp
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

// NEW: Remove entire entry if Delegatees is now empty
if (existDelegateeInfoList.Delegatees.Count == 0)
{
    State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateInfo.ContractAddress]
        [delegateInfo.MethodName] = null;
}
else
{
    State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateInfo.ContractAddress]
        [delegateInfo.MethodName] = existDelegateeInfoList;
}
```

**2. Add Cleanup Logic in ModifyDelegation:**

Remove delegation entries when they reach zero, remove delegatees when all their delegations are exhausted, and remove the entire object when empty.

**3. Fix Fallback Logic in TryToChargeTransactionFee:**

Change lines 100-102 to check for empty Delegatees map:

```csharp
var methodSpecificEntry = State.TransactionFeeDelegateInfoMap[fromAddress][input.ContractAddress][input.MethodName];
var transactionFeeDelegatees = (methodSpecificEntry?.Delegatees?.Count > 0) 
    ? methodSpecificEntry 
    : State.TransactionFeeDelegateesMap[fromAddress];
```

**4. Add Similar Fix in ChargeFromDelegations:**

Apply the same empty-check logic at lines 174-176.

**5. Add Test Cases:**

- Test that method-specific delegation with exhausted amounts falls back to global
- Test that removed method-specific delegations fall back to global
- Test that empty Delegatees map is cleaned up from state

### Proof of Concept

**Initial State:**
1. User Alice has address A
2. Delegatee Bob has address B
3. Bob is set as global delegatee for Alice with 1000 ELF via `SetTransactionFeeDelegations`
4. Bob is set as method-specific delegatee for Alice for ContractX.MethodY with 100 ELF via `SetTransactionFeeDelegateInfos`

**Transaction Steps:**

Step 1: Alice calls ContractX.MethodY multiple times
- Method-specific delegation (100 ELF) is consumed via `ModifyDelegation`
- After consumption, `TransactionFeeDelegateInfoMap[A][ContractX][MethodY]` exists but has Delegatees with 0 or depleted amounts

Step 2: Bob explicitly removes his method-specific delegation via `RemoveTransactionFeeDelegateeInfos`
- Line 383 removes Bob from the Delegatees map
- Lines 385-386 save the now-empty `TransactionFeeDelegatees` object back to state
- Object exists but `Delegatees.Count == 0`

Step 3: Alice attempts to call ContractX.MethodY again
- Line 100-102: `TransactionFeeDelegateInfoMap[A][ContractX][MethodY]` returns non-null object (with empty Delegatees)
- The `??` operator does NOT trigger, global delegatees NOT consulted
- Line 105: `delegateeAddress` is empty map
- Line 106: foreach loop executes 0 iterations
- Line 119: `chargingResult` is false
- Line 120-121: Returns failure with "Transaction fee not enough"

**Expected Result:**
Transaction should succeed using Bob's global delegation of 1000 ELF

**Actual Result:**
Transaction fails even though Bob has 1000 ELF available as global delegatee

**Success Condition:**
The vulnerability is confirmed if Alice's transaction fails when method-specific entry is empty but global delegation exists and is sufficient.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L100-102)
```csharp
            var transactionFeeDelegatees =
                State.TransactionFeeDelegateInfoMap[fromAddress][input.ContractAddress][input.MethodName] ??
                State.TransactionFeeDelegateesMap[fromAddress];
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L103-116)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L174-176)
```csharp
        var delegationInfo =
            State.TransactionFeeDelegateInfoMap[delegatorAddress][input.ContractAddress][input.MethodName]?.Delegatees ?? 
            State.TransactionFeeDelegateesMap[delegatorAddress]?.Delegatees;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L200-204)
```csharp
            if (!delegations.IsUnlimitedDelegate)
            {
                ModifyDelegation(delegateeBill, delegateeAllowanceBill, fromAddress, input.ContractAddress,
                    input.MethodName, delegatorAddress);
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L212-235)
```csharp
    private void ModifyDelegation(TransactionFeeBill bill, TransactionFreeFeeAllowanceBill allowanceBill,
        Address delegateeAddress, Address contractAddress, string methodName, Address delegatorAddress)
    {
        foreach (var (symbol, amount) in bill.FeesMap)
        {
            if (amount <= 0) continue;
            var delegateInfo =
                State.TransactionFeeDelegateInfoMap[delegatorAddress][contractAddress][methodName] ??
                State.TransactionFeeDelegateesMap[delegatorAddress];
            delegateInfo.Delegatees[delegateeAddress.ToBase58()].Delegations[symbol] =
                delegateInfo.Delegatees[delegateeAddress.ToBase58()].Delegations[symbol].Sub(amount);
        }

        foreach (var (symbol, amount) in allowanceBill.FreeFeeAllowancesMap)
        {
            if (amount <= 0) continue;

            var delegateInfo =
                State.TransactionFeeDelegateInfoMap[delegatorAddress][contractAddress][methodName] ??
                State.TransactionFeeDelegateesMap[delegatorAddress];
            delegateInfo.Delegatees[delegateeAddress.ToBase58()].Delegations[symbol] =
                delegateInfo.Delegatees[delegateeAddress.ToBase58()].Delegations[symbol].Sub(amount);
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L233-245)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L371-387)
```csharp
    private void RemoveTransactionFeeDelegateInfo(List<DelegateTransaction> delegateTransactionList,Address delegatorAddress,string delegateeAddress)
    {
        var toCancelTransactionList = new DelegateTransactionList();
        foreach (var delegateTransaction in delegateTransactionList.Distinct())
        {
            Assert(delegateTransaction.ContractAddress != null && !string.IsNullOrEmpty(delegateTransaction.MethodName),
                "Invalid contract address and method name.");

            var delegateeInfo =
                State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateTransaction.ContractAddress][
                    delegateTransaction.MethodName];
            if (delegateeInfo == null || !delegateeInfo.Delegatees.ContainsKey(delegateeAddress)) continue;
            delegateeInfo.Delegatees.Remove(delegateeAddress);
            toCancelTransactionList.Value.Add(delegateTransaction);
            State.TransactionFeeDelegateInfoMap[delegatorAddress][delegateTransaction.ContractAddress][
                delegateTransaction.MethodName] = delegateeInfo;
        }
```
