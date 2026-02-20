# Audit Report

## Title
State Update Pattern Violation in SetTransactionFeeDelegations Causes Empty Delegatee Entries to Persist

## Summary
The `SetTransactionFeeDelegations` function contains a critical state management bug where delegatees with zero delegations are not properly removed from storage. The function persists empty delegatee entries by writing state before attempting removal, then uses an incorrect direct state modification pattern that fails to trigger AElf's state persistence mechanism, causing ghost entries to accumulate until users hit the 24-delegatee hard limit.

## Finding Description

The vulnerability exists in the update path for existing delegatees when all their delegations are removed. [1](#0-0) 

The flawed execution sequence is:
1. Lines 68-80 modify the delegations map, potentially removing all delegation entries for a delegatee
2. **Line 83 writes state** with `State.TransactionFeeDelegateesMap[input.DelegatorAddress] = allDelegatees;` - this PERSISTS the delegatee entry to state even though it now has zero delegations
3. Lines 86-90 check if the delegation count is non-zero; if zero (meaning no delegations remain), execution continues to line 91
4. **Line 91 attempts removal** using `State.TransactionFeeDelegateesMap[input.DelegatorAddress].Delegatees.Remove(delegateeAddress);` - this is direct state property modification without the read-modify-write pattern

The critical flaw at line 91 is a pattern violation. In AElf's state management with protobuf messages, accessing `State.Something[key]` returns a value/copy of the protobuf object. Modifying that returned object's nested properties does not persist unless the modified object is reassigned back to state.

This is evident when comparing with the correct pattern used in all other removal operations in the same file:

**Correct pattern in RemoveTransactionFeeDelegator:** [2](#0-1) 

**Correct pattern in RemoveTransactionFeeDelegatee:** [3](#0-2) 

Both follow the pattern: read state into local variable → modify the variable → write back to state. Line 91 violates this by directly calling `Remove()` on a nested state property without reassignment, which does not trigger AElf's state persistence mechanism.

The result: line 83 persists the delegatee with empty delegations, and line 91's removal attempt fails silently, leaving ghost entries in state that violate the invariant "delegatees with zero delegations should not exist in the delegatees map."

## Impact Explanation

The impact affects protocol availability and efficiency:

**1. Delegatee Limit DoS:** The contract enforces a hard limit on delegatee count. [4](#0-3) [5](#0-4) 

Users who accumulate ghost delegatee entries will hit this 24-delegatee limit and become unable to add new legitimate delegatees, even though their actual active delegatees are fewer than 24. This is a functional DoS that blocks users from managing transaction fee delegation relationships.

**2. Gas Inefficiency:** During transaction fee charging, the system iterates through all delegatees including ghost entries. [6](#0-5) 

Empty delegatees waste gas during iteration even though they have no delegations to process, degrading system efficiency as ghost entries accumulate.

**3. State Pollution:** Ghost entries accumulate in state permanently with no cleanup mechanism, consuming storage resources indefinitely.

## Likelihood Explanation

The likelihood is **HIGH**:

**Reachability:** `SetTransactionFeeDelegations` is a public method callable by any user to manage their delegation relationships. [7](#0-6) 

**Trigger Conditions:** The bug triggers during normal delegation management when a user has an existing delegatee with delegations and calls `SetTransactionFeeDelegations` to remove delegations by setting values to 0 or negative. This is a standard cleanup operation users perform when changing delegation preferences.

**Frequency:** Over the protocol's lifetime, as users repeatedly manage delegations (adding, modifying, removing), empty entries accumulate. Each user can accumulate up to 24 ghost entries before being completely blocked from delegation functionality.

**No Attack Required:** This is a logic bug that occurs during normal, legitimate operations. No malicious behavior is needed to trigger it.

**Test Gap:** The existing test suite fails to detect this bug. [8](#0-7) 

The test only verifies that `delegations.Count` is 0, not whether the delegatee entry itself was removed from the delegatees map. The query function `GetTransactionFeeDelegationsOfADelegatee` returns an empty object both when the delegatee doesn't exist AND when it exists with empty delegations, masking the bug.

## Recommendation

Fix line 91 to follow the correct read-modify-write pattern used throughout the rest of the codebase:

```csharp
// Replace line 91 with:
var delegatees = State.TransactionFeeDelegateesMap[input.DelegatorAddress];
delegatees.Delegatees.Remove(delegateeAddress);
State.TransactionFeeDelegateesMap[input.DelegatorAddress] = delegatees;
```

This ensures the removal is properly persisted to state by explicitly reassigning the modified object.

Additionally, add a test case that verifies the delegatee entry is actually removed from the delegatees list (using `GetTransactionFeeDelegatees`) rather than just checking that the delegations count is zero.

## Proof of Concept

```csharp
[Fact]
public async Task SetTokenDelegation_GhostDelegateeRemains_Test()
{
    await Initialize();
    
    // Setup: Add delegations
    var delegations = new Dictionary<string, long>
    {
        [NativeToken] = 1000,
        [BasicFeeSymbol] = 500
    };
    await TokenContractStub.SetTransactionFeeDelegations.SendAsync(
        new SetTransactionFeeDelegationsInput()
        {
            DelegatorAddress = User1Address,
            Delegations = { delegations }
        });
    
    // Verify delegatee was added
    var delegateesBefore = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput()
        {
            DelegatorAddress = User1Address
        });
    delegateesBefore.DelegateeAddresses.Count.ShouldBe(1);
    delegateesBefore.DelegateeAddresses[0].ShouldBe(DefaultAddress);
    
    // Remove all delegations by setting to 0
    var emptyDelegations = new Dictionary<string, long>
    {
        [NativeToken] = 0,
        [BasicFeeSymbol] = 0
    };
    await TokenContractStub.SetTransactionFeeDelegations.SendAsync(
        new SetTransactionFeeDelegationsInput()
        {
            DelegatorAddress = User1Address,
            Delegations = { emptyDelegations }
        });
    
    // BUG: Delegatee entry should be removed but still exists
    var delegateesAfter = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput()
        {
            DelegatorAddress = User1Address
        });
    
    // This assertion FAILS - delegatee count is still 1 (ghost entry)
    delegateesAfter.DelegateeAddresses.Count.ShouldBe(0); // Expected: 0, Actual: 1
    
    // The ghost delegatee still exists in the list
    // This prevents users from adding new delegatees once they hit the 24-entry limit
}
```

This test demonstrates that after removing all delegations, the delegatee entry persists as a "ghost" in the delegatees map, proving the state management bug exists.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L12-13)
```csharp
    public override SetTransactionFeeDelegationsOutput SetTransactionFeeDelegations(
        SetTransactionFeeDelegationsInput input)
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L30-31)
```csharp
            // If there has been already DELEGATEE_MAX_COUNT delegatees, and still try to add，fail.
            if (allDelegateesMap.Count() >= TokenContractConstants.DELEGATEE_MAX_COUNT)
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L66-91)
```csharp
        else // This delegatee exists, so update
        {
            var delegationsMap = allDelegateesMap[delegateeAddress].Delegations;
            foreach (var (key, value) in delegationsToInput)
            {
                if (value <= 0 && delegationsMap.ContainsKey(key))
                {
                    delegationsMap.Remove(key);
                }
                else if (value > 0)
                {
                    AssertValidToken(key, value);
                    delegationsMap[key] = value;
                }
            }

            // Set and Fire logEvent
            State.TransactionFeeDelegateesMap[input.DelegatorAddress] = allDelegatees;

            // If a delegatee has no delegations, remove it!
            if (allDelegateesMap[delegateeAddress].Delegations.Count != 0)
                return new SetTransactionFeeDelegationsOutput()
                {
                    Success = true
                };
            State.TransactionFeeDelegateesMap[input.DelegatorAddress].Delegatees.Remove(delegateeAddress);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L122-124)
```csharp
        var delegatees = State.TransactionFeeDelegateesMap[input.DelegatorAddress];
        delegatees.Delegatees.Remove(Context.Sender.ToBase58());
        State.TransactionFeeDelegateesMap[input.DelegatorAddress] = delegatees;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L151-153)
```csharp
        var delegatees = State.TransactionFeeDelegateesMap[Context.Sender];
        delegatees.Delegatees.Remove(input.DelegateeAddress.ToBase58());
        State.TransactionFeeDelegateesMap[Context.Sender] = delegatees;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L18-18)
```csharp
    public const int DELEGATEE_MAX_COUNT = 24;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L100-115)
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
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenDelegationTest.cs (L51-76)
```csharp
    public async Task SetTokenDelegation_removeDelegatee_Test()
    {
        await SetTokenDelegation_Test();
        var delegations = new Dictionary<string, long>
        {
            [NativeToken] = 0,
            [BasicFeeSymbol] = 0,
            [SizeFeeSymbol] = 0
        };
        await TokenContractStub.SetTransactionFeeDelegations.SendAsync(new SetTransactionFeeDelegationsInput()
        {
            DelegatorAddress = User1Address,
            Delegations =
            {
                delegations
            }
        });

        var delegateAllowance = await TokenContractStub.GetTransactionFeeDelegationsOfADelegatee.CallAsync(
            new GetTransactionFeeDelegationsOfADelegateeInput()
            {
                DelegateeAddress = DefaultAddress,
                DelegatorAddress = User1Address
            });
        delegateAllowance.Delegations.Count().ShouldBe(0);
    }
```
