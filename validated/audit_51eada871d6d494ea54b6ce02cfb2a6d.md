# Audit Report

## Title
State Update Pattern Violation in SetTransactionFeeDelegations Causes Empty Delegatee Entries to Persist

## Summary
The `SetTransactionFeeDelegations` function contains a state consistency bug where delegatees with zero delegations are not properly removed from storage. The function writes state with the empty delegatee before attempting removal using direct state modification without the proper write-back pattern, causing ghost entries to accumulate until users hit the hard limit of 24 delegatees and become unable to add new legitimate delegatees.

## Finding Description

In the `SetTransactionFeeDelegations` function, when an existing delegatee's delegations are updated to remove all tokens, the code follows a flawed sequence that violates AElf's state management requirements. [1](#0-0) 

The problematic flow occurs when updating an existing delegatee (else branch starting at line 66):

1. **Lines 68-80**: The delegations map is modified, potentially removing all delegation entries for a delegatee
2. **Line 83**: State is written with `allDelegatees`, which still contains the delegatee entry even though it now has zero delegations - this PERSISTS the empty delegatee to state
3. **Lines 86-90**: Checks if delegation count is non-zero; if zero (no delegations remain), continues to line 91
4. **Line 91**: Attempts to remove the empty delegatee using direct state property modification

The critical bug is at line 91, which uses direct state modification without the proper read-modify-write-back pattern. This pattern violation is evident when comparing with ALL other removal operations in the same file. [2](#0-1) [3](#0-2) 

Both `RemoveTransactionFeeDelegator` and `RemoveTransactionFeeDelegatee` follow the correct pattern: read state into local variable → modify the variable → write back to state. Line 91 violates this by directly calling `Remove()` on a nested state property without re-assignment, which does not trigger AElf's state persistence mechanism.

The result is that line 83 persists the delegatee with empty delegations, and line 91's removal attempt fails silently, leaving ghost entries in state.

## Impact Explanation

The impact is operationally significant and affects protocol availability:

**1. Delegatee Limit DoS**: The contract enforces a hard limit on delegatee count: [4](#0-3) [5](#0-4) 

Users who accumulate ghost delegatee entries will hit this 24-delegatee limit and become unable to add new legitimate delegatees, even though their actual active delegatees are fewer than 24. This is a functional DoS that prevents users from managing their transaction fee delegation relationships.

**2. Gas Inefficiency**: During transaction fee charging, the system iterates through all delegatees including ghost entries: [6](#0-5) 

Empty delegatees waste gas during iteration even though they have no delegations to process, degrading system efficiency over time as ghost entries accumulate.

**3. State Pollution**: Ghost entries accumulate in state permanently with no cleanup mechanism, consuming storage resources.

## Likelihood Explanation

The likelihood of this bug manifesting is **HIGH**:

**Reachability**: `SetTransactionFeeDelegations` is a public method callable by any user to manage their delegation relationships. No special privileges are required.

**Trigger Conditions**: The bug triggers during normal delegation management when:
- A user has an existing delegatee with delegations
- The user calls `SetTransactionFeeDelegations` to remove delegations by setting values to 0 or negative
- This is a standard cleanup operation users would perform when changing delegation preferences

**Frequency**: Over the protocol's lifetime, as users repeatedly manage delegations (adding, modifying, removing), empty entries accumulate. Each user can accumulate up to 24 ghost entries before being completely blocked from delegation functionality.

**No Attack Required**: This is a logic bug that occurs during normal, legitimate operations. No malicious behavior is needed to trigger it.

**Test Gap**: The existing test suite fails to detect this bug: [7](#0-6) 

The test only verifies that `delegations.Count` is 0, not whether the delegatee entry itself was removed from the delegatees map. The query function `GetTransactionFeeDelegationsOfADelegatee` returns an empty object both when the delegatee doesn't exist AND when it exists with empty delegations, masking the bug.

## Recommendation

Fix the state update pattern violation by following the established read-modify-write-back pattern. Replace line 91 with the correct sequence:

```csharp
// Read state into local variable
var delegatees = State.TransactionFeeDelegateesMap[input.DelegatorAddress];
// Modify the local variable
delegatees.Delegatees.Remove(delegateeAddress);
// Write back to state
State.TransactionFeeDelegateesMap[input.DelegatorAddress] = delegatees;
```

Alternatively, move the state write (currently at line 83) to AFTER the delegatee removal check, and only write if the delegatee should be kept:

```csharp
// Lines 68-80: Modify delegations
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

// Check if delegatee should be removed BEFORE writing state
if (allDelegateesMap[delegateeAddress].Delegations.Count == 0)
{
    // Remove from local variable
    allDelegateesMap.Remove(delegateeAddress);
    // Write state once with removal already applied
    State.TransactionFeeDelegateesMap[input.DelegatorAddress] = allDelegatees;
    Context.Fire(new TransactionFeeDelegationCancelled()
    {
        Caller = Context.Sender,
        Delegatee = Context.Sender,
        Delegator = input.DelegatorAddress
    });
}
else
{
    // Write state with delegatee retained
    State.TransactionFeeDelegateesMap[input.DelegatorAddress] = allDelegatees;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task POC_EmptyDelegateeNotRemoved_CausesLimitDoS()
{
    await Initialize();

    // Step 1: Set up a delegatee with delegations
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

    // Verify delegatee was added - should have 1 delegatee
    var delegateesBefore = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput()
        {
            DelegatorAddress = User1Address
        });
    delegateesBefore.DelegateeAddresses.Count.ShouldBe(1);

    // Step 2: Remove all delegations by setting to 0
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

    // Step 3: BUG DEMONSTRATION - delegatee entry still exists as ghost
    var delegateesAfter = await TokenContractStub.GetTransactionFeeDelegatees.CallAsync(
        new GetTransactionFeeDelegateesInput()
        {
            DelegatorAddress = User1Address
        });
    
    // This assertion will FAIL - ghost entry persists
    // Expected: 0 delegatees (entry should be removed)
    // Actual: 1 delegatee (ghost entry remains)
    delegateesAfter.DelegateeAddresses.Count.ShouldBe(0, 
        "BUG: Delegatee with zero delegations should be removed but persists as ghost entry");
}
```

This test demonstrates the bug by showing that after removing all delegations, the delegatee entry persists in the `GetTransactionFeeDelegatees` list even though it has no delegations, proving the removal at line 91 does not persist to state.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L30-37)
```csharp
            // If there has been already DELEGATEE_MAX_COUNT delegatees, and still try to add，fail.
            if (allDelegateesMap.Count() >= TokenContractConstants.DELEGATEE_MAX_COUNT)
            {
                return new SetTransactionFeeDelegationsOutput()
                {
                    Success = false
                };
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L66-98)
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
            Context.Fire(new TransactionFeeDelegationCancelled()
            {
                Caller = Context.Sender,
                Delegatee = Context.Sender,
                Delegator = input.DelegatorAddress
            });
        }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L183-207)
```csharp
        foreach (var (delegatee, delegations) in delegationInfo)
        {
            // compare current block height with the block height when the delegatee added
            if (Context.Transaction.RefBlockNumber < delegations.BlockHeight) continue;

            var delegateeBill = new TransactionFeeBill();
            var delegateeAllowanceBill = new TransactionFreeFeeAllowanceBill();
            var delegateeAddress = Address.FromBase58(delegatee);
            var delegateeChargingResult = ChargeTransactionFeesToBill(input, delegateeAddress,
                ref delegateeBill, ref delegateeAllowanceBill, fee, isSizeFeeFree, delegations);

            if (!delegateeChargingResult) continue;

            bill = delegateeBill;
            allowanceBill = delegateeAllowanceBill;
            fromAddress = delegateeAddress;
            chargingResult = true;
            if (!delegations.IsUnlimitedDelegate)
            {
                ModifyDelegation(delegateeBill, delegateeAllowanceBill, fromAddress, input.ContractAddress,
                    input.MethodName, delegatorAddress);
            }

            break;
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
