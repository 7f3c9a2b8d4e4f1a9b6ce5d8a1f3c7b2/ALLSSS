### Title
Stale BlockHeight in SetTransactionFeeDelegations Allows Exploitation of Increased Delegation Amounts with Pre-Signed Transactions

### Summary
The `SetTransactionFeeDelegations` function fails to update the `BlockHeight` field when modifying existing delegatee amounts, creating an inconsistency with `SetTransactionFeeDelegateInfos`. This allows malicious delegatees to hold pre-signed transactions and later submit them to consume increased delegation amounts that didn't exist when the transaction was created, violating temporal ordering invariants.

### Finding Description

**Root Cause:**

BlockHeight is stored in `TransactionFeeDelegations` to enforce temporal ordering - preventing transactions created before a delegation from using it. The check occurs at [1](#0-0) 

However, there's a critical inconsistency in how BlockHeight is updated:

1. **SetTransactionFeeDelegateInfos** (newer API) properly updates BlockHeight in both add and update paths:
   - AddDelegateInfo: [2](#0-1) 
   - UpdateDelegateInfo: [3](#0-2) 

2. **SetTransactionFeeDelegations** (older API) only sets BlockHeight when adding NEW delegatees: [4](#0-3) 

3. But when updating EXISTING delegatees, BlockHeight is NOT updated: [5](#0-4) 

**Why Protection Fails:**

The temporal check at line 186 compares `Context.Transaction.RefBlockNumber < delegations.BlockHeight`. When BlockHeight becomes stale (not updated during delegation increases), transactions with old RefBlockNumbers pass this check and consume new delegation amounts.

AElf uses reference-block expiry (512 blocks) for replay protection [6](#0-5)  with no transaction nonce system, confirmed by the lack of nonce fields in the transaction structure and replay protection relying solely on RefBlockNumber/RefBlockPrefix validation [7](#0-6) 

### Impact Explanation

**Direct Fund Impact:**
Delegators lose control over when delegation amount increases take effect. A malicious delegatee can:
- Receive initial delegation (e.g., 100 ELF) at block 1000
- Create pre-signed transaction with RefBlockNumber=1000
- Wait for delegator to increase delegation to 1000 ELF at block 1200 via `SetTransactionFeeDelegations`
- Submit old transaction which passes check (1000 ≮ 1000) and consumes 900 ELF more than intended

**Who is Affected:**
- **Delegators** who use `SetTransactionFeeDelegations` to increase delegation amounts suffer unexpected fee consumption
- **Users** who gradually build trust (start with small delegations, increase over time) are most vulnerable

**Severity Justification:**
Medium severity - requires specific conditions (delegation increase, 512-block timing window) but violates core temporal ordering invariant and enables unauthorized consumption of delegated funds beyond delegator's intent at transaction creation time.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an existing delegatee with legitimate access
- Can create and hold valid transactions without submitting them
- No special privileges required beyond normal delegatee status

**Attack Complexity:**
Low - straightforward exploitation requiring only:
1. Create transaction when delegation is small
2. Wait for delegation increase (or social engineer it)
3. Submit transaction within 512-block validity window (~42 minutes at 5s/block)

**Feasibility Conditions:**
- Delegation must be increased via `SetTransactionFeeDelegations` (not `SetTransactionFeeDelegateInfos`)
- Transaction must be submitted within 512 blocks of its RefBlockNumber
- Common in scenarios with progressive trust building or dynamic delegation adjustments

**Economic Rationality:**
Highly rational - attacker gains access to additional delegated fees (potentially orders of magnitude more) with no additional cost beyond normal transaction submission.

### Recommendation

**Code-Level Mitigation:**

Update `SetTransactionFeeDelegations` to set BlockHeight when modifying existing delegatees, matching the behavior of `SetTransactionFeeDelegateInfos`:

At [5](#0-4) , add BlockHeight update after modifying delegation amounts:

```csharp
else // This delegatee exists, so update
{
    var delegationsMap = allDelegateesMap[delegateeAddress].Delegations;
    foreach (var (key, value) in delegationsToInput)
    {
        // ... existing logic ...
    }
    
    // ADD THIS LINE:
    allDelegateesMap[delegateeAddress].BlockHeight = currentHeight;
    
    // Set and Fire logEvent
    State.TransactionFeeDelegateesMap[input.DelegatorAddress] = allDelegatees;
    // ... rest of logic ...
}
```

**Invariant Check:**
Ensure BlockHeight is always updated to current block height whenever delegation amounts are modified, not just when delegatees are added.

**Test Cases:**
Add regression test verifying that after updating delegation amounts via `SetTransactionFeeDelegations`, transactions with RefBlockNumber from before the update cannot use the increased amounts (should fail the BlockHeight check).

### Proof of Concept

**Initial State:**
- Delegator: User A
- Delegatee: User B  
- Block height: 1000
- Delegation: 100 ELF to User B

**Attack Steps:**

1. **Block 1000:** User A calls `SetTransactionFeeDelegations` to delegate 100 ELF to User B
   - BlockHeight set to 1000 [4](#0-3) 

2. **Block 1001:** User B (delegatee) creates Transaction T1 with RefBlockNumber=1000, but doesn't submit it
   - Transaction valid until block 1512 (1000 + 512)

3. **Block 1200:** User A calls `SetTransactionFeeDelegations` again to increase delegation to 1000 ELF
   - Enters update path [5](#0-4) 
   - Delegation amount updated to 1000 ELF
   - **BlockHeight remains 1000 (BUG - not updated)**

4. **Block 1201:** User B submits Transaction T1
   - Fee charging occurs [8](#0-7) 
   - Check at line 186: `RefBlockNumber (1000) < BlockHeight (1000)` evaluates to FALSE
   - Transaction proceeds to use delegation
   - Consumes fees from 1000 ELF delegation pool

**Expected Result:** Transaction T1 should be rejected because it was created when only 100 ELF was delegated

**Actual Result:** Transaction T1 succeeds and consumes fees from the 1000 ELF delegation, exploiting the stale BlockHeight

**Success Condition:** User B successfully consumes more delegated fees than existed when Transaction T1 was created, violating temporal ordering invariant.

### Notes

The BlockHeight field IS actually checked and enforced (contrary to the initial prompt statement). The vulnerability lies specifically in the inconsistent update behavior between the two delegation management APIs. The `SetTransactionFeeDelegateInfos` path correctly updates BlockHeight on modifications [9](#0-8) , but `SetTransactionFeeDelegations` does not. This creates a temporal ordering violation that delegatees can exploit within the 512-block transaction validity window.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L167-210)
```csharp
    private bool ChargeFromDelegations(ChargeTransactionFeesInput input, ref Address fromAddress,
        ref TransactionFeeBill bill, ref TransactionFreeFeeAllowanceBill allowanceBill,
        Dictionary<string, long> fee, bool isSizeFeeFree, Address delegatorAddress)
    {
        var chargingResult = false;
        // Try to charge delegatees
        // Get delegatee list according to the delegator
        var delegationInfo =
            State.TransactionFeeDelegateInfoMap[delegatorAddress][input.ContractAddress][input.MethodName]?.Delegatees ?? 
            State.TransactionFeeDelegateesMap[delegatorAddress]?.Delegatees;

        if (delegationInfo == null)
        {
            return false;
        }

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

        return chargingResult;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L54-54)
```csharp
                allDelegateesMap[delegateeAddress].BlockHeight = currentHeight;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L263-263)
```csharp
        existDelegateeList.BlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Delegation.cs (L272-311)
```csharp
    private DelegateTransaction UpdateDelegateInfo(TransactionFeeDelegations existDelegateInfo, DelegateInfo delegateInfo)
    {
        var existDelegation = existDelegateInfo.Delegations;
        if (delegateInfo.IsUnlimitedDelegate)
        {
            existDelegation.Clear();
        }
        else
        {
            var delegation = delegateInfo.Delegations;
            foreach (var (symbol, amount) in delegation)
            {
                if (existDelegation.ContainsKey(symbol))
                {
                    if (amount <= 0)
                    {
                        existDelegation.Remove(symbol);
                    }
                    else
                    {
                        AssertValidToken(symbol, amount);
                        existDelegation[symbol] = amount;
                    }
                }
                else
                {
                    AssertValidToken(symbol, amount);
                    existDelegation[symbol] = amount;
                }
            }
        }

        existDelegateInfo.BlockHeight = Context.CurrentHeight;
        existDelegateInfo.IsUnlimitedDelegate = delegateInfo.IsUnlimitedDelegate;
        return new DelegateTransaction
        {
            ContractAddress = delegateInfo.ContractAddress,
            MethodName = delegateInfo.MethodName
        };
    }
```

**File:** src/AElf.Kernel.Types/KernelConstants.cs (L8-8)
```csharp
    public const long ReferenceBlockValidPeriod = 64 * 8;
```

**File:** src/AElf.Kernel.Core/Extensions/TransactionExtensions.cs (L28-32)
```csharp
    public static bool VerifyExpiration(this Transaction transaction, long chainBranchBlockHeight)
    {
        return transaction.RefBlockNumber <= chainBranchBlockHeight &&
               transaction.GetExpiryBlockNumber() > chainBranchBlockHeight;
    }
```
