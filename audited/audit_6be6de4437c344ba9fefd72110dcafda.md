### Title
Resource Token Debt Accumulates Indefinitely Without Repayment Mechanism, Causing Eventual Overflow

### Summary
The `PayResourceTokens()` function accumulates resource token debt in `OwningResourceToken` state when contracts lack sufficient balance, but unlike the similar `OwningRental` system, provides no mechanism to repay or clear this debt. This causes unbounded debt accumulation that will eventually exceed `long.MaxValue`, triggering an overflow exception in the system transaction `DonateResourceToken` and potentially disrupting block production.

### Finding Description

The vulnerability exists in the `PayResourceTokens()` function where debt accumulation occurs without any corresponding repayment logic. [1](#0-0) 

When a contract consumes resource tokens but has insufficient balance, the code calculates the shortfall (`owned = amount.Sub(existingBalance)`), adds it to existing debt, and updates the state. However, there is no code path that reduces this debt when the contract later has sufficient balance.

The `CheckResourceToken()` function only verifies that balance exceeds debt but does not reduce the accumulated debt: [2](#0-1) 

**Root Cause:** Missing debt repayment logic. A grep search confirms that line 974 is the only location where `OwningResourceToken` state is modified, and it only performs addition, never subtraction.

**Why Existing Protections Fail:** 
- The `.Add()` operation uses checked arithmetic for overflow detection: [3](#0-2) 

This means when debt accumulation exceeds `long.MaxValue` (9,223,372,036,854,775,807), the operation will throw an `OverflowException` rather than silently wrapping around.

**Inconsistency with Similar Code:** The `PayRental()` function implements proper debt repayment for `OwningRental`: [4](#0-3) 

This repayment logic explicitly clears debt (`State.OwningRental[symbol] = 0`) when sufficient balance exists, demonstrating the expected pattern that `PayResourceTokens()` fails to implement.

**Execution Path:** `DonateResourceToken()` is called as a system transaction at the end of each block, which invokes `PayResourceTokens()`: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Operational Harm:** When the accumulated debt exceeds `long.MaxValue`, the overflow exception will cause `DonateResourceToken` system transaction to fail. Since this transaction is generated automatically at the end of each block as part of the resource fee collection mechanism, its failure could disrupt block production and consensus operations.

**Accounting Integrity:** Once debt begins accumulating, it never clears even when contracts have sufficient balance. This violates the expected invariant that debts should be repayable, making the debt tracking system meaningless and preventing accurate resource accounting.

**Affected Parties:** 
- Contracts that consume resources without maintaining sufficient balances
- The entire chain when overflow causes system transaction failures
- Node operators attempting to produce blocks

**Severity Justification:** Medium severity due to concrete DoS potential affecting critical system operations, though exploitation requires extended timeline.

### Likelihood Explanation

**Attacker Capabilities:** Any contract that consumes resource tokens can contribute to debt accumulation simply by operating without sufficient balance. No special privileges required.

**Attack Complexity:** Low complexity - passive accumulation through normal resource consumption when balance is insufficient.

**Feasibility Conditions:**
1. Contract must consistently consume resource tokens (CPU, RAM, DISK, NET)
2. Contract must maintain insufficient balance relative to consumption
3. Accumulation must continue until reaching `long.MaxValue`

**Timeline Constraints:** For a token with 8 decimals (like ELF), reaching overflow requires accumulating ~92 billion tokens worth of debt. At 1,000 tokens per block, this would require ~92 million blocks (~11.6 years at 4 seconds per block). However, contracts with higher consumption rates or multiple tokens could accelerate this.

**Detection:** Debt accumulation is tracked on-chain via `ResourceTokenOwned` events and queryable through transaction results, but there is no mechanism to clear it.

**Probability:** Low-to-Medium. While normal operations are unlikely to reach overflow quickly, the lack of any repayment mechanism means ANY debt accumulation is permanent and will eventually cause issues over sufficient time.

### Recommendation

Implement debt repayment logic in `PayResourceTokens()` similar to the pattern used in `PayRental()`:

```
Before the existing balance check at line 968-982, add:
1. Check if OwningResourceToken[bill.ContractAddress][symbol] > 0
2. If debt exists and existingBalance > debt:
   - First pay down the debt completely
   - Set State.OwningResourceToken[bill.ContractAddress][symbol] = 0
   - Reduce availableBalance by debt amount
   - Fire debt repayment event
3. Then proceed with normal resource token payment using remaining balance
```

**Invariant to Enforce:** `OwningResourceToken` debt must be reducible to zero when sufficient balance exists, maintaining parity with `OwningRental` behavior.

**Test Cases:**
1. Contract with existing debt receives sufficient balance - verify debt is cleared
2. Contract with existing debt receives partial balance - verify proportional debt reduction
3. Debt repayment across multiple blocks - verify complete clearance over time
4. Multiple contracts with varying debt levels - verify independent repayment tracking

### Proof of Concept

**Initial State:**
- Contract A deployed and active
- Contract A configured to consume 100 CPU tokens per block via resource-intensive operations
- Contract A initially has 0 CPU token balance

**Transaction Sequence:**
1. Block N: Contract A executes transactions consuming 100 CPU
   - `DonateResourceToken` called at block end
   - `PayResourceTokens` executes: `OwningResourceToken[A][CPU] = 0 + 100 = 100`

2. Block N+1: Contract A executes transactions consuming 100 CPU, still has 0 balance
   - `OwningResourceToken[A][CPU] = 100 + 100 = 200`

3. Block N+2: User transfers 500 CPU to Contract A
   - Contract A now has balance = 500 CPU
   - Contract A executes transactions consuming 100 CPU
   - `PayResourceTokens` executes: balance (500) > amount (100), so deducts 100
   - **Expected:** Debt should be reduced: `OwningResourceToken[A][CPU] = max(0, 200 - 400)` 
   - **Actual:** Debt unchanged: `OwningResourceToken[A][CPU] = 200` (never cleared)

4. Repeat for millions of blocks...

5. Eventually: `OwningResourceToken[A][CPU]` approaches `long.MaxValue`
   - Next debt accumulation causes: `long.MaxValue.Add(owned)` → `OverflowException`
   - `DonateResourceToken` system transaction fails
   - Block production disrupted

**Success Condition:** After step 3, `OwningResourceToken[A][CPU]` remains at 200 despite Contract A having sufficient balance, confirming debt never decreases. Overflow eventually occurs given sufficient time.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L602-614)
```csharp
    public override Empty CheckResourceToken(Empty input)
    {
        AssertTransactionGeneratedByPlugin();
        foreach (var symbol in Context.Variables.GetStringArray(TokenContractConstants.PayTxFeeSymbolListName))
        {
            var balance = GetBalance(Context.Sender, symbol);
            var owningBalance = State.OwningResourceToken[Context.Sender][symbol];
            Assert(balance > owningBalance,
                $"Contract balance of {symbol} token is not enough. Owning {owningBalance}.");
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L945-945)
```csharp
        PayResourceTokens(input, isMainChain);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L972-974)
```csharp
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1046-1058)
```csharp
            // Try to update owning rental.
            var owningRental = State.OwningRental[symbol];
            if (owningRental > 0)
            {
                // If Creator own this symbol and current balance can cover the debt, pay the debt at first.
                if (availableBalance > owningRental)
                {
                    donates = owningRental;
                    // Need to update available balance,
                    // cause existing balance not necessary equals to available balance.
                    availableBalance = availableBalance.Sub(owningRental);
                    State.OwningRental[symbol] = 0;
                }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L100-106)
```csharp
    public static long Add(this long a, long b)
    {
        checked
        {
            return a + b;
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/DonateResourceTransactionGenerator.cs (L65-65)
```csharp
                MethodName = nameof(TokenContractImplContainer.TokenContractImplStub.DonateResourceToken),
```
