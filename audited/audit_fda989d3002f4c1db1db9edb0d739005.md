# Audit Report

## Title
Off-by-One Error in CheckResourceToken Blocks Solvent Contracts from Execution

## Summary
The `CheckResourceToken` method contains an off-by-one error using strict greater-than comparison (`balance > owningBalance`) instead of greater-than-or-equal (`balance >= owningBalance`). This prevents contracts with exactly sufficient balance to match their accumulated resource token debt from executing transactions, creating an artificial denial-of-service condition for solvent contracts.

## Finding Description

The vulnerability exists in the `CheckResourceToken` method which executes as a pre-plugin transaction before every method call on ACS8-compliant contracts. The assertion at line 609 uses a strict greater-than comparison that rejects the valid break-even state where `balance == owningBalance`. [1](#0-0) 

**Root Cause**: The `OwningResourceToken` state variable tracks cumulative resource token debt. When contracts cannot pay resource fees during transaction execution, the deficit is recorded and accumulated in this state variable. [2](#0-1) 

**Critical Issue**: The debt counter **never decreases**. Analysis of all write operations to `State.OwningResourceToken` confirms it only accumulates - there is no debt clearing logic in `PayResourceTokens`, unlike the `PayRental` method which does clear `OwningRental` debt (though it also suffers from the same off-by-one issue). [3](#0-2) 

**Inconsistency Evidence**: The related `ChargeResourceToken` method validates current transaction resource needs using the correct `>=` comparison, demonstrating that equality should be acceptable. [4](#0-3) 

**Execution Flow**:
1. Contract accumulates resource token debt when balance is insufficient
2. Owner tops up contract to exactly `owningBalance` amount
3. `CheckResourceToken` pre-plugin executes before next transaction
4. Assertion `balance > owningBalance` fails (100 > 100 = false)
5. Transaction reverts with error: "Contract balance of {symbol} token is not enough. Owning {owningBalance}."
6. Contract remains blocked until receiving at least 1 additional token

## Impact Explanation

**Operational Denial-of-Service**: Contracts with `balance == owningBalance` are in a solvent break-even state - they have exactly enough balance to cover their historical maximum debt. However, the strict `>` check incorrectly treats this as insufficient, preventing all contract method execution.

**Permanent Penalty**: Since `OwningResourceToken` never decreases (only accumulates), contracts must maintain perpetual excess balance beyond their debt to remain operational. This creates an artificial economic barrier where exact debt recovery is insufficient.

**Affected Parties**:
- Any ACS8 contract that has historically accumulated resource token debt
- Contract owners attempting to restore operations by transferring exact debt amounts
- Users unable to interact with contracts stuck at break-even balance

**Severity**: Medium - causes operational denial-of-service affecting contract availability and user experience, but does not result in direct fund loss. Workaround exists (send 1 extra token), but represents flawed economic logic that contradicts the semantic meaning of "solvent."

## Likelihood Explanation

**High Likelihood**: This issue is easily triggered during normal contract operations without any special setup or attacker actions.

**Triggering Scenario**:
1. Contract operates normally until resource token balance is exhausted
2. Transaction attempts with insufficient balance accumulate debt in `OwningResourceToken`
3. Contract owner or user calculates exact debt amount and transfers it to contract
4. Next transaction attempt automatically triggers `CheckResourceToken` pre-plugin
5. Assertion fails, contract remains blocked

**No Special Permissions Required**: The `CheckResourceToken` method executes automatically as a pre-plugin transaction for all ACS8 contracts - any user attempting to call a contract method will trigger this validation.

**Natural User Behavior**: Users attempting "exact recovery" by transferring precisely the debt amount is a completely natural scenario, making this highly likely to occur in production environments.

## Recommendation

Change the comparison operator from strict greater-than to greater-than-or-equal:

```csharp
// Current (incorrect):
Assert(balance > owningBalance, 
    $"Contract balance of {symbol} token is not enough. Owning {owningBalance}.");

// Fixed:
Assert(balance >= owningBalance,
    $"Contract balance of {symbol} token is not enough. Owning {owningBalance}.");
```

This allows contracts at break-even state (`balance == owningBalance`) to execute transactions, which is semantically correct since they have sufficient balance to cover their debt.

**Additional Recommendation**: Consider implementing debt clearing logic in `PayResourceTokens` similar to `PayRental`, and fix the same off-by-one issue in `PayRental` at line 1051 (should use `>=` instead of `>`).

## Proof of Concept

```csharp
[Fact]
public async Task CheckResourceToken_OffByOne_ExactBalance_Should_Pass_But_Fails()
{
    // Setup: Contract accumulates debt
    // 1. Deploy contract with insufficient resource tokens
    // 2. Execute transactions causing resource token debt accumulation
    // 3. Verify OwningResourceToken is set (e.g., 100 READ tokens)
    
    // Action: Top up to exact debt amount
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = ContractAddress,
        Symbol = "READ", 
        Amount = 100 // Exactly matching owingBalance
    });
    
    // Verify: Balance equals debt (break-even state)
    var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = ContractAddress,
        Symbol = "READ"
    });
    balance.Balance.ShouldBe(100);
    
    // Bug: Next transaction should succeed but fails
    var result = await ContractStub.SomeMethod.SendWithExceptionAsync(new Empty());
    
    // Expected: Transaction succeeds (balance >= owingBalance)
    // Actual: Transaction fails with "Contract balance of READ token is not enough. Owning 100."
    result.TransactionResult.Error.ShouldContain("token is not enough. Owning");
    
    // Workaround: Need 1 extra token
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = ContractAddress,
        Symbol = "READ",
        Amount = 1
    });
    
    // Now it works with 101 tokens (balance > owingBalance)
    var successResult = await ContractStub.SomeMethod.SendAsync(new Empty());
    successResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

---

## Notes

This vulnerability represents a clear off-by-one error with measurable operational impact. The inconsistency between `CheckResourceToken` using `>` and `ChargeResourceToken` using `>=`, combined with the fact that `OwningResourceToken` never decreases while `OwningRental` has clearing logic, strongly indicates this is a bug rather than intentional design. The issue violates the semantic expectation that solvent contracts (those with sufficient balance to cover their debt) should be able to execute transactions.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L576-582)
```csharp
        foreach (var pair in input.CostDic)
        {
            Context.LogDebug(() => $"Charging {pair.Value} {pair.Key} tokens.");
            var existingBalance = GetBalance(Context.Sender, pair.Key);
            Assert(existingBalance >= pair.Value,
                $"Insufficient resource of {pair.Key}. Need balance: {pair.Value}; Current balance: {existingBalance}.");
            bill.FeesMap.Add(pair.Key, pair.Value);
```

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L970-982)
```csharp
                if (amount > existingBalance)
                {
                    var owned = amount.Sub(existingBalance);
                    var currentOwning = State.OwningResourceToken[bill.ContractAddress][symbol].Add(owned);
                    State.OwningResourceToken[bill.ContractAddress][symbol] = currentOwning;
                    Context.Fire(new ResourceTokenOwned
                    {
                        Symbol = symbol,
                        Amount = currentOwning,
                        ContractAddress = bill.ContractAddress
                    });
                    amount = existingBalance;
                }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1047-1058)
```csharp
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
