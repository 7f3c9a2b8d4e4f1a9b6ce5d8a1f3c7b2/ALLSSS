# Audit Report

## Title
Fee Atomicity Violation: Partial Charge Applied on Transaction Failure

## Summary
The AElf fee charging system deducts users' available token balances even when transactions fail due to insufficient fees. When a user has partial balance (e.g., 5 ELF when 10 ELF is required), the system charges the available 5 ELF but still prevents the transaction from executing, resulting in permanent fund loss without any service provided.

## Finding Description

The vulnerability exists in the transaction fee charging flow implemented in the MultiToken contract. The fundamental issue is that fee charging and fee deduction are not atomic operations.

**Root Cause**: When `ChargeFirstSufficientToken` returns false (indicating insufficient funds), but identifies a token symbol to charge, the `ChargeBaseFee` function adds the user's entire existing balance to the transaction bill as a partial charge. [1](#0-0) 

**Unconditional Deduction**: Regardless of whether charging succeeds or fails, `ModifyBalance` is called unconditionally to process the bill. This function deducts all amounts in the bill from user balances and fires `TransactionFeeCharged` events. [2](#0-1) 

The `ModifyBalance` function processes every entry in the bill without checking if the overall charging was successful: [3](#0-2) 

**Transaction Prevention**: After partial fees are deducted, the pre-execution plugin checks the `Success` flag and prevents the main transaction from executing: [4](#0-3) 

**Concrete Execution Flow**:
1. User initiates transaction requiring 100,000 tokens in fees
2. User has only 99,999 tokens available
3. `ChargeFirstSufficientToken` returns false but outputs the primary token symbol
4. `ChargeBaseFee` adds 99,999 tokens to the bill (lines 351-352)
5. `ModifyBalance` is called unconditionally and deducts the 99,999 tokens
6. Function returns `Success = false` with message "Transaction fee not enough"
7. Pre-execution plugin stops the main transaction from executing
8. **Result**: User loses 99,999 tokens but their transaction never executes

**Test Case Confirmation**: The codebase includes a test that explicitly validates this behavior, confirming that users with balance of 99,999 tokens lose their entire balance even when the required fee is 100,000 and the transaction fails: [5](#0-4) 

The same issue affects size fee charging through the `GenerateBill` function, which adds available balance to the bill even when insufficient: [6](#0-5) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes direct, permanent fund loss for users. When users have insufficient balance for transaction fees, they lose their available funds without receiving any service in return. This violates the fundamental blockchain invariant that transaction fees should only be charged when transactions successfully execute.

**Quantified Impact**:
- For a user with balance B where B < required fee F:
  - User loses: min(B, F) tokens permanently
  - User receives: Nothing (transaction doesn't execute)
  - Net loss: Complete loss of attempted fee amount with zero benefit

**Affected Parties**:
- Any user attempting transactions with insufficient fee balance
- Common scenarios: balance depletion, fee price increases, concurrent transactions, miscalculated fees
- No special privileges or attack required - affects normal user operations

**Protocol Impact**:
- Breaks fundamental fee atomicity guarantee
- Affects the core transaction processing mechanism (applies to every transaction type)
- No recovery mechanism exists - deducted funds are permanently lost
- Erodes user trust in the platform

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically in normal transaction flow without requiring any malicious actor:

**Reachable Entry Point**: The `ChargeTransactionFees` method is a public contract function automatically invoked by the ACS1 pre-execution plugin before every transaction executes: [7](#0-6) 

**Preconditions**: The only requirement is that a user has insufficient balance for their transaction fees. This happens naturally when:
- User balance is gradually depleted by multiple transactions
- Transaction fee prices increase
- User miscalculates required fees
- Multiple concurrent transactions drain balance
- Network congestion increases size fees

**Execution Practicality**: No special transaction construction or contract calls required. The vulnerability triggers automatically for any regular transaction when the user has partial but insufficient funds.

**Frequency**: Given the high volume of transactions on blockchain networks and the inevitable occurrence of insufficient balances, this affects users regularly in production environments.

## Recommendation

Implement proper atomicity for fee charging by ensuring that partial charges are not applied when the total required fee cannot be collected. The fix should modify the logic to only deduct fees when the full amount is available.

**Recommended Fix**:

1. **Option 1 - Early Return on Insufficient Funds**: Modify `ChargeBaseFee` to NOT add partial amounts to the bill when charging fails. Instead, return immediately without modifying the bill:

```csharp
private bool ChargeBaseFee(...)
{
    if (!ChargeFirstSufficientToken(...))
    {
        // Don't add partial amounts - return false without modifying bill
        return false;
    }
    
    // Only add to bill if charging succeeds
    if (existingAllowance > amountToChargeBaseFee)
    {
        allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee);
        bill.FeesMap.Add(symbolToChargeBaseFee, 0);
    }
    else
    {
        allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, existingAllowance);
        bill.FeesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee.Sub(existingAllowance));
    }
    
    return true;
}
```

2. **Option 2 - Conditional ModifyBalance**: Only call `ModifyBalance` when `chargingResult` is true:

```csharp
private ChargeTransactionFeesOutput TryToChargeTransactionFee(...)
{
    // ... existing delegation logic ...
    
    // Only deduct fees if charging was successful
    if (chargingResult)
    {
        ModifyBalance(fromAddress, bill, allowanceBill);
    }
    
    var chargingOutput = new ChargeTransactionFeesOutput { Success = chargingResult };
    if (!chargingResult)
        chargingOutput.ChargingInformation = "Transaction fee not enough.";
    
    return chargingOutput;
}
```

3. **Apply Same Fix to Size Fees**: Ensure `GenerateBill` is only called when sufficient funds are available, or modify `ChargeSizeFee` to return early before calling `GenerateBill` when funds are insufficient for non-delegation cases.

## Proof of Concept

The existing test case `ChargeFee_TxFee_FailedTest` demonstrates this vulnerability:

```csharp
// Test setup: User receives 99,999 tokens
// Fee requirement: 100,000 tokens
// Expected behavior: Transaction should fail without deducting funds
// Actual behavior: Transaction fails BUT 99,999 tokens are deducted

// Test validates:
// 1. Transaction status is Failed
// 2. Error message is "Pre-Error: Transaction fee not enough."
// 3. User balance after transaction is 0 (all funds deducted)
// 4. Transaction fee charged is 99,999 (the user's entire balance)
```

This test explicitly confirms that partial fees are deducted even when transactions fail, validating the vulnerability described in this report.

**Notes**

This is a systemic protocol-level defect, not an exploit requiring attacker involvement. The vulnerability affects the fundamental transaction processing mechanism and violates the core principle that fees should only be charged for successfully executed transactions. The existing test suite confirms this behavior is currently implemented and operating in production, making this a critical issue requiring immediate remediation.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L24-53)
```csharp
    public override ChargeTransactionFeesOutput ChargeTransactionFees(ChargeTransactionFeesInput input)
    {
        Context.LogDebug(() => "ChargeTransactionFees Start");
        AssertPermissionAndInput(input);
        // Primary token not created yet.
        if (State.ChainPrimaryTokenSymbol.Value == null)
        {
            return new ChargeTransactionFeesOutput { Success = true };
        }

        // Record tx fee bill during current charging process.
        var bill = new TransactionFeeBill();
        var allowanceBill = new TransactionFreeFeeAllowanceBill();
        var fromAddress = Context.Sender;
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L118-126)
```csharp
        ModifyBalance(fromAddress, bill, allowanceBill);
        var chargingOutput = new ChargeTransactionFeesOutput { Success = chargingResult };
        if (!chargingResult)
            chargingOutput.ChargingInformation = "Transaction fee not enough.";
        
        Context.LogDebug(() => "TryToChargeTransactionFee End");
        Context.LogDebug(() => "ChargeTransactionFees End");
        return chargingOutput;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L237-266)
```csharp
    private void ModifyBalance(Address fromAddress, TransactionFeeBill bill,
        TransactionFreeFeeAllowanceBill allowanceBill)
    {
        Assert(!IsInTransferBlackListInternal(fromAddress), "Charge fee address is in transfer blacklist.");
        SetOrRefreshTransactionFeeFreeAllowances(fromAddress);
        var freeAllowancesMap = CalculateTransactionFeeFreeAllowances(fromAddress);

        // Update balances and allowances
        foreach (var (symbol, amount) in bill.FeesMap)
        {
            if (amount <= 0) continue;
            ModifyBalance(fromAddress, symbol, -amount);
            Context.Fire(new TransactionFeeCharged
            {
                Symbol = symbol,
                Amount = amount,
                ChargingAddress = fromAddress
            });
        }

        if (freeAllowancesMap.Map == null || freeAllowancesMap.Map.Count == 0) return;

        foreach (var (symbol, amount) in allowanceBill.FreeFeeAllowancesMap)
        {
            if (amount > 0)
            {
                ModifyFreeFeeAllowanceAmount(fromAddress, freeAllowancesMap, symbol, -amount);
            }
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L343-356)
```csharp
        if (!ChargeFirstSufficientToken(methodFeeMap, fromAddress, out var symbolToChargeBaseFee,
                out var amountToChargeBaseFee, out var existingBalance, out var existingAllowance,
                transactionFeeFreeAllowancesMap,
                delegations))
        {
            Context.LogDebug(() => "Failed to charge first sufficient token.");
            if (symbolToChargeBaseFee != null)
            {
                bill.FeesMap.Add(symbolToChargeBaseFee, existingBalance);
                allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, existingAllowance);
            } // If symbol == 

            return false;
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L519-564)
```csharp
    private void GenerateBill(long txSizeFeeAmount, string symbolToPayTxFee, string symbolChargedForBaseFee,
        long availableBalance, long availableAllowance, ref TransactionFeeBill bill,
        ref TransactionFreeFeeAllowanceBill allowanceBill)
    {
        var chargeAmount = 0L;
        var chargeAllowanceAmount = 0L;
        if (availableBalance.Add(availableAllowance) > txSizeFeeAmount)
        {
            // Allowance > size fee, all allowance
            if (availableAllowance > txSizeFeeAmount)
            {
                chargeAllowanceAmount = txSizeFeeAmount;
            }
            else
            {
                // Allowance is not enough
                chargeAllowanceAmount = availableAllowance;
                chargeAmount = txSizeFeeAmount.Sub(chargeAllowanceAmount);
            }
        }
        else
        {
            chargeAllowanceAmount = availableAllowance;
            chargeAmount = availableBalance;
        }

        if (symbolChargedForBaseFee == symbolToPayTxFee)
        {
            bill.FeesMap[symbolToPayTxFee] =
                bill.FeesMap[symbolToPayTxFee].Add(chargeAmount);
            allowanceBill.FreeFeeAllowancesMap[symbolToPayTxFee] =
                allowanceBill.FreeFeeAllowancesMap[symbolToPayTxFee].Add(chargeAllowanceAmount);
        }
        else
        {
            if (chargeAmount > 0)
            {
                bill.FeesMap.Add(symbolToPayTxFee, chargeAmount);
            }

            if (chargeAllowanceAmount > 0)
            {
                allowanceBill.FreeFeeAllowancesMap.Add(symbolToPayTxFee, chargeAllowanceAmount);
            }
        }
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L123-129)
```csharp
    public bool IsStopExecuting(ByteString txReturnValue, out string preExecutionInformation)
    {
        var chargeTransactionFeesOutput = new ChargeTransactionFeesOutput();
        chargeTransactionFeesOutput.MergeFrom(txReturnValue);
        preExecutionInformation = chargeTransactionFeesOutput.ChargingInformation;
        return !chargeTransactionFeesOutput.Success;
    }
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutionPluginForMethodFeeTest.cs (L306-342)
```csharp
    public async Task ChargeFee_TxFee_FailedTest()
    {
        await DeployTestContractAsync();

        var issueAmount = 99999;
        var tokenContractStub = await GetTokenContractStubAsync();
        await SetPrimaryTokenSymbolAsync(tokenContractStub);

        await tokenContractStub.Transfer.SendAsync(new TransferInput
        {
            Symbol = "ELF",
            Amount = issueAmount,
            To = Accounts[1].Address,
            Memo = "Set for token converter."
        });

        var feeAmount = 100000;
        await SetMethodFee_Successful(feeAmount);

        var userTestContractStub =
            GetTester<ContractContainer.ContractStub>(_testContractAddress,
                Accounts[1].KeyPair);
        var dummy = await userTestContractStub.DummyMethod
            .SendWithExceptionAsync(new Empty()); // This will deduct the fee
        dummy.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        dummy.TransactionResult.Error.ShouldBe("Pre-Error: Transaction fee not enough.");
        var transactionFeeDic = dummy.TransactionResult.GetChargedTransactionFees();
        await CheckTransactionFeesMapAsync(Accounts[1].Address,transactionFeeDic);

        var afterFee = (await tokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Owner = Accounts[1].Address,
            Symbol = "ELF"
        })).Balance;
        afterFee.ShouldBe(0);
        transactionFeeDic[Accounts[1].Address]["ELF"].ShouldBe(issueAmount);
    }
```
