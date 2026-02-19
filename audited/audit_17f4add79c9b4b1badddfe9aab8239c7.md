### Title
Integer Overflow in Method Fee Aggregation Completely Bypasses Transaction Fee Collection

### Summary
The `amount >= 0` validation in `AssertValidToken()` only checks individual fee entries but does not prevent setting multiple `MethodFee` entries for the same symbol whose sum exceeds `long.MaxValue`. When fees are collected, the unchecked LINQ `Sum()` operation in `GetBaseFeeDictionary()` causes integer overflow to large negative values, which then bypass all fee charging logic, allowing transactions to execute without paying any fees.

### Finding Description

The vulnerability exists across the fee setting and collection flow:

**1. Insufficient Validation at Fee Setting:**
The `SetMethodFee()` function validates each fee individually using `AssertValidToken()` which only checks `amount >= 0`: [1](#0-0) 

This validation does not prevent setting multiple `MethodFee` entries with the same `symbol` whose sum exceeds `long.MaxValue`. The `MethodFees` message structure explicitly allows multiple fees: [2](#0-1) 

**2. Unchecked Overflow in Fee Aggregation:**
When fees are collected, `GetBaseFeeDictionary()` groups fees by symbol and uses LINQ's `Sum()` method which operates in an **unchecked** arithmetic context: [3](#0-2) 

Unlike the SafeMath extension methods used elsewhere in the codebase (which use `checked` blocks): [4](#0-3) 

The LINQ `Sum()` method silently wraps around when overflow occurs, producing a large negative value (e.g., `long.MaxValue + 1` becomes `long.MinValue`).

**3. Negative Fee Amounts Bypass All Charging Logic:**
When `ChargeBaseFee()` processes the negative fee amount, the comparison `existingAllowance > amountToChargeBaseFee` always evaluates to true for negative values, causing the method to add the negative amount to the allowance bill and zero to the balance bill: [5](#0-4) 

Finally, in `ModifyBalance()`, both charging operations are skipped because the bill amount is zero (skipped by `amount <= 0` check) and the allowance amount is negative (skipped by `amount > 0` check): [6](#0-5) 

**Result:** The transaction executes successfully without charging any fees whatsoever.

### Impact Explanation

**Direct Economic Impact:**
- Complete bypass of transaction fee collection for affected methods
- All transactions using overflowed method fees execute at zero cost
- Loss of all fee revenue that should flow to miners, Treasury, and other fee recipients
- Economic system integrity compromised as fee mechanisms provide no cost barrier

**Operational Impact:**
- Potential for spam/DoS attacks using free transactions
- Resource exhaustion without economic cost to attacker
- Affects any contract implementing ACS1 standard (TokenHolder, Profit, and potentially others)

**Severity:** HIGH - Complete fee bypass represents a critical failure of the economic security model. While exploitation requires governance action, the impact is total fee collection failure.

### Likelihood Explanation

**Attack Prerequisites:**
- Requires the method fee controller (typically Parliament governance) to set malicious or accidentally overflowing fees
- Method fee controller is set via governance: [7](#0-6) 

**Exploitation Scenarios:**

1. **Accidental:** Legitimate governance proposals that incrementally add fees for the same symbol could accidentally exceed `long.MaxValue` without detection
2. **Malicious Insider:** A compromised or malicious governance participant could intentionally create overflow conditions
3. **Governance Capture:** An attacker gaining voting control could set exploitative fees

**Feasibility:** MEDIUM-HIGH
- The attack path is straightforward and well-defined
- No complex state manipulation required
- Test case demonstrates multiple fees for same symbol are supported: [8](#0-7) 
- Once set, all users benefit from fee bypass automatically
- Detection: Fee bypass would be observable through fee collection metrics, but the root cause (overflow) might not be immediately apparent

### Recommendation

**1. Validate Aggregated Fee Totals:**
Add validation in `SetMethodFee()` to ensure the sum of all `BasicFee` values for each symbol does not exceed `long.MaxValue`:

```csharp
// In SetMethodFee() after individual validation
var feesBySymbol = input.Fees.GroupBy(f => f.Symbol);
foreach (var group in feesBySymbol)
{
    long total = 0;
    foreach (var fee in group)
    {
        checked { total += fee.BasicFee; } // Use checked arithmetic
    }
}
```

**2. Use Checked Arithmetic in Fee Aggregation:**
Replace LINQ's unchecked `Sum()` with SafeMath's checked `Add()` in `GetBaseFeeDictionary()`:

```csharp
return methodFees.Fees.Where(f => !string.IsNullOrEmpty(f.Symbol))
    .GroupBy(f => f.Symbol, f => f.BasicFee)
    .ToDictionary(g => g.Key, g => g.Aggregate(0L, (sum, fee) => sum.Add(fee)));
```

**3. Add Invariant Checks:**
Assert that fee amounts are positive before processing in `ChargeBaseFee()` to fail fast if negative values appear.

**4. Add Regression Tests:**
Create test cases that attempt to set fees exceeding `long.MaxValue` and verify proper rejection.

### Proof of Concept

**Initial State:**
- Token contract deployed with method fee controller set to Parliament
- User has sufficient balance to pay normal fees

**Attack Steps:**

1. **Governance proposes and executes `SetMethodFee()` with overflow:**
   ```
   MethodFees {
     method_name: "Transfer",
     fees: [
       { symbol: "ELF", basic_fee: 9223372036854775807 },  // long.MaxValue
       { symbol: "ELF", basic_fee: 1 }
     ]
   }
   ```

2. **User calls `Transfer()` method**

3. **Fee collection executes:**
   - `GetBaseFeeDictionary()` sums: `9223372036854775807 + 1 = -9223372036854775808` (overflow to long.MinValue)
   - `ChargeBaseFee()` receives negative amount
   - Checks pass due to `existingAllowance > negative_amount`
   - Bill set to: `{balance: 0, allowance: -9223372036854775808}`

4. **`ModifyBalance()` processes bill:**
   - Balance charge skipped: `if (amount <= 0) continue`
   - Allowance charge skipped: `if (amount > 0)` is false

**Expected Result:** User charged 9223372036854775808 tokens in fees

**Actual Result:** User charged 0 tokens, transaction succeeds with complete fee bypass

**Success Condition:** User's balance remains unchanged despite method fee being set. Fee collection events show zero fees charged.

---

**Notes:**

This vulnerability affects the core economic security model. While it requires governance/controller action to exploit, the `amount >= 0` check provides false security by only validating individual entries rather than aggregate totals. The use of unchecked LINQ `Sum()` instead of the SafeMath helpers used elsewhere in the codebase represents an inconsistent security pattern that created this critical gap.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L11-20)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L78-87)
```csharp
    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }
```

**File:** protobuf/acs1.proto (L40-52)
```text
message MethodFees {
    // The name of the method to be charged.
    string method_name = 1;
    // List of fees to be charged.
    repeated MethodFee fees = 2;
    bool is_size_fee_free = 3;// Optional based on the implementation of SetMethodFee method.
}

message MethodFee {
    // The token symbol of the method fee.
    string symbol = 1;
    // The amount of fees to be charged.
    int64 basic_fee = 2;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L245-265)
```csharp
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L322-327)
```csharp
    private Dictionary<string, long> GetBaseFeeDictionary(MethodFees methodFees)
    {
        return methodFees.Fees.Where(f => !string.IsNullOrEmpty(f.Symbol))
            .GroupBy(f => f.Symbol, f => f.BasicFee)
            .ToDictionary(g => g.Key, g => g.Sum());
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L358-369)
```csharp
        // Succeed to charge, freeAllowance first.
        if (existingAllowance > amountToChargeBaseFee)
        {
            allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee);
            // free fee allowance has covered fee, add 0 for size fee
            bill.FeesMap.Add(symbolToChargeBaseFee, 0);
        }
        else
        {
            allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, existingAllowance);
            bill.FeesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee.Sub(existingAllowance));
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

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest.cs (L66-104)
```csharp
    public async Task Set_Repeat_Token_Test()
    {
        await IssueTokenToDefaultSenderAsync(NativeTokenSymbol, 100000_00000000);
        await SetPrimaryTokenSymbolAsync();
        var address = DefaultSender;
        var methodName = nameof(TokenContractContainer.TokenContractStub.Transfer);
        var basicMethodFee = 1000;
        var methodFee = new MethodFees
        {
            MethodName = methodName,
            Fees =
            {
                new MethodFee
                {
                    Symbol = NativeTokenSymbol,
                    BasicFee = basicMethodFee
                },
                new MethodFee
                {
                    Symbol = NativeTokenSymbol,
                    BasicFee = basicMethodFee
                }
            }
        };
        var sizeFee = 0;
        await TokenContractImplStub.SetMethodFee.SendAsync(methodFee);
        var beforeChargeBalance = await GetBalanceAsync(address, NativeTokenSymbol);
        var chargeTransactionFeesInput = new ChargeTransactionFeesInput
        {
            MethodName = methodName,
            ContractAddress = TokenContractAddress,
            TransactionSizeFee = sizeFee,
        };

        var chargeFeeRet = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeTransactionFeesInput);
        chargeFeeRet.Output.Success.ShouldBeTrue();
        var afterChargeBalance = await GetBalanceAsync(address, NativeTokenSymbol);
        beforeChargeBalance.Sub(afterChargeBalance).ShouldBe(basicMethodFee.Add(basicMethodFee));
    }
```
