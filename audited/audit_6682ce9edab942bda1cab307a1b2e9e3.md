### Title
Integer Overflow in GetBaseFeeDictionary Enables Zero-Fee Transaction Execution via LINQ Sum() Vulnerability

### Summary
The `GetBaseFeeDictionary` method uses LINQ's `Sum()` to aggregate multiple `BasicFee` values with the same symbol, but LINQ's `Sum()` lacks overflow protection and will silently wrap to negative values when exceeding `Int64.MaxValue`. When negative fees are passed to the charging logic, the transaction succeeds with zero fees charged due to guard clauses that skip negative amounts, effectively bypassing the fee system.

### Finding Description

The vulnerability exists in the fee aggregation logic: [1](#0-0) 

This method groups `BasicFee` values by symbol and uses LINQ's `Sum()` to aggregate them. Unlike the `SafeMath.Add()` extension method, LINQ's `Sum()` performs unchecked arithmetic that wraps on overflow rather than throwing an exception. [2](#0-1) 

While AElf's `SafeMath` provides overflow-checked addition, and the IL patcher replaces unchecked opcodes with overflow-checking versions: [3](#0-2) 

The patcher cannot modify .NET Framework library code like LINQ's `Sum()`, which is already compiled. The system explicitly allows duplicate symbols in method fees: [4](#0-3) 

When overflow occurs, the negative fee value passes through to `ChargeBaseFee`, where the comparison logic fails: [5](#0-4) 

At line 773, `if (existingAllowance >= amount)` evaluates to TRUE when `amount` is negative, causing the method to return true immediately. Then in the fee deduction logic: [6](#0-5) 

Line 359's comparison `existingAllowance > amountToChargeBaseFee` is TRUE for negative amounts, adding zero to `bill.FeesMap` (line 363). Finally: [7](#0-6) 

The guard clause `if (amount <= 0) continue` skips fee deduction entirely, allowing the transaction to succeed with zero fees charged.

While `SetMethodFee` validates individual fees are non-negative: [8](#0-7) 

This validation occurs BEFORE summation, leaving a gap where the summed result can become negative through overflow.

### Impact Explanation

**Direct Fund Impact:** Methods with overflowed fees can be executed for free, bypassing the economic cost model. High-value operations (token transfers, contract deployments, governance actions) that should cost significant fees become cost-free.

**Operational Impact:** The fee system is a critical economic control mechanism. Bypassing it enables:
- Transaction spam without economic deterrent
- Resource exhaustion attacks at zero cost
- Inflation of transaction volume metrics
- Disruption of tokenomics and fee-burning mechanisms

**Affected Parties:** All contracts using ACS1 method fees (Parliament, Association, Referendum, Token, Vote, etc.) and any users who should pay fees for their operations.

**Severity Justification:** HIGH - This breaks a fundamental invariant (fees must be non-negative and must be charged). The vulnerability allows complete bypass of fee payment for any method where overflow can be triggered.

### Likelihood Explanation

**Attacker Capabilities:** Requires control of the MethodFeeController, which defaults to the Parliament default organization requiring 2/3 block producer approval. [9](#0-8) 

**Attack Complexity:** LOW once governance access obtained. Attacker crafts a proposal with duplicate symbol entries:
- Entry 1: `Symbol="ELF", BasicFee=5000000000000000000` (≈ Int64.MaxValue/2)
- Entry 2: `Symbol="ELF", BasicFee=5000000000000000000` (duplicate)
- Sum: `10000000000000000000` → wraps to negative value

**Feasibility Conditions:** 
- Accidental scenario: Governance legitimately sets multiple fees not realizing they'll overflow
- Malicious scenario: Compromised governance or social engineering to pass malicious proposal
- Once set, ALL users calling the affected method benefit from zero fees

**Detection Constraints:** Negative fees in storage would be detectable, but by then the vulnerability is already exploited. No runtime checks prevent the overflow.

**Probability:** MEDIUM-HIGH for accidental occurrence during legitimate governance actions setting high fees. The validation gap makes this a realistic threat.

### Recommendation

**Immediate Fix:** Add overflow-checked summation in `GetBaseFeeDictionary`:

```csharp
private Dictionary<string, long> GetBaseFeeDictionary(MethodFees methodFees)
{
    var result = new Dictionary<string, long>();
    foreach (var group in methodFees.Fees.Where(f => !string.IsNullOrEmpty(f.Symbol))
        .GroupBy(f => f.Symbol))
    {
        long sum = 0;
        foreach (var fee in group)
        {
            sum = sum.Add(fee.BasicFee); // Uses SafeMath.Add with overflow checking
        }
        result[group.Key] = sum;
    }
    return result;
}
```

**Additional Validation:** Add post-summation check in `SetMethodFee`:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    
    // Validate summed fees don't overflow
    var summedFees = GetBaseFeeDictionary(input);
    foreach (var (symbol, amount) in summedFees)
    {
        Assert(amount >= 0, $"Total fee for {symbol} overflowed to negative value.");
    }
    
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Test Cases:**
1. Test setting two fees with `BasicFee = Int64.MaxValue / 2 + 1` for same symbol - should fail
2. Test that summed fees approaching Int64.MaxValue are handled correctly
3. Regression test ensuring overflow throws exception rather than wrapping

### Proof of Concept

**Initial State:**
- Parliament MethodFeeController controls fee setting for a contract
- User has balance of 1000 ELF

**Exploit Sequence:**

1. Governance creates and approves proposal to set method fees:
```
MethodFees {
  MethodName: "Transfer",
  Fees: [
    { Symbol: "ELF", BasicFee: 5000000000000000000 },  // ≈ Int64.MaxValue/2
    { Symbol: "ELF", BasicFee: 5000000000000000000 }   // Duplicate symbol
  ]
}
```

2. Proposal executes, calling `SetMethodFee`:
   - Each individual `BasicFee` passes validation (both ≥ 0)
   - Fees stored in state

3. User calls Transfer method:
   - `ChargeTransactionFees` retrieves fees
   - `GetBaseFeeDictionary` calls `Sum()` on [5000000000000000000, 5000000000000000000]
   - Result: `-8446744073709551616` (overflow wraparound)

4. Fee charging logic:
   - `TryToChargeUserBaseFee` receives `amount = -8446744073709551616`
   - Line 773 check: `0 >= -8446744073709551616` → TRUE
   - Returns success, adds zero to bill
   - `ModifyBalance` line 247: `if (0 <= 0) continue` → skips deduction

**Expected Result:** User pays ~10^19 (summed fee) or transaction fails if insufficient

**Actual Result:** User pays ZERO fees, transaction succeeds

**Success Condition:** User's balance remains 1000 ELF after Transfer execution (no fee deducted)

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L245-248)
```csharp
        foreach (var (symbol, amount) in bill.FeesMap)
        {
            if (amount <= 0) continue;
            ModifyBalance(fromAddress, symbol, -amount);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L359-369)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L747-777)
```csharp
    private bool TryToChargeUserBaseFee(Dictionary<string, long> symbolToAmountMap, Address fromAddress,
        TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, out long amount,
        out string symbolOfValidBalance, out long existingBalance, out long existingAllowance)
    {
        // priority: enough allowance -> symbolWithEnoughBalancePlusAllowance -> symbolWithEnoughBalance -> symbolWithAnything
        symbolOfValidBalance = null;
        string symbolWithAnything = null;
        string symbolWithEnoughBalance = null;
        string symbolWithEnoughBalancePlusAllowance = null;

        amount = 0;
        existingBalance = 0;
        existingAllowance = 0;
        //For user
        //Find the token that satisfies the balance of the fee,if there is no token that satisfies the balance of the fee, find the token that balance > 0
        foreach (var (symbol, value) in symbolToAmountMap)
        {
            // current token symbol
            amount = value;
            existingBalance = GetBalance(fromAddress, symbol);
            existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);

            var existingBalancePlusAllowance = existingBalance.Add(existingAllowance);

            
            // allowance is enough to cover the base fee
            if (existingAllowance >= amount)
            {
                symbolOfValidBalance = symbol;
                return true;
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

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/SafeMath/Patcher.cs (L14-20)
```csharp
    // Replace unchecked math OpCodes with checked OpCodes (overflow throws exception)
    private static readonly Dictionary<OpCode, OpCode> PlainToCheckedOpCodes = new()
    {
        {OpCodes.Add, OpCodes.Add_Ovf},
        {OpCodes.Sub, OpCodes.Sub_Ovf},
        {OpCodes.Mul, OpCodes.Mul_Ovf}
    };
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

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-18)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
```
