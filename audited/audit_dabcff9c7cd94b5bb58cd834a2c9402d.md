# Audit Report

## Title
Integer Division Rounding Allows Zero Transaction Size Fee Bypass

## Summary
The transaction size fee charging mechanism fails to prevent zero-fee transactions when integer division causes `txSizeFeeAmount` to round down to 0. Users can bypass size fees entirely by selecting alternative payment tokens with weight ratios that cause the fee conversion to round to zero, breaking the protocol's economic model and spam protection.

## Finding Description

The vulnerability exists in the `ChargeSizeFee` function's fee conversion logic and the subsequent billing process in `GenerateBill`.

**Root Cause:** When converting transaction size fees from the primary token to an alternative token, the calculation uses integer division without rounding protection: [1](#0-0) 

The `Div()` method performs standard integer division that truncates toward zero: [2](#0-1) 

For example, if `txSizeFeeAmount = 5`, `AddedTokenWeight = 1`, and `BaseTokenWeight = 10`, the calculation becomes `5 * 1 / 10 = 0` due to integer truncation.

**Why Protections Fail:** When the converted `txSizeFeeAmount` becomes 0, the `ChargeSizeFee` function still succeeds because the check passes: [3](#0-2) 

This evaluates to `true` whenever the user has any balance. The `GenerateBill` function then sets both charge amounts to 0: [4](#0-3) 

When `txSizeFeeAmount = 0` and the user has balance, line 525's condition is true, leading to either line 530 (setting `chargeAllowanceAmount = 0`) or lines 535-536 (setting both amounts to 0).

Finally, the `ModifyBalance` wrapper skips zero amounts entirely: [5](#0-4) 

This means no fee is deducted and no `TransactionFeeCharged` event is fired.

**Insufficient Validation:** The `SetSymbolsToPayTxSizeFee` function only validates that weights are positive: [6](#0-5) 

There is no check to ensure weight ratios don't cause rounding issues for typical transaction sizes.

## Impact Explanation

**Protocol Invariant Break:** This vulnerability breaks the fundamental protocol invariant that transactions must pay fees. The fee mechanism serves dual purposes: (1) preventing spam by making it costly to flood the network, and (2) funding network operations through fee distribution to miners and treasury.

**Direct Economic Impact:**
- Network loses 100% of size fee revenue on affected transactions
- For transactions with fees < 10 units using a 1:10 ratio token: complete fee bypass
- For transactions with fees < 100 units using a 1:100 ratio token: complete fee bypass
- Spam protection is disabled, opening the network to DoS attacks

**Affected Parties:**
- **Network operators:** Loss of fee revenue that funds operations
- **Miners:** Reduced block rewards from fee distribution
- **Legitimate users:** Potential service degradation from spam transactions
- **Token economics:** Treasury and profit distribution contracts receive no funds from affected transactions

**Severity:** Medium-High. While governance controls token configuration, even reasonable-seeming ratios (e.g., 1:10 for a token worth 1/10th of ELF) enable fee bypass for small transactions, which are common in real-world usage.

## Likelihood Explanation

**Attacker Capabilities:** Any user who can submit transactions. No special privileges required - users simply select which configured token to pay fees with as part of normal transaction submission.

**Attack Complexity:** Trivial. The exploit requires no special knowledge or tools:
1. User checks which alternative tokens are configured
2. User identifies tokens with weight ratios causing rounding (e.g., AddedTokenWeight=1, BaseTokenWeight≥10)
3. User submits small-fee transactions selecting that token
4. System automatically performs vulnerable conversion, charging 0 fee

**Preconditions:**
- Alternative tokens must be configured via `SetSymbolsToPayTxSizeFee` (governance-controlled but highly likely in production)
- Token weight ratios must cause rounding for transaction sizes (common with ratios ≥1:10)
- User must have any balance in the alternative token

**Feasibility:** High. Test cases demonstrate alternative tokens are actively used in the system: [7](#0-6) 

**Probability:** Medium. Requires governance to have configured alternative tokens (realistic in any multi-token ecosystem), then exploitation is automatic for any user choosing that token.

## Recommendation

**Solution:** Add a minimum fee enforcement after conversion to prevent zero-fee transactions:

```csharp
private bool ChargeSizeFee(ChargeTransactionFeesInput input, Address fromAddress, ref TransactionFeeBill bill,
    TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap,
    ref TransactionFreeFeeAllowanceBill allowanceBill,
    TransactionFeeDelegations delegations = null)
{
    // ... existing code ...
    
    if (availableSymbol != null && availableSymbol.TokenSymbol != symbolToPayTxFee)
    {
        symbolToPayTxFee = availableSymbol.TokenSymbol;
        txSizeFeeAmount = txSizeFeeAmount.Mul(availableSymbol.AddedTokenWeight)
            .Div(availableSymbol.BaseTokenWeight);
        
        // ADD THIS: Enforce minimum fee of 1 to prevent rounding to zero
        if (input.TransactionSizeFee > 0 && txSizeFeeAmount == 0)
        {
            txSizeFeeAmount = 1;
        }
        
        GetAvailableBalance(symbolToPayTxFee, fromAddress, bill, transactionFeeFreeAllowancesMap, allowanceBill,
            out symbolChargedForBaseFee, out amountChargedForBaseFee, out amountChargedForBaseAllowance,
            out availableBalance, out availableAllowance);
    }
    
    // ... rest of function ...
}
```

**Additional Validation:** Add ratio validation in `SetSymbolsToPayTxSizeFee` to warn governance about problematic configurations:

```csharp
// After line 635, add:
var minFeeThreshold = 100; // Define appropriate threshold
if (tokenWeightInfo.BaseTokenWeight > tokenWeightInfo.AddedTokenWeight.Mul(minFeeThreshold))
{
    Context.LogDebug(() => $"Warning: Token {tokenWeightInfo.TokenSymbol} ratio may cause fee rounding issues for fees < {minFeeThreshold}");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ChargeTransactionFees_ZeroFee_Due_To_Integer_Division_Rounding()
{
    // Setup: Configure alternative token with 1:10 ratio
    await SetPrimaryTokenSymbolAsync();
    var alternativeToken = "ALT";
    await CreateTokenAsync(DefaultSender, alternativeToken);
    await IssueTokenToDefaultSenderAsync(alternativeToken, 10000);
    
    var sizeFeeSymbolList = new SymbolListToPayTxSizeFee();
    sizeFeeSymbolList.SymbolsToPayTxSizeFee.Add(new SymbolToPayTxSizeFee
    {
        TokenSymbol = NativeTokenSymbol,
        AddedTokenWeight = 1,
        BaseTokenWeight = 1
    });
    sizeFeeSymbolList.SymbolsToPayTxSizeFee.Add(new SymbolToPayTxSizeFee
    {
        TokenSymbol = alternativeToken,
        AddedTokenWeight = 1,  // 1 ALT = 0.1 ELF
        BaseTokenWeight = 10
    });
    await TokenContractImplStub.SetSymbolsToPayTxSizeFee.SendAsync(sizeFeeSymbolList);
    
    // Attack: Submit transaction with size fee = 5 (in primary token)
    // Conversion: 5 * 1 / 10 = 0 (integer division)
    var balanceBefore = await GetBalanceAsync(DefaultSender, alternativeToken);
    
    var chargeInput = new ChargeTransactionFeesInput
    {
        MethodName = "Transfer",
        ContractAddress = TokenContractAddress,
        TransactionSizeFee = 5, // Small fee that rounds to 0
    };
    chargeInput.SymbolsToPayTxSizeFee.AddRange(sizeFeeSymbolList.SymbolsToPayTxSizeFee);
    
    var result = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeInput);
    result.Output.Success.ShouldBeTrue(); // Transaction succeeds
    
    var balanceAfter = await GetBalanceAsync(DefaultSender, alternativeToken);
    
    // Verify: No fee was charged (balance unchanged)
    balanceAfter.ShouldBe(balanceBefore); // Vulnerability confirmed: 0 fee charged
}
```

**Notes:**
- This vulnerability affects all transactions where the converted size fee rounds to zero
- The issue is deterministic and reproducible with any weight ratio causing rounding
- Even "reasonable" token configurations (1:10 for lower-value tokens) enable the bypass
- The validation gap allows governance to unknowingly create exploitable configurations

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L245-248)
```csharp
        foreach (var (symbol, amount) in bill.FeesMap)
        {
            if (amount <= 0) continue;
            ModifyBalance(fromAddress, symbol, -amount);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L403-404)
```csharp
                txSizeFeeAmount = txSizeFeeAmount.Mul(availableSymbol.AddedTokenWeight)
                    .Div(availableSymbol.BaseTokenWeight);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L417-417)
```csharp
        var chargeResult = availableBalance.Add(availableAllowance) >= txSizeFeeAmount;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L519-543)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L634-635)
```csharp
            Assert(tokenWeightInfo.AddedTokenWeight > 0 && tokenWeightInfo.BaseTokenWeight > 0,
                $"symbol:{tokenWeightInfo.TokenSymbol} weight should be greater than 0");
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest.cs (L107-122)
```csharp
    // 1 => ELF  2 => CWJ  3 => YPA   method fee : native token: 1000
    [Theory]
    [InlineData(new[] { 1, 2, 3 }, new[] { 10000L, 0, 0 }, new[] { 1, 1, 1 }, new[] { 1, 1, 1 }, 1000, "ELF", 2000,
        true)]
    [InlineData(new[] { 2, 1, 3 }, new[] { 10000L, 10000L, 0 }, new[] { 1, 1, 1 }, new[] { 1, 1, 1 }, 1000, "CWJ", 1000,
        true)]
    [InlineData(new[] { 2, 1, 3 }, new[] { 10000L, 10000L, 0 }, new[] { 1, 1, 1 }, new[] { 2, 1, 1 }, 1000, "CWJ", 2000,
        true)]
    [InlineData(new[] { 2, 1, 3 }, new[] { 10000L, 10000L, 0 }, new[] { 4, 1, 1 }, new[] { 2, 1, 1 }, 1000, "CWJ", 500,
        true)]
    [InlineData(new[] { 2, 1, 3 }, new[] { 100L, 1000L, 0 }, new[] { 1, 1, 1 }, new[] { 1, 1, 1 }, 1000, "CWJ", 100,
        false)]
    [InlineData(new[] { 3, 1, 2 }, new[] { 10L, 1000L, 100 }, new[] { 1, 1, 1 }, new[] { 1, 1, 1 }, 1000, "YPA", 10,
        false)]
    public async Task ChargeTransactionFees_With_Different_Transaction_Size_Fee_Token(int[] order, long[] balance,
        int[] baseWeight, int[] tokenWeight, long sizeFee, string chargeSymbol, long chargeAmount, bool isSuccess)
```
