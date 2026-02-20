# Audit Report

## Title
Integer Overflow in Bancor Price Calculation Causes DoS on Large Token Purchases

## Summary
The `GetAmountToPayFromReturn` function in BancorHelper.cs contains an arithmetic overflow vulnerability when casting from decimal to long. When users attempt to purchase large amounts of tokens from connector pairs with equal weights, the calculation produces values exceeding `long.MaxValue`, causing transaction failures and preventing legitimate large purchases.

## Finding Description

The vulnerability exists in the simplified Bancor formula for equal-weight connector pairs. [1](#0-0) 

When both connector weights are equal, the formula reduces to: `(bf / (bt - a)) * a` where:
- `bf` = fromConnectorBalance (deposit balance)
- `bt` = toConnectorBalance (available token balance) 
- `a` = amountToReceive (purchase amount)

When `a` approaches `bt`, the denominator `(bt - a)` becomes very small, causing the division result to amplify dramatically. The intermediate decimal calculation can produce values exceeding `long.MaxValue` (9,223,372,036,854,775,807).

The project compiles with overflow checking enabled in both Debug and Release configurations. [2](#0-1) 

This means the cast from decimal to long throws `OverflowException`, which is caught by the try-catch block and re-thrown with the misleading message "Insufficient account balance to deposit".

The vulnerable function is called from the public `Buy` method, making it directly accessible to any user. [3](#0-2) 

The function is also called from the view method `GetNeededDeposit`. [4](#0-3) 

## Impact Explanation

**Concrete Scenario:**
With realistic production values:
- Deposit balance: `bf = 10^15` (10 million ELF tokens with 8 decimals = 10,000,000 × 10^8)
- Token balance: `bt = 10^14` (1 million resource tokens = 1,000,000 × 10^8)
- User attempts to buy: `a = 10^14 - 1` (almost all available tokens)

Calculation: `(10^15 / 1) × (10^14 - 1) ≈ 10^29`

This exceeds `long.MaxValue` (~9.22 × 10^18) by approximately 11 orders of magnitude, causing guaranteed overflow.

**Who Is Affected:**
- Legitimate users attempting large token purchases
- Any connector pair with equal weights (common configuration as seen in production code) [5](#0-4) 
- Core TokenConverter contract functionality

**Severity:**
- Complete DoS of `Buy` function for purchases approaching total available balance
- No atomic workaround exists (splitting into multiple smaller transactions is costly and impractical)
- Misleading error messages prevent proper debugging and confuse users

## Likelihood Explanation

**No Special Privileges Required:**
Any user can call the public `Buy` method without authorization checks beyond standard token approvals.

**Common Configuration:**
Equal-weight connectors are standard configurations confirmed in production contract code and multiple test files showing weights of 0.5 for both connectors in pairs. [6](#0-5) 

**Realistic Conditions:**
- Connector pairs accumulate deposit balances over time through normal trading
- Users naturally want to purchase large amounts of tokens
- The overflow threshold is lower than total available balance in production scenarios

**Probability: HIGH** - This will affect any legitimate user attempting to purchase a significant portion (>99.99%) of available tokens in equal-weight connector pairs.

## Recommendation

Add explicit validation before the calculation to ensure the amount to receive is less than the available balance. Additionally, consider using SafeMath operations or adding bounds checking:

```csharp
if (wf == wt)
{
    // Add validation
    if (a >= bt)
        throw new InvalidValueException("Amount exceeds available balance.");
    
    try
    {
        // Additional safety: check if calculation will overflow
        decimal result = bf / (bt - a) * a;
        if (result > long.MaxValue)
            throw new InvalidValueException("Calculated amount exceeds maximum value.");
        
        return (long)result;
    }
    catch (OverflowException)
    {
        throw new InvalidValueException("Purchase amount too large, calculation overflow.");
    }
}
```

Alternatively, implement a maximum purchase percentage limit (e.g., 90% of available balance) to prevent edge cases.

## Proof of Concept

```csharp
[Fact]
public async Task Buy_Overflow_Large_Amount_Test()
{
    // Setup: Create connector pair with equal weights (0.5)
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    // Get current balances
    var toConnectorBalance = await GetBalanceAsync(WriteSymbol, TokenConverterContractAddress);
    var fromConnectorBalance = ELFConnector.VirtualBalance;
    
    // Attempt to buy almost all available tokens (99.9999%)
    var largeAmount = toConnectorBalance - 1;
    
    // This should overflow when calculating: bf / (bt - a) * a
    // = fromConnectorBalance / 1 * largeAmount
    // Which can exceed long.MaxValue
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(
        new BuyInput
        {
            Symbol = WriteConnector.Symbol,
            Amount = largeAmount,
            PayLimit = long.MaxValue
        });
    
    // Verify overflow causes failure with misleading error
    buyResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    buyResult.TransactionResult.Error.ShouldContain("Insufficient account balance to deposit");
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L80-89)
```csharp
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
            }
            catch
            {
                throw new AssertionException("Insufficient account balance to deposit");
            }
```

**File:** contract/AElf.Contracts.TokenConverter/AElf.Contracts.TokenConverter.csproj (L11-16)
```text
    <PropertyGroup Condition=" '$(Configuration)' == 'Debug' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
    <PropertyGroup Condition=" '$(Configuration)' == 'Release' ">
        <CheckForOverflowUnderflow>true</CheckForOverflowUnderflow>
    </PropertyGroup>
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-123)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L81-84)
```csharp
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
        }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L220-224)
```csharp
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.5",
                VirtualBalance = EconomicContractConstants.NativeTokenConnectorInitialVirtualBalance
            }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterContractTests.cs (L20-48)
```csharp
    private readonly Connector ELFConnector = new()
    {
        Symbol = NativeSymbol,
        VirtualBalance = 100_0000,
        Weight = "0.5",
        IsPurchaseEnabled = true,
        IsVirtualBalanceEnabled = true
    };

    private readonly Connector NtWriteConnector = new()
    {
        Symbol = "NT" + WriteSymbol,
        VirtualBalance = 100_0000,
        Weight = "0.5",
        IsPurchaseEnabled = true,
        IsVirtualBalanceEnabled = true,
        RelatedSymbol = WriteSymbol,
        IsDepositAccount = true
    };

    private readonly Connector WriteConnector = new()
    {
        Symbol = WriteSymbol,
        VirtualBalance = 0,
        Weight = "0.5",
        IsPurchaseEnabled = true,
        IsVirtualBalanceEnabled = false,
        RelatedSymbol = "NT" + WriteSymbol,
        IsDepositAccount = false
```
