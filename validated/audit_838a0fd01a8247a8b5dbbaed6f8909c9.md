# Audit Report

## Title
Integer Overflow in Bancor Price Calculation Causes DoS on Large Token Purchases

## Summary
The `GetAmountToPayFromReturn` function in the TokenConverter contract contains an arithmetic overflow vulnerability in its equal-weight optimization path. When users attempt to purchase amounts approaching the available token balance, the calculation exceeds `long.MaxValue`, causing transaction failures with misleading error messages.

## Finding Description

The vulnerability exists in the equal-weight connector optimization within the Bancor pricing formula. [1](#0-0) 

When both connector weights are equal, the formula simplifies to `bf / (bt - a) * a`. As the purchase amount `a` approaches the available balance `bt`, the denominator `(bt - a)` becomes very small, causing the division result to amplify dramatically. The subsequent multiplication by `a` produces values exceeding `long.MaxValue` (9,223,372,036,854,775,807).

The project explicitly enables overflow checking for both Debug and Release configurations. [2](#0-1)  This means casting a decimal exceeding `long.MaxValue` to `long` throws an `OverflowException`, which is caught by the generic catch block and re-thrown with the misleading message "Insufficient account balance to deposit".

**Execution Path:**

The vulnerable function is invoked from the public `Buy` method accessible to any user. [3](#0-2) 

The same vulnerability also affects the `GetNeededDeposit` view function. [4](#0-3) 

**Production Configuration:**

Equal-weight connector pairs are confirmed in production deployment, where both resource and native token connectors use weight 0.005. [5](#0-4) 

The production constants define realistic values that enable this vulnerability. [6](#0-5) 

## Impact Explanation

This vulnerability causes complete denial of service for legitimate large token purchases in equal-weight connector pairs. Users attempting to purchase significant portions of available tokens (approaching 99% depending on balance ratios) will experience transaction failures.

**Concrete Example:**
- Deposit balance: `bf = 10,000,000_00000000` (10 million ELF)
- Available token balance: `bt = 100,000_00000000` (100k resource tokens)  
- User attempts: `a = 99,999_00000000` (99,999 tokens)
- Calculation: `bf / (bt - a) * a = 10^15 / 10^8 * 9.9999×10^12 ≈ 9.9999×10^19`
- Result: Exceeds `long.MaxValue` causing `OverflowException`

The misleading error message ("Insufficient account balance to deposit") prevents users from understanding the root cause. There is no workaround for atomic large purchases - users must split into smaller batches, suffering from:
1. Price slippage between transactions
2. Increased transaction fees  
3. Risk of front-running between batches

## Likelihood Explanation

This vulnerability will affect any legitimate user attempting large token purchases when:
1. The connector pair uses equal weights (confirmed in production with weight 0.005)
2. The purchase amount exceeds the critical threshold (~98-99% of available balance)

No special privileges are required - any user can call the public `Buy` function. While the percentage threshold is high, such large purchases are realistic for:
- Institutional investors or whales entering positions
- Market makers establishing liquidity
- Protocol treasury operations
- Token migration or consolidation activities

The likelihood is **MEDIUM to HIGH** for scenarios involving large capital movements, which are expected in a production token conversion system. This is especially likely after many users have already purchased tokens, depleting the contract's available balance.

## Recommendation

Add validation before the calculation to prevent overflow scenarios:

```csharp
if (wf == wt)
{
    try
    {
        // Check if calculation will overflow before performing it
        var denominator = bt - a;
        if (denominator <= 0)
            throw new InvalidValueException("Purchase amount too large");
        
        // Check if result would exceed long.MaxValue
        // Approximate: bf / denominator should not exceed long.MaxValue / a
        if (bf / denominator > long.MaxValue / a)
            throw new InvalidValueException("Purchase amount would cause price overflow");
            
        return (long)(bf / denominator * a);
    }
    catch (InvalidValueException)
    {
        throw;
    }
    catch
    {
        throw new AssertionException("Insufficient account balance to deposit");
    }
}
```

Alternatively, use `BigInteger` for intermediate calculations or impose a maximum purchase limit relative to available balance (e.g., max 95% per transaction).

## Proof of Concept

```csharp
[Fact]
public async Task Test_Buy_LargeAmount_CausesOverflow()
{
    // Setup: Create connector pair with equal weights (0.005)
    var resourceSymbol = "TEST";
    var nativeSymbol = "(NT)TEST";
    
    await TokenConverterStub.Initialize.SendAsync(new InitializeInput
    {
        BaseTokenSymbol = "ELF",
        FeeRate = "0.005",
        Connectors = {
            new Connector {
                Symbol = resourceSymbol,
                Weight = "0.005",
                IsPurchaseEnabled = true,
                RelatedSymbol = nativeSymbol
            },
            new Connector {
                Symbol = nativeSymbol,
                Weight = "0.005",
                IsPurchaseEnabled = true,
                IsDepositAccount = true,
                VirtualBalance = 10_000_000_00000000L, // 10M ELF
                RelatedSymbol = resourceSymbol
            }
        }
    });
    
    // Issue 100k resource tokens to converter
    await TokenContractStub.Issue.SendAsync(new IssueInput {
        Symbol = resourceSymbol,
        Amount = 100_000_00000000L,
        To = TokenConverterContractAddress
    });
    
    // Approve large amount
    await TokenContractStub.Approve.SendAsync(new ApproveInput {
        Spender = TokenConverterContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });
    
    // Attempt to buy 99,999 tokens (99.999% of available)
    var result = await TokenConverterStub.Buy.SendWithExceptionAsync(new BuyInput {
        Symbol = resourceSymbol,
        Amount = 99_999_00000000L
    });
    
    // Verify overflow causes failure
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Insufficient account balance to deposit");
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L81-83)
```csharp
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L234-245)
```csharp
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
                VirtualBalance = EconomicContractConstants.ResourceTokenInitialVirtualBalance,
                RelatedSymbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsDepositAccount = false
            };
            var nativeTokenConnector = new Connector
            {
                Symbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L5-20)
```csharp
    public const long NativeTokenConnectorInitialVirtualBalance = 100_000_00000000;

    // Token Converter Contract related.
    public const string TokenConverterFeeRate = "0.005";

    // Resource token related.
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;

    public const int ResourceTokenDecimals = 8;

    //resource to sell
    public const long ResourceTokenInitialVirtualBalance = 100_000;

    public const string NativeTokenPrefix = "nt";

    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```
