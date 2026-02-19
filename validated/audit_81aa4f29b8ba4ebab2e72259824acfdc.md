# Audit Report

## Title
Domain Constraint Violation in GetAmountToPayFromReturn Causes DoS for Large Buy Orders

## Summary
The TokenConverter contract's `GetAmountToPayFromReturn` function contains an undocumented mathematical domain constraint that prevents users from purchasing more than approximately 50% of a token pool's balance in a single transaction. When this limit is exceeded, transactions revert with a cryptic error message, causing gas fee losses and operational denial-of-service for legitimate large purchases. [1](#0-0) 

## Finding Description

The vulnerability stems from the mathematical constraints of the `Ln` function used in the Bancor pricing formula. The `GetAmountToPayFromReturn` function calculates `x = bt / (bt - a)` where `bt` is `toConnectorBalance` and `a` is `amountToReceive`, then passes this value to `Ln(x)`. [2](#0-1) 

The `Ln` function implements a Taylor series approximation that strictly requires its input parameter to be within the range (0, 2). If the input falls outside this range, the function throws an `InvalidValueException` with the message "must be 0 < a < 2". [3](#0-2) 

**Mathematical Proof:**
- For `Ln(x)` to succeed: `0 < x < 2`
- Given `x = bt / (bt - a)` where `bt > a > 0`
- For `x < 2`: `bt / (bt - a) < 2` → `bt < 2(bt - a)` → `bt < 2bt - 2a` → `2a < bt` → `a < bt/2`
- **Therefore: when `amountToReceive >= toConnectorBalance / 2`, then `x >= 2`, violating the domain constraint**

The `Buy` method calls `GetAmountToPayFromReturn` without any validation on the maximum `amountToReceive` relative to the connector balance: [4](#0-3) 

The only existing validation in `GetAmountToPayFromReturn` checks that values are positive, but does not enforce the derived 50% constraint: [5](#0-4) 

## Impact Explanation

**Operational DoS:**
- Users cannot purchase more than ~50% of a token pool's balance in a single transaction
- All such attempts fail with the cryptic error message "must be 0 < a < 2" that does not explain the business constraint
- Users lose gas fees on these failed transactions without understanding why

**User Experience Impact:**
- No upfront validation or clear error messaging about the 50% limit
- Users must discover this limitation through trial-and-error, incurring gas costs
- Workaround requires splitting large purchases into multiple smaller transactions, significantly increasing total gas costs

**Economic Impact:**
- Large legitimate trades are blocked, affecting market liquidity
- Increased friction for high-volume traders and institutional participants
- Potential liquidity limitations during periods of market volatility
- Unnecessary operational costs from failed transactions

**Affected Users:**
- Whales or institutions attempting large purchases
- Treasury operations or protocol-owned liquidity movements  
- Any user wanting to buy substantial portions of available liquidity

While this does not result in fund theft or state corruption, it represents a significant operational limitation that affects core token conversion functionality and constitutes a medium-severity availability issue.

## Likelihood Explanation

**Attacker Capabilities:**
- No special permissions required - any user can trigger this condition
- Accessible through the public `Buy` method
- No complex setup or preconditions needed beyond having sufficient funds

**Trigger Complexity:**
- Extremely simple: User only needs to call `Buy` with `amount >= toConnectorBalance / 2`
- No sequence of operations required
- Deterministically triggered whenever the mathematical constraint is violated

**Feasibility Conditions:**
- Always feasible when connector balance exists
- More likely during low liquidity periods when pools are smaller
- Guaranteed to trigger when the mathematical constraint is violated

**Probability:**
- HIGH for users attempting large purchases (>50% of available liquidity)
- MEDIUM for general user population
- Increases during specific market conditions or for smaller liquidity pools

Note: While buying >50% of a pool would result in extreme price slippage in Bancor's bonding curve model (making it economically inefficient), the constraint is never communicated to users. Users may have legitimate reasons for attempting such trades (emergency treasury operations, large institutional purchases, arbitrage opportunities) without understanding this hidden limitation.

## Recommendation

Implement explicit validation and clear error messaging:

1. **Add validation in the `Buy` method**:
```csharp
public override Empty Buy(BuyInput input)
{
    var toConnector = State.Connectors[input.Symbol];
    Assert(toConnector != null, "[Buy]Can't find to connector.");
    Assert(toConnector.IsPurchaseEnabled, "can't purchase");
    Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
    var fromConnector = State.Connectors[toConnector.RelatedSymbol];
    Assert(fromConnector != null, "[Buy]Can't find from connector.");
    
    // Add this validation
    var toBalance = GetSelfBalance(toConnector);
    var maxPurchaseAmount = toBalance / 2;
    Assert(input.Amount < maxPurchaseAmount, 
        $"Purchase amount exceeds maximum allowed ({maxPurchaseAmount}). Please split large purchases into multiple transactions.");
    
    var amountToPay = BancorHelper.GetAmountToPayFromReturn(
        GetSelfBalance(fromConnector), GetWeight(fromConnector),
        toBalance, GetWeight(toConnector),
        input.Amount);
    // ... rest of the method
}
```

2. **Add validation in `GetAmountToPayFromReturn`**:
```csharp
public static long GetAmountToPayFromReturn(long fromConnectorBalance, decimal fromConnectorWeight,
    long toConnectorBalance, decimal toConnectorWeight, long amountToReceive)
{
    if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
        throw new InvalidValueException("Connector balance needs to be a positive number.");

    if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
    
    // Add this validation
    if (amountToReceive >= toConnectorBalance / 2)
        throw new InvalidValueException(
            $"Amount to receive ({amountToReceive}) must be less than 50% of connector balance ({toConnectorBalance / 2}). " +
            "Please reduce your purchase amount or split into multiple transactions.");
    
    // ... rest of the method
}
```

3. **Update documentation** to clearly communicate this limitation to users and integrators.

## Proof of Concept

```csharp
[Fact]
public async Task Buy_Exceeds_50_Percent_DoS_Test()
{
    // Setup: Initialize contract with token pool
    await CreateWriteToken();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    // Get the current connector balance
    var toConnectorBalance = await GetBalanceAsync(WriteSymbol, TokenConverterContractAddress);
    
    // Attempt to buy more than 50% of the pool
    var amountToBuy = toConnectorBalance / 2 + 1;
    
    // This should fail with cryptic error message
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(
        new BuyInput
        {
            Symbol = WriteConnector.Symbol,
            Amount = amountToBuy,
            PayLimit = long.MaxValue // Set high limit to avoid PayLimit error
        });
    
    // Verify transaction fails with domain constraint error
    buyResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    buyResult.TransactionResult.Error.ShouldContain("must be 0 < a < 2");
    
    // User has lost gas fees but received no clear explanation
    // This demonstrates the DoS condition and poor UX
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L67-94)
```csharp
    public static long GetAmountToPayFromReturn(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long amountToReceive)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = amountToReceive;
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

        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L124-143)
```csharp
    private static decimal Ln(decimal a)
    {
        /*
        ln(a) = log(1-x) = - x - x^2/2 - x^3/3 - ...   (where |x| < 1)
            x: a = 1-x    =>   x = 1-a = 1 - 1.004 = -.004
        */
        var x = 1 - a;
        if (Math.Abs(x) >= 1)
            throw new InvalidValueException("must be 0 < a < 2");

        decimal result = 0;
        uint iteration = _LOOPS;
        while (iteration > 0)
        {
            result -= Pow(x, iteration) / iteration;
            iteration--;
        }

        return result;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-159)
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
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());

        var amountToPayPlusFee = amountToPay.Add(fee);
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = amountToPay
            });
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
        // Transfer bought token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });

        Context.Fire(new TokenBought
        {
            Symbol = input.Symbol,
            BoughtAmount = input.Amount,
            BaseAmount = amountToPay,
            FeeAmount = fee
        });
        return new Empty();
    }
```
