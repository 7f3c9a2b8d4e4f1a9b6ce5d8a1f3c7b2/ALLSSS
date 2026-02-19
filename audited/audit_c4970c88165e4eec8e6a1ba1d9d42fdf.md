### Title
Decimal Overflow in GetAmountToPayFromReturn Due to Unbounded Connector Weight Ratios

### Summary
The `GetAmountToPayFromReturn` function in BancorHelper can overflow when computing the amount to pay for a token purchase if connector weights have extreme ratios. The calculation `bf * (Exp(y * Ln(x)) - decimal.One)` can exceed C# decimal's maximum value (~7.9 × 10^28) when the weight ratio `y = toConnectorWeight / fromConnectorWeight` is large, causing transaction reversion and DoS of the token converter.

### Finding Description
The vulnerability exists in the Bancor formula calculation at [1](#0-0) 

The calculation multiplies `fromConnectorBalance` by `Exp(y * Ln(x))` where:
- `y = toConnectorWeight / fromConnectorWeight` (ratio of connector weights)
- `x = toConnectorBalance / (toConnectorBalance - amountToReceive)`

Connector weights are validated to be between 0 and 1 (exclusive) at [2](#0-1)  and enforced at [3](#0-2) 

However, **there is no minimum bound** on connector weights beyond > 0. This allows governance to create connector pairs with extreme weight ratios through `AddPairConnector` [4](#0-3)  where `ResourceWeight` and `NativeWeight` can be set independently.

When users call `Buy` [5](#0-4) , the calculation at [6](#0-5)  invokes the vulnerable function with potentially extreme weight ratios.

### Impact Explanation
**Operational DoS**: When overflow occurs, the C# runtime throws `OverflowException`, reverting the entire transaction. This makes the token converter completely unusable for affected connector pairs.

**Concrete scenario**:
- Connector weights: `fromConnectorWeight = 0.01` (1%), `toConnectorWeight = 0.99` (99%)
- Weight ratio: `y = 99`
- Balances: `fromConnectorBalance = 1,000,000,000,000` (1 trillion tokens)
- Purchase: User wants `amountToReceive = 4,000,000,000` (40% of toConnectorBalance = 10 billion)
- Calculation: `x = 1.667`, `Ln(x) ≈ 0.511`, `y * Ln(x) ≈ 50.6`
- Result: `Exp(50.6) ≈ 4.7 × 10^21`, `bf * Exp(50.6) ≈ 4.7 × 10^33`
- **Overflow**: Exceeds decimal.MaxValue (~7.9 × 10^28)

**Affected parties**: All users attempting to buy/sell through the affected connector pair, effectively locking liquidity.

### Likelihood Explanation
**Medium-High likelihood** due to:

1. **Reachable entry point**: Public `Buy` function accessible to all users
2. **Feasible preconditions**: Requires governance to set unbalanced weights via `AddPairConnector` or `UpdateConnector` [7](#0-6) 
3. **No explicit prevention**: The weight validation only checks `> 0 && < 1`, with no minimum ratio constraints
4. **Realistic scenario**: Governance might intentionally set asymmetric weights for economic reasons (e.g., to control price impact), or unintentionally during configuration
5. **Natural growth**: Even moderate weight imbalances (e.g., 0.05/0.95) can cause overflow as balances grow over time

The Economic contract initialization uses balanced weights [8](#0-7)  (both 0.005), but the system allows governance to create arbitrary pairs with extreme ratios.

### Recommendation

**1. Add minimum weight ratio bounds:**
```csharp
private void AssertValidConnectorWeight(Connector connector)
{
    var weight = AssertedDecimal(connector.Weight);
    Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
    // Add minimum bound, e.g., weight >= 0.01 (1%)
    Assert(weight >= 0.01m, "Connector weight must be at least 0.01 to prevent overflow.");
    connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
}
```

**2. Validate weight ratios during pair creation:**
```csharp
public override Empty AddPairConnector(PairConnectorParam input)
{
    // ... existing code ...
    var resourceWeight = decimal.Parse(input.ResourceWeight);
    var nativeWeight = decimal.Parse(input.NativeWeight);
    var maxRatio = Math.Max(resourceWeight / nativeWeight, nativeWeight / resourceWeight);
    Assert(maxRatio <= 10m, "Weight ratio between connectors must not exceed 10:1.");
    // ... rest of code ...
}
```

**3. Add overflow protection in GetAmountToPayFromReturn:**
```csharp
var exponent = y * Ln(x);
Assert(exponent <= 50m, "Calculation would overflow - purchase amount too large or weight ratio too extreme.");
return (long)(bf * (Exp(exponent) - decimal.One));
```

**4. Add regression tests for extreme weight ratios and large balances**

### Proof of Concept

**Initial State:**
1. Deploy TokenConverter with connector pair via `AddPairConnector`:
   - ResourceWeight = "0.01" (1%)
   - NativeWeight = "0.99" (99%)
   - Both weights pass validation (0 < weight < 1)

2. Initialize connector balances:
   - fromConnectorBalance (native/deposit) = 1,000,000,000,000 (1 trillion)
   - toConnectorBalance (resource) = 10,000,000,000 (10 billion)

**Attack Steps:**
1. User calls `Buy` with:
   - Symbol = resource token symbol
   - Amount = 4,000,000,000 (40% of resource balance)
   
**Calculation Flow:**
1. `GetAmountToPayFromReturn` called with above parameters
2. `x = 10,000,000,000 / 6,000,000,000 = 1.667`
3. `y = 0.99 / 0.01 = 99`
4. `Ln(1.667) ≈ 0.511`
5. `y * Ln(x) = 99 * 0.511 ≈ 50.6`
6. `Exp(50.6) ≈ 4.7 × 10^21`
7. `bf * Exp(50.6) = 10^12 * 4.7 × 10^21 = 4.7 × 10^33`

**Expected Result:** Transaction completes with calculated `amountToPay`

**Actual Result:** `OverflowException` thrown at line 93, transaction reverts

**Success Condition:** Transaction reverts with overflow error, connector becomes unusable for any substantial purchase amounts.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L93-93)
```csharp
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-76)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.Symbol), "input symbol can not be empty'");
        var targetConnector = State.Connectors[input.Symbol];
        Assert(targetConnector != null, "Can not find target connector.");
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
        if (!string.IsNullOrEmpty(input.Weight))
        {
            var weight = AssertedDecimal(input.Weight);
            Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
            targetConnector.Weight = input.Weight.ToString(CultureInfo.InvariantCulture);
        }

        if (targetConnector.IsDepositAccount && input.VirtualBalance > 0)
            targetConnector.VirtualBalance = input.VirtualBalance;
        State.Connectors[input.Symbol] = targetConnector;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-110)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.ResourceConnectorSymbol),
            "resource token symbol should not be empty");
        var nativeConnectorSymbol = NewNtTokenPrefix.Append(input.ResourceConnectorSymbol);
        Assert(State.Connectors[input.ResourceConnectorSymbol] == null,
            "resource token symbol has existed");
        var resourceConnector = new Connector
        {
            Symbol = input.ResourceConnectorSymbol,
            IsPurchaseEnabled = false,
            RelatedSymbol = nativeConnectorSymbol,
            Weight = input.ResourceWeight
        };
        Assert(IsValidSymbol(resourceConnector.Symbol), "Invalid symbol.");
        AssertValidConnectorWeight(resourceConnector);
        var nativeTokenToResourceConnector = new Connector
        {
            Symbol = nativeConnectorSymbol,
            VirtualBalance = input.NativeVirtualBalance,
            IsVirtualBalanceEnabled = true,
            IsPurchaseEnabled = false,
            RelatedSymbol = input.ResourceConnectorSymbol,
            Weight = input.NativeWeight,
            IsDepositAccount = true
        };
        AssertValidConnectorWeight(nativeTokenToResourceConnector);
        State.Connectors[resourceConnector.Symbol] = resourceConnector;
        State.Connectors[nativeTokenToResourceConnector.Symbol] = nativeTokenToResourceConnector;
        return new Empty();
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L354-357)
```csharp
    private static bool IsBetweenZeroAndOne(decimal number)
    {
        return number > decimal.Zero && number < decimal.One;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L418-423)
```csharp
    private void AssertValidConnectorWeight(Connector connector)
    {
        var weight = AssertedDecimal(connector.Weight);
        Assert(IsBetweenZeroAndOne(weight), "Connector Shares has to be a decimal between 0 and 1.");
        connector.Weight = weight.ToString(CultureInfo.InvariantCulture);
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L235-245)
```csharp
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
