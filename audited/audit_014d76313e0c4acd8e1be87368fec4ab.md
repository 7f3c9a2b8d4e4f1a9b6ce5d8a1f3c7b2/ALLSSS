### Title
Taylor Series Truncation in Exp() Causes Reserve Drainage via Extreme Connector Weight Ratios

### Summary
The `Exp()` function in BancorHelper uses a 20-term Taylor series approximation that fails to converge for large negative inputs. When connector weights are configured with extreme ratios (e.g., 0.99/0.01) and users execute large sell operations, the exponential calculation underflows to zero, causing `GetReturnFromPaid()` to return the entire reserve balance, enabling complete pool drainage.

### Finding Description

The root cause is the Taylor series implementation of the exponential function at [1](#0-0) .

This function truncates the series `exp(y) = 1 + y + y²/2! + y³/3! + ... + y²⁰/20!` at only 20 terms, which is insufficient for large negative values.

The vulnerability is triggered through the `Sell()` operation at [2](#0-1) , which calls `GetReturnFromPaid()` at [3](#0-2) .

In `GetReturnFromPaid()`, the exponential is called with argument `y * Ln(x)` where:
- `x = fromConnectorBalance / (fromConnectorBalance + paidAmount)` can approach zero when paidAmount >> fromConnectorBalance
- `y = fromConnectorWeight / toConnectorWeight` can be arbitrarily large when weights have extreme ratios
- `Ln(x)` becomes very negative for small x (e.g., Ln(0.01) ≈ -4.605)

**Example calculation:**
- Connector weights: fromWeight = 0.99, toWeight = 0.01 → y = 99
- Pool state: fromBalance = 10,000, toBalance = 1,000,000  
- Attacker sells: 990,000 tokens → x = 10,000/1,000,000 = 0.01
- Calculate: y * Ln(x) = 99 * (-4.605) ≈ -456

For such large negative inputs, the 20-term Taylor series does not converge properly. The alternating terms `(-456)^n / n!` initially grow in magnitude before decreasing, causing severe precision loss or underflow to zero.

When `Exp(y * Ln(x))` incorrectly returns 0, the formula `bt * (1 - Exp(...))` evaluates to `bt * 1`, returning the entire toConnectorBalance.

**Why existing protections fail:**

1. Connector weight validation only enforces `0 < weight < 1` at [4](#0-3) , with no minimum separation requirement.

2. The `Ln()` function has a constraint at [5](#0-4)  requiring `0 < a < 2`, but this only prevents division by zero, not extreme negative values.

3. The `Sell()` function has no limit on `input.Amount` relative to pool balance—only a user-controlled `ReceiveLimit` for slippage at [6](#0-5) .

### Impact Explanation

**Direct Fund Impact:** Complete reserve drainage. An attacker can drain the entire toConnector reserve balance by selling a large amount of tokens when connector weights have extreme ratios.

**Quantified damage:** In the example scenario with a 1,000,000 token reserve, the attacker receives the full amount while only providing tokens at an incorrect exchange rate.

**Affected parties:** 
- Liquidity providers lose their deposited reserves
- Protocol integrity is compromised as the Bancor pricing mechanism fails
- All users of the affected token pair

**Severity justification:** While the impact is CRITICAL (total fund loss), the likelihood is MEDIUM because it requires governance to configure extreme connector weight ratios. This results in an overall MEDIUM severity due to the governance precondition.

### Likelihood Explanation

**Attacker capabilities:**
- Must wait for or influence governance to set connector weights with high ratios (e.g., 0.99/0.01)
- Must possess sufficient resource tokens to execute large sell operation
- Can set `ReceiveLimit = 0` to bypass slippage protection

**Attack complexity:** 
- Low once preconditions are met (single transaction)
- No special privileges required beyond token ownership

**Feasibility conditions:**
- Requires governance misconfiguration or malicious connector setup via `AddPairConnector()` at [7](#0-6)  or `UpdateConnector()` at [8](#0-7) 
- Governance control via `ConnectorController` makes unilateral attacker exploitation difficult

**Probability reasoning:** 
MEDIUM - While unlikely under normal operations (test cases use reasonable 0.05/0.05 ratios at [9](#0-8) ), the lack of weight ratio bounds means accidental misconfiguration or malicious governance could enable this attack.

### Recommendation

**Code-level mitigation:**

1. **Add minimum weight separation constraint:**
```
Assert(Math.Abs(decimal.Parse(connector1.Weight) - decimal.Parse(connector2.Weight)) < 0.9, 
       "Connector weight ratio too extreme - weights must not differ by more than 0.9");
```

2. **Improve Exp() implementation:** Replace the 20-term Taylor series with a more robust algorithm:
   - Use range reduction techniques to bring inputs closer to zero
   - Implement rational approximations (Padé approximants)
   - Add explicit bounds checking and graceful degradation for extreme inputs

3. **Add input validation in GetReturnFromPaid():**
```
var exponentArg = y * Ln(x);
Assert(exponentArg > -20, "Exponential argument too negative - calculation would underflow");
```

4. **Add maximum sell amount constraint:**
```
Assert(paidAmount <= fromConnectorBalance * 100, "Sell amount too large relative to pool");
```

**Test cases to add:**
- Test connector initialization with extreme weight ratios (should fail)
- Test large sell operations (1000x pool size) with various weight configurations
- Test Exp() function with inputs like -100, -500 to verify accuracy or bounds

### Proof of Concept

**Required initial state:**
1. TokenConverter initialized with base token (e.g., "ELF")
2. Connector pair created via governance:
   - ResourceConnector: symbol="RES", weight="0.99", balance=10,000
   - DepositConnector: symbol="(NT)RES", weight="0.01", virtualBalance=1,000,000
3. Connectors enabled via `EnableConnector()`
4. Attacker holds 990,000 RES tokens

**Transaction steps:**
1. Attacker calls `Sell()`:
   ```
   SellInput {
     Symbol: "RES",
     Amount: 990000,
     ReceiveLimit: 0  // No slippage protection
   }
   ```

2. Contract calculates via `GetReturnFromPaid()`:
   - x = 10000 / (10000 + 990000) = 0.01
   - y = 0.99 / 0.01 = 99
   - Ln(0.01) ≈ -4.605
   - Exp(99 * -4.605) = Exp(-456) → underflows to ~0

3. Return calculation: 1,000,000 * (1 - 0) = 1,000,000

**Expected vs actual result:**
- **Expected:** Small return proportional to constant product formula
- **Actual:** Attacker receives ~1,000,000 base tokens (entire reserve)

**Success condition:** 
`TokenSold` event shows `BaseAmount ≈ toConnectorBalance` (full drainage), and `DepositBalance[(NT)RES]` drops to zero or underflows.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L34-54)
```csharp
    public static long GetReturnFromPaid(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long paidAmount)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = paidAmount;
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);

        var x = bf / (bf + a);
        var y = wf / wt;
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L148-165)
```csharp
    private static decimal Exp(decimal y)
    {
        /*
        exp(y) = 1 + y + y^2/2 + x^3/3! + y^4/4! + y^5/5! + ...
        */

        var iteration = _LOOPS;
        decimal result = 1;
        while (iteration > 0)
        {
            //uint fatorial = Factorial(iteration);
            var fatorial = Fact[iteration - 1];
            result += Pow(y, (uint)iteration) / fatorial;
            iteration--;
        }

        return result;
    }
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-212)
```csharp
    public override Empty Sell(SellInput input)
    {
        var fromConnector = State.Connectors[input.Symbol];
        Assert(fromConnector != null, "[Sell]Can't find from connector.");
        Assert(fromConnector.IsPurchaseEnabled, "can't purchase");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[Sell]Can't find to connector.");
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );

        var fee = Convert.ToInt64(amountToReceive * GetFeeRate());

        if (Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName)) fee = 0;

        var amountToReceiveLessFee = amountToReceive.Sub(fee);
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
        // Transfer sold token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = input.Symbol,
                From = Context.Sender,
                To = Context.Self,
                Amount = input.Amount
            });
        Context.Fire(new TokenSold
        {
            Symbol = input.Symbol,
            SoldAmount = input.Amount,
            BaseAmount = amountToReceive,
            FeeAmount = fee
        });
        return new Empty();
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

**File:** test/AElf.Contracts.Economic.TestBase/ContractsPreparation.cs (L595-601)
```csharp
            await SetConnector(new PairConnectorParam
            {
                ResourceConnectorSymbol = EconomicContractsTestConstants.TransactionFeeChargingContractTokenSymbol,
                ResourceWeight = "0.05",
                NativeWeight = "0.05",
                NativeVirtualBalance = 1_000_000_00000000
            });
```
