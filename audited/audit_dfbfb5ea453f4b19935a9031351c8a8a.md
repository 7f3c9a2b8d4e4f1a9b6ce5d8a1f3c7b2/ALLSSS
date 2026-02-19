# Audit Report

## Title
Numerical Instability in Ln Function Causes Incorrect Bancor Pricing for Large Trades

## Summary
The `Ln` function in `BancorHelper.cs` uses a Taylor series approximation with only 20 iterations, causing significant approximation errors (5-6%) when inputs approach the boundary value of 2. This leads to underpriced token conversions when users purchase amounts approaching 50% of the connector balance, resulting in direct protocol fund loss.

## Finding Description

The `Ln` function implements the natural logarithm using a truncated Taylor series with a fixed iteration count of 20. [1](#0-0)  The function computes `ln(a) = -x - x^2/2 - x^3/3 - ...` where `x = 1 - a`. [2](#0-1) 

The boundary check only rejects inputs where `Math.Abs(x) >= 1`, allowing values arbitrarily close to 2. [3](#0-2) 

In `GetAmountToPayFromReturn`, the function calculates `x = bt / (bt - a)` where `bt` is the connector balance and `a` is the amount to receive, then calls `Ln(x)`. [4](#0-3)  When a user requests an amount approaching `bt/2`, the input to `Ln` approaches 2, causing the internal variable to approach -1.

For an alternating Taylor series truncated at 20 terms with `x = -0.99` (input ≈ 1.99):
- True value: ln(1.99) ≈ 0.688
- Approximation error: ≈ |x|^21/21 ≈ 0.039
- Relative error: ~5.6%

The `Buy` function uses `GetAmountToPayFromReturn` to determine payment amount. [5](#0-4)  When `Ln` underestimates, the calculated `amountToPay` is lower than the Bancor formula requires. The user then transfers this underestimated amount while receiving the full requested tokens. [6](#0-5) 

The `PayLimit` check is user-controlled and does not prevent the exploit. [7](#0-6) 

## Impact Explanation

**Direct Protocol Fund Loss**: When a user buys tokens with `amountToReceive` approaching `bt/2`, the 5-6% approximation error directly translates to the protocol receiving 5-6% less payment than required by the Bancor pricing invariant.

**Quantified Example**: 
- Connector balance: 10,000,000 tokens
- User requests: 4,999,000 tokens (just under half)
- Input to Ln: 10M/(10M-4.999M) ≈ 1.9996
- Approximation error: ~6%
- If correct cost is 5,000,000 base tokens, user pays only ~4,700,000
- **Protocol loss: ~300,000 base tokens per exploit**

**Affected Parties**: The TokenConverter contract and its liquidity providers suffer direct financial loss. The pricing invariant is violated, causing reserve imbalances that affect all subsequent trades.

**Severity**: Medium - concrete fund loss on economically rational attacks, limited by capital requirements but feasible for large traders.

## Likelihood Explanation

**Attacker Capabilities**: Requires capital equivalent to ~40-50% of the connector balance. While this represents significant capital (potentially millions in production), it is within reach of:
- Large institutional traders
- Whale wallets in DeFi ecosystems  
- Coordinated attack groups
- Potentially leveraged positions

**Attack Complexity**: Low - simply call the `Buy` function with an amount approaching `bt/2`. No special privileges or technical sophistication required.

**Economic Rationality**: For a $5M trade with 6% advantage, the attacker gains $300K. In DeFi contexts where MEV opportunities of 1-2% are actively exploited, a 5-6% advantage is highly rational despite capital requirements.

**Detection**: The trade would be visible due to size, but by the time it's detected, the underpayment is irreversible.

## Recommendation

Increase the iteration count (`_LOOPS`) to at least 50-100 to reduce approximation error to negligible levels (< 0.1%). Alternatively:

1. **Implement range reduction**: Transform inputs near boundaries to safer ranges before applying Taylor series
2. **Add maximum trade size limits**: Prevent trades exceeding a safe percentage (e.g., 25%) of connector balance
3. **Use more robust numerical methods**: Consider Padé approximants or pre-computed lookup tables with interpolation
4. **Add explicit validation**: Reject trades where the Ln input would exceed 1.5 to avoid the high-error region

## Proof of Concept

While I cannot provide executable test code within this validation context, the vulnerability can be demonstrated by:

1. Setting up a connector with 10,000,000 token balance
2. Calling `Buy` with `amount = 4,999,000` (approaching 50% of balance)
3. Observing that `GetAmountToPayFromReturn` calculates Ln(1.9996)
4. Comparing the calculated `amountToPay` against the mathematically correct Bancor formula result
5. Confirming a ~5-6% discrepancy favoring the buyer

The mathematical error propagates deterministically through the call chain: `Ln` underestimation → `Exp` underestimation → `amountToPay` underestimation → protocol fund loss.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L98-98)
```csharp
    private const int _LOOPS = 20; // Max = 20
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L127-127)
```csharp
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L133-149)
```csharp
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
```
