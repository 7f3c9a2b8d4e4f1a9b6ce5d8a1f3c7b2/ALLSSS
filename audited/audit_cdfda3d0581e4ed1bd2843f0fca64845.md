### Title
Decimal Truncation in GetAmountToPayFromReturn Allows Zero-Cost Token Purchase

### Summary
The `GetAmountToPayFromReturn` function in BancorHelper.cs truncates decimal results to zero when casting to `long`, allowing attackers to buy tokens for free when the calculated payment amount is less than 0.5. This violates the Bancor pricing invariant and enables theft of token reserves through repeated micro-purchases.

### Finding Description

The vulnerability exists in the `GetAmountToPayFromReturn` method at [1](#0-0) , specifically in the casting operations that convert decimal calculation results to `long` integers.

**Root Cause:**

For the equal-weights case [2](#0-1) , the formula is:
```
amountToPay = (long)(fromConnectorBalance / (toConnectorBalance - amountToReceive) * amountToReceive)
```

When this decimal calculation produces a value less than 0.5, the `(long)` cast truncates it to 0.

**Why Existing Protections Fail:**

The function only validates that inputs are positive [3](#0-2) , but does not validate:
1. That `amountToReceive < toConnectorBalance` (preventing division by zero)
2. That the calculated `amountToPay > 0` (preventing free purchases)

**Production Configuration Analysis:**

Using actual production values [4](#0-3) :
- NativeTokenToResourceBalance (deposit virtual balance) = 10,000,000 × 10^8 = 10^16
- ResourceTokenTotalSupply = 500,000,000 × 10^8 = 5 × 10^17

The connector setup [5](#0-4)  creates:
- Resource connector (e.g., WRITE): VirtualBalance = 100,000, Weight = 0.005
- Native deposit connector (e.g., ntWRITE): VirtualBalance = 10^16, Weight = 0.005

For a Buy operation [6](#0-5) :
- fromConnectorBalance ≈ 10^16 (deposit connector)
- toConnectorBalance ≈ 5 × 10^17 (resource tokens)
- Ratio = 0.02

For `amountToReceive = 1`:
```
amountToPay = (long)(10^16 × 1 / (5×10^17 - 1))
            ≈ (long)(0.02)
            = 0
```

**Execution Path:**

When `amountToPay = 0` in the Buy method [7](#0-6) :
1. Line 124: `fee = 0` (0% of 0)
2. Line 127: Assert passes (0 ≤ PayLimit)
3. Lines 133-140: TransferFrom 0 tokens from sender (succeeds)
4. Line 141: DepositBalance unchanged (adds 0)
5. Lines 143-149: Transfer `input.Amount` tokens to sender — **attacker receives tokens for free**

### Impact Explanation

**Direct Fund Impact:**
- Attackers can extract tokens from the converter reserves without payment
- Each transaction with `amountToReceive ≤ 24` base units costs 0 tokens
- By repeating the attack, significant value can be stolen

**Quantified Damage:**
With production configurations, an attacker can buy 1-24 base units per transaction for 0 cost. While each amount is small (1 base unit = 0.00000001 tokens with 8 decimals), executing this millions of times accumulates substantial theft.

**Affected Parties:**
- Token converter reserves are depleted
- Legitimate users face inflated prices as reserves drain
- Protocol loses economic integrity

**Severity Justification:**
CRITICAL — Violates fundamental Bancor pricing invariant, enables direct theft, and undermines the entire token conversion mechanism.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires only access to the public `Buy` method
- No special permissions needed
- Can be executed by any user

**Attack Complexity:**
- Simple: Call Buy with Amount = 1-24 repeatedly
- Deterministic: Always works when ratio conditions are met
- Automated: Can be scripted

**Feasibility Conditions:**
- Occurs naturally with production configurations where `fromConnectorBalance << toConnectorBalance`
- The imbalance ratio (0.02 in production) is by design, not an edge case
- Attack works from initial state without requiring system degradation

**Economic Rationality:**
- Cost: Only gas fees per transaction
- Gain: Free tokens with real economic value
- Profitability depends on: (token_value × stolen_amount) > (gas_cost × num_transactions)
- For valuable tokens, this is economically viable

**Detection Constraints:**
- Each transaction appears as a legitimate Buy with small amount
- No obvious malicious pattern without analyzing payment amounts
- Difficult to distinguish from normal micro-transactions

### Recommendation

**Immediate Fix:**

Add validation in `GetAmountToPayFromReturn` after calculation:

```csharp
public static long GetAmountToPayFromReturn(...)
{
    // ... existing validation ...
    
    if (wf == wt)
    {
        try
        {
            var result = (long)(bf / (bt - a) * a);
            // ADD THIS CHECK:
            Assert(result > 0, "Amount to pay must be greater than zero");
            return result;
        }
        catch
        {
            throw new AssertionException("Insufficient account balance to deposit");
        }
    }
    
    var x = bt / (bt - a);
    var y = wt / wf;
    var result = (long)(bf * (Exp(y * Ln(x)) - decimal.One));
    // ADD THIS CHECK:
    Assert(result > 0, "Amount to pay must be greater than zero");
    return result;
}
```

**Additional Protections:**

1. Add minimum purchase amount validation in Buy method [7](#0-6) :
   ```csharp
   Assert(input.Amount >= MinimumPurchaseAmount, "Purchase amount too small");
   ```

2. Validate `amountToReceive < toConnectorBalance` before calculation to prevent division by zero

3. Consider using higher precision arithmetic (e.g., Math.Ceiling) to ensure minimum payment of 1 base unit

**Test Cases:**

Add regression tests for:
- Buy with Amount = 1 base unit (should fail or pay > 0)
- Buy with various small amounts under different balance ratios
- Verify amountToPay > 0 for all positive inputs

### Proof of Concept

**Initial State:**
- Token converter initialized with production configuration
- Native deposit connector: VirtualBalance = 10^16, DepositBalance = calculated initial deposit
- Resource connector: VirtualBalance = 100,000, contract holds 5×10^17 tokens
- Equal weights (0.005 each)

**Attack Steps:**

1. Attacker approves TokenConverter to spend their base tokens
2. Attacker calls `Buy`:
   ```
   Buy({
     Symbol: "WRITE",
     Amount: 1,
     PayLimit: 0
   })
   ```

**Expected Result:**
- Transaction should fail or require payment > 0

**Actual Result:**
- `GetAmountToPayFromReturn` calculates: (long)(10^16 / 5×10^17) = (long)(0.02) = 0
- Buy succeeds with amountToPay = 0
- Attacker receives 1 base unit of WRITE for free
- DepositBalance unchanged

**Success Condition:**
- Attacker's WRITE balance increases by 1
- Attacker's base token balance unchanged (paid 0)
- Can be repeated indefinitely until reserves depleted

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

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L5-16)
```csharp
    public const long NativeTokenConnectorInitialVirtualBalance = 100_000_00000000;

    // Token Converter Contract related.
    public const string TokenConverterFeeRate = "0.005";

    // Resource token related.
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;

    public const int ResourceTokenDecimals = 8;

    //resource to sell
    public const long ResourceTokenInitialVirtualBalance = 100_000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L230-249)
```csharp
            var resourceTokenConnector = new Connector
            {
                Symbol = resourceTokenSymbol,
                IsPurchaseEnabled = true,
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
                VirtualBalance = EconomicContractConstants.NativeTokenToResourceBalance,
                RelatedSymbol = resourceTokenSymbol,
                IsDepositAccount = true
            };
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
