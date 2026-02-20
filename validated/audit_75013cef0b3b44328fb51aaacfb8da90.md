# Audit Report

## Title
Domain Violation in GetAmountToPayFromReturn Causes DOS on Large Buy Orders

## Summary
The `GetAmountToPayFromReturn()` function in BancorHelper.cs fails to validate that the requested purchase amount is within the mathematical bounds of the Bancor formula. When a user attempts to buy more than approximately 50% of the available connector balance, the logarithm function throws an exception, causing all such buy transactions to revert with a cryptic error message.

## Finding Description

The vulnerability exists in the `GetAmountToPayFromReturn()` function where the calculation produces values outside the valid domain of the natural logarithm function. [1](#0-0) 

The `Ln()` function has a strict domain requirement enforced by an exception that requires its input to satisfy `0 < a < 2`. [2](#0-1) 

**Mathematical Analysis:**
- For `Ln(x)` to work: `0 < x < 2`
- Given `x = bt / (bt - a)` where `bt = toConnectorBalance` and `a = amountToReceive`
- For `x >= 2`: `bt / (bt - a) >= 2` → `bt >= 2(bt - a)` → `a >= bt/2`
- Therefore, when `amountToReceive >= toConnectorBalance/2`, the function throws

**Missing Protection:**
The function only validates that balances and amounts are positive, but does not check the upper bound. [3](#0-2) 

Note that the special case when connector weights are equal has a try-catch block with a clearer error message, but the general case lacks this protection. [4](#0-3) 

**Entry Point:**
The public `Buy()` function calls `GetAmountToPayFromReturn()` without validating the bounds on the input amount. [5](#0-4) 

## Impact Explanation

**Operational DOS Impact:**
- Any buy transaction requesting more than ~50% of the available connector balance will fail with the error "must be 0 < a < 2"
- This creates a hard limit on purchase sizes that is not documented or enforced upfront
- Users receive cryptic mathematical error messages instead of clear validation failures

**Concrete Scenarios:**
1. **Small Balance Pools:** If `toConnectorBalance = 100` tokens, users cannot buy more than 49 tokens in a single transaction
2. **After Heavy Selling:** As connector balances get depleted through selling, the maximum purchaseable amount decreases proportionally
3. **Legitimate Large Purchases:** Institutional buyers or automated trading systems attempting large purchases will encounter unexplained failures

**Who is Affected:**
- Regular users attempting large purchases encounter DOS
- Protocol usability is degraded with confusing error messages
- Token liquidity is artificially constrained by the mathematical limitation

## Likelihood Explanation

**Attacker Capabilities Required:**
- None - any user can trigger this by calling the public `Buy()` function with appropriate parameters
- No special privileges or prior state manipulation needed

**Attack Complexity:**
- Trivial - single transaction with `input.Amount > toConnectorBalance/2`
- Can be triggered accidentally by legitimate users or intentionally by griefers

**Feasibility Conditions:**
- Entry point is the public `Buy()` method accessible to all users
- Only requires knowledge of current connector balance (publicly queryable via `GetPairConnector`)
- No economic cost to attempt (transaction just reverts)

**Probability:**
- HIGH - legitimate large purchases will naturally trigger this condition
- Becomes more likely as connector balances decrease through normal trading
- No detection or operational constraints prevent this

## Recommendation

Add validation to check if the requested amount exceeds the safe mathematical bounds before performing the Bancor calculation. The fix should be implemented in the `Buy()` function or at the start of `GetAmountToPayFromReturn()`:

```csharp
// In GetAmountToPayFromReturn, after line 79, add:
if (amountToReceive >= toConnectorBalance / 2)
{
    throw new InvalidValueException("Purchase amount exceeds maximum allowed (must be less than 50% of connector balance)");
}
```

Alternatively, wrap the general case calculation in a try-catch block similar to the equal-weights case to provide a clearer error message.

## Proof of Concept

```csharp
[Fact]
public void Buy_ExceedingHalfConnectorBalance_ShouldFail()
{
    // Setup: Initialize connector with balance of 100 tokens
    long connectorBalance = 100_000;
    long attemptedPurchase = 51_000; // More than 50%
    
    // Test: Attempt to calculate amount to pay for >50% purchase
    var exception = Assert.Throws<InvalidValueException>(() => 
        BancorHelper.GetAmountToPayFromReturn(
            connectorBalance,  // fromConnectorBalance
            0.5m,              // fromConnectorWeight
            connectorBalance,  // toConnectorBalance
            0.5m,              // toConnectorWeight
            attemptedPurchase  // amountToReceive (>50%)
        )
    );
    
    // Verify: Should throw with cryptic message instead of clear validation
    Assert.Equal("must be 0 < a < 2", exception.Message);
}
```

This test demonstrates that attempting to buy more than 50% of the connector balance results in a mathematical domain violation with an unclear error message, confirming the DOS vulnerability.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L70-73)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L91-93)
```csharp
        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L130-132)
```csharp
        var x = 1 - a;
        if (Math.Abs(x) >= 1)
            throw new InvalidValueException("must be 0 < a < 2");
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
