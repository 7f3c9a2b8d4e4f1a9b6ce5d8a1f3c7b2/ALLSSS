# Audit Report

## Title
Domain Violation in GetAmountToPayFromReturn Causes DOS on Large Buy Orders

## Summary
The `GetAmountToPayFromReturn()` function in BancorHelper.cs fails to validate that the requested purchase amount is within the mathematical bounds of the Bancor formula. When a user attempts to buy more than approximately 50% of the available connector balance, the logarithm function throws an exception, causing all such buy transactions to revert with a cryptic error message.

## Finding Description

The vulnerability exists in the `GetAmountToPayFromReturn()` function where the calculation at line 91 can produce values outside the valid domain of the natural logarithm function. [1](#0-0) 

The `Ln()` function has a strict domain requirement that its input must satisfy `0 < a < 2`, enforced by an exception at lines 131-132. [2](#0-1) 

**Mathematical Analysis:**
- For `Ln(x)` to work: `0 < x < 2`
- Given `x = bt / (bt - a)` where `bt = toConnectorBalance` and `a = amountToReceive`
- For `x >= 2`: `bt / (bt - a) >= 2` → `bt >= 2(bt - a)` → `a >= bt/2`
- Therefore, when `amountToReceive >= toConnectorBalance/2`, the function throws

**Missing Protection:**
The function only validates that balances and amounts are positive, but does not check the upper bound. [3](#0-2) 

Note that the special case when connector weights are equal has a try-catch block with a clearer error message, but the general case at lines 91-93 lacks this protection. [4](#0-3) 

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
- Entry point is the public `Buy()` method accessible to all users [6](#0-5) 
- Only requires knowledge of current connector balance (publicly queryable via `GetPairConnector`)
- No economic cost to attempt (transaction just reverts)

**Probability:**
- HIGH - legitimate large purchases will naturally trigger this condition
- Becomes more likely as connector balances decrease through normal trading
- No detection or operational constraints prevent this

## Recommendation

Add validation in `GetAmountToPayFromReturn()` to check that `amountToReceive` is within safe bounds before performing the calculation:

```csharp
// Add after line 73 in BancorHelper.cs
if (amountToReceive >= toConnectorBalance)
    throw new InvalidValueException("Amount to receive must be less than connector balance.");
    
// For safety, also check the domain constraint will be satisfied
// x = bt / (bt - a) must be < 2, so a must be < bt/2
if (amountToReceive >= toConnectorBalance / 2)
    throw new InvalidValueException("Amount to receive exceeds maximum safe purchase size (must be less than half of connector balance).");
```

Alternatively, wrap the calculation in a try-catch block with a more user-friendly error message:

```csharp
try
{
    var x = bt / (bt - a);
    var y = wt / wf;
    return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
}
catch (InvalidValueException)
{
    throw new InvalidValueException("Purchase amount exceeds maximum safe transaction size. Please reduce the amount or split into multiple transactions.");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Buy_LargeAmount_ShouldFail_WithDomainViolation()
{
    // Setup: Initialize token converter with connectors
    await InitializeTokenConverterContract();
    
    // Get the current connector balance
    var pairConnector = await DefaultStub.GetPairConnector.CallAsync(new TokenSymbol
    {
        Symbol = WriteConnector.Symbol
    });
    var toConnectorBalance = pairConnector.ResourceConnector.VirtualBalance;
    
    // Attempt to buy more than 50% of connector balance
    var buyAmount = toConnectorBalance / 2 + 1;
    
    // This should throw with "must be 0 < a < 2" error
    var result = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = WriteConnector.Symbol,
        Amount = buyAmount,
        PayLimit = 0
    });
    
    // Verify the transaction failed with the domain violation error
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("must be 0 < a < 2");
}
```

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-112)
```csharp
    public override Empty Buy(BuyInput input)
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```
