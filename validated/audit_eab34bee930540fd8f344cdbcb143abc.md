# Audit Report

## Title
Token Balance Manipulation Leads to Incorrect Deposit Calculation in EnableConnector

## Summary
The `EnableConnector()` function calculates required base token deposits by querying the TokenConverter's current resource token balance. This balance can be manipulated through frontrunning, causing under-collateralization of the Bancor reserve pool and breaking critical pricing invariants. The vulnerability exists because EnableConnector has no access control and GetNeededDeposit blindly trusts the current on-chain balance without validation.

## Finding Description

The vulnerability exists in the interaction between `GetNeededDeposit()` and `EnableConnector()` functions in the TokenConverter contract.

**Vulnerable Logic Flow:**

The `GetNeededDeposit()` function queries the converter's current resource token balance via external call [1](#0-0) , then calculates the amount of tokens "out of converter" by subtracting this balance from total supply [2](#0-1) . This value is used in the Bancor formula to determine required deposit [3](#0-2) .

The `EnableConnector()` function has no access control [4](#0-3) , calls GetNeededDeposit [5](#0-4) , and directly sets the DepositBalance to the returned value [6](#0-5) .

**Attack Sequence:**

1. Attacker observes pending `EnableConnector()` transaction in mempool
2. Attacker frontruns by transferring X resource tokens to converter address
3. When `EnableConnector()` executes, `GetNeededDeposit()` sees inflated balance
4. Calculation: `amountOutOfTokenConvert = totalSupply - (0 + X) - AmountToTokenConvert` is artificially reduced by X
5. Bancor formula returns lower deposit requirement
6. DepositBalance is set to insufficient value
7. Converter now holds more resource tokens than properly backed by deposit

**Why Protections Fail:**

The vulnerability persists because:
- No access control prevents anyone from calling EnableConnector (unlike other admin functions that use `AssertPerformedByConnectorController()` [7](#0-6) )
- No validation checks that converter balance should be zero before enablement
- GetNeededDeposit calculation blindly trusts current on-chain state
- Token transfers to converter address are permissionless

**Invariant Break:**

Subsequent Buy/Sell operations use `GetSelfBalance()` which returns actual token balance for resource tokens [8](#0-7)  but tracked DepositBalance for deposit accounts [9](#0-8) . This breaks the Bancor reserve ratio invariant because:
- More resource tokens exist than DepositBalance accounts for
- Bancor formula in Buy [10](#0-9)  and Sell [11](#0-10)  operations uses mismatched balances
- Pricing becomes incorrect, sellers receive less base tokens than they should

## Impact Explanation

**Severity: HIGH**

The vulnerability causes under-collateralization of the Bancor reserve pool with concrete financial impact:

1. **Mispricing**: The Bancor formula relies on accurate balance tracking. When DepositBalance is artificially low while resource token balance is high, the reserve ratio is broken. This causes systematic mispricing in all subsequent Buy/Sell operations.

2. **Economic Loss**: Future sellers of the resource token receive less base token than they should because the DepositBalance pool is undersized. This creates direct financial harm to users.

3. **Protocol Integrity**: The core invariant of the Bancor Converter—that deposits properly back circulating tokens according to weight ratios—is violated. This undermines trust in the entire token conversion mechanism.

4. **Reserve Depletion Risk**: Because more tokens are "in circulation" than properly backed, the reserve pool can be depleted before all tokens can be sold back [12](#0-11) , potentially leaving some token holders unable to exit their positions.

**Affected Parties:**
- Token sellers who receive unfair prices
- Protocol reputation and trustworthiness
- The legitimate EnableConnector caller who unknowingly enables a misconfigured connector

## Likelihood Explanation

**Probability: MEDIUM**

**Attacker Requirements:**
- Ownership of resource tokens (obtainable via standard token acquisition)
- Ability to observe mempool (standard blockchain monitoring)
- Ability to submit higher-priority transactions (standard frontrunning techniques)
- No special permissions needed

**Execution Complexity: LOW**
- Single transaction: Transfer resource tokens to converter address
- No sophisticated exploit logic required
- Standard frontrunning attack pattern
- Works on any connector being enabled for first time

**Realistic Scenarios:**
1. **Intentional Attack**: Malicious actor frontruns to grief protocol or manipulate pricing
2. **Accidental Occurrence**: Users mistakenly transfer tokens to converter before enablement
3. **Coordinated Gaming**: Related parties manipulate deposit requirements

**Mitigating Factors:**
- Attack window exists only during connector enablement (one-time event per connector)
- Attacker must sacrifice tokens (though this damages protocol more than attacker)
- Requires mempool visibility

**Overall Assessment:**
While economic incentive for direct profit is limited, the technical barrier is extremely low and the attack can easily occur through accidental transfers or intentional griefing. The permissionless nature of both EnableConnector and token transfers makes this vulnerability readily exploitable.

## Recommendation

Add access control to `EnableConnector()` to restrict it to the connector controller, similar to other administrative functions:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // Add this authorization check
    var fromConnector = State.Connectors[input.TokenSymbol];
    // ... rest of function
}
```

Additionally, add a validation check that the converter's token balance should be zero (or expected value) before enabling:

```csharp
var balance = State.TokenContract.GetBalance.Call(
    new GetBalanceInput
    {
        Owner = Context.Self,
        Symbol = input.TokenSymbol
    }).Balance;
Assert(balance == 0, "Converter must have zero balance before enabling connector");
```

## Proof of Concept

A test demonstrating the vulnerability would follow this pattern:

1. Create and add a pair connector
2. Issue resource tokens to an attacker account
3. Attacker transfers tokens directly to converter address before EnableConnector is called
4. Legitimate user calls EnableConnector
5. Verify that DepositBalance is lower than it should be
6. Demonstrate that subsequent Sell operations receive insufficient base tokens

The test would show that the DepositBalance calculated is `needDeposit(totalSupply - attackerTokens - AmountToTokenConvert)` instead of the correct `needDeposit(totalSupply - AmountToTokenConvert)`, resulting in under-collateralization by the amount corresponding to the attacker's frontrun tokens.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L67-72)
```csharp
        var balance = State.TokenContract.GetBalance.Call(
            new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = input.TokenSymbol
            }).Balance;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-73)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L81-83)
```csharp
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L60-60)
```csharp
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-171)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L193-194)
```csharp
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-270)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L276-276)
```csharp
        var needDeposit = GetNeededDeposit(input);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L297-297)
```csharp
        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L377-378)
```csharp
        if (connector.IsDepositAccount)
            realBalance = State.DepositBalance[connector.Symbol];
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L380-385)
```csharp
            realBalance = State.TokenContract.GetBalance.Call(
                new GetBalanceInput
                {
                    Owner = Context.Self,
                    Symbol = connector.Symbol
                }).Balance;
```
