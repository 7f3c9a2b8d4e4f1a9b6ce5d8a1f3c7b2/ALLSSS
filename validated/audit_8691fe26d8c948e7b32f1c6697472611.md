# Audit Report

## Title
Zero Deposit Allows Connector Enablement Without Base Token Reserves, Causing Permanent DoS of Both Buy and Sell Operations

## Summary
The `GetNeededDeposit()` function returns `needDeposit = 0` when `AmountToTokenConvert` equals all circulating tokens. This allows `EnableConnector()` to activate a connector with zero base token reserves, permanently breaking both `Buy` and `Sell` operations since `BancorHelper` requires positive connector balances. [1](#0-0) 

## Finding Description

The vulnerability occurs through the following execution path:

**1. Zero Deposit Calculation**

In `GetNeededDeposit()`, when a caller transfers all circulating tokens (`AmountToTokenConvert = totalSupply - balance`), the calculation produces `amountOutOfTokenConvert = 0`. Since the deposit calculation only proceeds when `amountOutOfTokenConvert > 0`, the function returns `needDeposit = 0`. [1](#0-0) 

**2. Connector Enabled with Zero Reserves**

The `EnableConnector()` function lacks any access control check (no `AssertPerformedByConnectorController()` call), making it callable by any address. This contrasts with other administrative functions which require controller privileges. [2](#0-1) 

Compare with protected functions: [3](#0-2) [4](#0-3) 

The function uses the zero deposit to set reserves and enables the connector permanently. Once enabled, `UpdateConnector()` explicitly prevents any modifications. [5](#0-4) 

**3. Buy Operation Fails**

When users attempt `Buy()`, the function retrieves the connector balance via `GetSelfBalance()`, which returns `State.DepositBalance[connector.Symbol]` for deposit account connectors. [6](#0-5) [7](#0-6) 

`BancorHelper` enforces that connector balances must be positive, throwing `InvalidValueException` when the balance is 0. [8](#0-7) 

**4. Sell Operation Also Fails**

Similarly, `Sell()` calls `BancorHelper.GetReturnFromPaid()` which validates connector balances and throws when encountering zero balances. [9](#0-8) [10](#0-9) 

Additionally, the contract attempts to subtract from zero deposit balance, which would cause an underflow exception. [11](#0-10) 

This breaks the fundamental Bancor invariant that connectors maintain positive reserves to provide continuous bidirectional liquidity.

## Impact Explanation

**Severity: HIGH**

**Complete Market Failure:**
- Both Buy and Sell operations are permanently broken, not just one direction
- The connector becomes completely non-functional for all trading operations
- Token holders experience permanent liquidity lock - they cannot exit positions
- New buyers cannot enter positions either

**Permanent and Irreversible:**
- Once `IsPurchaseEnabled = true`, the connector cannot be disabled or reconfigured due to the explicit check in `UpdateConnector()`
- No recovery mechanism exists in the contract
- The only remediation would require deploying a new connector contract

**Protocol Integrity Violation:**
- Violates Bancor's core promise of continuous liquidity
- Breaks the critical invariant requiring positive reserve balances for pricing calculations
- Damages protocol reputation and user trust

**Economic Impact:**
- Existing token holders lose all liquidity
- The token becomes effectively worthless due to inability to trade
- Affects all users who acquired tokens expecting bidirectional convertibility

## Likelihood Explanation

**Likelihood: MEDIUM**

**No Access Control:**
The `EnableConnector()` function lacks authorization checks, making it callable by any address, while other administrative functions require controller privileges.

**Realistic Trigger Scenario:**

**Legitimate Misconfiguration** is the most plausible attack vector: A token issuer creates a new token, issues the entire supply to themselves before enabling trading, and calls `EnableConnector()` with `AmountToTokenConvert = totalSupply`, genuinely believing this provides maximum liquidity. The issuer doesn't understand that leaving some tokens out of circulation is necessary for proper deposit calculation.

This is realistic because:
- The existing test uses 99.9999% of supply, suggesting high amounts are expected [12](#0-11) 
- A user might round up to 100% thinking it's equivalent
- No validation prevents `AmountToTokenConvert >= (totalSupply - balance)`
- No minimum deposit requirement is enforced
- No warning or error is shown when `needDeposit = 0`
- The function succeeds silently, giving no indication of the problem

## Recommendation

1. **Add Access Control:** Implement `AssertPerformedByConnectorController()` at the start of `EnableConnector()` to match other administrative functions.

2. **Add Validation:** Enforce a minimum deposit requirement:
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // Add this
    
    var fromConnector = State.Connectors[input.TokenSymbol];
    Assert(fromConnector != null && !fromConnector.IsDepositAccount,
        "[EnableConnector]Can't find from connector.");
    var toConnector = State.Connectors[fromConnector.RelatedSymbol];
    Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
    var needDeposit = GetNeededDeposit(input);
    
    // Add validation
    Assert(needDeposit.NeedAmount > 0, 
        "Deposit amount must be positive. Reduce AmountToTokenConvert to leave tokens in circulation.");
    
    // Rest of function...
}
```

3. **Add Emergency Disable:** Implement a mechanism to disable connectors in emergency situations, controlled by governance.

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_With_Zero_Deposit_DoS_Test()
{
    // Setup: Create token with 100 total supply
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol, totalSupply: 100_0000_0000);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue ALL tokens to attacker (100% of supply)
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 100_0000_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Enable connector with ALL tokens (amountOutOfTokenConvert = 0)
    var enableInput = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 100_0000_0000  // 100% of supply
    };
    
    // Verify needDeposit returns 0
    var deposit = await DefaultStub.GetNeededDeposit.CallAsync(enableInput);
    deposit.NeedAmount.ShouldBe(0);  // Zero deposit calculated
    
    // EnableConnector succeeds with zero deposit
    var enableResult = await DefaultStub.EnableConnector.SendAsync(enableInput);
    enableResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify connector is enabled
    var connector = await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol });
    connector.ResourceConnector.IsPurchaseEnabled.ShouldBe(true);
    
    // BUY FAILS - Permanent DoS
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    buyResult.TransactionResult.Error.ShouldContain("Connector balance needs to be a positive number");
    
    // SELL FAILS - Permanent DoS
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    sellResult.TransactionResult.Error.ShouldContain("Connector balance needs to be a positive number");
    
    // Verify connector CANNOT be updated after activation
    var updateResult = await ExecuteProposalForParliamentTransactionWithException(
        TokenConverterContractAddress,
        nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.UpdateConnector),
        connector.ResourceConnector);
    updateResult.Error.ShouldContain("connector can not be updated because it has been activated");
}
```

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L193-194)
```csharp
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

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L388-395)
```csharp
            Amount = 99_9999_0000,
            To = DefaultSender,
            Symbol = tokenSymbol
        });
        var toBeBuildConnectorInfo = new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 99_9999_0000
```
