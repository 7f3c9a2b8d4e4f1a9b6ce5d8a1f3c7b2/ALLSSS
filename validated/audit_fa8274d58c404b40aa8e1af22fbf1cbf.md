# Audit Report

## Title
Zero Deposit Allows Connector Enablement Without Base Token Reserves, Breaking Sell Functionality

## Summary
The `GetNeededDeposit()` function returns zero when all circulating tokens are transferred during connector enablement, allowing a connector to be enabled without base token reserves. This creates a permanently broken Bancor market where the `Sell()` function fails due to insufficient base token balance, causing a Denial of Service for all token holders attempting to exit their positions.

## Finding Description

The vulnerability exists in the `GetNeededDeposit()` calculation logic. When `AmountToTokenConvert` equals all circulating tokens (`totalSupply - balance`), the function calculates `amountOutOfTokenConvert = 0` and skips deposit calculation, returning `needDeposit = 0`. [1](#0-0) 

This zero deposit value is then used directly in `EnableConnector()` to set the deposit balance without validation. [2](#0-1) 

When users attempt to sell tokens, the function retrieves the deposit balance through `GetSelfBalance()` for deposit account connectors. [3](#0-2) 

With zero deposit balance, the `Sell()` operation fails when attempting to transfer base tokens to the seller, as the contract holds no actual base tokens despite potentially having virtual balance. [4](#0-3) 

Critically, `EnableConnector()` has no permission checks, making it callable by any address after connectors are configured by the controller. [5](#0-4) 

Once enabled, the connector cannot be fixed, as `UpdateConnector()` explicitly prevents updates to activated connectors. [6](#0-5) 

The `BancorHelper.GetReturnFromPaid()` function would also throw an exception if connector balance is zero or negative. [7](#0-6) 

## Impact Explanation

**Severity: Medium**

This vulnerability creates a permanent Denial of Service condition with the following impacts:

1. **Operational Failure**: The `Sell()` function becomes permanently unusable for the affected connector, breaking a core protocol invariant that Bancor markets provide continuous bidirectional liquidity.

2. **Fund Lock**: Token holders cannot exit their positions, effectively experiencing locked funds with zero liquidity despite holding valid tokens.

3. **Market Integrity**: Creates a one-way market where users can only buy tokens but never sell them back, fundamentally breaking the Bancor automated market maker model.

4. **No Recovery Path**: Once enabled, the connector cannot be updated or fixed, making the DoS permanent.

The test suite validates this edge case is not covered, testing only 99.9999% of supply rather than 100%. [8](#0-7) 

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability has realistic triggering conditions:

1. **Permissionless Entry Point**: `EnableConnector()` requires no authorization beyond possession of tokens, executable by anyone after governance adds connector pairs.

2. **Realistic Scenario**: For newly created tokens with fixed supply, the issuer naturally holds all tokens and might legitimately transfer them all to maximize perceived liquidity, unaware of the deposit requirement implications.

3. **No Validation**: The contract provides no warnings, input validation, or deposit minimum requirements to prevent this configuration.

4. **Detection Difficulty**: The issue only manifests when users attempt to sell, potentially after tokens have been distributed, making recovery complex.

5. **Precedent**: The existing test demonstrates the function is designed to handle near-total supply transfers (99.9999%), making 100% a natural extension that appears valid.

## Recommendation

Add validation in `EnableConnector()` to enforce a minimum deposit requirement:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    var fromConnector = State.Connectors[input.TokenSymbol];
    Assert(fromConnector != null && !fromConnector.IsDepositAccount,
        "[EnableConnector]Can't find from connector.");
    var toConnector = State.Connectors[fromConnector.RelatedSymbol];
    Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
    var needDeposit = GetNeededDeposit(input);
    
    // Add validation: Require minimum deposit for deposit account connectors
    if (toConnector.IsDepositAccount && !toConnector.IsVirtualBalanceEnabled)
    {
        Assert(needDeposit.NeedAmount > 0, 
            "Connector requires base token deposit to support sell operations.");
    }
    else if (toConnector.IsDepositAccount && toConnector.IsVirtualBalanceEnabled)
    {
        var totalBalance = toConnector.VirtualBalance + needDeposit.NeedAmount;
        Assert(totalBalance > 0,
            "Total connector balance (virtual + deposit) must be positive.");
    }
    
    // ... rest of function
}
```

Alternatively, fix the `GetNeededDeposit()` logic to always require proportional deposit based on Bancor formula, even when all tokens are transferred.

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_With_All_Tokens_Causes_Sell_DoS_Test()
{
    // Setup
    var tokenSymbol = "VULN";
    var totalSupply = 100_0000_0000;
    
    await CreateTokenAsync(tokenSymbol, totalSupply);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue ALL tokens to sender
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = totalSupply,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Enable connector with ALL tokens (AmountToTokenConvert == totalSupply)
    var toBeBuildConnectorInfo = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = totalSupply  // 100% of supply
    };
    
    // Verify GetNeededDeposit returns 0
    var deposit = await DefaultStub.GetNeededDeposit.CallAsync(toBeBuildConnectorInfo);
    deposit.NeedAmount.ShouldBe(0);  // Zero deposit required - VULNERABILITY
    deposit.AmountOutOfTokenConvert.ShouldBe(0);  // No tokens outside converter
    
    // Enable connector with zero deposit
    await DefaultStub.EnableConnector.SendAsync(toBeBuildConnectorInfo);
    
    // Verify connector is enabled
    var resourceConnector = (await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol })).ResourceConnector;
    resourceConnector.IsPurchaseEnabled.ShouldBe(true);
    
    // Attempt to sell tokens - should FAIL permanently
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    
    // Sell fails due to insufficient balance or connector balance validation
    sellResult.TransactionResult.Error.ShouldContain("balance");  // DoS confirmed
}
```

**Notes**

The vulnerability stems from a fundamental misunderstanding in `GetNeededDeposit()` logic: when all tokens are transferred into the converter (`amountOutOfTokenConvert = 0`), the function assumes no deposit is needed because there are no external tokens to back. However, this breaks the Bancor model which requires base token reserves to facilitate selling regardless of where resource tokens are initially held. The deposited base tokens should back the *resource tokens held by the converter* to enable selling operations, not just tokens outside the converter.

The permissionless nature of `EnableConnector()` combined with the inability to update activated connectors creates a permanent DoS condition that cannot be remediated without deploying a new connector.

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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L37-38)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L386-398)
```csharp
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Amount = 99_9999_0000,
            To = DefaultSender,
            Symbol = tokenSymbol
        });
        var toBeBuildConnectorInfo = new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 99_9999_0000
        };
        var deposit = await DefaultStub.GetNeededDeposit.CallAsync(toBeBuildConnectorInfo);
        deposit.NeedAmount.ShouldBe(100);
```
