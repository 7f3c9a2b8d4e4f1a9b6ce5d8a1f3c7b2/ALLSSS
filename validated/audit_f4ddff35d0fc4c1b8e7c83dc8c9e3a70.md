# Audit Report

## Title
Zero Deposit Allows Connector Enablement Without Base Token Reserves, Breaking Sell Functionality

## Summary
The permissionless `EnableConnector()` function allows anyone to enable a connector with zero base token deposit when `AmountToTokenConvert` equals all circulating tokens. This creates a broken market state where `Sell()` operations fail due to the contract having no actual base tokens to transfer to sellers, despite virtual balance making Bancor calculations succeed.

## Finding Description

The vulnerability chain begins in `GetNeededDeposit()`, which calculates the required base token deposit. When a caller provides `AmountToTokenConvert` equal to all circulating tokens (`totalSupply - contractBalance`), the calculation `amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert` results in zero, causing the function to skip deposit calculation and return `needDeposit = 0`. [1](#0-0) 

This zero deposit value flows directly into `EnableConnector()`, which sets `State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount` without validating it must be positive. The function also lacks any authorization checks, making it callable by anyone after governance adds connector pairs. [2](#0-1) 

When deposit connectors are created via `AddPairConnector()`, they are configured with `IsVirtualBalanceEnabled = true` and a positive `VirtualBalance`. This allows `GetSelfBalance()` to return the virtual balance even when `DepositBalance` is zero. [3](#0-2) [4](#0-3) 

During `Sell()` operations, the contract uses virtual balance for Bancor price calculations but must transfer actual base tokens to sellers. When the contract has zero actual base token balance, the `Transfer` operation fails with "Insufficient balance", causing transaction reversion. [5](#0-4) 

The connector cannot be fixed after enabling because `UpdateConnector()` explicitly prevents updates to activated connectors. [6](#0-5) 

## Impact Explanation

**Severity: Medium**

This vulnerability breaks the core protocol invariant that enabled connectors provide bidirectional liquidity:

1. **Operational DoS**: `Sell()` operations fail immediately after connector enablement, preventing token holders from exiting positions until sufficient `Buy()` operations accumulate base token reserves.

2. **Griefing Vector**: Attackers can front-run legitimate connector enablement to create this broken state, disrupting new token launches.

3. **User Experience Degradation**: Users face unexpected failures and must wait for organic `Buy` activity before selling becomes possible, creating one-way market conditions.

4. **No Direct Recovery**: The only recovery path is organic `Buy` operations - `UpdateConnector()` cannot fix enabled connectors, and no admin function adds deposit balance directly.

While `Buy()` operations can eventually restore functionality (preventing truly permanent DoS), the broken initial state violates user expectations and protocol design.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack has highly realistic triggering conditions:

1. **Permissionless Execution**: `EnableConnector()` has no authorization checks - anyone holding the required tokens can call it after governance adds connector pairs.

2. **Natural Scenario**: Token issuers legitimately hold all tokens of new fixed-supply tokens and may reasonably attempt to enable connectors by transferring their entire holdings, unaware this bypasses deposit requirements.

3. **No Input Validation**: The contract provides no warnings that zero deposit is dangerous, no minimum deposit requirements, and no checks preventing this configuration.

4. **Test Gap**: The existing test suite validates 99.9999% of supply transfers but not 100%, suggesting this edge case was not considered during development. [7](#0-6) [8](#0-7) 

## Recommendation

Add validation to `EnableConnector()` requiring minimum deposit balance:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    var fromConnector = State.Connectors[input.TokenSymbol];
    Assert(fromConnector != null && !fromConnector.IsDepositAccount,
        "[EnableConnector]Can't find from connector.");
    var toConnector = State.Connectors[fromConnector.RelatedSymbol];
    Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
    var needDeposit = GetNeededDeposit(input);
    
    // Add validation
    Assert(needDeposit.NeedAmount > 0, 
        "Cannot enable connector with zero deposit. Must deposit base tokens to support Sell operations.");
    
    State.TokenContract.TransferFrom.Send(
        new TransferFromInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            From = Context.Sender,
            To = Context.Self,
            Amount = needDeposit.NeedAmount
        });
    // ... rest of function
}
```

Alternatively, require authorization for `EnableConnector()` by adding:
```csharp
AssertPerformedByConnectorController();
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_ZeroDeposit_BreaksSell_Test()
{
    // Setup: Create token and add connector pair
    var tokenSymbol = "VULN";
    var totalSupply = 100_0000_0000L;
    await CreateTokenAsync(tokenSymbol, totalSupply);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue ALL tokens to one user
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = totalSupply,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Enable connector with ALL tokens (100% of supply)
    var toBeBuildConnectorInfo = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = totalSupply // 100% of circulating supply
    };
    
    // Verify needDeposit is 0
    var deposit = await DefaultStub.GetNeededDeposit.CallAsync(toBeBuildConnectorInfo);
    deposit.NeedAmount.ShouldBe(0); // Zero deposit calculated!
    
    // Enable connector successfully with zero deposit
    await DefaultStub.EnableConnector.SendAsync(toBeBuildConnectorInfo);
    
    // Verify connector is enabled
    var connector = await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol });
    connector.ResourceConnector.IsPurchaseEnabled.ShouldBe(true);
    
    // Attempt to sell tokens - should fail with insufficient balance
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    
    // Sell fails because contract has no base tokens to transfer
    sellResult.TransactionResult.Error.ShouldContain("Insufficient balance");
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

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L505-517)
```csharp
    private async Task CreateTokenAsync(string symbol, long totalSupply = 100_0000_0000)
    {
        await ExecuteProposalForParliamentTransaction(TokenContractAddress, nameof(TokenContractStub.Create),
            new CreateInput
            {
                Symbol = symbol,
                TokenName = symbol + " name",
                TotalSupply = totalSupply,
                Issuer = DefaultSender,
                Owner = DefaultSender,
                IsBurnable = true,
                LockWhiteList = { TokenContractAddress, TokenConverterContractAddress }
            });
```
