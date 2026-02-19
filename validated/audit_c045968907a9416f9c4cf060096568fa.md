# Audit Report

## Title
Missing Input Validation in GetNeededDeposit Allows Negative AmountToTokenConvert Leading to Connector State Corruption and Denial of Service

## Summary
The `GetNeededDeposit` view function lacks validation for negative `AmountToTokenConvert` values, and `EnableConnector` has no access control restrictions. When a negative value is passed to `EnableConnector`, an arithmetic miscalculation inflates the deposit requirement while preventing resource token transfer, resulting in a permanently corrupted connector state that renders both buy and sell operations inoperative.

## Finding Description

The vulnerability exists in the interaction between two functions: [1](#0-0)  and [2](#0-1) 

The `AmountToTokenConvert` field is defined as `int64` in the protobuf specification [3](#0-2) , which allows negative values without type-level constraints.

In `GetNeededDeposit`, the calculation at line 73 does not validate that `AmountToTokenConvert` is non-negative: [4](#0-3) 

When `AmountToTokenConvert` is negative (e.g., -100), the subtraction operation becomes addition: `TotalSupply - balance - (-100) = TotalSupply - balance + 100`. This artificially inflates `amountOutOfTokenConvert`, causing it to pass the conditional check and trigger an inflated deposit calculation.

The `EnableConnector` function then consumes this incorrect value: [5](#0-4) 

The function transfers the inflated base token deposit: [6](#0-5) 

However, the resource token transfer is skipped due to the negative value check: [7](#0-6) 

Despite this mismatch, the function proceeds to set the `DepositBalance` to the inflated amount: [8](#0-7) 

And enables both connectors: [9](#0-8) 

Critically, `EnableConnector` has no access control checks, unlike other administrative functions such as `UpdateConnector`, `AddPairConnector`, and `SetFeeRate` which all enforce `AssertPerformedByConnectorController()`. This allows any user to call it.

## Impact Explanation

**State Corruption:** The connector is enabled with `DepositBalance` set to an inflated value that does not correspond to actual reserves. The `GetSelfBalance` helper uses `DepositBalance` for deposit connectors [10](#0-9) , meaning all Bancor pricing calculations will use incorrect reserve amounts.

**Denial of Service on Buy Operations:** When users attempt to buy resource tokens, the contract will try to transfer tokens it doesn't possess, causing transaction failure [11](#0-10) 

**Denial of Service on Sell Operations:** The Bancor formula requires positive connector balances [12](#0-11) . If the resource connector balance is zero (no tokens transferred), all sell operations will revert with an exception.

**Permanent Protocol Damage:** Once a connector is corrupted, there is no mechanism to recalculate or reset the `DepositBalance`. The connector pair becomes permanently unusable, affecting all users who intended to trade through it and damaging the protocol's economic functionality.

## Likelihood Explanation

**No Access Control:** Unlike other administrative functions in the TokenConverter contract, `EnableConnector` lacks authorization checks, making it callable by any address.

**Simple Attack Vector:** An attacker only needs to call `EnableConnector` with a negative `AmountToTokenConvert` value. No complex setup or privileged access is required.

**Normal Preconditions:** The attack requires only that a connector pair exists (added by governance) but is not yet enabled—a standard operational state during token launch preparation.

**Low Detection:** The malicious transaction will execute successfully without reverting. The corruption only becomes apparent when subsequent users attempt to trade and encounter failures.

## Recommendation

1. **Add input validation to GetNeededDeposit:**
```csharp
public override DepositInfo GetNeededDeposit(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    // ... rest of function
}
```

2. **Add access control to EnableConnector:**
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController();
    // ... rest of function
}
```

3. **Add consistency validation:**
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    // ... existing code ...
    var actualTokensTransferred = input.AmountToTokenConvert > 0 ? input.AmountToTokenConvert : 0;
    Assert(actualTokensTransferred == input.AmountToTokenConvert, 
        "Resource token transfer amount must match declared amount.");
    // ... rest of function
}
```

4. **Prevent duplicate enablement:**
```csharp
Assert(!toConnector.IsPurchaseEnabled && !fromConnector.IsPurchaseEnabled, 
    "Connector pair already enabled.");
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_NegativeAmount_CorruptsState()
{
    // Setup: Create token and add connector pair
    await DefaultStub.Initialize.SendAsync(new InitializeInput { FeeRate = "0.005" });
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue tokens to attacker but don't approve transfer
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 100_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Attack: Call EnableConnector with negative AmountToTokenConvert
    var maliciousInput = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = -50_0000  // Negative value
    };
    
    // Get the inflated deposit calculation
    var deposit = await DefaultStub.GetNeededDeposit.CallAsync(maliciousInput);
    deposit.AmountOutOfTokenConvert.ShouldBeGreaterThan(100_0000); // Inflated!
    
    // Enable connector with corrupted state
    await DefaultStub.EnableConnector.SendAsync(maliciousInput);
    
    // Verify connector is enabled
    var connector = await DefaultStub.GetPairConnector.CallAsync(new TokenSymbol { Symbol = tokenSymbol });
    connector.ResourceConnector.IsPurchaseEnabled.ShouldBe(true);
    
    // Verify state corruption: contract has 0 resource tokens
    var contractBalance = await GetBalanceAsync(tokenSymbol, TokenConverterContractAddress);
    contractBalance.ShouldBe(0);
    
    // Attempt to buy tokens - should fail (no tokens to transfer)
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 100,
        PayLimit = 1000000
    });
    buyResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

## Notes

The vulnerability combines two separate security weaknesses: missing input validation and missing access control. While the attacker must pay an inflated deposit (self-harm), the primary impact is the permanent corruption of protocol state, rendering the connector pair unusable for all users. This constitutes a valid denial-of-service vulnerability through state corruption rather than a fund theft vulnerability.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L56-91)
```csharp
    public override DepositInfo GetNeededDeposit(ToBeConnectedTokenInfo input)
    {
        var toConnector = State.Connectors[input.TokenSymbol];
        Assert(toConnector != null && !toConnector.IsDepositAccount, "[GetNeededDeposit]Can't find to connector.");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[GetNeededDeposit]Can't find from connector.");
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(
            new GetTokenInfoInput
            {
                Symbol = input.TokenSymbol
            });
        var balance = State.TokenContract.GetBalance.Call(
            new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = input.TokenSymbol
            }).Balance;
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

        return new DepositInfo
        {
            NeedAmount = needDeposit,
            AmountOutOfTokenConvert = amountOutOfTokenConvert
        };
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L143-149)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });
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

**File:** protobuf/token_converter_contract.proto (L183-183)
```text
    int64 amount_to_token_convert = 2;
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L37-38)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");
```
