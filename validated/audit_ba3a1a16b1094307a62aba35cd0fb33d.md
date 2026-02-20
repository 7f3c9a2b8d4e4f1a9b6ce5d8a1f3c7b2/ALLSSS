# Audit Report

## Title
Insufficient Deposit Calculation Due to Pre-Transferred Tokens in EnableConnector

## Summary
The `GetNeededDeposit` function includes pre-existing token balances in its deposit calculation, allowing an attacker to artificially reduce required deposits by directly transferring resource tokens to the TokenConverter contract before calling the unrestricted `EnableConnector` method. This creates an imbalance where insufficient base token deposits back the resource token supply, permanently breaking the Bancor pricing invariant.

## Finding Description

The vulnerability exists in the deposit calculation logic when enabling connector pairs. The `GetNeededDeposit` function retrieves the contract's current balance of the resource token and calculates `amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert`. [1](#0-0) 

This formula assumes any tokens already held by the contract (`balance`) are legitimately "in the system" and don't require deposit backing. However, there is no restriction preventing direct token transfers to the contract address. If an attacker transfers resource tokens to the contract before calling `EnableConnector`, this artificially inflates the `balance` value, reducing `amountOutOfTokenConvert` and thus lowering the calculated `needDeposit`.

The `EnableConnector` function has no access control restrictions, unlike other administrative functions such as `UpdateConnector`, `AddPairConnector`, and `SetFeeRate` which all require connector controller authorization. [2](#0-1) 

Compare with the access-controlled `UpdateConnector`: [3](#0-2) 

The insufficient `needDeposit` is then set as the deposit balance: [4](#0-3) 

During subsequent `Buy` and `Sell` operations, the Bancor pricing formula uses `GetSelfBalance` which returns different values for each connector: [5](#0-4) 

- For deposit connectors (base token): it uses `State.DepositBalance[connector.Symbol]` (artificially LOW)
- For resource connectors: it queries the actual contract balance (artificially HIGH due to pre-transfer)

This imbalance skews the Bancor pricing mechanism since the reserve ratio no longer matches the intended economic model. [6](#0-5) 

## Impact Explanation

**Critical severity** is justified because:

1. **Fund Security**: The deposit pool becomes drainable through arbitrage exploitation of the mispriced Bancor formula
2. **Core Invariant Violation**: The fundamental guarantee of proper reserve backing for token conversion is broken from initialization
3. **Permanence**: Once enabled with incorrect reserves, the connector cannot be fixed - `UpdateConnector` explicitly blocks updates after enablement [7](#0-6) 
4. **Widespread Impact**: All subsequent Buy/Sell transactions operate with incorrect pricing, affecting every user
5. **Protocol Trust**: Breaks the economic security model users rely on for fair token conversion rates

## Likelihood Explanation

**High likelihood** assessment is based on:

**Low Complexity**: Attack requires only two simple operations:
- Standard token transfer to contract address  
- Public call to `EnableConnector` (no special permissions needed)

**Realistic Preconditions**: The attack window exists between when `AddPairConnector` is called (by controller) and when legitimate `EnableConnector` occurs - a normal operational state.

**Economic Rationality**: Profits from exploiting the mispricing exceed transaction costs, providing strong incentive.

**No Detection Barriers**: Direct token transfers appear as normal blockchain transactions with no on-chain validation to prevent this behavior.

**Accessibility**: Any actor with resource tokens can execute the attack without special timing, privileges, or sophisticated interactions.

## Recommendation

Add access control to the `EnableConnector` function to restrict it to the connector controller:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // Add this line
    var fromConnector = State.Connectors[input.TokenSymbol];
    // ... rest of the function
}
```

Alternatively, modify `GetNeededDeposit` to not include pre-existing balances in the calculation, or validate that the contract balance is zero before enabling:

```csharp
var balance = State.TokenContract.GetBalance.Call(
    new GetBalanceInput
    {
        Owner = Context.Self,
        Symbol = input.TokenSymbol
    }).Balance;
Assert(balance == input.AmountToTokenConvert, "Unexpected token balance in contract");
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_PreTransfer_Attack_Test()
{
    // Setup: Create token and add connector pair
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue tokens to attacker
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 1000_0000_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // ATTACK: Transfer tokens directly to TokenConverter before EnableConnector
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = TokenConverterContractAddress,
        Symbol = tokenSymbol,
        Amount = 500_0000_0000 // Transfer half the supply
    });
    
    // Check deposit calculation is now artificially low
    var depositInfo = await DefaultStub.GetNeededDeposit.CallAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = 0
        });
    
    // Should require deposit for full supply, but only calculates for remaining half
    // because pre-transferred balance is excluded from amountOutOfTokenConvert
    depositInfo.AmountOutOfTokenConvert.ShouldBe(500_0000_0000); // Only half!
    
    // Enable connector with insufficient deposit
    await DefaultStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 0
    });
    
    // Verify connector is enabled with broken pricing
    var connector = (await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol })).ResourceConnector;
    connector.IsPurchaseEnabled.ShouldBe(true);
    
    // GetSelfBalance now returns imbalanced values causing pricing exploit
}
```

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L67-73)
```csharp
        var balance = State.TokenContract.GetBalance.Call(
            new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = input.TokenSymbol
            }).Balance;
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-64)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.Symbol), "input symbol can not be empty'");
        var targetConnector = State.Connectors[input.Symbol];
        Assert(targetConnector != null, "Can not find target connector.");
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
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
