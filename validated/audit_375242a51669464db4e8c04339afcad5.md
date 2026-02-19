# Audit Report

## Title
EnableConnector Allows Re-Enabling with Zero Deposit, Corrupting DepositBalance Accounting

## Summary
The `EnableConnector` function in the TokenConverter contract lacks validation to prevent re-enabling already-enabled connectors and unconditionally overwrites the `DepositBalance` state variable. An attacker can exploit this by calling `EnableConnector` on an active connector with sufficient resource tokens to force `needDeposit.NeedAmount = 0`, erasing accumulated base token deposits and causing permanent DoS of all Sell operations plus pricing manipulation.

## Finding Description

The `EnableConnector` function has two critical architectural flaws that enable state corruption:

**Flaw 1: Missing Re-Enabling Protection**

Unlike `UpdateConnector` which explicitly prevents modification of enabled connectors [1](#0-0) , the `EnableConnector` function contains no check to prevent calls on already-enabled connectors. The function simply sets `IsPurchaseEnabled = true` unconditionally [2](#0-1) .

**Flaw 2: Unconditional DepositBalance Overwrite**

The function unconditionally assigns `State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount` [3](#0-2)  using direct assignment rather than addition. This contrasts with the `Buy` function which correctly adds to existing balance [4](#0-3) .

**Exploitation Mechanism**

The `GetNeededDeposit` function calculates required deposits based on tokens outside the contract [5](#0-4) . When `amountOutOfTokenConvert <= 0`, the function returns `needDeposit = 0` [6](#0-5) .

An attacker providing `AmountToTokenConvert >= totalSupply - balance` satisfies this condition. The conditional transfer only executes when `needDeposit.NeedAmount > 0` [7](#0-6) , so when zero, line 297 sets `DepositBalance` to zero, erasing accumulated deposits from prior Buy operations.

**Attack Path**

1. Initial state: Connector enabled, users performed Buy operations, `DepositBalance > 0`
2. Attacker acquires resource tokens totaling `≥ totalSupply - balance`
3. Attacker calls `EnableConnector` (no authorization required [8](#0-7) )
4. `GetNeededDeposit` returns `NeedAmount = 0`
5. Line 297 sets `DepositBalance[toConnector.Symbol] = 0`
6. Actual base tokens remain in contract, but tracked balance is zero

## Impact Explanation

**Critical Impact: Complete Sell Operation DoS**

The `Sell` function subtracts from `DepositBalance` using checked arithmetic [9](#0-8) . The `Sub` extension method uses checked blocks that throw `OverflowException` on underflow [10](#0-9) . With `DepositBalance = 0`, any Sell attempt with `amountToReceive > 0` will throw, making all Sell operations permanently unavailable for all users.

**High Impact: Bancor Pricing Manipulation**

The `GetSelfBalance` function returns `DepositBalance` for deposit accounts [11](#0-10) . This value feeds into Bancor pricing calculations in Buy operations [12](#0-11) . Corrupted `DepositBalance` causes incorrect balance reporting, leading to mispriced Buy operations that enable arbitrage exploitation.

**Critical Impact: Irreversible State Corruption**

Once a connector is enabled, `UpdateConnector` prevents any modifications [1](#0-0) . No other contract function can modify `DepositBalance` to fix the corruption. The damage is permanent and unrecoverable without contract upgrade.

**Affected Parties**
- All users holding resource tokens who cannot sell them
- New buyers receiving mispriced tokens
- Protocol integrity due to accounting mismatch between actual and tracked balances

## Likelihood Explanation

**Attack Prerequisites:**
- Target connector already enabled with `DepositBalance > 0` from prior Buy operations
- Attacker must acquire `AmountToTokenConvert >= totalSupply - balance` resource tokens
- For actively-traded connectors, most tokens are held by users (small `balance`), requiring attacker to acquire approximately `totalSupply` worth of tokens

**Execution Complexity: LOW**
- No authorization required - any external user can call `EnableConnector`
- Standard approve + call pattern
- Single transaction execution

**Economic Feasibility:**

The likelihood varies by token characteristics:

**Medium-High for Low/Medium Cap Tokens:** Acquisition cost may be justified by:
- Shorting token before attack for profit
- Arbitrage profits from mispriced Buy operations post-corruption
- Griefing attacks for competitive/reputational damage

**Medium for High Cap Tokens:** High acquisition cost reduces economic viability unless attacker has substantial capital and multi-vector profit strategy.

**High for Malicious Token Creators:** If the token creator is malicious, they can mint tokens to themselves at minimal cost, making the attack essentially free.

**Overall Assessment: MEDIUM-HIGH**

While requiring capital investment, the complete lack of protective checks makes this exploitable against any connector. The permanent damage and critical impact elevate severity regardless of acquisition cost.

## Recommendation

**Immediate Fix: Add Re-Enabling Protection**

Add validation to prevent re-enabling already-enabled connectors:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    var fromConnector = State.Connectors[input.TokenSymbol];
    Assert(fromConnector != null && !fromConnector.IsDepositAccount,
        "[EnableConnector]Can't find from connector.");
    var toConnector = State.Connectors[fromConnector.RelatedSymbol];
    Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
    
    // ADD THIS CHECK
    Assert(!fromConnector.IsPurchaseEnabled && !toConnector.IsPurchaseEnabled, 
        "Connector already enabled");
    
    var needDeposit = GetNeededDeposit(input);
    // ... rest of function
}
```

**Critical Fix: Change Assignment to Addition**

Change line 297 from assignment to addition to preserve existing deposits:

```csharp
// Before:
State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;

// After:
State.DepositBalance[toConnector.Symbol] = 
    State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount);
```

**Additional Consideration**

Add authorization check similar to other privileged operations:
```csharp
AssertPerformedByConnectorController();
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_ReEnabling_Corrupts_DepositBalance_Test()
{
    // Setup: Initialize and create token
    await DefaultStub.Initialize.SendAsync(new InitializeInput { FeeRate = "0.005" });
    var tokenSymbol = "VULN";
    var totalSupply = 100_0000_0000;
    await CreateTokenAsync(tokenSymbol, totalSupply);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue all tokens to attacker
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = totalSupply,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Enable connector initially (legitimate)
    await DefaultStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = totalSupply
    });
    
    // Simulate legitimate Buy operation that adds to DepositBalance
    await DefaultStub.Buy.SendAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 10000,
        PayLimit = 10000
    });
    
    // Get DepositBalance after Buy - should be > 0
    var pairConnectorBefore = await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol });
    var depositBalanceBefore = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol });
    depositBalanceBefore.Value.ShouldBeGreaterThan(0);
    
    // ATTACK: Re-enable with AmountToTokenConvert >= totalSupply - balance
    // This forces needDeposit.NeedAmount = 0
    var attackResult = await DefaultStub.EnableConnector.SendAsync(new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = totalSupply  // >= totalSupply - balance
    });
    attackResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // VERIFY: DepositBalance corrupted to 0
    var depositBalanceAfter = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol });
    depositBalanceAfter.Value.ShouldBe(0);  // CORRUPTED!
    
    // VERIFY: Sell now permanently DoS'd due to underflow
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = tokenSymbol,
        Amount = 1000,
        ReceiveLimit = 0
    });
    sellResult.TransactionResult.Error.ShouldContain("Overflow");
}
```

## Notes

This vulnerability represents a critical failure in state transition validation where the absence of re-entrancy protection for connector activation combined with assignment-instead-of-addition logic creates a permanent DoS vector. The severity is elevated by the irreversible nature of the corruption and the lack of any authorization requirements, making it exploitable by any external actor with sufficient capital to acquire the required tokens.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L64-64)
```csharp
        Assert(!targetConnector.IsPurchaseEnabled, "connector can not be updated because it has been activated");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-269)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L277-285)
```csharp
        if (needDeposit.NeedAmount > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = State.BaseTokenSymbol.Value,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = needDeposit.NeedAmount
                });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L297-297)
```csharp
        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L298-299)
```csharp
        toConnector.IsPurchaseEnabled = true;
        fromConnector.IsPurchaseEnabled = true;
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-73)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L74-84)
```csharp
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```
