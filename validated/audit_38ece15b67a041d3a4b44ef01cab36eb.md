# Audit Report

## Title
EnableConnector Allows Re-Enabling with Zero Deposit, Corrupting DepositBalance Accounting

## Summary
The `EnableConnector` function lacks authorization checks and re-enabling protection, allowing any external user to corrupt the `DepositBalance` accounting by re-enabling already-active connectors with zero deposit. This causes permanent denial of service for Sell operations and corrupts Bancor pricing calculations.

## Finding Description

The `EnableConnector` function contains three critical security flaws that enable unauthorized state corruption:

**Flaw 1: Missing Authorization Check**

Unlike `UpdateConnector` which enforces controller-only access [1](#0-0) , the `EnableConnector` function has no authorization validation [2](#0-1) . Any external user can invoke it.

**Flaw 2: No Re-Enabling Protection**

`UpdateConnector` explicitly prevents updates to enabled connectors [3](#0-2) , but `EnableConnector` lacks this guard and can be called repeatedly on already-active connectors.

**Flaw 3: Unconditional DepositBalance Overwrite**

The function unconditionally assigns (not adds to) the deposit balance [4](#0-3) , erasing any previously accumulated value from Buy operations [5](#0-4) .

**Attack Vector:**

When `GetNeededDeposit` calculates that `amountOutOfTokenConvert = totalSupply - balance - AmountToTokenConvert <= 0` [6](#0-5) , it returns `needDeposit = 0` [7](#0-6) . An attacker can trigger this by supplying `AmountToTokenConvert >= totalSupply - balance`, causing the conditional deposit transfer to be skipped while still executing the unconditional DepositBalance assignment to zero.

## Impact Explanation

**1. Permanent Sell Operation DoS**

The Sell function subtracts from DepositBalance [8](#0-7) . The `.Sub()` method uses checked arithmetic [9](#0-8)  that throws on underflow. With DepositBalance corrupted to zero, any Sell attempt throws an overflow exception, permanently blocking all sell operations and trapping users' tokens.

**2. Bancor Pricing Corruption**

`GetSelfBalance` returns DepositBalance for deposit accounts [10](#0-9) , which is used in Bancor pricing formulas for both Buy and Sell operations [11](#0-10) . Corrupted DepositBalance causes incorrect price calculations, enabling arbitrage exploitation and unfair trades.

**3. Irreversible State Corruption**

The UpdateConnector protection prevents fixing enabled connectors [3](#0-2) , and no other mechanism exists to disable or repair corrupted connectors, making the damage permanent.

## Likelihood Explanation

**Attacker Capabilities**: The attack requires no special privileges. `EnableConnector` is a public RPC method [12](#0-11)  callable by any external address.

**Attack Complexity**: LOW
- Step 1: Acquire resource tokens equal to `totalSupply - balance` (via market or existing holdings)
- Step 2: Approve TokenConverter contract for token transfer [13](#0-12) 
- Step 3: Call EnableConnector with calculated `AmountToTokenConvert`

**Feasibility**: HIGH for active, high-value connector pairs. The attacker needs sufficient resource tokens (feasible for any moderately-funded actor), and economic incentive exists through arbitrage profit from mispricing or competitive sabotage.

**Detection Difficulty**: The malicious transaction appears identical to legitimate EnableConnector calls, making real-time prevention difficult.

## Recommendation

Add three critical protections to `EnableConnector`:

1. **Authorization Check**: Add `AssertPerformedByConnectorController()` at the function start
2. **Re-Enabling Protection**: Assert that `!fromConnector.IsPurchaseEnabled && !toConnector.IsPurchaseEnabled` 
3. **Additive Deposit Update**: Change line 297 from assignment to addition: `State.DepositBalance[toConnector.Symbol] = State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount)`

## Proof of Concept

The vulnerability can be demonstrated by:
1. Creating and enabling a connector pair normally
2. Performing Buy operations to accumulate DepositBalance
3. Calling EnableConnector again with `AmountToTokenConvert >= totalSupply - balance` to reset DepositBalance to 0
4. Attempting Sell operation which will fail with overflow exception

The attack succeeds because no authorization or re-enabling checks prevent the second EnableConnector call, and the unconditional assignment overwrites the accumulated deposit balance.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L60-60)
```csharp
        AssertPerformedByConnectorController();
```

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L377-378)
```csharp
        if (connector.IsDepositAccount)
            realBalance = State.DepositBalance[connector.Symbol];
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-97)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
```

**File:** protobuf/token_converter_contract.proto (L48-49)
```text
    rpc EnableConnector (ToBeConnectedTokenInfo) returns (google.protobuf.Empty) {
    }
```
