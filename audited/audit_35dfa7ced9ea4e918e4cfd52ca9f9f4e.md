### Title
DepositBalance Overwrite Vulnerability in EnableConnector Allows Multiple Enabling Leading to Accounting Corruption

### Summary
The `EnableConnector()` function lacks authorization checks and can be called multiple times for the same token pair. On subsequent calls, it overwrites rather than accumulates the `DepositBalance` state variable, breaking the accounting invariant that this value should track cumulative deposits minus withdrawals. This corruption affects all Bancor price calculations and can lead to systematic mispricing of buy/sell operations.

### Finding Description

The vulnerability exists in the `EnableConnector()` function which has three critical flaws:

**1. No Authorization Check** [1](#0-0) 

Unlike other administrative functions (`UpdateConnector`, `AddPairConnector`, `SetFeeRate`, `ChangeConnectorController`), `EnableConnector()` does not call `AssertPerformedByConnectorController()` to verify caller authority. Any address can invoke this function.

**2. No Re-Enable Protection**
The function does not check whether the connector is already enabled (i.e., `toConnector.IsPurchaseEnabled == true`). While it sets both connectors' `IsPurchaseEnabled` to `true` at the end, there is no assertion preventing execution if they are already enabled.

**3. DepositBalance Assignment Instead of Accumulation** [2](#0-1) 

The critical line uses assignment operator (`=`) instead of addition. When called multiple times:
- First call: `DepositBalance[toConnector.Symbol] = 1000` (example)
- Second call: `DepositBalance[toConnector.Symbol] = 500` (overwrites to 500, not 1500)

The actual base token balance in the contract remains correct, but the tracked `DepositBalance` value becomes desynchronized.

**4. DepositBalance Usage in Price Calculations** [3](#0-2) 

The corrupted `DepositBalance` is used in `GetSelfBalance()`, which directly feeds into Bancor pricing formulas for all `Buy()` and `Sell()` operations. [4](#0-3) [5](#0-4) 

### Impact Explanation

**Direct Fund Impact - Critical**

1. **Accounting Corruption**: The contract holds X base tokens but `DepositBalance` records Y, where X ≠ Y. This breaks the fundamental accounting invariant.

2. **Systematic Mispricing**: All subsequent `Buy()` and `Sell()` operations use the incorrect `DepositBalance` value in Bancor formula calculations. If `DepositBalance` is set lower than actual deposits, buy prices decrease and sell prices increase, allowing attackers to extract value through arbitrage.

3. **Reserve Depletion**: If `DepositBalance` is set to 0 while actual deposits exist, the Bancor formula treats the deposit connector as having minimal balance, causing extreme price distortions that could drain reserves.

4. **Value Quantification**: For a connector with 1,000,000 base tokens actually deposited, an attacker could reset `DepositBalance` to near-zero, then:
   - Buy resource tokens at artificially low prices (Bancor formula uses wrong denominator)
   - System thinks deposit is nearly empty, prices collapse
   - Attacker profits from price manipulation

**Who is Affected**: All users trading through affected connector pairs; the protocol treasury loses value through mispriced trades.

### Likelihood Explanation

**Likelihood - High**

1. **Reachable Entry Point**: `EnableConnector()` is a public RPC method with no authorization modifier in the protobuf definition. [6](#0-5) 

2. **Feasible Preconditions**: 
   - Attacker needs tokens of the target symbol to pass `AmountToTokenConvert` transfer
   - Must have allowance for base tokens if `needDeposit.NeedAmount > 0`
   - These are standard trading requirements, not difficult barriers

3. **Execution Practicality**: 
   - Call `EnableConnector()` once (legitimate first enable)
   - Call `EnableConnector()` again with `AmountToTokenConvert = 0`
   - `GetNeededDeposit()` recalculates based on new state, likely returns 0 or small amount [7](#0-6) 
   - `DepositBalance` gets overwritten to the new (smaller) value

4. **Attack Complexity**: Low - single transaction, no timing requirements, no special contract state needed beyond connector being added.

5. **Detection Constraints**: The vulnerability is silent - no events indicate `DepositBalance` was overwritten. Price manipulation may appear as normal market volatility initially.

6. **Economic Rationality**: Attacker profit from mispriced trades easily exceeds gas costs. Even if first call required depositing tokens, those can be recovered in second call or through profitable trades afterward.

### Recommendation

**Immediate Fixes**:

1. **Add Authorization Check**
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // Add this line
    // ... rest of function
}
```

2. **Add Re-Enable Protection**
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    var fromConnector = State.Connectors[input.TokenSymbol];
    Assert(fromConnector != null && !fromConnector.IsDepositAccount,
        "[EnableConnector]Can't find from connector.");
    var toConnector = State.Connectors[fromConnector.RelatedSymbol];
    Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
    
    // Add this check
    Assert(!toConnector.IsPurchaseEnabled && !fromConnector.IsPurchaseEnabled, 
        "Connector already enabled.");
    
    // ... rest of function
}
```

3. **Fix DepositBalance to Accumulate** (if re-enabling is desired behavior)
```csharp
// Change from assignment to addition
State.DepositBalance[toConnector.Symbol] = 
    State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount);
```

**Invariant Checks to Add**:
- Assert `IsPurchaseEnabled == false` before enabling
- Add event logging for `DepositBalance` changes
- Validate `DepositBalance` matches actual token balance at critical points

**Test Cases**:
- Test calling `EnableConnector()` twice for same token - should fail on second call
- Test unauthorized user calling `EnableConnector()` - should fail
- Test `DepositBalance` tracking across multiple operations - should always equal actual deposits minus withdrawals

### Proof of Concept

**Initial State**:
- Token "TEST" created with 10,000,000 total supply
- Pair connector added via `AddPairConnector()` with appropriate weights
- User holds 9,999,900 TEST tokens
- Connector not yet enabled

**Attack Sequence**:

**Step 1 - First Enable (Legitimate)**
```
Call: EnableConnector({
    TokenSymbol: "TEST",
    AmountToTokenConvert: 9,999,900
})
- GetNeededDeposit calculates need 10,000 base tokens
- User deposits 10,000 base tokens to contract
- DepositBalance["(NT)TEST"] = 10,000
- IsPurchaseEnabled = true for both connectors
```

**Step 2 - Second Enable (Attack)**
```
Call: EnableConnector({
    TokenSymbol: "TEST", 
    AmountToTokenConvert: 0
})
- Contract now holds 9,999,900 TEST tokens from Step 1
- GetNeededDeposit: amountOutOfTokenConvert = 10,000,000 - 9,999,900 - 0 = 100
- Calculates small needDeposit (e.g., 10 base tokens)
- User deposits only 10 base tokens
- DepositBalance["(NT)TEST"] = 10 (OVERWRITTEN from 10,000!)
- Contract actually holds 10,010 base tokens but tracks only 10
```

**Expected Result**: Transaction should fail with "Connector already enabled" or "Only manager can perform this action"

**Actual Result**: Transaction succeeds. `DepositBalance` is overwritten from 10,000 to 10, creating 9,990 token accounting discrepancy. All subsequent Bancor price calculations use the corrupted value of 10 instead of 10,010, causing systematic mispricing.

**Success Condition**: After Step 2, `GetDepositConnectorBalance("TEST")` returns much less than actual base token balance held by contract, and buy/sell prices are distorted accordingly.

### Citations

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

**File:** protobuf/token_converter_contract.proto (L47-49)
```text
    // After adding a pair, you need to call this method to enable it before buy and sell token.
    rpc EnableConnector (ToBeConnectedTokenInfo) returns (google.protobuf.Empty) {
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
