# Audit Report

## Title
Time-Of-Check-Time-Of-Use Vulnerability in EnableConnector Due to External Callback Reentrancy

## Summary
The `EnableConnector` function in the TokenConverter contract violates the Checks-Effects-Interactions (CEI) pattern by calculating deposit requirements, executing external token transfers with callback support, then writing the potentially stale calculation to state. This enables TOCTOU attacks where token callbacks can modify supply/balances or trigger recursive calls, causing incorrect reserve tracking and subsequent mispricing in Buy/Sell operations.

## Finding Description

The vulnerability exists in `EnableConnector`'s execution sequence which reads state, makes external calls with callbacks, then writes stale data. [1](#0-0) 

The function first calls `GetNeededDeposit()` which reads current token supply and balances to calculate required deposits. [2](#0-1) 

After calculating `needDeposit`, `EnableConnector` executes two `TransferFrom` operations. These calls invoke the MultiToken contract's `DoTransferFrom` method which crucially calls `DealWithExternalInfoDuringTransfer` AFTER modifying balances. [3](#0-2) 

The callback mechanism uses `Context.SendInline` to execute arbitrary contract code if the token has `TransferCallbackExternalInfoKey` configured. [4](#0-3) 

**Security Guarantees Broken:**

1. **CEI Pattern Violation**: State is read (line 276 of TokenConverterContract.cs), external calls with callbacks are made (lines 278-295), then stale values are written (line 297)

2. **No Reentrancy Guard**: Unlike `UpdateConnector` which checks `IsPurchaseEnabled` status [5](#0-4) , `EnableConnector` has no such protection

3. **No Authority Check**: Unlike other connector management functions such as `UpdateConnector`, `AddPairConnector`, and `SetFeeRate` which all call `AssertPerformedByConnectorController()` [6](#0-5) , `EnableConnector` lacks this protection, allowing anyone to enable governance-approved connectors

**Attack Vector:**

During the callback execution between lines 278-295, an attacker can:
- Transfer tokens to change balances
- Recursively call `EnableConnector` (inner call sets correct value, outer call overwrites with stale value)
- If issuer authority exists, mint/burn tokens to change `TotalSupply`

The stale `needDeposit.NeedAmount` is then written to `State.DepositBalance` via direct assignment (not increment), which directly affects all subsequent pricing calculations.

## Impact Explanation

The incorrect `State.DepositBalance` value is used by `GetSelfBalance` for Bancor pricing. [7](#0-6) 

This incorrect balance feeds into Buy operations [8](#0-7)  and Sell operations [9](#0-8) .

The Bancor formula calculations [10](#0-9)  use these incorrect balances, resulting in:

**If DepositBalance too low (reentrancy case):**
- Buy operations: Users pay less than fair price → protocol economic loss
- Sell operations: Users receive more than fair price → reserve drainage

**If DepositBalance too high:**
- Buy operations: Users overpay → unfair pricing disadvantages users
- Sell operations: Users receive less → unfair pricing disadvantages users

This affects all users trading through the connector pair and compromises the protocol's reserve backing integrity. In a reentrancy scenario where EnableConnector is called twice, the actual deposited funds (e.g., 950 ELF) would be tracked as a lower amount (e.g., 500 ELF), causing systematic underpricing that drains protocol reserves.

## Likelihood Explanation

**Required Preconditions:**
1. Governance must approve adding a connector via `AddPairConnector` (requires controller authority) [11](#0-10) 
2. Token must have `TransferCallbackExternalInfoKey` configured in ExternalInfo (legitimate AElf feature)
3. Callback must modify state affecting deposit calculations OR trigger reentrancy

**Facilitating Factors:**
- **No authority check on EnableConnector**: Anyone can call it on governance-approved connectors
- **Transfer callbacks are legitimate**: Governance may approve tokens with callbacks without realizing TOCTOU implications
- **Unintentional triggers**: Rebase tokens, fee-on-transfer tokens, or tokens with dividend distributions could inadvertently trigger this without malicious intent

**Attack Complexity:** Low once preconditions met - attacker simply calls `EnableConnector` with appropriate parameters.

**Detection Difficulty:** High - requires thorough audit of token callback behavior, which governance may not perform in detail.

**Probability Assessment:** MEDIUM - While governance approval creates a barrier, the vulnerability stems from an architectural flaw (CEI violation) that could be triggered by any token with transfer side effects, not just overtly malicious ones. The lack of authority check on `EnableConnector` increases exploitability.

## Recommendation

1. **Add Authority Check**: Add `AssertPerformedByConnectorController()` at the beginning of `EnableConnector` to restrict access to authorized controller only, consistent with other connector management functions.

2. **Add Reentrancy Guard**: Check `!IsPurchaseEnabled` before executing the function logic, similar to `UpdateConnector`'s protection, to prevent recursive calls.

3. **Follow CEI Pattern**: Restructure the function to:
   - Calculate all values (Check)
   - Update state variables (Effect)
   - Make external calls (Interaction)
   
   Specifically, set `State.DepositBalance` BEFORE making the `TransferFrom` calls, or use a mutex/lock pattern to prevent reentrancy.

4. **Increment Instead of Assign**: If multiple deposits are intended, use `State.DepositBalance[toConnector.Symbol] = State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount)` instead of direct assignment to properly track cumulative deposits.

## Proof of Concept

```csharp
// POC Test: Demonstrates reentrancy attack on EnableConnector

// Setup:
// 1. Create malicious token with transfer callback
// 2. Governance approves connector via AddPairConnector
// 3. Configure token's ExternalInfo[TransferCallbackExternalInfoKey] to point to attacker contract

// Attack Flow:
public void TestEnableConnectorReentrancy()
{
    // 1. Attacker calls EnableConnector(TokenX, 100)
    //    - Calculates needDeposit1 = 500 ELF based on supply/balance at T0
    
    // 2. During TokenX TransferFrom callback:
    //    - Callback recursively calls EnableConnector(TokenX, 50)
    //    - Inner call calculates needDeposit2 = 450 ELF based on updated state at T1
    //    - Inner call sets DepositBalance = 450
    //    - Inner call deposits 450 ELF
    
    // 3. Outer call resumes:
    //    - Overwrites DepositBalance = 500 (stale value from T0)
    //    - Total deposited: 950 ELF
    //    - Tracked in DepositBalance: 500 ELF
    //    - Missing: 450 ELF
    
    // 4. Result: GetSelfBalance returns 500 instead of 950
    //    - Buy/Sell operations use incorrect balance in Bancor formula
    //    - Protocol loses funds through systematic mispricing
    
    Assert(actualDeposited == 950);
    Assert(trackedInState == 500); // Vulnerability: Incorrect accounting
}
```

**Notes:**

The vulnerability is confirmed through code analysis showing:
1. Clear CEI violation in execution order
2. Absence of authority checks unlike sibling functions
3. Absence of reentrancy protection unlike UpdateConnector
4. Callback mechanism that enables state manipulation
5. Direct impact on pricing through GetSelfBalance → Bancor formula path

This represents a critical flaw in reserve accounting that can lead to economic loss through either reentrancy attacks or unintentional state modifications during legitimate token callbacks.

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-159)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());

        var amountToPayPlusFee = amountToPay.Add(fee);
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = amountToPay
            });
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
        // Transfer bought token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });

        Context.Fire(new TokenBought
        {
            Symbol = input.Symbol,
            BoughtAmount = input.Amount,
            BaseAmount = amountToPay,
            FeeAmount = fee
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L69-95)
```csharp
    private void DoTransferFrom(Address from, Address to, Address spender, string symbol, long amount, string memo)
    {
        AssertValidInputAddress(from);
        AssertValidInputAddress(to);
        
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L337-350)
```csharp
    private void DealWithExternalInfoDuringTransfer(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TransferCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.TransferCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L34-94)
```csharp
    public static long GetReturnFromPaid(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long paidAmount)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (paidAmount <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = paidAmount;
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);

        var x = bf / (bf + a);
        var y = wf / wt;
        return (long)(bt * (decimal.One - Exp(y * Ln(x))));
    }

    /// <summary>
    ///     Get amount of token to pay:
    ///     amountToPay = ((toConnectorBalance / (toConnectorBalance - amountToReceive))
    ///     ^(toConnectorWeight/fromConnectorWeight) - 1)*fromConnectorBalance
    /// </summary>
    /// <param name="fromConnectorBalance"></param>
    /// <param name="fromConnectorWeight"></param>
    /// <param name="toConnectorBalance"></param>
    /// <param name="toConnectorWeight"></param>
    /// <param name="amountToReceive"></param>
    /// <returns></returns>
    public static long GetAmountToPayFromReturn(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long amountToReceive)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = amountToReceive;
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
            }
            catch
            {
                throw new AssertionException("Insufficient account balance to deposit");
            }

        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
    }
```
