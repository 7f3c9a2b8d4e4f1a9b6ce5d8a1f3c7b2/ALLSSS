# Audit Report

## Title
Race Condition in EnableConnector: Token Supply Manipulation via Transfer Callback Leads to Under-Collateralization

## Summary
The `EnableConnector()` function in TokenConverter has a time-of-check to time-of-use (TOCTOU) vulnerability where it calculates the required deposit based on the current token supply, but the supply can be manipulated through a transfer callback before the deposit balance is set. This violates the checks-effects-interactions pattern and results in critical under-collateralization of the Bancor connector pair.

## Finding Description

The vulnerability exists in `EnableConnector()` where the deposit calculation occurs before external interactions, but the state update happens after. [1](#0-0) 

The execution sequence creates a race window:

1. The function calls `GetNeededDeposit(input)` which queries the token's current total supply and calculates the required deposit using the Bancor formula. [2](#0-1) 

2. Resource tokens are transferred to the contract via `TransferFrom`, which triggers the MultiToken transfer callback mechanism through `DoTransferFrom`. [3](#0-2) 

3. The callback is invoked via `Context.SendInline` in `DealWithExternalInfoDuringTransfer` after the transfer completes. [4](#0-3) 

4. During the callback execution, if the callback contract is configured as the token's Issuer, it can call `Issue()` to mint additional tokens, as the Issue function only checks that the sender is the token's Issuer. [5](#0-4) 

5. The deposit balance is set to the originally calculated amount at line 297, which no longer reflects the actual circulating supply after the minting in step 4.

**Critical Finding**: Unlike other TokenConverter management functions (`UpdateConnector`, `AddPairConnector`, `SetFeeRate`) which all call `AssertPerformedByConnectorController()` for authorization [6](#0-5) , `EnableConnector` has **no authorization checks**, making it publicly callable by anyone once the connector pair exists.

## Impact Explanation

**Under-Collateralization Scenario:**

The Bancor formula maintains pricing based on the relationship between deposit balance and token supply. When users sell tokens, the pricing calculation uses `GetSelfBalance()` which returns the stored `DepositBalance` for deposit connectors. [7](#0-6) [8](#0-7) 

**Concrete Attack:**
- Initial supply: 1,000 tokens  
- `AmountToTokenConvert`: 100 tokens
- Calculated deposit: For 900 circulating tokens = X ELF
- **During transfer callback**: Attacker mints 100,000 additional tokens
- Actual circulating supply: 100,900 tokens
- Deposit remains: X ELF (only sufficient for 900 tokens)

**Direct Consequences:**
1. Bancor formula calculates incorrect pricing due to artificially low deposit balance
2. Attacker sells the newly minted tokens, draining the under-collateralized deposit
3. Later sellers face DoS when deposit is exhausted
4. Protocol-level invariant broken: deposit cannot cover all circulating tokens

## Likelihood Explanation

**Prerequisites:**
1. Parliament approves a connector pair via `AddPairConnector` (requires governance vote)
2. Token has transfer callback configured in `ExternalInfo` metadata
3. Callback contract address is set as the token's Issuer (allowing `Issue()` calls)
4. Anyone can then call `EnableConnector` (no authorization required)

**Feasibility Assessment: MEDIUM**

While Parliament approval is required, several factors increase likelihood:

1. **Subtle Attack Vector**: Transfer callbacks are configured in `ExternalInfo` metadata, which may be overlooked during governance review of token proposals

2. **No Authorization on EnableConnector**: Unlike other management functions, `EnableConnector` is public, allowing the attacker to trigger the exploit after Parliament approval

3. **Legitimate Use Case Confusion**: Transfer callbacks have legitimate purposes (notification systems, cross-contract interactions), making malicious configurations less obvious

4. **Defense-in-Depth Violation**: Smart contracts should not rely solely on external governance to prevent exploitable code paths. This represents a fundamental design flaw violating the checks-effects-interactions pattern.

## Recommendation

1. **Add Authorization Check**: Add `AssertPerformedByConnectorController()` at the start of `EnableConnector()` to match other management functions

2. **Follow Checks-Effects-Interactions Pattern**: Move the deposit balance state update (line 297) to occur BEFORE the resource token transfer (lines 287-295)

3. **Re-calculate After Transfer**: After the resource token transfer completes, re-query the token's TotalSupply and verify it hasn't changed, or recalculate the required deposit

4. **Add Re-entrancy Guard**: Implement a re-entrancy lock to prevent any state manipulation during external calls

## Proof of Concept

A valid PoC would require:
1. Creating a malicious token with a transfer callback configured in ExternalInfo
2. Setting the callback contract as the token's Issuer
3. The callback contract implements a method that calls Issue() to mint tokens when invoked
4. Parliament approves AddPairConnector for this token
5. Attacker calls EnableConnector with AmountToTokenConvert > 0
6. During the TransferFrom, the callback mints additional tokens
7. Verify that DepositBalance is under-sized relative to actual circulating supply
8. Demonstrate deposit drainage by selling the minted tokens

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-110)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L154-178)
```csharp
    public override Empty Issue(IssueInput input)
    {
        Assert(input.To != null, "To address not filled.");
        AssertValidMemo(input.Memo);
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
        Assert(tokenInfo.Issuer == Context.Sender || Context.Sender == Context.GetZeroSmartContractAddress(),
            $"Sender is not allowed to issue token {input.Symbol}.");

        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(input.To, input.Symbol, input.Amount);

        Context.Fire(new Issued
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = input.To,
            Memo = input.Memo
        });
        return new Empty();
    }
```
