# Audit Report

## Title
Reentrancy Vulnerability in TokenConverter Buy/Sell Methods Allows Price Manipulation via Token Callbacks

## Summary
The TokenConverter contract's `Buy` and `Sell` methods violate the checks-effects-interactions pattern by updating critical state (`State.DepositBalance`) after making external token transfers. If the base token has a callback configured via `ExternalInfo`, an attacker can reenter these methods during transfers, observing stale connector balances and manipulating Bancor pricing to drain reserves.

## Finding Description

The vulnerability exists due to incorrect operation ordering in both trading methods:

**Buy Method Vulnerability:** [1](#0-0) 

The price calculation reads `State.DepositBalance[fromConnector.Symbol]` at lines 120-123, but this state is only updated at line 141, AFTER external calls at lines 130 and 133-140. During these external calls, if the base token has a callback, the attacker can reenter with stale balance data.

**Sell Method Vulnerability:** [2](#0-1) 

Similar pattern where price calculation at lines 168-172 uses current balances, but the deposit balance decrement occurs at lines 193-194, AFTER external transfers at lines 183 and 186-192.

**Callback Mechanism:** [3](#0-2) 

The MultiToken contract's `DealWithExternalInfoDuringTransfer` method checks for `TransferCallbackExternalInfoKey` in the token's `ExternalInfo` and makes an external call via `Context.SendInline` to the configured callback contract. This callback is triggered during `TransferFrom` and `Transfer` operations. [4](#0-3) 

The `DoTransferFrom` method calls `DealWithExternalInfoDuringTransfer` after balance modifications, providing the reentrancy window.

**Balance Reading:** [5](#0-4) 

The `GetSelfBalance` method reads `State.DepositBalance[connector.Symbol]` for deposit accounts, which remains stale during reentrant calls before the state update.

**No Protection:**
The TokenConverter contract has no reentrancy guards or mutex mechanisms to prevent reentrant calls during the vulnerable window.

## Impact Explanation

**Direct Financial Loss:**
An attacker exploiting this vulnerability can manipulate the Bancor pricing mechanism by:
1. Initiating a Buy/Sell transaction
2. Receiving a callback during base token transfer
3. Reentering Buy/Sell with stale `State.DepositBalance` values
4. Executing trades at artificially favorable prices based on outdated reserves
5. Repeating the process to compound gains

The Bancor formula's exponential nature amplifies the impact - even small balance discrepancies translate to significant price advantages. With substantial reserves (e.g., millions in base tokens), the attacker can extract considerable value through repeated exploitation.

**Protocol Integrity:**
- Connector reserve ratios become corrupted
- Price discovery mechanism fails
- Legitimate users face unfavorable rates due to depleted reserves
- TokenConverter's core invariant (accurate Bancor pricing reflecting actual reserves) is violated

**Severity: MEDIUM** - While the vulnerability enables direct fund theft and violates critical protocol invariants, exploitation requires a specific precondition: the base token must have `TransferCallbackExternalInfoKey` configured in its `ExternalInfo`. This limits immediate exploitability but doesn't eliminate long-term risk.

## Likelihood Explanation

**Precondition Analysis:**
The vulnerability can only be exploited if the **base token** (typically ELF) has a transfer callback configured. Resource token callbacks cannot exploit this issue because their transfers occur after state updates (Buy line 143, Sell line 196). [6](#0-5) 

Token `ExternalInfo` is set during creation and includes callback configuration. For system tokens like ELF created during genesis, callbacks are unlikely to be configured.

**Likelihood: LOW to MEDIUM**
- **Current State**: Native token (ELF) likely has no callback, making immediate exploitation unlikely
- **Future Risk**: If base token changes, or if callbacks are added for legitimate purposes (compliance, logging), the vulnerability becomes exploitable
- **Structural Nature**: The vulnerability exists permanently in the code and will affect any future configuration where base token has callbacks

**Attack Complexity:**
- Moderate technical sophistication required
- Attacker needs sufficient base tokens to execute profitable trades
- Single-transaction attack makes it atomic and difficult to prevent mid-execution

## Recommendation

Implement the checks-effects-interactions pattern by moving state updates before external calls:

**For Buy Method:**
```
// 1. Calculate amounts
var amountToPay = BancorHelper.GetAmountToPayFromReturn(...);

// 2. Update state FIRST
State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);

// 3. Then make external calls
if (fee > 0) HandleFee(fee);
State.TokenContract.TransferFrom.Send(...);
State.TokenContract.Transfer.Send(...);
```

**For Sell Method:**
```
// 1. Calculate amounts
var amountToReceive = BancorHelper.GetReturnFromPaid(...);

// 2. Update state FIRST
State.DepositBalance[toConnector.Symbol] = State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);

// 3. Then make external calls
if (fee > 0) HandleFee(fee);
State.TokenContract.Transfer.Send(...);
State.TokenContract.TransferFrom.Send(...);
```

Additionally, consider implementing a reentrancy guard pattern using a state variable to track execution:
```
private bool _locked;

private void NonReentrant() 
{
    Assert(!_locked, "Reentrancy detected");
    _locked = true;
}

private void UnlockReentrancy()
{
    _locked = false;
}
```

## Proof of Concept

A complete PoC would require:
1. Creating a custom token with `aelf_transfer_callback` configured in `ExternalInfo` pointing to an attacker contract
2. Configuring this token as the base token in TokenConverter
3. Implementing the attacker contract with a callback method that reenters Buy/Sell
4. Demonstrating price manipulation through balance observation

```csharp
// Conceptual PoC structure:
// 1. Deploy MaliciousCallback contract with Buy reentrancy logic
// 2. Create token with ExternalInfo: {"aelf_transfer_callback": {"ContractAddress": MaliciousCallback, "MethodName": "OnTransfer"}}
// 3. Use as TokenConverter base token
// 4. Call Buy() -> triggers callback -> reenters Buy() with stale balance -> profit

// MaliciousCallback.OnTransfer would contain:
public override Empty OnTransfer(TransferFromInput input)
{
    if (!_reentered) {
        _reentered = true;
        // Reentrant call to TokenConverter.Buy()
        // Observes stale State.DepositBalance before line 141 update
        State.TokenConverter.Buy.Send(new BuyInput { ... });
    }
    return new Empty();
}
```

## Notes

**Critical Clarification:** Only callbacks on the **base token** (not resource tokens) can exploit this vulnerability, as resource token transfers occur after state updates. This significantly limits the attack surface but doesn't eliminate the structural risk. The vulnerability should be fixed regardless of current exploitability to prevent future issues if token configurations change.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-141)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-194)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
```csharp
        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
            Owner = input.Owner
        };
```
