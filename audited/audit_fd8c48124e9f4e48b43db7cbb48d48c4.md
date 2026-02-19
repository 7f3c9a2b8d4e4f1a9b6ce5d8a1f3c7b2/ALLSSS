### Title
Missing Input Validation in GetNeededDeposit Allows Negative AmountToTokenConvert Leading to Incorrect Bancor Reserve Initialization

### Summary
The `GetNeededDeposit` function lacks validation for negative `input.AmountToTokenConvert` values. When a negative value is provided, the arithmetic calculation at line 73 produces an inflated `amountOutOfTokenConvert` that passes the check at line 75, resulting in an incorrectly calculated deposit requirement. This causes `EnableConnector` to initialize the Bancor pricing model with mismatched reserve ratios, breaking critical pricing invariants. [1](#0-0) 

### Finding Description

The vulnerability exists in the `GetNeededDeposit` view function where `input.AmountToTokenConvert` (defined as `int64` in protobuf) is used without validation: [2](#0-1) 

At line 73, the calculation `amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert` treats negative inputs incorrectly. When `AmountToTokenConvert` is negative (e.g., -100), the subtraction becomes addition: `TotalSupply - balance - (-100) = TotalSupply - balance + 100`, artificially inflating the calculated amount. [3](#0-2) 

The inflated value passes the check at line 75, triggering deposit calculation with incorrect parameters: [4](#0-3) 

This incorrect `needDeposit` value is then consumed by `EnableConnector`, which:
1. Transfers the inflated deposit amount of base tokens (lines 277-285)
2. Fails to transfer resource tokens due to the negative value check at line 287
3. Sets `DepositBalance` to the inflated amount (line 297)
4. Enables both connectors despite the broken reserve ratio [5](#0-4) 

The critical issue is at line 287 where `if (input.AmountToTokenConvert > 0)` prevents token transfer for negative values, but the function continues to execute and corrupts state: [6](#0-5) 

### Impact Explanation

**Broken Bancor Invariants:** The Bancor pricing model relies on maintaining correct reserve ratios between base tokens and resource tokens. With negative input, the deposit balance is set based on an inflated calculation while no corresponding resource tokens are transferred to the contract, violating the fundamental pricing invariant.

**State Corruption:** The `DepositBalance` is set to an incorrect value that doesn't match the intended Bancor model parameters. Since `GetSelfBalance` uses `DepositBalance` for deposit connectors, all subsequent pricing calculations will be based on incorrect reserve amounts: [7](#0-6) 

**Operational Impact:** The connector is enabled in a broken state where:
- The deposit reserve is higher than it should be for the actual resource token distribution
- Resource tokens expected to be in the contract are not present (zero transferred)
- Trading operations may fail or execute at incorrect prices
- The protocol's ability to fairly price token swaps is compromised

**Affected Parties:** All users attempting to trade through the misconfigured connector pair, as well as the protocol's economic integrity.

### Likelihood Explanation

**Reachable Entry Point:** `EnableConnector` is a public function with no access control checks, callable by any user for connectors previously added by governance. [8](#0-7) 

**Attack Complexity:** Low - attacker simply needs to call `EnableConnector` with a negative `AmountToTokenConvert` value. The int64 type allows negative values without type-level constraints.

**Preconditions:** A connector pair must exist (added via `AddPairConnector`) but not yet enabled. This is a normal operational state during connector setup.

**Detection:** The vulnerability is difficult to detect as the transaction will succeed, and the broken state only manifests during subsequent trading operations when prices appear incorrect.

**Economic Rationality:** While the immediate attacker cost is paying an inflated deposit, the broken connector initialization could be exploited through:
1. Intentional misconfiguration by malicious token creators
2. Accidental invocation with incorrect parameters
3. Exploitation of mispriced trading opportunities by informed actors

### Recommendation

**Input Validation:** Add explicit validation in `GetNeededDeposit` to ensure `AmountToTokenConvert` is non-negative:

```csharp
public override DepositInfo GetNeededDeposit(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    // ... rest of function
}
```

**Consistent Validation:** Add the same check in `EnableConnector` before calling `GetNeededDeposit`:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    // ... rest of function
}
```

**State Consistency Check:** After enabling, verify that the actual reserves match expected ratios:

```csharp
// After line 295, before line 297
if (input.AmountToTokenConvert > 0) {
    var actualBalance = State.TokenContract.GetBalance.Call(...).Balance;
    Assert(actualBalance >= input.AmountToTokenConvert, 
        "Insufficient tokens transferred to contract.");
}
```

**Test Cases:** Add regression tests for:
- Negative `AmountToTokenConvert` values (should revert)
- Zero `AmountToTokenConvert` (edge case)
- Verification that deposit balance matches expected Bancor ratios after enabling

### Proof of Concept

**Initial State:**
- New token created with `TotalSupply = 1,000,000`
- Token balance in TokenConverter contract: 0
- Connector pair added via `AddPairConnector` but not yet enabled
- Base token (ELF) virtual balance: 10,000

**Attack Sequence:**

1. Attacker calls `EnableConnector` with:
   - `TokenSymbol = "NEWTOKEN"`
   - `AmountToTokenConvert = -500,000` (negative)

2. In `GetNeededDeposit` calculation:
   - `amountOutOfTokenConvert = 1,000,000 - 0 - (-500,000) = 1,500,000` (inflated)
   - Check at line 75: `1,500,000 > 0` passes
   - `BancorHelper.GetAmountToPayFromReturn` calculates deposit for 1,500,000 tokens
   - Returns inflated `needDeposit` (e.g., 15,000 ELF)

3. In `EnableConnector` execution:
   - Lines 277-285: Transfer 15,000 ELF from attacker to contract ✓
   - Line 287: Check `if (-500,000 > 0)` fails, NO NEWTOKEN transferred ✗
   - Line 297: `DepositBalance` set to 15,000 ELF
   - Connectors marked as enabled

**Actual Result:**
- Deposit balance: 15,000 ELF (inflated)
- Resource tokens in contract: 0 (expected: should be proportional to deposit)
- Bancor ratio broken: reserves don't match intended model

**Expected Result:** 
- Transaction should revert with "AmountToTokenConvert must be non-negative"
- No state changes

**Success Condition:**
The vulnerability is confirmed if a transaction with negative `AmountToTokenConvert` completes successfully and sets `DepositBalance` to a non-zero value while transferring zero resource tokens to the contract.

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

**File:** protobuf/token_converter_contract.proto (L179-184)
```text
message ToBeConnectedTokenInfo{
    // The token symbol.
    string token_symbol = 1;
    // Specifies the number of tokens to convert to the TokenConvert contract.
    int64 amount_to_token_convert = 2;
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
