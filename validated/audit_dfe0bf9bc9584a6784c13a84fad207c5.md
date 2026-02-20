# Audit Report

## Title
Missing Input Validation in GetNeededDeposit Allows Negative AmountToTokenConvert Leading to Incorrect Bancor Reserve Initialization

## Summary
The `GetNeededDeposit` function lacks validation for negative `input.AmountToTokenConvert` values, causing an arithmetic error that inflates the calculated deposit requirement. When consumed by `EnableConnector`, this results in permanently corrupted Bancor reserve ratios, breaking pricing for all subsequent trades on the affected connector pair.

## Finding Description

The vulnerability exists in the `GetNeededDeposit` view function where `input.AmountToTokenConvert` is used without validation. The field is defined as `int64` in the protobuf specification, allowing negative values. [1](#0-0) 

The core issue occurs in the arithmetic calculation that treats negative inputs incorrectly. [2](#0-1) 

When `AmountToTokenConvert` is negative (e.g., -100), the subtraction operation becomes addition: `TotalSupply - balance - (-100) = TotalSupply - balance + 100`. This artificially inflates `amountOutOfTokenConvert`, causing it to pass the validation check and trigger Bancor calculations with incorrect parameters. [3](#0-2) 

This inflated `needDeposit` value is then consumed by `EnableConnector`, which is a public function with no access control (unlike other administrative functions that use `AssertPerformedByConnectorController()`). [4](#0-3) 

The critical divergence occurs when `EnableConnector` transfers the inflated deposit amount but skips the resource token transfer. [5](#0-4) 

The conditional at line 287 prevents resource token transfer for negative values, but execution continues, setting the deposit balance to the incorrect inflated amount and enabling both connectors. [6](#0-5) 

This creates a connector pair where:
- Deposit connector: Has inflated balance (attacker's overpayment)
- Resource connector: Has 0 or minimal balance (no tokens transferred)
- Both connectors enabled with broken reserve ratios

The Bancor pricing model depends on `GetSelfBalance` which uses the corrupted `DepositBalance` value for pricing calculations. [7](#0-6) 

## Impact Explanation

**Broken Bancor Invariants:** The Bancor automated market maker requires correct reserve ratios between base and resource tokens. With the deposit balance inflated and resource balance at 0 or minimal levels, the fundamental pricing invariant produces completely incorrect results. The `Buy` and `Sell` operations rely on these balances for price calculation. [8](#0-7) 

**Permanent State Corruption:** Once enabled, connectors cannot be updated due to the protection in `UpdateConnector`. [9](#0-8) 

This means the corrupted state is permanent without governance intervention to potentially deploy new connectors.

**Operational Impact:**
- Buy operations will likely fail or provide extreme prices due to attempting to purchase from near-zero resource balance
- Sell operations will use incorrect pricing due to the inflated deposit balance
- The protocol's ability to fairly price token swaps is compromised for this connector pair
- All users attempting to trade through the misconfigured connector are affected

## Likelihood Explanation

**Reachable Entry Point:** The `EnableConnector` function is public with no authorization checks, callable by any address for connectors previously added by governance. This contrasts with other administrative functions like `UpdateConnector`, `SetFeeRate`, and `AddPairConnector` which all require `AssertPerformedByConnectorController()`. [10](#0-9) 

**Low Attack Complexity:** An attacker simply needs to call `EnableConnector` with a negative `AmountToTokenConvert` value. The `int64` protobuf type allows negative values without type-level constraints.

**Realistic Preconditions:** A connector pair must exist (added via `AddPairConnector`) but not yet be enabled. This is a standard operational state during connector setup, occurring whenever governance adds new trading pairs.

**Economic Rationality:** While the attacker must pay an inflated deposit (self-harm), they achieve permanent corruption of the connector. This could be:
1. Griefing attack to disrupt protocol operations
2. Market manipulation by a malicious token creator
3. Front-running legitimate enablement to force incorrect pricing
4. Accidental misconfiguration due to lack of input validation

**No Detection Barriers:** The transaction succeeds normally with no reverts. The broken state only becomes apparent during subsequent trade attempts when users encounter incorrect prices or failures.

## Recommendation

Add input validation to reject negative `AmountToTokenConvert` values in both `GetNeededDeposit` and `EnableConnector`:

In `GetNeededDeposit`:
```csharp
public override DepositInfo GetNeededDeposit(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    var toConnector = State.Connectors[input.TokenSymbol];
    // ... rest of the method
}
```

In `EnableConnector`:
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    var fromConnector = State.Connectors[input.TokenSymbol];
    // ... rest of the method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_With_Negative_AmountToTokenConvert_Corrupts_Reserves()
{
    // Setup: Initialize contract and create token
    await DefaultStub.Initialize.SendAsync(new InitializeInput { FeeRate = "0.005" });
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol, 1000_000);
    await AddPairConnectorAsync(tokenSymbol);
    
    // Issue tokens to sender for approval
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 1000_000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Approve TokenConverter to spend tokens
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = TokenConverterContractAddress,
        Symbol = "ELF",
        Amount = 1000_000
    });
    
    // Exploit: Call EnableConnector with NEGATIVE AmountToTokenConvert
    var negativeAmount = -1000;
    var depositInfoBefore = await DefaultStub.GetNeededDeposit.CallAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = negativeAmount
        });
    
    // Deposit amount is inflated due to arithmetic error
    depositInfoBefore.NeedAmount.ShouldBeGreaterThan(0);
    
    // Enable connector with negative amount
    var result = await DefaultStub.EnableConnector.SendAsync(
        new ToBeConnectedTokenInfo
        {
            TokenSymbol = tokenSymbol,
            AmountToTokenConvert = negativeAmount
        });
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify corruption: Deposit balance is inflated, resource balance is minimal/zero
    var depositBalance = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol });
    depositBalance.Value.ShouldBe(depositInfoBefore.NeedAmount); // Inflated
    
    var resourceBalance = await GetBalanceAsync(tokenSymbol, TokenConverterContractAddress);
    resourceBalance.ShouldBe(0); // No tokens transferred due to negative amount check
    
    // Connectors are enabled but with broken ratios
    var connector = await DefaultStub.GetPairConnector.CallAsync(
        new TokenSymbol { Symbol = tokenSymbol });
    connector.ResourceConnector.IsPurchaseEnabled.ShouldBeTrue();
    connector.DepositConnector.IsPurchaseEnabled.ShouldBeTrue();
}
```

## Notes

This vulnerability demonstrates a critical input validation failure that leads to permanent state corruption in the TokenConverter contract. The absence of access control on `EnableConnector` combined with the lack of negative value validation creates a publicly exploitable attack vector. The corrupted state cannot be reversed due to the `IsPurchaseEnabled` check in `UpdateConnector`, making this a permanent protocol-level issue affecting all users of the corrupted connector pair.

### Citations

**File:** protobuf/token_converter_contract.proto (L183-183)
```text
    int64 amount_to_token_convert = 2;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-73)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L75-84)
```csharp
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L120-123)
```csharp
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-276)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
        var fromConnector = State.Connectors[input.TokenSymbol];
        Assert(fromConnector != null && !fromConnector.IsDepositAccount,
            "[EnableConnector]Can't find from connector.");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
        var needDeposit = GetNeededDeposit(input);
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L287-300)
```csharp
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L377-378)
```csharp
        if (connector.IsDepositAccount)
            realBalance = State.DepositBalance[connector.Symbol];
```
