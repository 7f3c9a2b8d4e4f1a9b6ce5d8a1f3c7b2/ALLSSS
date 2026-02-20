# Audit Report

## Title
Missing Access Control and Input Validation in EnableConnector Allows Connector State Corruption and Permanent Denial of Service

## Summary
The `EnableConnector` function lacks authorization checks present in all other administrative functions, allowing any user to enable connectors. Combined with missing input validation for negative `AmountToTokenConvert` values in `GetNeededDeposit`, this enables an attacker to permanently corrupt connector state by inflating the deposit balance while preventing resource token transfer, resulting in irreversible denial of service for all buy and sell operations on that token pair.

## Finding Description

The vulnerability stems from two critical security flaws:

**1. Missing Access Control:** The `EnableConnector` function has no authorization check, unlike all other administrative functions. [1](#0-0) 

Compare this to administrative functions that properly enforce access control:
- `UpdateConnector` [2](#0-1) 
- `AddPairConnector` [3](#0-2) 
- `SetFeeRate` [4](#0-3) 
- `ChangeConnectorController` [5](#0-4) 

**2. Missing Input Validation:** The `AmountToTokenConvert` field is defined as `int64` in the protobuf specification, allowing negative values. [6](#0-5) 

The `GetNeededDeposit` calculation does not validate that `AmountToTokenConvert` is non-negative: [7](#0-6) 

When `AmountToTokenConvert` is negative (e.g., -100), the subtraction becomes addition: `TotalSupply - balance - (-100) = TotalSupply - balance + 100`, artificially inflating `amountOutOfTokenConvert` and causing an inflated deposit calculation via the Bancor formula. [8](#0-7) 

**Attack Execution Path:**

In `EnableConnector`, the inflated deposit is transferred from the attacker: [9](#0-8) 

However, the resource token transfer is skipped because the negative value fails the conditional check: [10](#0-9) 

Despite this mismatch, `DepositBalance` is set to the inflated amount and both connectors are enabled: [11](#0-10) 

## Impact Explanation

**State Corruption:** The connector is enabled with `DepositBalance` set to an inflated value that does not match actual reserves. The `GetSelfBalance` helper uses `DepositBalance` for deposit connectors, [12](#0-11)  meaning all Bancor pricing calculations will use incorrect reserve amounts.

**Denial of Service on Buy Operations:** When users attempt to buy resource tokens, the contract will try to transfer tokens it doesn't possess, causing transaction failures. [13](#0-12) 

**Denial of Service on Sell Operations:** The Bancor formula requires positive connector balances and will throw exceptions if balances are invalid. [14](#0-13) 

**Permanent Protocol Damage:** Once a connector is enabled, the `UpdateConnector` function explicitly prevents modifications to activated connectors. [15](#0-14)  There is no mechanism to disable connectors or reset `DepositBalance`, making the corruption permanent and affecting all users who intended to trade through that token pair.

## Likelihood Explanation

**No Access Control:** The `EnableConnector` function can be called by any address without authorization, as evidenced by test cases showing direct invocation without governance proposals. [16](#0-15) 

Compare this to `AddPairConnector` which requires governance approval. [17](#0-16) 

**Simple Attack Vector:** An attacker only needs to call `EnableConnector` with a negative `AmountToTokenConvert` value. The attack requires no complex setup beyond the connector pair existing but not yet enabled—a standard operational state during token launch preparation.

**Guaranteed Execution:** While the attacker must transfer the inflated deposit amount (self-harm), the protocol damage is disproportionate and permanent, affecting all users of that token pair with no recovery mechanism.

## Recommendation

1. **Add Access Control:** Implement `AssertPerformedByConnectorController()` check at the beginning of `EnableConnector` to match the authorization model of other administrative functions:

```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController();
    // ... rest of function
}
```

2. **Add Input Validation:** Validate that `AmountToTokenConvert` is non-negative in both `GetNeededDeposit` and `EnableConnector`:

```csharp
public override DepositInfo GetNeededDeposit(ToBeConnectedTokenInfo input)
{
    Assert(input.AmountToTokenConvert >= 0, "AmountToTokenConvert must be non-negative.");
    // ... rest of function
}
```

3. **Add Disable Mechanism:** Implement a governance-controlled function to disable corrupted connectors and reset state if needed.

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_NegativeAmount_Corrupts_State()
{
    // Setup: Create token and add connector pair via governance
    var tokenSymbol = "VULN";
    await CreateTokenAsync(tokenSymbol);
    await AddPairConnectorAsync(tokenSymbol);
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Amount = 100_000,
        To = DefaultSender,
        Symbol = tokenSymbol
    });
    
    // Attack: Enable connector with negative AmountToTokenConvert
    var maliciousInput = new ToBeConnectedTokenInfo
    {
        TokenSymbol = tokenSymbol,
        AmountToTokenConvert = -50_000  // Negative value!
    };
    
    // This succeeds without authorization check
    await DefaultStub.EnableConnector.SendAsync(maliciousInput);
    
    // Verify corruption: DepositBalance is inflated but resource tokens not transferred
    var depositBalance = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = tokenSymbol });
    var resourceBalance = await GetBalanceAsync(tokenSymbol, TokenConverterContractAddress);
    
    // DepositBalance is positive (inflated) but resource balance is 0
    depositBalance.Value.ShouldBeGreaterThan(0);
    resourceBalance.ShouldBe(0);
    
    // Verify DoS: Buy operation fails
    var buyResult = await DefaultStub.Buy.SendWithExceptionAsync(new BuyInput
    {
        Symbol = tokenSymbol,
        Amount = 1000
    });
    buyResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L143-149)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L303-305)
```csharp
    public override Empty ChangeConnectorController(AuthorityInfo input)
    {
        AssertPerformedByConnectorController();
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

**File:** protobuf/token_converter_contract.proto (L179-184)
```text
message ToBeConnectedTokenInfo{
    // The token symbol.
    string token_symbol = 1;
    // Specifies the number of tokens to convert to the TokenConvert contract.
    int64 amount_to_token_convert = 2;
}
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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L70-73)
```csharp
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L301-303)
```csharp
            await ExecuteProposalForParliamentTransaction(TokenConverterContractAddress,
                nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.AddPairConnector),
                pairConnector);
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L399-399)
```csharp
        await DefaultStub.EnableConnector.SendAsync(toBeBuildConnectorInfo);
```
