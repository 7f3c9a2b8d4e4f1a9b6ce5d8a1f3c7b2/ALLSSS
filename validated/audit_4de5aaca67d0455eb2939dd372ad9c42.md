# Audit Report

## Title
Precision Loss in Bancor Formula Causes Zero Token Return for Small Trades with Large Connector Balances

## Summary
The `GetReturnFromPaid` function performs integer truncation that causes zero token returns when connector balances are large relative to payment amounts. Users who set `ReceiveLimit = 0` (documented as "no limit") will lose their tokens without receiving anything in return, as the transaction succeeds despite returning zero base tokens.

## Finding Description

The vulnerability exists in the Bancor formula implementation when calculating token returns. When connector weights are equal, the simplified formula casts a decimal calculation directly to `long`: [1](#0-0) 

When `fromConnectorBalance` is much larger than `paidAmount`, the decimal result becomes less than 1.0, which truncates to 0 upon casting to `long`.

**Realistic protocol initialization values create immediate vulnerability:**

Resource tokens are initialized with total supply of 500,000,000 tokens (with 8 decimals): [2](#0-1) 

The entire supply is issued to the TokenConverter contract: [3](#0-2) 

Native token deposit connector virtual balance is initialized at 10,000,000 ELF: [4](#0-3) 

This creates the vulnerable state where selling small amounts of resource tokens (fromConnectorBalance ≈ 500_000_000_00000000) against the native deposit (toConnectorBalance ≈ 10_000_000_00000000) results in truncation to zero.

**Execution path in Sell():**

The `Sell()` method calls `GetReturnFromPaid` to calculate returns: [5](#0-4) 

The protection check validates against user-specified limits: [6](#0-5) 

Per the protocol specification, `ReceiveLimit = 0` means "no limit": [7](#0-6) 

When `amountToReceive = 0` and user sets `ReceiveLimit = 0`, the assertion `0 == 0 || 0 >= 0` passes. The transaction then transfers 0 base tokens to the user: [8](#0-7) 

But still transfers the user's tokens to the contract: [9](#0-8) 

Result: User loses tokens, receives nothing.

## Impact Explanation

**Direct Fund Loss:** Users permanently lose their sold tokens while receiving zero base tokens in return. This violates the fundamental protocol invariant that valid trades should return proportional value.

**Severity:** High impact because:
- Funds are permanently lost with no recovery mechanism
- The transaction succeeds without error or warning
- Users following documented behavior (`ReceiveLimit = 0` for "no limit") are vulnerable
- The issue exists from genesis initialization and affects all resource tokens
- As connector balances grow through normal protocol operation, increasingly larger trades will return zero

## Likelihood Explanation

**High Likelihood:**
- No attacker required - this occurs naturally through normal protocol usage
- Connector balances are initialized at problematic levels from genesis
- Users commonly set `ReceiveLimit = 0` following the documented "no limit" interpretation
- For resource token trades with amounts below ~50 smallest units, zero returns occur immediately

**Triggering Conditions:**
1. Connector balances at initialization values (guaranteed from genesis)
2. User makes small trade where `paidAmount` results in decimal calculation < 1.0
3. User sets `ReceiveLimit = 0` or any value ≤ actual zero return

## Recommendation

Implement minimum return validation regardless of `ReceiveLimit` value:

```csharp
// In TokenConverterContract.cs Sell() method, after line 172:
Assert(amountToReceive > 0, "Trade amount too small, would result in zero return.");

// Or modify line 180 to:
Assert(input.ReceiveLimit == 0 ? amountToReceiveLessFee > 0 : amountToReceiveLessFee >= input.ReceiveLimit, 
    "Price not good.");
```

Additionally, consider using higher-precision arithmetic in BancorHelper to reduce truncation, or implement minimum trade size limits.

## Proof of Concept

```csharp
[Fact]
public async Task Sell_SmallAmount_ReturnsZero_UserLosesFunds_Test()
{
    // Setup: Initialize converter with realistic values matching mainnet
    await InitializeTokenConverterWithMainnetValues();
    
    // Create and issue resource token (e.g., WRITE) with total supply to converter
    await CreateResourceToken("WRITE", 500_000_000_00000000);
    
    // Setup native token deposit connector with realistic virtual balance
    await SetupNativeDepositConnector("NTWRITE", 10_000_000_00000000);
    
    var userInitialBalance = await GetBalanceAsync("WRITE", DefaultSender);
    var userInitialElfBalance = await GetBalanceAsync("ELF", DefaultSender);
    
    // User attempts to sell small amount (50 smallest units) with ReceiveLimit = 0 (no limit)
    var sellResult = await DefaultStub.Sell.SendAsync(new SellInput
    {
        Symbol = "WRITE",
        Amount = 50, // Small amount that will truncate to 0
        ReceiveLimit = 0 // User sets 0 meaning "no limit" per documentation
    });
    
    sellResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Transaction succeeds!
    
    var userFinalBalance = await GetBalanceAsync("WRITE", DefaultSender);
    var userFinalElfBalance = await GetBalanceAsync("ELF", DefaultSender);
    
    // Assert: User lost WRITE tokens but received 0 ELF
    userFinalBalance.ShouldBe(userInitialBalance - 50); // User lost 50 WRITE tokens
    userFinalElfBalance.ShouldBe(userInitialElfBalance); // User received 0 ELF (no change)
    
    // Vulnerability confirmed: User permanently lost tokens with zero return
}
```

## Notes

This vulnerability is particularly severe because:
1. It affects the TokenConverter contract from genesis initialization
2. The documented behavior (`ReceiveLimit = 0` = "no limit") is what makes users vulnerable
3. The truncation threshold varies with connector balance ratios, affecting increasingly larger trades as balances grow
4. There is no warning or revert - the transaction succeeds silently with zero return

### Citations

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L47-49)
```csharp
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L11-11)
```csharp
    public const long ResourceTokenTotalSupply = 500_000_000_00000000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L20-20)
```csharp
    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L96-102)
```csharp
            State.TokenContract.Issue.Send(new IssueInput
            {
                Symbol = resourceTokenSymbol,
                Amount = EconomicContractConstants.ResourceTokenTotalSupply,
                To = tokenConverter,
                Memo = "Initialize for resource trade"
            });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L180-180)
```csharp
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-192)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L196-203)
```csharp
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = input.Symbol,
                From = Context.Sender,
                To = Context.Self,
                Amount = input.Amount
            });
```

**File:** protobuf/token_converter_contract.proto (L140-142)
```text
    // Limits on tokens obtained by selling. If the token obtained is less than this value, the sale will be abandoned.
    // And 0 is no limit.
    int64 receive_limit = 3;
```
