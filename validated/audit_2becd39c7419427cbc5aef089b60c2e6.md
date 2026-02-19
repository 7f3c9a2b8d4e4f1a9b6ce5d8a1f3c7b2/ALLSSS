# Audit Report

## Title
Treasury Accepts Unfavorable Prices Due to Missing Slippage Protection on Token Conversion

## Summary
The Treasury contract lacks slippage protection when converting donated non-native tokens to native tokens, allowing attackers to manipulate exchange rates through front-running and causing direct financial losses to the protocol's Treasury reserves.

## Finding Description

When users donate non-native tokens to Treasury, the `Donate` method converts them to native tokens by calling the internal `ConvertToNativeToken` helper function. [1](#0-0) 

The `ConvertToNativeToken` method calls `TokenConverterContract.Sell` but only provides the `Symbol` and `Amount` parameters, completely omitting the `ReceiveLimit` parameter that provides slippage protection: [2](#0-1) 

The `SellInput` message defines `receive_limit` as a field specifically designed for slippage protection - it specifies the minimum amount of base tokens that must be received, or the transaction fails: [3](#0-2) 

In the TokenConverter's `Sell` method, the price check logic explicitly bypasses validation when `ReceiveLimit` is zero (the default value): [4](#0-3) 

The TokenConverter uses the Bancor pricing formula which is deterministic and directly depends on connector balance ratios. An attacker can manipulate these balances through normal Buy/Sell operations: [5](#0-4) 

**Attack Flow**: When an attacker observes a pending Treasury donation transaction in the mempool, they can front-run it by executing a Buy transaction to deplete the connector balance, artificially worsening the sell price. Treasury's Sell then executes at this manipulated unfavorable rate. The attacker can subsequently back-run to restore balances or realize arbitrage profits, while the Treasury suffers a permanent value loss.

## Impact Explanation

This vulnerability causes **direct financial loss to the AElf Treasury**, which is the protocol's main profit distribution scheme. The Treasury is exempt from conversion fees [6](#0-5)  but this fee exemption does not prevent price manipulation attacks.

Each time a non-native token donation is converted, the Treasury receives less native tokens than the fair market value would provide. The magnitude of loss depends on:
- The donation amount (larger donations = larger absolute losses)
- Connector liquidity depth (lower liquidity = easier manipulation)
- Attacker capital availability (more capital = greater price impact)

Since donations are a core economic mechanism for funding miner rewards, voter welfare, and other ecosystem incentives, cumulative value leakage directly harms protocol sustainability and reduces benefits for all stakeholders.

## Likelihood Explanation

This attack has **high likelihood** because:

1. **Public Entry Point**: The `Donate` method is public and can be invoked by anyone without special privileges [7](#0-6) 

2. **Observable Transactions**: Donation transactions are visible in the mempool before block inclusion, providing attackers the opportunity to front-run

3. **Deterministic Exploitation**: The Bancor formula is fully deterministic and publicly known, allowing attackers to precisely calculate the manipulation needed to achieve desired price impact

4. **No Access Controls**: Anyone can execute Buy/Sell operations on TokenConverter to manipulate connector balances - the only barriers are transaction fees and capital requirements

5. **Economic Rationality**: The attack is economically viable - attackers may profit from arbitrage or at minimum break even after covering gas costs, while Treasury always loses value

6. **Repeatable**: The vulnerability can be exploited on every non-native token donation, making it a persistent systemic risk rather than a one-time exploit

## Recommendation

Add slippage protection by calculating and passing a minimum acceptable `ReceiveLimit` to the TokenConverter's Sell method. The fix should:

1. Query the expected return amount before executing the sell
2. Apply a reasonable slippage tolerance (e.g., 2-5%)
3. Pass the calculated minimum as `ReceiveLimit`

Example fix for `ConvertToNativeToken`:

```csharp
private void ConvertToNativeToken(string symbol, long amount)
{
    // Query expected return to calculate minimum acceptable amount
    var connector = State.TokenConverterContract.GetPairConnector.Call(new TokenSymbol { Symbol = symbol });
    var expectedReturn = CalculateExpectedReturn(connector, amount); // Helper to use Bancor formula
    var minimumReturn = expectedReturn.Mul(95).Div(100); // 5% slippage tolerance
    
    State.TokenContract.Approve.Send(new ApproveInput
    {
        Spender = State.TokenConverterContract.Value,
        Symbol = symbol,
        Amount = amount
    });

    State.TokenConverterContract.Sell.Send(new SellInput
    {
        Symbol = symbol,
        Amount = amount,
        ReceiveLimit = minimumReturn  // Add slippage protection
    });

    Context.SendInline(Context.Self, nameof(DonateAll), new DonateAllInput
    {
        Symbol = Context.Variables.NativeSymbol
    });
}
```

Alternatively, implement a TWAP (Time-Weighted Average Price) oracle or require donations to be executed at specific intervals with price validation.

## Proof of Concept

The following test demonstrates that Treasury's conversion accepts any price when ReceiveLimit is not set:

```csharp
[Fact]
public async Task Treasury_Donation_Vulnerable_To_Price_Manipulation()
{
    // Setup: Initialize contracts and create convertible token connector
    await InitializeContracts();
    var resourceToken = "RESOURCE";
    await SetupTokenConnector(resourceToken);
    
    // Step 1: Record initial connector balances
    var initialDepositBalance = await GetConnectorBalance(resourceToken);
    
    // Step 2: Attacker front-runs by buying resource tokens to deplete connector
    await TokenConverterStub.Buy.SendAsync(new BuyInput
    {
        Symbol = resourceToken,
        Amount = 10000L  // Large buy to manipulate price
    });
    
    // Step 3: Treasury donation executes at manipulated price
    var donationAmount = 1000L;
    await IssueTokens(TreasuryDonor, resourceToken, donationAmount);
    var treasuryBalanceBefore = await GetTreasuryNativeBalance();
    
    await TreasuryStub.Donate.SendAsync(new DonateInput
    {
        Symbol = resourceToken,
        Amount = donationAmount
    });
    
    var treasuryBalanceAfter = await GetTreasuryNativeBalance();
    var actualReceived = treasuryBalanceAfter - treasuryBalanceBefore;
    
    // Step 4: Calculate what should have been received at fair price
    var fairPrice = CalculateFairPrice(initialDepositBalance, resourceToken);
    var expectedReceived = donationAmount * fairPrice;
    
    // Assert: Treasury received significantly less than fair value
    actualReceived.ShouldBeLessThan(expectedReceived.Mul(90).Div(100)); // Lost >10%
}
```

## Notes

- The vulnerability exists because Treasury assumes honest pricing from TokenConverter, but TokenConverter's pricing is manipulable through public trading operations
- While Treasury is exempt from conversion fees, this exemption does not provide any protection against price manipulation
- The existing test suite does not validate that conversions receive fair prices - tests only check that transactions succeed
- This is distinct from general MEV concerns as it affects protocol-owned funds (Treasury) rather than user transactions

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L174-174)
```csharp
    public override Empty Donate(DonateInput input)
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L204-208)
```csharp
        var needToConvert = !isNativeSymbol && canExchangeWithNativeSymbol;
        if (needToConvert)
        {
            ConvertToNativeToken(input.Symbol, input.Amount);
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L676-680)
```csharp
        State.TokenConverterContract.Sell.Send(new SellInput
        {
            Symbol = symbol,
            Amount = amount
        });
```

**File:** protobuf/token_converter_contract.proto (L135-143)
```text
message SellInput {
    // The token symbol you want to sell.
    string symbol = 1;
    // The amount you want to sell.
    int64 amount = 2;
    // Limits on tokens obtained by selling. If the token obtained is less than this value, the sale will be abandoned.
    // And 0 is no limit.
    int64 receive_limit = 3;
}
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L176-177)
```csharp
        if (Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName)) fee = 0;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L179-180)
```csharp
        var amountToReceiveLessFee = amountToReceive.Sub(fee);
        Assert(input.ReceiveLimit == 0 || amountToReceiveLessFee >= input.ReceiveLimit, "Price not good.");
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L34-54)
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
```
