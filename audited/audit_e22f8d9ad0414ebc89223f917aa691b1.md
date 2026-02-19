### Title
Treasury Accepts Unfavorable Prices Due to Missing Slippage Protection on Token Conversion

### Summary
The Treasury contract converts donated non-native tokens to native tokens by calling TokenConverterContract.Sell without specifying a `ReceiveLimit` parameter for slippage protection. This allows attackers to front-run donation transactions with price-manipulating swaps, causing Treasury to accept arbitrarily unfavorable exchange rates and lose significant value on each conversion.

### Finding Description

When users donate non-native tokens to Treasury, the `Donate` method checks if the token can be converted to the native token and calls `ConvertToNativeToken` to perform the conversion. [1](#0-0) 

The `ConvertToNativeToken` method calls `TokenConverterContract.Sell` with only the `Symbol` and `Amount` parameters, omitting the `ReceiveLimit` parameter: [2](#0-1) 

The `ReceiveLimit` parameter in `SellInput` is designed to provide slippage protection - it specifies the minimum amount of base tokens that must be received, or the transaction reverts with "Price not good": [3](#0-2) 

In the TokenConverter's `Sell` method, when `ReceiveLimit` is not set (defaults to 0), the price check is bypassed: [4](#0-3) 

The TokenConverter uses Bancor pricing which is deterministic and based on current connector balances. The price calculation directly depends on the ratio of connector balances: [5](#0-4) 

### Impact Explanation

**Direct Financial Loss to Treasury**: Each time non-native tokens are donated and converted, an attacker can manipulate the Bancor connector balances through front-running to worsen the exchange rate. For example:
- Expected conversion: 1000 RESOURCE tokens → 100,000 ELF at fair price
- After price manipulation: 1000 RESOURCE tokens → 50,000 ELF
- Treasury loses 50,000 ELF in value per transaction

The loss magnitude depends on:
1. The amount of tokens being donated (larger donations = larger absolute losses)
2. The liquidity depth in the connector (lower liquidity = easier to manipulate)
3. The attacker's capital (more capital = larger price impact possible)

This vulnerability affects every donation of non-native convertible tokens to Treasury, which is a core economic mechanism in the AElf ecosystem. The cumulative impact across all donations could result in significant value leakage from Treasury reserves, directly harming the protocol's economic sustainability and reducing rewards available for miners, voters, and other stakeholders.

### Likelihood Explanation

**High Likelihood - Attack is Practical and Economically Rational**:

1. **Reachable Entry Point**: The `Donate` method is public and can be called by anyone. The attack doesn't require privileged access. [6](#0-5) 

2. **Observable Transactions**: Pending donation transactions are visible in the mempool before execution, giving attackers the opportunity to front-run with price-manipulating swaps.

3. **Deterministic Exploitation**: The Bancor pricing formula is deterministic and publicly calculable. Attackers can precisely compute the required manipulation to achieve desired price impact.

4. **No Access Controls**: Anyone can execute swaps on TokenConverter to manipulate connector balances. The only cost is transaction fees and capital requirements.

5. **Profitable Attack**: Attackers can:
   - Front-run: Buy resource tokens (depleting connector balance, worsening sell price)
   - Wait: Treasury's sell executes at manipulated unfavorable price
   - Back-run: Sell resource tokens back, potentially profiting from arbitrage
   - Net result: Treasury loses value, attacker may gain or break even after fees

6. **Repeatable**: The attack can be executed on every donation transaction, making it a persistent vulnerability rather than a one-time exploit.

### Recommendation

**Immediate Fix**: Modify `ConvertToNativeToken` to calculate and specify an appropriate `ReceiveLimit` based on a reasonable slippage tolerance:

```csharp
private void ConvertToNativeToken(string symbol, long amount)
{
    State.TokenContract.Approve.Send(new ApproveInput
    {
        Spender = State.TokenConverterContract.Value,
        Symbol = symbol,
        Amount = amount
    });

    // Query expected return amount
    var expectedReturn = State.TokenConverterContract.GetExpectedReturn.Call(new GetExpectedReturnInput
    {
        Symbol = symbol,
        Amount = amount,
        IsBuy = false
    });
    
    // Set minimum acceptable return with slippage tolerance (e.g., 1-2%)
    var minReceiveLimit = expectedReturn.Value.Mul(98).Div(100); // 2% slippage tolerance

    State.TokenConverterContract.Sell.Send(new SellInput
    {
        Symbol = symbol,
        Amount = amount,
        ReceiveLimit = minReceiveLimit
    });

    Context.SendInline(Context.Self, nameof(DonateAll), new DonateAllInput
    {
        Symbol = Context.Variables.NativeSymbol
    });
}
```

**Additional Recommendations**:
1. Add a configurable slippage tolerance parameter controlled by Treasury governance
2. Implement view methods in TokenConverter to preview expected returns before executing swaps
3. Add integration tests that verify slippage protection works correctly under adverse price conditions
4. Consider time-weighted average pricing or other MEV-resistant pricing mechanisms for critical protocol operations

**Test Case to Add**:
Create a test that simulates price manipulation by executing a large swap before Treasury's donation, then verifies that Treasury's conversion reverts due to the ReceiveLimit protection.

### Proof of Concept

**Initial State**:
- TokenConverter has connector with 1,000,000 ELF and 10,000 RESOURCE tokens
- Normal exchange rate: 1 RESOURCE = 100 ELF
- User prepares to donate 1,000 RESOURCE tokens to Treasury

**Attack Sequence**:

1. **Attacker monitors mempool** and sees pending donation transaction of 1,000 RESOURCE tokens

2. **Attacker front-runs** with transaction:
   - Calls `TokenConverter.Buy` to purchase 5,000 RESOURCE tokens
   - This depletes RESOURCE balance to 5,000 and increases ELF balance
   - Price of RESOURCE increases significantly due to Bancor curve

3. **Victim's donation executes**:
   - Calls `Treasury.Donate` with 1,000 RESOURCE tokens
   - Treasury calls `ConvertToNativeToken(RESOURCE, 1000)`
   - Calls `TokenConverter.Sell(RESOURCE, 1000, ReceiveLimit=0)`
   - Due to manipulated balances, receives only ~50,000 ELF instead of expected ~100,000 ELF
   - Transaction succeeds because `ReceiveLimit=0` bypasses price validation

4. **Expected Result**: Treasury should receive ~100,000 ELF (minus small fee)

5. **Actual Result**: Treasury receives only ~50,000 ELF due to manipulated price

6. **Attack Success Condition**: Treasury's conversion completes at unfavorable price, and attacker can optionally back-run to restore price and capture arbitrage profit

**Notes**

The vulnerability exists because Treasury trusts TokenConverter's price without validation. While TokenConverter itself has slippage protection mechanisms via the `ReceiveLimit` parameter (as demonstrated in test cases [7](#0-6) ), Treasury fails to utilize this protection when converting donated tokens. The special fee exemption for Treasury [8](#0-7)  does not provide price protection, only fee savings.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L174-176)
```csharp
    public override Empty Donate(DonateInput input)
    {
        Assert(input.Amount > 0, "Invalid amount of donating. Amount needs to be greater than 0.");
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L180-180)
```csharp
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

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterContractTests.cs (L338-346)
```csharp
        var sellResultPriceNotGood = (await DefaultStub.Sell.SendWithExceptionAsync(
            new SellInput
            {
                Symbol = WriteConnector.Symbol,
                Amount = 1000L,
                ReceiveLimit = 2000L
            })).TransactionResult;
        sellResultPriceNotGood.Status.ShouldBe(TransactionResultStatus.Failed);
        sellResultPriceNotGood.Error.Contains("Price not good.").ShouldBeTrue();
```
