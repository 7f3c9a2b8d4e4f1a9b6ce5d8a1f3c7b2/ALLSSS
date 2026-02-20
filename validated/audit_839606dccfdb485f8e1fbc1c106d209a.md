# Audit Report

## Title
Transaction Fee Free Allowance Overflow Causes DoS Due to Missing Sum Validation

## Summary
The MultiToken contract's transaction fee free allowance system allows parliament to configure multiple threshold symbols that grant allowances for the same token. When calculating total allowances, the system sums these values using checked arithmetic without validating that the cumulative sum stays within `long.MaxValue` bounds. If the sum exceeds `long.MaxValue`, an `OverflowException` is thrown during transaction fee charging, causing a denial-of-service for affected users.

## Finding Description

The transaction fee system stores threshold-based free allowance configurations where each threshold symbol can grant free allowances for multiple fee tokens. [1](#0-0) 

When a user qualifies for multiple threshold symbols (by holding sufficient balances in each), the system calculates their total available allowances by iterating through all qualified thresholds and summing the allowance amounts for each fee token. [2](#0-1) 

The summation uses the `.Add()` extension method, which implements checked arithmetic that throws `OverflowException` when the result exceeds type bounds. [3](#0-2) 

Parliament configures these allowances via `ConfigTransactionFeeFreeAllowances`. The validation checks that threshold and refresh_seconds are non-negative, but **does not validate that the sum of allowances across all threshold symbols for any given token stays within `long.MaxValue`**. [4](#0-3) 

The `GetFreeFeeAllowanceAmount` method is called during transaction fee charging through multiple code paths, including base fee calculation [5](#0-4)  and size fee calculation. [6](#0-5) 

When overflow occurs, the exception propagates through the call stack starting from `ChargeTransactionFees`, causing the entire transaction fee charging operation to fail. [7](#0-6) 

Test evidence confirms that multiple threshold symbols granting allowances for the same token is a supported design pattern, where both ELF and USDT thresholds can grant allowances for the same NativeTokenSymbol. [8](#0-7) 

The SafeMath tests confirm that operations exceeding `long.MaxValue` throw `OverflowException`. [9](#0-8) 

## Impact Explanation

Users who hold sufficient balances to qualify for multiple threshold symbols, where the cumulative allowances for any fee token exceed `long.MaxValue`, experience complete denial-of-service. Every transaction they attempt to submit will fail during the pre-execution fee charging phase with an `OverflowException`.

This breaks the availability guarantee of the system - users cannot perform ANY on-chain transactions including transfers, contract calls, or governance participation. While no funds are lost, the operational disruption is complete for affected users.

The impact is severe for affected users but limited in scope to those qualifying for multiple high-value thresholds. The issue is reversible through parliament reconfiguration.

## Likelihood Explanation

**Preconditions:**
- Parliament must configure multiple threshold symbols
- The cumulative allowances for at least one fee token must exceed `long.MaxValue` (9,223,372,036,854,775,807)
- A user must hold sufficient balances to qualify for multiple thresholds

**Feasibility Assessment:**

With tokens using 8 decimals, `long.MaxValue` represents approximately 92.2 billion tokens. Realistic scenarios:

1. Parliament configures 10 threshold symbols, each granting 10 billion tokens allowance → Total: 100 billion > 92.2 billion
2. Parliament configures 100 threshold symbols, each granting 1 billion tokens → Total: 100 billion > 92.2 billion

While parliament is a trusted governance body, configuration errors are realistic due to:
- Human error when setting allowance values
- Thinking in "human-readable" amounts without considering decimal precision  
- Lack of warnings or validation when configuring
- No tooling to preview cumulative effects across thresholds

The test suite demonstrates that multiple thresholds for the same token is an intended feature, making this scenario architecturally supported but mathematically unsafe.

## Recommendation

Add validation in `ConfigTransactionFeeFreeAllowances` to verify that the cumulative sum of allowances for each fee token across all configured threshold symbols does not exceed `long.MaxValue`:

```csharp
// After line 1262, before storing the configuration:
var cumulativeAllowances = new Dictionary<string, long>();

foreach (var thresholdSymbol in State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols)
{
    var existingConfig = State.TransactionFeeFreeAllowancesConfigMap[thresholdSymbol];
    if (existingConfig?.FreeAllowances?.Map != null)
    {
        foreach (var (feeSymbol, allowance) in existingConfig.FreeAllowances.Map)
        {
            if (!cumulativeAllowances.ContainsKey(feeSymbol))
                cumulativeAllowances[feeSymbol] = 0;
            
            // Check if adding this allowance would overflow
            Assert(long.MaxValue - cumulativeAllowances[feeSymbol] >= allowance.Amount,
                $"Cumulative allowances for {feeSymbol} would exceed long.MaxValue");
            
            cumulativeAllowances[feeSymbol] = cumulativeAllowances[feeSymbol].Add(allowance.Amount);
        }
    }
}

// Include new configuration in the check
foreach (var allowance in allowances.TransactionFeeFreeAllowances!.Value!)
{
    if (!cumulativeAllowances.ContainsKey(allowance.Symbol))
        cumulativeAllowances[allowance.Symbol] = 0;
    
    Assert(long.MaxValue - cumulativeAllowances[allowance.Symbol] >= allowance.Amount,
        $"Cumulative allowances for {allowance.Symbol} would exceed long.MaxValue");
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ConfigTransactionFeeFreeAllowances_Overflow_DoS_Test()
{
    await SetPrimaryTokenSymbolAsync();
    await CreateTokenAsync(DefaultSender, "THRESHOLD1");
    await CreateTokenAsync(DefaultSender, "THRESHOLD2");
    
    // Issue tokens so user qualifies for both thresholds
    await IssueTokenToDefaultSenderAsync("THRESHOLD1", 1_00000000);
    await IssueTokenToDefaultSenderAsync("THRESHOLD2", 1_00000000);
    
    // Configure two thresholds, each granting allowances that sum to > long.MaxValue
    long allowancePerThreshold = long.MaxValue / 2 + 1; // Each > 50% of max
    
    await TokenContractImplStub.ConfigTransactionFeeFreeAllowances.SendAsync(
        new ConfigTransactionFeeFreeAllowancesInput
        {
            Value =
            {
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "THRESHOLD1",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value =
                        {
                            new TransactionFeeFreeAllowance
                            {
                                Symbol = NativeTokenSymbol,
                                Amount = allowancePerThreshold
                            }
                        }
                    },
                    RefreshSeconds = 600,
                    Threshold = 1_00000000
                },
                new ConfigTransactionFeeFreeAllowance
                {
                    Symbol = "THRESHOLD2",
                    TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                    {
                        Value =
                        {
                            new TransactionFeeFreeAllowance
                            {
                                Symbol = NativeTokenSymbol,
                                Amount = allowancePerThreshold
                            }
                        }
                    },
                    RefreshSeconds = 600,
                    Threshold = 1_00000000
                }
            }
        });
    
    // Set method fee
    await TokenContractImplStub.SetMethodFee.SendAsync(new MethodFees
    {
        MethodName = nameof(TokenContractContainer.TokenContractStub.Transfer),
        Fees = { new MethodFee { Symbol = NativeTokenSymbol, BasicFee = 100 } }
    });
    
    // Attempt to charge transaction fee - should throw OverflowException
    var chargeInput = new ChargeTransactionFeesInput
    {
        MethodName = nameof(TokenContractContainer.TokenContractStub.Transfer),
        ContractAddress = TokenContractAddress
    };
    
    var exception = await Assert.ThrowsAsync<Exception>(() => 
        TokenContractStub.ChargeTransactionFees.SendAsync(chargeInput));
    
    exception.Message.ShouldContain("Overflow");
}
```

### Citations

**File:** protobuf/token_contract_impl.proto (L384-393)
```text
message TransactionFeeFreeAllowanceConfig {
    string symbol = 1;
    TransactionFeeFreeAllowanceMap free_allowances = 2;
    int64 refresh_seconds = 3;
    int64 threshold = 4;
}

message TransactionFeeFreeAllowanceMap {
    map<string, TransactionFeeFreeAllowance> map = 1;
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L179-194)
```csharp
    private long GetFreeFeeAllowanceAmount(TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, string symbol)
    {
        var allowance = 0L;
        var map = transactionFeeFreeAllowancesMap.Map;

        if (map == null) return allowance;

        foreach (var freeAllowances in map.Values)
        {
            freeAllowances.Map.TryGetValue(symbol, out var freeAllowance);

            allowance = allowance.Add(freeAllowance?.Amount ?? 0L);
        }

        return allowance;
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L100-106)
```csharp
    public static long Add(this long a, long b)
    {
        checked
        {
            return a + b;
        }
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L24-53)
```csharp
    public override ChargeTransactionFeesOutput ChargeTransactionFees(ChargeTransactionFeesInput input)
    {
        Context.LogDebug(() => "ChargeTransactionFees Start");
        AssertPermissionAndInput(input);
        // Primary token not created yet.
        if (State.ChainPrimaryTokenSymbol.Value == null)
        {
            return new ChargeTransactionFeesOutput { Success = true };
        }

        // Record tx fee bill during current charging process.
        var bill = new TransactionFeeBill();
        var allowanceBill = new TransactionFreeFeeAllowanceBill();
        var fromAddress = Context.Sender;
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L456-459)
```csharp
        availableAllowance = symbolChargedForBaseFee == symbolToPayTxFee
            ? GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbolToPayTxFee)
                .Sub(amountChargedForBaseAllowance)
            : GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbolToPayTxFee);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L747-767)
```csharp
    private bool TryToChargeUserBaseFee(Dictionary<string, long> symbolToAmountMap, Address fromAddress,
        TransactionFeeFreeAllowancesMap transactionFeeFreeAllowancesMap, out long amount,
        out string symbolOfValidBalance, out long existingBalance, out long existingAllowance)
    {
        // priority: enough allowance -> symbolWithEnoughBalancePlusAllowance -> symbolWithEnoughBalance -> symbolWithAnything
        symbolOfValidBalance = null;
        string symbolWithAnything = null;
        string symbolWithEnoughBalance = null;
        string symbolWithEnoughBalancePlusAllowance = null;

        amount = 0;
        existingBalance = 0;
        existingAllowance = 0;
        //For user
        //Find the token that satisfies the balance of the fee,if there is no token that satisfies the balance of the fee, find the token that balance > 0
        foreach (var (symbol, value) in symbolToAmountMap)
        {
            // current token symbol
            amount = value;
            existingBalance = GetBalance(fromAddress, symbol);
            existingAllowance = GetFreeFeeAllowanceAmount(transactionFeeFreeAllowancesMap, symbol);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1224-1266)
```csharp
    public override Empty ConfigTransactionFeeFreeAllowances(ConfigTransactionFeeFreeAllowancesInput input)
    {
        AssertSenderAddressWith(GetDefaultParliamentController().OwnerAddress);
        Assert(input.Value != null && input.Value.Count > 0, "Invalid input");

        State.TransactionFeeFreeAllowancesSymbolList.Value ??= new TransactionFeeFreeAllowancesSymbolList
        {
            Symbols = { new RepeatedField<string>() }
        };

        foreach (var allowances in input.Value!)
        {
            ValidateToken(allowances.Symbol);
            Assert(
                allowances.TransactionFeeFreeAllowances?.Value != null &&
                allowances.TransactionFeeFreeAllowances.Value.Count > 0,
                "Invalid input allowances");
            Assert(allowances.Threshold >= 0, "Invalid input threshold");
            Assert(allowances.RefreshSeconds >= 0, "Invalid input refresh seconds");

            var config = new TransactionFeeFreeAllowanceConfig
            {
                Symbol = allowances.Symbol,
                Threshold = allowances.Threshold,
                RefreshSeconds = allowances.RefreshSeconds,
                FreeAllowances = new TransactionFeeFreeAllowanceMap()
            };

            foreach (var allowance in allowances.TransactionFeeFreeAllowances!.Value!)
            {
                config.FreeAllowances.Map.TryAdd(allowance.Symbol, allowance);
            }

            State.TransactionFeeFreeAllowancesConfigMap[allowances.Symbol] = config;

            if (!State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols.Contains(allowances.Symbol))
            {
                State.TransactionFeeFreeAllowancesSymbolList.Value.Symbols.Add(allowances.Symbol);
            }
        }

        return new Empty();
    }
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest_FreeAllowance.cs (L574-614)
```csharp
        await TokenContractImplStub.ConfigTransactionFeeFreeAllowances.SendAsync(
            new ConfigTransactionFeeFreeAllowancesInput
            {
                Value =
                {
                    new ConfigTransactionFeeFreeAllowance
                    {
                        Symbol = NativeTokenSymbol,
                        TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                        {
                            Value =
                            {
                                new TransactionFeeFreeAllowance
                                {
                                    Symbol = NativeTokenSymbol,
                                    Amount = freeAmountELF
                                }
                            }
                        },
                        RefreshSeconds = refreshSecondsELF,
                        Threshold = thresholdELF
                    },
                    new ConfigTransactionFeeFreeAllowance
                    {
                        Symbol = USDT,
                        TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                        {
                            Value =
                            {
                                new TransactionFeeFreeAllowance
                                {
                                    Symbol = NativeTokenSymbol,
                                    Amount = freeAmountUSDT
                                }
                            }
                        },
                        RefreshSeconds = refreshSecondsUSDT,
                        Threshold = thresholdUSDT
                    }
                }
            });
```

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L63-66)
```csharp
        number1.Add(5).ShouldBe(11UL);
        number2.Add(5).ShouldBe(11L);
        Should.Throw<OverflowException>(() => { long.MaxValue.Add(8); });
        Should.Throw<OverflowException>(() => { ulong.MaxValue.Add(8); });
```
