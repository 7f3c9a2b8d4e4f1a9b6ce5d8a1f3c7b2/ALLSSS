# Audit Report

## Title
Missing Negative Amount Validation in Transaction Fee Free Allowances Configuration Causes User Overcharging

## Summary
The `ConfigTransactionFeeFreeAllowances()` function fails to validate that allowance amounts are non-negative. When negative amounts are configured by the parliament controller, users are overcharged during fee deduction due to arithmetic subtraction of negative values, causing direct fund loss proportional to the negative allowance magnitude.

## Finding Description

The vulnerability exists in `ConfigTransactionFeeFreeAllowances()` which validates threshold and refresh time parameters but omits validation for allowance amounts themselves. [1](#0-0) 

The function validates `threshold >= 0` and `refresh_seconds >= 0` at lines 1241-1242, but the loop at lines 1252-1254 adds allowances to configuration without validating that `allowance.Amount >= 0`. The protobuf definition confirms `amount` is `int64` (signed integer): [2](#0-1) 

When users meet the threshold balance, `SetOrRefreshTransactionFeeFreeAllowances()` clones configured allowances (including negative values) to user state: [3](#0-2) 

The aggregation function `GetFreeFeeAllowanceAmount()` sums all allowances including negative values: [4](#0-3) 

During fee charging, `ChargeBaseFee()` performs arithmetic that causes overcharging. When `existingAllowance` is negative and less than the fee amount, the else branch at line 365 executes: [5](#0-4) 

Line 368 calculates `amountToChargeBaseFee.Sub(existingAllowance)`. When `existingAllowance` is -100 and `amountToChargeBaseFee` is 50, this becomes: 50 - (-100) = 150, storing 150 in `bill.FeesMap` instead of 50.

Finally, `ModifyBalance()` deducts the inflated amount from the user's balance: [6](#0-5) 

At line 248, it deducts the amount from `bill.FeesMap`, which contains 150 instead of the correct 50.

## Impact Explanation

**HIGH SEVERITY** - This causes direct and quantifiable fund loss:

1. **Direct Fund Loss**: Users are overcharged by the absolute value of the negative allowance. Example: If a user should pay 50 ELF but has a -100 ELF allowance configured, they are charged 150 ELF (loss of 100 ELF extra).

2. **Denial of Service**: Users with sufficient balance for the actual fee but insufficient balance for the inflated charge will have transactions fail, blocking their ability to use the system despite having adequate funds.

3. **Scope**: All users whose token balance meets the configured threshold are affected when allowances refresh. Impact scales with both the magnitude of negative allowances and transaction frequency.

This violates the critical invariant that users should only pay correct transaction fee amounts, causing unauthorized fund extraction without user consent or awareness.

## Likelihood Explanation

**MEDIUM-HIGH** for the following reasons:

**Entry Point**: `ConfigTransactionFeeFreeAllowances()` is accessible to the parliament controller, a trusted governance role. [7](#0-6) 

**Attack Complexity**: LOW - Simply call the function with negative amount values. No complex state manipulation or timing requirements needed.

**Feasibility Conditions**:
- Parliament controller configures allowances (either through error or malicious intent)
- Users' balances meet the threshold (automatic trigger)
- Users execute fee-paying transactions (normal operation)

**Probability Assessment**: MEDIUM-HIGH for accidental misconfiguration during routine fee structure updates. While parliament controller is a trusted role, the absence of input validation represents a clear defensive programming gap. Even trusted roles should have validation to prevent configuration errors that directly harm users. The signed integer type (`int64`) allows negative values without explicit validation.

## Recommendation

Add validation in `ConfigTransactionFeeFreeAllowances()` to ensure all allowance amounts are non-negative:

```csharp
foreach (var allowance in allowances.TransactionFeeFreeAllowances!.Value!)
{
    Assert(allowance.Amount >= 0, "Invalid allowance amount: must be non-negative");
    config.FreeAllowances.Map.TryAdd(allowance.Symbol, allowance);
}
```

This validation should be placed after line 1251 and before line 1254 in the configuration loop.

## Proof of Concept

```csharp
[Fact]
public async Task ConfigureNegativeAllowance_CausesUserOvercharging()
{
    // Setup: Configure negative allowance via parliament
    var configInput = new ConfigTransactionFeeFreeAllowancesInput
    {
        Value =
        {
            new ConfigTransactionFeeFreeAllowance
            {
                Symbol = "ELF",
                Threshold = 1000_00000000,
                RefreshSeconds = 86400,
                TransactionFeeFreeAllowances = new TransactionFeeFreeAllowances
                {
                    Value =
                    {
                        new TransactionFeeFreeAllowance
                        {
                            Symbol = "ELF",
                            Amount = -100_00000000 // Negative allowance
                        }
                    }
                }
            }
        }
    };
    
    // Parliament controller configures (no validation stops this)
    await TokenContractStub.ConfigTransactionFeeFreeAllowances.SendAsync(configInput);
    
    // User has sufficient balance to meet threshold
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = UserAddress,
        Symbol = "ELF",
        Amount = 2000_00000000
    });
    
    // User executes transaction with 50 ELF fee
    // Expected charge: 50 ELF
    // Actual charge: 150 ELF (50 - (-100) = 150)
    var balanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddress,
        Symbol = "ELF"
    })).Balance;
    
    await UserTokenContractStub.SomeTransactionWithFee.SendAsync(...);
    
    var balanceAfter = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddress,
        Symbol = "ELF"
    })).Balance;
    
    // Assert: User was charged 150 ELF instead of 50 ELF
    var actualCharged = balanceBefore - balanceAfter;
    Assert.Equal(150_00000000, actualCharged); // Proves overcharging
    Assert.NotEqual(50_00000000, actualCharged); // Should have been 50
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L237-255)
```csharp
    private void ModifyBalance(Address fromAddress, TransactionFeeBill bill,
        TransactionFreeFeeAllowanceBill allowanceBill)
    {
        Assert(!IsInTransferBlackListInternal(fromAddress), "Charge fee address is in transfer blacklist.");
        SetOrRefreshTransactionFeeFreeAllowances(fromAddress);
        var freeAllowancesMap = CalculateTransactionFeeFreeAllowances(fromAddress);

        // Update balances and allowances
        foreach (var (symbol, amount) in bill.FeesMap)
        {
            if (amount <= 0) continue;
            ModifyBalance(fromAddress, symbol, -amount);
            Context.Fire(new TransactionFeeCharged
            {
                Symbol = symbol,
                Amount = amount,
                ChargingAddress = fromAddress
            });
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L302-319)
```csharp
    private void SetOrRefreshTransactionFeeFreeAllowances(Address address)
    {
        var config = State.TransactionFeeFreeAllowancesSymbolList.Value;
        if (config == null) return;

        foreach (var symbol in config.Symbols)
        {
            if (State.Balances[address][symbol] <
                State.TransactionFeeFreeAllowancesConfigMap[symbol].Threshold) continue;
            var lastRefreshTime = State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol];

            if (lastRefreshTime != null && State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds >
                (Context.CurrentBlockTime - lastRefreshTime).Seconds) continue;

            State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol] = Context.CurrentBlockTime;
            State.TransactionFeeFreeAllowances[address][symbol] =
                State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone();
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L359-369)
```csharp
        if (existingAllowance > amountToChargeBaseFee)
        {
            allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee);
            // free fee allowance has covered fee, add 0 for size fee
            bill.FeesMap.Add(symbolToChargeBaseFee, 0);
        }
        else
        {
            allowanceBill.FreeFeeAllowancesMap.Add(symbolToChargeBaseFee, existingAllowance);
            bill.FeesMap.Add(symbolToChargeBaseFee, amountToChargeBaseFee.Sub(existingAllowance));
        }
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

**File:** protobuf/token_contract_impl.proto (L356-359)
```text
message TransactionFeeFreeAllowance {
    string symbol = 1;
    int64 amount = 2;
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
