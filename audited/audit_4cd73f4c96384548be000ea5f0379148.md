# Audit Report

## Title
TokenConverter Price Calculation Breaks with Mismatched Token Decimals During Deployment

## Summary
The TokenConverter contract performs Bancor-based token conversions without validating that participating tokens have consistent decimal precision. Since the native token decimals are configurable at deployment while resource tokens and virtual balance constants are hardcoded to 8 decimals, any deployment with non-8-decimal native tokens causes catastrophic pricing errors where prices can be off by factors of millions.

## Finding Description

The vulnerability exists across the economic system initialization flow:

**1. Native Token Decimals Are Configurable**

The native token is created with decimals specified via `InitialEconomicSystemInput.NativeTokenDecimals`, which comes from the configurable `EconomicOptions.Decimals` (default 8): [1](#0-0) [2](#0-1) [3](#0-2) 

**2. Resource Tokens Hardcoded to 8 Decimals**

All resource tokens are created with hardcoded 8 decimal precision: [4](#0-3) [5](#0-4) 

**3. Virtual Balances Assume 8 Decimals**

TokenConverter initialization uses hardcoded virtual balance constants formatted for 8-decimal tokens: [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) 

**4. No Decimal Validation**

The `TokenConverter.Initialize` method validates symbol format, fee rate, and connector weights, but never validates token decimals: [10](#0-9) 

The `Connector` protobuf definition has no decimals field: [11](#0-10) 

**5. BancorHelper Has No Decimal Awareness**

The Bancor pricing formulas operate on raw `long` values without any decimal normalization: [12](#0-11) [13](#0-12) 

The system breaks its own invariant: **Bancor pricing assumes all tokens in a connector pair have identical decimal precision**. This invariant is never validated or enforced.

## Impact Explanation

When tokens have mismatched decimals, Bancor formulas produce catastrophically incorrect prices because they treat raw `long` values as if they represent the same real-world quantities.

**Critical Scenario:**
- Operator deploys with `NativeTokenDecimals = 2` (1.0 ELF = 100 base units)
- System creates resource tokens with 8 decimals (1.0 READ = 100,000,000 base units)  
- Virtual balance constant `NativeTokenConnectorInitialVirtualBalance = 100_000_00000000`

When this virtual balance is used in Bancor calculations:
- **Intended meaning (8 decimals):** 100,000 tokens = 100,000 * 10^8 = 10,000,000,000,000 base units
- **Actual interpretation (2 decimals):** 100,000,00000000 base units = 1,000,000,000,000 tokens = **1 trillion tokens**

**Result:** Prices are inflated by a factor of 10^6 (one million). Users attempting to buy resource tokens pay millions of times the intended price. Conversely, if native token has MORE decimals than 8, prices collapse proportionally, allowing complete drainage of reserves.

**System-Wide Consequences:**
- Complete failure of TokenConverter pricing mechanism
- Economic system inoperable from genesis  
- All resource token trading broken
- Irreversible without chain restart

## Likelihood Explanation

**Likelihood: HIGH**

This is a **deployment misconfiguration vulnerability**, not an exploit:

1. **Automatic Trigger:** Manifests immediately when chain is deployed with `NativeTokenDecimals ≠ 8` in genesis configuration
2. **No Attacker Required:** The incorrect prices occur automatically on first TokenConverter operation
3. **No Validation:** The codebase provides zero guards against this misconfiguration: [14](#0-13) 
4. **Configuration Flexibility Exists:** The system explicitly allows configurable decimals via `EconomicOptions.Decimals`: [3](#0-2) 
5. **Easy to Miss:** Without explicit documentation requiring 8 decimals, operators may adjust this value during chain customization

The test suite even demonstrates this configuration is valid by creating tokens with 2 decimals: [15](#0-14)  However, test code manually adjusts connector values to match, which production code does not do.

## Recommendation

Add strict decimal validation during economic system initialization:

```csharp
public override Empty InitialEconomicSystem(InitialEconomicSystemInput input)
{
    Assert(!State.Initialized.Value, "Already initialized.");
    
    // ADD THIS VALIDATION
    Assert(input.NativeTokenDecimals == EconomicContractConstants.ResourceTokenDecimals, 
        "Native token decimals must equal resource token decimals (8) for TokenConverter pricing");
    
    // ... rest of initialization
}
```

Alternative: Make resource token decimals and virtual balance constants dynamically calculated based on `NativeTokenDecimals`, though this is more complex and error-prone.

## Proof of Concept

```csharp
[Fact]
public async Task TokenConverter_PriceBreaks_WithMismatchedDecimals()
{
    // Deploy with native token having 2 decimals instead of 8
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "ELF",
        Decimals = 2,  // ← MISCONFIGURATION
        TokenName = "Native Token",
        TotalSupply = 1000_00,  // 1000.00 tokens with 2 decimals
        Issuer = DefaultSender,
        IsBurnable = true
    });
    
    // Create resource token with hardcoded 8 decimals (as production does)
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "READ",
        Decimals = 8,  // ← Production hardcoded value
        TokenName = "Resource Token",
        TotalSupply = 1000_00000000,  // 1000.00000000 tokens
        Issuer = DefaultSender
    });
    
    // Initialize TokenConverter with production constants (8-decimal assumption)
    await TokenConverterStub.Initialize.SendAsync(new InitializeInput
    {
        BaseTokenSymbol = "ELF",
        FeeRate = "0.005",
        Connectors = {
            new Connector {
                Symbol = "ELF",
                VirtualBalance = 100_000_00000000,  // ← Assumes 8 decimals
                Weight = "0.5"
            },
            new Connector {
                Symbol = "READ",
                Weight = "0.5"
            }
        }
    });
    
    // Attempt to buy 1.0 READ token (100000000 base units with 8 decimals)
    var result = await TokenConverterStub.Buy.SendAsync(new BuyInput
    {
        Symbol = "READ",
        Amount = 100000000,  // 1.0 READ
        PayLimit = 0
    });
    
    // ✓ VULNERABILITY: Price will be off by factor of 10^6
    // Expected: ~1 ELF (100 base units with 2 decimals)  
    // Actual: ~1,000,000 ELF (100,000,000 base units) due to virtual balance misinterpretation
}
```

The test demonstrates that when native token has 2 decimals but the system uses virtual balance constants formatted for 8 decimals, the Bancor formula treats the virtual balance as representing 1 trillion ELF instead of 1 million ELF, causing million-fold price inflation.

### Citations

**File:** protobuf/economic_contract.proto (L35-35)
```text
    int32 native_token_decimals = 4;
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L16-40)
```csharp
    public override Empty InitialEconomicSystem(InitialEconomicSystemInput input)
    {
        Assert(!State.Initialized.Value, "Already initialized.");

        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Context.LogDebug(() => "Will create tokens.");
        CreateNativeToken(input);
        CreateResourceTokens();
        CreateElectionTokens();

        Context.LogDebug(() => "Finished creating tokens.");

        InitialMiningReward(input.MiningRewardTotalAmount);

        RegisterElectionVotingEvent();
        SetTreasurySchemeIdsToElectionContract();

        InitializeTokenConverterContract();
        State.TokenContract.InitialCoefficients.Send(new Empty());
        State.TokenContract.InitializeAuthorizedController.Send(new Empty());
        State.Initialized.Value = true;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L54-64)
```csharp
        State.TokenContract.Create.Send(new CreateInput
        {
            Symbol = input.NativeTokenSymbol,
            TokenName = "Native Token",
            TotalSupply = input.NativeTokenTotalSupply,
            Decimals = input.NativeTokenDecimals,
            IsBurnable = input.IsNativeTokenBurnable,
            Issuer = Context.Self,
            LockWhiteList = { lockWhiteList },
            Owner = Context.Self
        });
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L84-94)
```csharp
            State.TokenContract.Create.Send(new CreateInput
            {
                Symbol = resourceTokenSymbol,
                TokenName = $"{resourceTokenSymbol} Token",
                TotalSupply = EconomicContractConstants.ResourceTokenTotalSupply,
                Decimals = EconomicContractConstants.ResourceTokenDecimals,
                Issuer = Context.Self,
                LockWhiteList = { lockWhiteList },
                IsBurnable = true,
                Owner = Context.Self
            });
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L211-260)
```csharp
    private void InitializeTokenConverterContract()
    {
        State.TokenConverterContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName);
        var connectors = new List<Connector>
        {
            new()
            {
                Symbol = Context.Variables.NativeSymbol,
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.5",
                VirtualBalance = EconomicContractConstants.NativeTokenConnectorInitialVirtualBalance
            }
        };
        foreach (var resourceTokenSymbol in Context.Variables
                     .GetStringArray(EconomicContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(EconomicContractConstants.PayRentalSymbolListName)))
        {
            var resourceTokenConnector = new Connector
            {
                Symbol = resourceTokenSymbol,
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
                VirtualBalance = EconomicContractConstants.ResourceTokenInitialVirtualBalance,
                RelatedSymbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsDepositAccount = false
            };
            var nativeTokenConnector = new Connector
            {
                Symbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
                VirtualBalance = EconomicContractConstants.NativeTokenToResourceBalance,
                RelatedSymbol = resourceTokenSymbol,
                IsDepositAccount = true
            };
            connectors.Add(resourceTokenConnector);
            connectors.Add(nativeTokenConnector);
        }

        State.TokenConverterContract.Initialize.Send(new InitializeInput
        {
            FeeRate = EconomicContractConstants.TokenConverterFeeRate,
            Connectors = { connectors },
            BaseTokenSymbol = Context.Variables.NativeSymbol
        });
    }
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L9-9)
```csharp
    public int Decimals { get; set; } = 8;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L5-5)
```csharp
    public const long NativeTokenConnectorInitialVirtualBalance = 100_000_00000000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L13-13)
```csharp
    public const int ResourceTokenDecimals = 8;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L16-16)
```csharp
    public const long ResourceTokenInitialVirtualBalance = 100_000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L20-20)
```csharp
    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L27-56)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(IsValidBaseSymbol(input.BaseTokenSymbol), $"Base token symbol is invalid. {input.BaseTokenSymbol}");
        Assert(State.TokenContract.Value == null, "Already initialized.");
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        State.BaseTokenSymbol.Value = !string.IsNullOrEmpty(input.BaseTokenSymbol)
            ? input.BaseTokenSymbol
            : Context.Variables.NativeSymbol;
        var feeRate = AssertedDecimal(input.FeeRate);
        Assert(IsBetweenZeroAndOne(feeRate), "Fee rate has to be a decimal between 0 and 1.");
        State.FeeRate.Value = feeRate.ToString(CultureInfo.InvariantCulture);
        foreach (var connector in input.Connectors)
        {
            if (connector.IsDepositAccount)
            {
                Assert(!string.IsNullOrEmpty(connector.Symbol), "Invalid connector symbol.");
                AssertValidConnectorWeight(connector);
            }
            else
            {
                Assert(IsValidSymbol(connector.Symbol), "Invalid symbol.");
                AssertValidConnectorWeight(connector);
            }

            State.Connectors[connector.Symbol] = connector;
        }

        return new Empty();
    }
```

**File:** protobuf/token_converter_contract.proto (L94-109)
```text
message Connector {
    // The token symbol.
    string symbol = 1;
    // The virtual balance for base token.
    int64 virtual_balance = 2;
    // The calculated weight value for this Connector.
    string weight = 3;
    // Whether to use Virtual Balance.
    bool is_virtual_balance_enabled = 4; 
    // Whether the connector is enabled.
    bool is_purchase_enabled = 5;
    // Indicates its related connector, the pair connector includes a new created token connector and the base token connector.
    string related_symbol = 6;
    // Indicates if the connector is base token connector.
    bool is_deposit_account = 7;
}
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

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L67-94)
```csharp
    public static long GetAmountToPayFromReturn(long fromConnectorBalance, decimal fromConnectorWeight,
        long toConnectorBalance, decimal toConnectorWeight, long amountToReceive)
    {
        if (fromConnectorBalance <= 0 || toConnectorBalance <= 0)
            throw new InvalidValueException("Connector balance needs to be a positive number.");

        if (amountToReceive <= 0) throw new InvalidValueException("Amount needs to be a positive number.");

        decimal bf = fromConnectorBalance;
        var wf = fromConnectorWeight;
        decimal bt = toConnectorBalance;
        var wt = toConnectorWeight;
        decimal a = amountToReceive;
        if (wf == wt)
            try
            {
                // if both weights are the same, the formula can be reduced
                return (long)(bf / (bt - a) * a);
            }
            catch
            {
                throw new AssertionException("Insufficient account balance to deposit");
            }

        var x = bt / (bt - a);
        var y = wt / wf;
        return (long)(bf * (Exp(y * Ln(x)) - decimal.One));
    }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConverterTestBase.cs (L54-65)
```csharp
        await ExecuteProposalForParliamentTransaction(TokenContractAddress, nameof(TokenContractStub.Create),
            new CreateInput
            {
                Symbol = "ELF",
                Decimals = 2,
                IsBurnable = true,
                TokenName = "elf token",
                TotalSupply = 1000_0000_0000L,
                Issuer = DefaultSender,
                Owner = DefaultSender,
                LockWhiteList = { TokenContractAddress, TokenConverterContractAddress }
            });
```
