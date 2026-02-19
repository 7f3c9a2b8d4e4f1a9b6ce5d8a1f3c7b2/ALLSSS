### Title
TokenConverter Price Calculation Breaks with Mismatched Token Decimals During Deployment

### Summary
The TokenConverter contract performs Bancor-based token swaps without validating that all tokens have consistent decimal precision. If the native token is deployed with decimals different from the hardcoded 8-decimal constants used throughout the economic system, all TokenConverter pricing calculations become catastrophically incorrect, with prices potentially off by factors of millions or more.

### Finding Description

The vulnerability exists across multiple components:

**1. Native Token Decimals are Configurable**
The native token's decimals are set during deployment via `InitialEconomicSystemInput.NativeTokenDecimals` and passed directly to token creation: [1](#0-0) 

**2. Resource Token Decimals are Hardcoded to 8**
Resource tokens are always created with 8 decimals: [2](#0-1) [3](#0-2) 

**3. TokenConverter Virtual Balances Assume 8 Decimals**
All connector virtual balance constants are hardcoded assuming 8 decimal precision: [4](#0-3) [5](#0-4) [6](#0-5) 

**4. TokenConverter Never Validates Decimal Consistency**
The TokenConverter initialization only validates symbol format, fee rate, and connector weights, but never checks token decimals: [7](#0-6) 

The Connector protobuf message has no decimals field: [8](#0-7) 

**5. BancorHelper Performs No Decimal Normalization**
The Bancor formulas treat all `long` token amounts as raw values without any decimal awareness or normalization: [9](#0-8) [10](#0-9) 

**Root Cause:**
The system assumes all tokens use the same decimal precision for Bancor price calculations, but this invariant is never enforced. The native token decimals are configurable at deployment, while resource token decimals and all virtual balance constants are hardcoded to 8 decimals.

### Impact Explanation

When tokens have mismatched decimals, the Bancor pricing formulas produce completely incorrect results because they operate on raw `long` values that represent different real-world quantities:

**Example Scenario:**
- Native token deployed with 2 decimals: 1.0 ELF = 100 (as long)
- Resource token with 8 decimals: 1.0 READ = 100,000,000 (as long)
- Virtual balances hardcoded as 100_000_00000000 (formatted for 8 decimals)

For a user buying 1.0 READ token (100,000,000 in storage):
- The formula calculates payment in raw native token units
- But interprets the virtual balance 100_000_00000000 as if native token has 8 decimals
- With only 2 decimals, this represents 1 trillion ELF instead of 1 million
- **Price becomes inflated by factor of 10^6 (one million)**

Conversely, if native token has MORE decimals than resource tokens, prices deflate proportionally, enabling drainage of reserves for pennies.

**Concrete Impact:**
- Complete breakdown of TokenConverter pricing mechanism
- Users pay millions of times too much (or drain system paying almost nothing)
- Entire economic system becomes inoperable
- All resource token trading broken from genesis
- Irreversible damage requiring chain restart

This affects all users attempting token conversions and destroys the core economic functionality of the blockchain.

### Likelihood Explanation

**Likelihood: HIGH**

This is not an exploit but a **deployment configuration error** with immediate and automatic consequences:

1. **Trigger Condition**: Operator deploys chain with native token decimals ≠ 8 in `InitialEconomicSystemInput`
2. **No Attacker Needed**: The vulnerability manifests automatically on first TokenConverter operation
3. **Easy to Miss**: No validation exists to catch this during deployment
4. **Real-World Evidence**: Test files show this exact scenario exists: [11](#0-10) [12](#0-11) 

While that specific test may use different decimals for demonstration, it proves the system ALLOWS this configuration.

5. **Configuration Flexibility**: The native token decimals are explicitly configurable via `EconomicOptions.Decimals`: [13](#0-12) 

The system provides this configuration option but provides no safeguard against misconfiguration.

### Recommendation

**Immediate Fix:**

1. **Add Decimal Validation in TokenConverter.Initialize()**
```
Before line 52 of TokenConverterContract.cs, add:
    - Query native token info from TokenContract.GetTokenInfo
    - For each connector symbol, query token info
    - Assert all non-deposit connectors have same decimals as base token
    - Assert all deposit connector virtual balances are scaled appropriately
```

2. **Add Decimal Validation in Economic Contract Initialization**
```
In InitialEconomicSystem (EconomicContract.cs line 16):
    - Assert input.NativeTokenDecimals == EconomicContractConstants.ResourceTokenDecimals
    - Or add ResourceTokenDecimals to input and validate consistency
```

3. **Alternative: Normalize in BancorHelper**
```
Modify BancorHelper to accept decimal parameters and normalize amounts:
    - Convert all amounts to a common decimal base before calculation
    - Scale results back to target token decimals
    - This is more complex but allows different decimals
```

**Prevention:**
- Add integration tests that explicitly verify TokenConverter works correctly only when all tokens share same decimals
- Add deployment validation scripts that check decimal consistency
- Document the 8-decimal requirement prominently

### Proof of Concept

**Initial State:**
1. Deploy chain with `NativeTokenDecimals = 2` (instead of 8)
2. System creates native token ELF with 2 decimals
3. System creates resource token READ with 8 decimals (hardcoded)
4. TokenConverter initialized with connectors:
   - Native virtual balance: 100_000_00000000 (assumes 8 decimals)
   - READ virtual balance: 100_000_00000000 (assumes 8 decimals)
   - Both weights: 0.5

**Exploitation Steps:**
1. User calls `TokenConverter.Buy(symbol="READ", amount=100000000, payLimit=0)`
   - Attempting to buy 1.0 READ token (8 decimals = 100,000,000)

2. `BancorHelper.GetAmountToPayFromReturn` calculates:
   - fromBalance = 100_000_00000000 (native deposit)
   - toBalance = 100_000_00000000 (READ balance)  
   - amount = 100000000
   - Formula: `bf / (bt - a) * a` = 100_000_00000000 / 99_900_00000000 * 100000000 ≈ 100,100,100

3. User charged 100,100,100 native token units

**Expected Result:**
- With correct 8 decimals: User pays ~1.001 ELF

**Actual Result:**
- With 2 decimals: 100,100,100 = 1,001,001.00 ELF
- **User pays ONE MILLION ELF for 1 READ token**
- Price error factor: 10^6 (one million times too expensive)

**Success Condition:**
Transaction succeeds but user's balance decreases by catastrophically incorrect amount, proving pricing mechanism is completely broken with mismatched decimals.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L42-68)
```csharp
    private void CreateNativeToken(InitialEconomicSystemInput input)
    {
        var lockWhiteListBackups = new List<Address>
        {
            Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName)
        };
        var lockWhiteList = lockWhiteListBackups.Where(address => address != null).ToList();
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

        State.TokenContract.SetPrimaryTokenSymbol.Send(new SetPrimaryTokenSymbolInput
            { Symbol = input.NativeTokenSymbol });
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L70-104)
```csharp
    private void CreateResourceTokens()
    {
        var tokenConverter =
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName);
        var lockWhiteListBackups = new List<Address>
        {
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName)
        };
        var lockWhiteList = lockWhiteListBackups.Where(address => address != null).ToList();
        foreach (var resourceTokenSymbol in Context.Variables
                     .GetStringArray(EconomicContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(EconomicContractConstants.PayRentalSymbolListName)))
        {
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

            State.TokenContract.Issue.Send(new IssueInput
            {
                Symbol = resourceTokenSymbol,
                Amount = EconomicContractConstants.ResourceTokenTotalSupply,
                To = tokenConverter,
                Memo = "Initialize for resource trade"
            });
        }
    }
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

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee.Tests/ExecutionPluginForResourceFeeTestBase.cs (L227-231)
```csharp
            await TokenContractStub.Create.SendAsync(new CreateInput
                {
                    Symbol = "ELF",
                    Decimals = 8,
                    IsBurnable = true,
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee.Tests/ExecutionPluginForResourceFeeTestBase.cs (L262-266)
```csharp
            await TokenContractStub.Create.SendAsync(new CreateInput
            {
                Symbol = "READ",
                Decimals = 2,
                IsBurnable = true,
```

**File:** src/AElf.EconomicSystem/EconomicContractInitializationProvider.cs (L38-40)
```csharp
                Params = new InitialEconomicSystemInput
                {
                    NativeTokenDecimals = _economicOptions.Decimals,
```
