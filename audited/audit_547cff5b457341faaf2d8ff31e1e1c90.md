# Audit Report

## Title
BaseTokenSymbol Collision with Non-Deposit Connector Causes Reserve Accounting Discrepancy and Bancor Pricing Manipulation

## Summary
The TokenConverter contract lacks validation preventing connectors from being created with symbols matching `BaseTokenSymbol.Value`. This causes `GetSelfBalance()` to return the contract's total base token balance for non-deposit connectors, inflating Bancor price calculations and enabling drainage of reserves belonging to other connector pairs, thereby breaking the fundamental reserve isolation invariant. [1](#0-0) 

## Finding Description

The vulnerability exists in the connector creation logic which fails to validate that connector symbols don't collide with `BaseTokenSymbol.Value`.

**Root Cause:**

Both `Initialize` and `AddPairConnector` validate connector symbols using only `IsValidSymbol()`, which performs regex format checking but does not prevent collision with `BaseTokenSymbol.Value`: [2](#0-1) [3](#0-2) [4](#0-3) 

**Balance Accounting Discrepancy:**

The `GetSelfBalance()` method determines balance source based on `IsDepositAccount`. For non-deposit connectors, it queries the contract's total token balance for that symbol: [5](#0-4) 

When a non-deposit connector's symbol equals `BaseTokenSymbol.Value` (e.g., "ELF"), this returns the **aggregate ELF balance** held by the contract, which includes all reserves tracked separately in `DepositBalance["(NT)XXX"]` for legitimate connector pairs.

**Exploitation Path:**

1. Parliament governance approves `AddPairConnector(ResourceConnectorSymbol: "ELF")` creating:
   - Resource connector: `Symbol = "ELF"`, `RelatedSymbol = "(NT)ELF"`, `IsDepositAccount = false`
   - Deposit connector: `Symbol = "(NT)ELF"`, `RelatedSymbol = "ELF"`, `IsDepositAccount = true`

2. Contract holds 1000 ELF in `DepositBalance["(NT)WRITE"]` for the legitimate WRITE pair

3. When `Buy("ELF")` is called on the malicious pair:
   - `GetSelfBalance(toConnector)` for the "ELF" connector returns the contract's total ELF balance (1000 ELF)
   - Bancor calculates artificially low prices assuming 1000 ELF available
   - The contract transfers actual ELF tokens from its total balance to users [6](#0-5) 

4. This drains ELF that belongs to the WRITE pair's reserves while `DepositBalance["(NT)WRITE"]` remains unchanged, breaking reserve isolation. [7](#0-6) 

## Impact Explanation

**Direct Fund Impact:**
- **Reserve Drainage**: ELF tokens tracked in `DepositBalance["(NT)XXX"]` for legitimate pairs can be transferred out through the malicious connector, as actual transfers use the contract's total balance while pricing uses inflated balance figures
- **Bancor Pricing Manipulation**: The inflated connector balance causes incorrect price calculations, allowing tokens to be bought/sold at prices that don't reflect actual per-pair reserves
- **Reserve Isolation Violation**: The fundamental Bancor invariant requiring isolated reserves per connector pair is broken

**Quantified Damage:**
If legitimate pairs have combined reserves of N ELF in various `DepositBalance` entries, the malicious connector would use all N ELF for pricing calculations when it should have 0 or only its own isolated reserve.

**Affected Parties:**
- Liquidity providers whose reserves get drained from legitimate pairs
- Protocol integrity as the Bancor reserve model breaks down
- Users trading on legitimate pairs after reserves are depleted [8](#0-7) 

## Likelihood Explanation

**Configuration Requirements:**

This requires privileged configuration via Parliament-approved `AddPairConnector` or deployment-time `Initialize`: [9](#0-8) [10](#0-9) 

**Feasibility:**
- Not an active attack by untrusted users
- Represents a **configuration mistake** that trusted administrators could make during setup
- The contract provides no defensive validation to catch this error
- Once misconfigured, automatically affects all subsequent Buy/Sell operations on that pair

**Probability:**
Medium likelihood because:
- Requires Parliament governance approval but represents an easy-to-make configuration mistake
- No validation exists to prevent this during connector creation
- Missing input validation is a preventable code quality issue
- Has concrete financial impact and breaks critical protocol invariants

## Recommendation

Add validation in both `Initialize` and `AddPairConnector` to prevent connector symbols from matching `BaseTokenSymbol.Value`:

```csharp
// In Initialize method, after line 48:
Assert(connector.Symbol != State.BaseTokenSymbol.Value, 
    "Connector symbol cannot match BaseTokenSymbol.");

// In AddPairConnector method, after line 94:
Assert(input.ResourceConnectorSymbol != State.BaseTokenSymbol.Value,
    "Resource connector symbol cannot match BaseTokenSymbol.");
```

This prevents the dangerous configuration while maintaining all legitimate use cases, as there is no valid reason to create a connector pair using the base token itself as the resource token.

## Proof of Concept

While I cannot provide an executable test without access to the full test infrastructure, the vulnerability can be demonstrated through the following logical flow:

1. Deploy TokenConverter with `BaseTokenSymbol = "ELF"`
2. Create legitimate WRITE/(NT)WRITE pair, deposit 1000 ELF into `DepositBalance["(NT)WRITE"]`
3. Parliament approves `AddPairConnector(ResourceConnectorSymbol: "ELF", ...)`
4. EnableConnector for the malicious ELF/(NT)ELF pair
5. Call `Buy("ELF", Amount: 100)`
   - Expected: Should use isolated reserves for ELF/(NT)ELF pair
   - Actual: `GetSelfBalance("ELF")` returns 1000 (total contract balance including WRITE pair reserves)
   - Result: Bancor pricing uses inflated 1000 ELF balance, allowing purchase at artificially low prices
6. The 100 ELF transferred to buyer comes from contract's total balance, which includes the 1000 ELF reserved for WRITE pair
7. `DepositBalance["(NT)WRITE"]` still shows 1000 ELF, but contract's actual balance is now only 900 ELF
8. Reserve isolation is broken: WRITE pair's reserves have been drained without updating its DepositBalance

The vulnerability is confirmed by examining the code paths in the citations above.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L39-53)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-110)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.ResourceConnectorSymbol),
            "resource token symbol should not be empty");
        var nativeConnectorSymbol = NewNtTokenPrefix.Append(input.ResourceConnectorSymbol);
        Assert(State.Connectors[input.ResourceConnectorSymbol] == null,
            "resource token symbol has existed");
        var resourceConnector = new Connector
        {
            Symbol = input.ResourceConnectorSymbol,
            IsPurchaseEnabled = false,
            RelatedSymbol = nativeConnectorSymbol,
            Weight = input.ResourceWeight
        };
        Assert(IsValidSymbol(resourceConnector.Symbol), "Invalid symbol.");
        AssertValidConnectorWeight(resourceConnector);
        var nativeTokenToResourceConnector = new Connector
        {
            Symbol = nativeConnectorSymbol,
            VirtualBalance = input.NativeVirtualBalance,
            IsVirtualBalanceEnabled = true,
            IsPurchaseEnabled = false,
            RelatedSymbol = input.ResourceConnectorSymbol,
            Weight = input.NativeWeight,
            IsDepositAccount = true
        };
        AssertValidConnectorWeight(nativeTokenToResourceConnector);
        State.Connectors[resourceConnector.Symbol] = resourceConnector;
        State.Connectors[nativeTokenToResourceConnector.Symbol] = nativeTokenToResourceConnector;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-159)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
        var amountToPay = BancorHelper.GetAmountToPayFromReturn(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount);
        var fee = Convert.ToInt64(amountToPay * GetFeeRate());

        var amountToPayPlusFee = amountToPay.Add(fee);
        Assert(input.PayLimit == 0 || amountToPayPlusFee <= input.PayLimit, "Price not good.");

        // Pay fee
        if (fee > 0) HandleFee(fee);

        // Transfer base token
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = amountToPay
            });
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
        // Transfer bought token
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = input.Symbol,
                To = Context.Sender,
                Amount = input.Amount
            });

        Context.Fire(new TokenBought
        {
            Symbol = input.Symbol,
            BoughtAmount = input.Amount,
            BaseAmount = amountToPay,
            FeeAmount = fee
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L359-362)
```csharp
    private static bool IsValidSymbol(string symbol)
    {
        return Regex.IsMatch(symbol, "^[a-zA-Z0-9]+$");
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L374-390)
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
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L397-403)
```csharp
    private void AssertPerformedByConnectorController()
    {
        if (State.ConnectorController.Value == null) State.ConnectorController.Value = GetDefaultConnectorController();

        Assert(Context.Sender == State.ConnectorController.Value.OwnerAddress,
            "Only manager can perform this action.");
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L405-416)
```csharp
    private AuthorityInfo GetDefaultConnectorController()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContractState.cs (L15-19)
```csharp
    public StringState BaseTokenSymbol { get; set; }
    public StringState FeeRate { get; set; }
    public MappedState<string, Connector> Connectors { get; set; }
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public MappedState<string, long> DepositBalance { get; set; }
```
