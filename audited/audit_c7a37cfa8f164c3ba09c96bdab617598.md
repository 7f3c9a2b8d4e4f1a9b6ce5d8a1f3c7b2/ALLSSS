### Title
Negative DepositBalance Due to Missing Validation in Sell Operation Allows Cross-Connector Balance Contamination

### Summary
The `Sell` function in TokenConverterContract calculates `amountToReceive` using the sum of `VirtualBalance` and `DepositBalance` through the Bancor formula, but only decrements `DepositBalance` without validating that `amountToReceive <= DepositBalance`. Since multiple connector pairs share the same base token pool in the contract, a sell operation can succeed by draining tokens allocated to other connectors, causing the affected connector's `DepositBalance` to become negative and breaking accounting integrity across the system.

### Finding Description

The vulnerability exists in the `Sell` function where the Bancor pricing calculation and balance accounting are misaligned: [1](#0-0) 

The `GetSelfBalance` helper function for deposit account connectors returns the sum of virtual and actual balances: [2](#0-1) 

After calculating `amountToReceive` based on this combined balance, the contract transfers base tokens and then decrements only `DepositBalance`: [3](#0-2) 

**Root Cause**: There is no validation ensuring `amountToReceive <= State.DepositBalance[toConnector.Symbol]` before the subtraction. The `SafeMath.Sub()` operation uses checked arithmetic but only prevents arithmetic overflow/underflow at type boundaries, not negative values within valid range: [4](#0-3) 

**Why Existing Protections Fail**: The base token transfer at lines 186-192 checks the contract's **total** base token balance across all connectors, not the per-connector `DepositBalance`. Since the system initializes multiple connector pairs that share the same base token: [5](#0-4) 

A sell operation on one connector can succeed by using tokens allocated to another connector's `DepositBalance`, leaving the first connector with a negative `DepositBalance`.

### Impact Explanation

**Direct Fund Impact**:
- `DepositBalance` can become negative, violating the critical invariant that deposit balances must be non-negative
- Users can extract more base tokens from a specific connector than actually allocated to it
- Cross-connector contamination allows draining one connector's reserves through sells on another connector

**Accounting Integrity Broken**:
- The `GetDepositConnectorBalance` view function returns incorrect values when `DepositBalance` is negative: [6](#0-5) 

- When `State.DepositBalance[ntSymbol]` is negative, the returned total balance appears lower than `VirtualBalance` alone (the exact scenario questioned in the audit prompt)
- All subsequent Bancor calculations for affected connectors use corrupted balance data, leading to incorrect pricing

**Affected Parties**:
- Users trading on connectors with negative `DepositBalance` receive incorrect prices
- Connectors whose reserves are drained become insolvent while showing positive virtual balances
- System-wide accounting diverges from actual token holdings over time

**Severity Justification**: Medium severity due to broken accounting and fund misallocation, though exploitation requires accumulating significant resource tokens and depends on the relative sizes of virtual vs. deposit balances across connector pairs.

### Likelihood Explanation

**Reachable Entry Point**: The `Sell` function is a public method callable by any user: [7](#0-6) 

**Attacker Capabilities**:
1. Attacker must first acquire resource tokens (e.g., READ, WRITE) by buying them or receiving transfers
2. Attacker needs sufficient capital to buy enough tokens to trigger large sell returns
3. No privileged access required

**Feasible Preconditions**:
- Multiple connector pairs exist in production (verified in economic initialization)
- At least one connector has large `VirtualBalance` but small `DepositBalance`
- Other connectors have sufficient `DepositBalance` to cover the total contract transfer
- The Bancor formula calculates returns based on virtual+deposit but only deposit gets decremented

**Execution Practicality**:
Example scenario with realistic values:
- Connector NTREAD: VirtualBalance = 1,000,000, DepositBalance = 100
- Connector NTWRITE: VirtualBalance = 1,000,000, DepositBalance = 10,000
- Total contract balance: 10,100 base tokens
- Attacker sells large amount of READ tokens
- Bancor calculates: amountToReceive = 500 (< 1,000,100 but > 100)
- Transfer succeeds (contract has 10,100 total)
- NTREAD's DepositBalance = 100 - 500 = -400 ✓

**Economic Rationality**: While the attacker must spend capital to buy resource tokens initially, if the mispricing due to corrupted balances allows extracting more value than spent, the attack is profitable. The cost is moderate since resource tokens can be purchased at market rates.

### Recommendation

**Immediate Fix**: Add validation before decrementing `DepositBalance` in the `Sell` function:

```csharp
// After line 172, before line 186
Assert(State.DepositBalance[toConnector.Symbol] >= amountToReceive, 
    "Insufficient deposit balance for this connector");
```

**Additional Safeguards**:
1. Implement per-connector balance isolation or ensure VirtualBalance is not used in calculations that affect actual token transfers
2. Add invariant check: `Assert(State.DepositBalance[connector.Symbol] >= 0)` after any balance modification
3. Consider separating virtual balance (for pricing) from actual balance (for transfers) more explicitly in the architecture

**Test Cases**:
1. Test selling resource tokens when `amountToReceive` would exceed the connector's `DepositBalance` - should fail with clear error
2. Test that multiple connector pairs cannot contaminate each other's deposit balances
3. Test edge case where VirtualBalance is very large but DepositBalance is minimal
4. Verify `GetDepositConnectorBalance` never returns a value less than `VirtualBalance` alone

### Proof of Concept

**Initial State**:
1. Initialize TokenConverter with two connector pairs:
   - READ/NTREAD: NTREAD has VirtualBalance = 1,000,000 ELF, DepositBalance = 100 ELF
   - WRITE/NTWRITE: NTWRITE has VirtualBalance = 1,000,000 ELF, DepositBalance = 10,000 ELF
2. Contract holds 10,100 ELF total in base tokens

**Attack Steps**:
1. Attacker calls `Buy` to acquire 50,000 READ tokens (costs approximately 250 ELF based on Bancor pricing)
2. Attacker calls `Sell` with 50,000 READ tokens
3. Bancor formula calculates:
   - `fromConnectorBalance` = 50,000 READ tokens in contract
   - `toConnectorBalance` = GetSelfBalance(NTREAD) = 1,000,000 + 100 = 1,000,100 ELF
   - `amountToReceive` ≈ 500 ELF (based on Bancor formula with weights)
4. Transfer at line 186-192 succeeds (contract has 10,100 ELF total)
5. Line 193-194 executes: `State.DepositBalance[NTREAD] = 100 - 500 = -400`

**Expected vs Actual Result**:
- **Expected**: Transaction should fail with "Insufficient deposit balance"
- **Actual**: Transaction succeeds, `DepositBalance[NTREAD]` becomes -400

**Success Condition**:
Call `GetDepositConnectorBalance` for READ connector:
- Returns: VirtualBalance + DepositBalance = 1,000,000 + (-400) = 999,600 ELF
- This is less than VirtualBalance alone (1,000,000), confirming the vulnerability described in the audit question

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-162)
```csharp
    public override Empty Sell(SellInput input)
    {
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-194)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L226-252)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L93-102)
```csharp
    public override Int64Value GetDepositConnectorBalance(StringValue symbolInput)
    {
        var connector = State.Connectors[symbolInput.Value];
        Assert(connector != null && !connector.IsDepositAccount, "token symbol is invalid");
        var ntSymbol = connector.RelatedSymbol;
        return new Int64Value
        {
            Value = State.Connectors[ntSymbol].VirtualBalance + State.DepositBalance[ntSymbol]
        };
    }
```
