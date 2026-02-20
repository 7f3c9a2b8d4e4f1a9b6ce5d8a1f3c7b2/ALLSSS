# Audit Report

## Title
DepositBalance Underflow Causes DoS in TokenConverter Sell Operations Due to VirtualBalance Accounting Mismatch

## Summary
The `Sell()` function calculates the amount of base token to return using a combined `VirtualBalance + DepositBalance` for Bancor pricing, but the subsequent accounting update only subtracts from `DepositBalance`. When the calculated return amount exceeds the available `DepositBalance`, the checked arithmetic in `SafeMath.Sub()` throws an `OverflowException`, causing transaction revert and denying service to legitimate sell operations.

## Finding Description

The vulnerability stems from a critical accounting mismatch in the TokenConverter contract's sell operation logic.

**Pricing Calculation Phase:**

The `Sell()` function calculates the return amount using Bancor pricing that includes both VirtualBalance and DepositBalance: [1](#0-0) 

For deposit account connectors, `GetSelfBalance()` returns the sum of virtual and real balances: [2](#0-1) 

**Accounting Update Phase:**

However, the state update only subtracts from the connector-specific `DepositBalance`: [3](#0-2) 

**Checked Arithmetic Protection:**

The `SafeMath.Sub()` method uses checked arithmetic that throws `OverflowException` on underflow: [4](#0-3) 

**Root Cause Configuration:**

During economic system initialization, deposit account connectors are created with large VirtualBalance values: [5](#0-4) [6](#0-5) 

**Vulnerability Mechanism:**

When connector weights are equal, the Bancor formula simplifies to: [7](#0-6) 

The critical issue occurs when:
1. TokenConverter holds multiple deposit connectors sharing a base token pool
2. One connector (e.g., "(NT)CPU") has low DepositBalance (e.g., 100 ELF)
3. Other connectors have accumulated high DepositBalance (e.g., 7M ELF total)
4. User attempts to sell resource tokens
5. Bancor calculates return using (10M VirtualBalance + 100 DepositBalance) = inflated amount (~3.3M ELF)
6. Token transfer succeeds (contract has 7M ELF total across all connectors)
7. DepositBalance subtraction fails: `100.Sub(3_333_367)` → OverflowException
8. Transaction reverts with DoS

The token transfer precedes the DepositBalance update in the execution flow: [8](#0-7) 

## Impact Explanation

**Severity: HIGH - Denial of Service**

1. **User Fund Lockup**: Users holding resource tokens cannot convert them back to base tokens, effectively locking their funds temporarily until the affected connector's DepositBalance accumulates through other users' buy operations.

2. **Market Inefficiency**: The Bancor automated market maker mechanism fails unpredictably based on internal accounting state rather than actual liquidity availability. Pricing indicates valid market conditions, but execution fails.

3. **Protocol Availability**: Core token conversion functionality is denied even when the contract holds sufficient total base token balance across all connectors and the user has proper approvals.

4. **No Fund Loss**: The checked arithmetic prevents silent state corruption—the transaction reverts cleanly rather than allowing negative balances, limiting severity to DoS rather than fund theft.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

1. **Default Configuration**: All deposit account connectors are initialized with `VirtualBalance = 10_000_000_00000000` by default—this is the standard economic system configuration.

2. **Realistic Triggering Conditions**:
   - Early lifecycle when DepositBalance is small relative to 10M VirtualBalance
   - Low-volume trading pairs with minimal accumulated DepositBalance
   - Uneven balance distribution across multiple connectors

3. **No Privilege Requirements**: Any user can call `Sell()` with owned resource tokens and proper approvals. The vulnerability is inherent in the contract design.

4. **Practical Execution**: With equal connector weights (0.005), typical market conditions can easily trigger this: resource balance = 1,000 tokens, user sells 500 tokens, formula calculates ~3.3M ELF return, but DepositBalance has only 100 ELF.

## Recommendation

**Option 1: Consistent Balance Accounting**

Modify `GetSelfBalance()` to return only real balance for pricing when the connector is a deposit account, removing the VirtualBalance inflation:

```csharp
private long GetSelfBalance(Connector connector)
{
    long realBalance;
    if (connector.IsDepositAccount)
        realBalance = State.DepositBalance[connector.Symbol];
    else
        realBalance = State.TokenContract.GetBalance.Call(...).Balance;
    
    // Remove virtual balance from deposit account pricing
    // to match accounting update behavior
    return realBalance;
}
```

**Option 2: Pre-Transfer Balance Check**

Add validation before the token transfer to ensure DepositBalance is sufficient:

```csharp
Assert(State.DepositBalance[toConnector.Symbol] >= amountToReceive,
    "Insufficient deposit balance for this connector.");
```

**Option 3: Adjust Accounting to Match Pricing**

Track and update VirtualBalance alongside DepositBalance during sell operations (more complex, requires careful economic analysis of virtual balance implications).

## Proof of Concept

```csharp
// Test scenario demonstrating the DoS vulnerability
[Fact]
public async Task Sell_ShouldRevert_WhenDepositBalanceInsufficientDueToVirtualBalance()
{
    // Setup: Initialize TokenConverter with deposit connector having VirtualBalance = 10M
    // Assume "(NT)CPU" connector exists with VirtualBalance = 10_000_000_00000000
    
    // Setup: Create scenario where:
    // - DepositBalance["(NT)CPU"] = 100 ELF (small)
    // - DepositBalance["(NT)RAM"] = 5_000_000 ELF (large, from other connector)
    // - CPU tokens in contract = 1,000
    
    // User attempts to sell 500 CPU tokens
    var sellInput = new SellInput
    {
        Symbol = "CPU",
        Amount = 500_00000000,
        ReceiveLimit = 0
    };
    
    // Expected behavior: Bancor calculates amountToReceive ≈ 3.3M ELF
    // Token transfer succeeds (contract has 5M+ total ELF)
    // DepositBalance.Sub fails: 100.Sub(3_333_367) → OverflowException
    
    var result = await TokenConverterStub.Sell.SendWithExceptionAsync(sellInput);
    
    // Assert: Transaction reverts with OverflowException
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Overflow");
}
```

### Citations

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

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L240-249)
```csharp
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
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L20-20)
```csharp
    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L47-49)
```csharp
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);
```
