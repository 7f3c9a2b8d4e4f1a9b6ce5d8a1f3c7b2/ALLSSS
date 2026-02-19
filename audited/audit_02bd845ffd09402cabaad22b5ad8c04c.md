### Title
RefreshSeconds Zero Value Allows Unlimited Transaction Fee Free Allowance Refreshes Within Same Block

### Summary
The `TransactionFeeFreeAllowancesConfigMap` allows `RefreshSeconds` to be set to zero, which bypasses the intended rate-limiting mechanism for transaction fee free allowances. When `RefreshSeconds` is zero, the refresh check logic fails to prevent same-block refreshes, allowing users to reset their free allowances to full amount on every transaction within the same block, effectively enabling unlimited free transactions per block.

### Finding Description
The vulnerability exists in the `SetOrRefreshTransactionFeeFreeAllowances` method where the refresh logic checks if enough time has elapsed before allowing a refresh: [1](#0-0) 

The condition `RefreshSeconds > (Context.CurrentBlockTime - lastRefreshTime).Seconds` is supposed to prevent refreshes until sufficient time has passed. However, when `RefreshSeconds = 0`:
- The condition becomes `0 > elapsed_seconds`
- This is ALWAYS false (elapsed seconds cannot be negative)
- Therefore, the `continue` statement never executes, and refreshes always occur

The validation in `ConfigTransactionFeeFreeAllowances` only requires `RefreshSeconds >= 0`: [2](#0-1) 

**Critical Issue**: `Context.CurrentBlockTime` remains constant for all transactions within the same block. When multiple transactions execute in the same block with `RefreshSeconds = 0`:

1. **Transaction 1**: 
   - `SetOrRefreshTransactionFeeFreeAllowances` called
   - Check: `0 > 0` = false, refresh executes
   - Sets `lastRefreshTime = CurrentBlockTime`
   - Allowances set to full amount
   - User consumes allowances for transaction fees

2. **Transaction 2 (same block)**:
   - `SetOrRefreshTransactionFeeFreeAllowances` called again
   - `lastRefreshTime = CurrentBlockTime` (from Transaction 1)
   - `elapsed = CurrentBlockTime - CurrentBlockTime = 0`
   - Check: `0 > 0` = false, refresh executes AGAIN
   - Allowances RESET to full amount, overwriting consumed allowances [3](#0-2) 

The method is called during fee charging before calculating available allowances: [4](#0-3) 

### Impact Explanation
**Direct Economic Impact**:
- Users can execute unlimited transactions with zero transaction fees within a single block
- Complete bypass of the transaction fee system for rate-limited free allowances
- Loss of expected transaction fee revenue for the network

**Who is Affected**:
- The AElf network loses transaction fee revenue
- Legitimate users who properly wait for refresh periods are disadvantaged
- System integrity of the fee-free allowance mechanism is compromised

**Severity Justification (High)**:
- Direct economic loss through fee evasion
- Trivial to exploit once `RefreshSeconds = 0` is configured
- Completely defeats the purpose of rate-limiting via refresh periods
- Can be exploited repeatedly by packing multiple transactions in each block

The vulnerability allows users to avoid paying transaction fees that would otherwise be required after exhausting their free allowances, directly impacting network economics.

### Likelihood Explanation
**Attacker Capabilities Required**:
- Only requires a governance proposal to set `RefreshSeconds = 0` via `ConfigTransactionFeeFreeAllowances`
- Once configured, ANY user can exploit by submitting multiple transactions in the same block
- No special permissions needed to exploit once the configuration is set

**Attack Complexity**: Low
- The exploit is straightforward: submit multiple transactions to be included in the same block
- Block producers naturally batch transactions, making this scenario common

**Feasibility Conditions**:
- `ConfigTransactionFeeFreeAllowances` must be called with `RefreshSeconds = 0`
- Configuration is controlled by Parliament (default governance)
- Could be set intentionally or accidentally (no documentation warns against zero)

**Detection**: Difficult
- The behavior appears normal from individual transaction perspective
- Only becomes apparent when analyzing multiple transactions from same user in same block
- No events or logs indicate the refresh exploitation

**Probability**: Medium-High
- Tests demonstrate `RefreshSeconds = 0` is considered valid: [5](#0-4) 

- However, existing tests don't verify multiple transactions in same block with zero refresh seconds, missing this edge case [6](#0-5) 

### Recommendation
**Option 1 (Recommended)**: Enforce minimum refresh seconds
```csharp
// Line 1242 in TokenContract_Fees.cs
Assert(allowances.RefreshSeconds > 0, "Invalid input refresh seconds, must be greater than zero");
```

This prevents the edge case entirely by requiring at least 1 second between refreshes, which is the minimum meaningful time interval.

**Option 2**: Fix comparison logic
```csharp
// Line 313-314 in TokenContract_Fees.cs
if (lastRefreshTime != null && State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds >=
    (Context.CurrentBlockTime - lastRefreshTime).Seconds) continue;
```

Change `>` to `>=` to prevent same-block refreshes even when `RefreshSeconds = 0`.

**Additional Safeguards**:
1. Add explicit documentation that `RefreshSeconds` must be > 0
2. Add integration test covering multiple transactions in same block with various `RefreshSeconds` values
3. Consider adding a maximum limit on transactions per user per block when free allowances are used

### Proof of Concept
**Initial State**:
- Token contract deployed and initialized
- Parliament governance configured
- User has balance above threshold (e.g., 1000 ELF)

**Exploitation Steps**:

1. **Governance Configuration** (via Parliament):
   ```
   ConfigTransactionFeeFreeAllowances({
     Symbol: "ELF",
     TransactionFeeFreeAllowances: [{ Symbol: "ELF", Amount: 100 }],
     RefreshSeconds: 0,  // <-- Zero value
     Threshold: 100
   })
   ```

2. **User Exploitation** (within single block):
   - Submit Transaction 1: Transfer(to: AddressA, amount: 1)
     - Before: freeAllowances = 100
     - SetOrRefreshTransactionFeeFreeAllowances executes (0 > 0 = false, refresh)
     - Allowances set to 100
     - Fee charged: 10 from allowances
     - After: freeAllowances = 90
   
   - Submit Transaction 2: Transfer(to: AddressB, amount: 1) [SAME BLOCK]
     - Before: freeAllowances = 90
     - SetOrRefreshTransactionFeeFreeAllowances executes (0 > 0 = false, refresh AGAIN)
     - Allowances RESET to 100 (overwrites the 90)
     - Fee charged: 10 from allowances
     - After: freeAllowances = 90 (should be 80!)
   
   - Submit Transactions 3-10: [SAME BLOCK]
     - Each transaction refreshes allowances to full 100
     - Each consumes 10, ends at 90
     - User pays zero actual tokens for all 10 transactions

**Expected vs Actual**:
- **Expected**: After 10 transactions consuming 10 each = 100 total, allowances exhausted, subsequent fees charged from balance
- **Actual**: All 10 transactions use free allowances (each sees refreshed full 100), no tokens charged from balance

**Success Condition**: User executes 10+ transactions in single block with only 100 total allowances configured, paying zero transaction fees instead of fees for transactions 2-10.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L241-242)
```csharp
        SetOrRefreshTransactionFeeFreeAllowances(fromAddress);
        var freeAllowancesMap = CalculateTransactionFeeFreeAllowances(fromAddress);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L313-314)
```csharp
            if (lastRefreshTime != null && State.TransactionFeeFreeAllowancesConfigMap[symbol].RefreshSeconds >
                (Context.CurrentBlockTime - lastRefreshTime).Seconds) continue;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L316-318)
```csharp
            State.TransactionFeeFreeAllowancesLastRefreshTimes[address][symbol] = Context.CurrentBlockTime;
            State.TransactionFeeFreeAllowances[address][symbol] =
                State.TransactionFeeFreeAllowancesConfigMap[symbol].FreeAllowances.Clone();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1242-1242)
```csharp
            Assert(allowances.RefreshSeconds >= 0, "Invalid input refresh seconds");
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest_FreeAllowance.cs (L1337-1373)
```csharp
        var chargeFeeRet = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeTransactionFeesInput);
        chargeFeeRet.Output.Success.ShouldBe(true);

        freeAllowances = await TokenContractImplStub.GetTransactionFeeFreeAllowances.CallAsync(DefaultSender);
        freeAllowances.Map.Keys.First().ShouldBe(NativeTokenSymbol);
        freeAllowances.Map.Values.First().Map.Keys.First().ShouldBe(Token1);
        freeAllowances.Map.Values.First().Map.Values.First().Symbol.ShouldBe(Token1);
        freeAllowances.Map.Values.First().Map.Values.First().Amount.ShouldBe(0);

        freeAllowances.Map.Keys.Last().ShouldBe(USDT);
        freeAllowances.Map.Values.Last().Map.Keys.First().ShouldBe(Token2);
        freeAllowances.Map.Values.Last().Map.Values.First().Symbol.ShouldBe(Token2);
        freeAllowances.Map.Values.Last().Map.Values.First().Amount.ShouldBe(500);

        await CheckDefaultSenderTokenAsync(NativeTokenSymbol, 10000);
        await CheckDefaultSenderTokenAsync(USDT, 10000);
        await CheckDefaultSenderTokenAsync(Token1, 10000);
        await CheckDefaultSenderTokenAsync(Token2, 10000);

        chargeFeeRet = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeTransactionFeesInput);
        chargeFeeRet.Output.Success.ShouldBe(true);

        freeAllowances = await TokenContractImplStub.GetTransactionFeeFreeAllowances.CallAsync(DefaultSender);
        freeAllowances.Map.Keys.First().ShouldBe(NativeTokenSymbol);
        freeAllowances.Map.Values.First().Map.Keys.First().ShouldBe(Token1);
        freeAllowances.Map.Values.First().Map.Values.First().Symbol.ShouldBe(Token1);
        freeAllowances.Map.Values.First().Map.Values.First().Amount.ShouldBe(0);

        freeAllowances.Map.Keys.Last().ShouldBe(USDT);
        freeAllowances.Map.Values.Last().Map.Keys.First().ShouldBe(Token2);
        freeAllowances.Map.Values.Last().Map.Values.First().Symbol.ShouldBe(Token2);
        freeAllowances.Map.Values.Last().Map.Values.First().Amount.ShouldBe(0);

        await CheckDefaultSenderTokenAsync(NativeTokenSymbol, 10000);
        await CheckDefaultSenderTokenAsync(USDT, 10000);
        await CheckDefaultSenderTokenAsync(Token1, 9000);
        await CheckDefaultSenderTokenAsync(Token2, 10000);
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest_FreeAllowance.cs (L1398-1398)
```csharp
    [InlineData(1000, 1000, 1000, 0, 10, 800, 1000, 1000, 100, 100)]
```
