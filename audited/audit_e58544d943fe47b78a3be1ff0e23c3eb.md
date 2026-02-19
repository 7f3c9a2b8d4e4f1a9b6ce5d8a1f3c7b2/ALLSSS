### Title
Authorization Check After Expensive Validation Loop Enables DOS Attack on SetMethodFee()

### Summary
The `SetMethodFee()` function in BasicContractZero performs expensive token validation in a foreach loop before checking authorization, allowing unauthorized callers to force costly cross-contract operations. An attacker can pass an input.Fees array with thousands of entries (up to the 5MB transaction size limit), causing each entry to trigger a cross-contract call to `TokenContract.IsTokenAvailableForMethodFee()` before the transaction fails at authorization, enabling a DOS attack that can congest the network and prevent legitimate fee updates.

### Finding Description

The vulnerability exists in the `SetMethodFee()` implementation: [1](#0-0) 

**Root Cause:** The authorization check at line 15 occurs AFTER the expensive validation loop at line 11. The foreach loop processes every entry in `input.Fees`, calling `AssertValidToken()` for each one: [2](#0-1) 

Each `AssertValidToken()` call makes a cross-contract call to `TokenContract.IsTokenAvailableForMethodFee()` at line 80, which reads token state to verify the token is burnable: [3](#0-2) 

**Why Protections Fail:**

1. **No array size limit**: Unlike ProfitContract which enforces a limit of 5 entries, BasicContractZero has no validation on `input.Fees.Count`: [4](#0-3) [5](#0-4) 

2. **Transaction size limit allows large arrays**: AElf's 5MB transaction size limit permits tens of thousands of `MethodFee` entries: [6](#0-5) 

3. **No resource token charging for BasicContractZero**: The contract implements ACS1 but not ACS8, so it doesn't pay resource tokens for execution: [7](#0-6) 

4. **Late authorization check pattern**: This same vulnerability exists across multiple system contracts (Parliament, TokenContract, etc.) that all perform validation before authorization: [8](#0-7) 

### Impact Explanation

**Operational DOS Impact:**
- An attacker can force network nodes to execute thousands of expensive cross-contract calls (each reading token state) before the transaction fails at authorization
- With an estimated 50 bytes per `MethodFee` entry, a 5MB transaction could contain ~100,000 entries, resulting in 100,000 cross-contract calls per transaction
- Repeated submission of such transactions can exhaust node computational resources and congest the network
- Legitimate `SetMethodFee()` calls from the authorized MethodFeeController (typically Parliament governance) may be delayed or unable to execute, effectively "freezing fee updates"

**Who is affected:**
- All network nodes processing these malicious transactions
- Governance system unable to update method fees during attack
- Protocol operations that depend on timely fee adjustments

**Severity justification:** High - This enables sustained DOS of a critical governance function (fee management) with practical attack parameters.

### Likelihood Explanation

**Reachable Entry Point:** `SetMethodFee()` is a public ACS1 method callable by anyone without pre-execution authorization checks.

**Attacker Capabilities:** 
- Attacker needs to craft transactions with large `MethodFees` arrays (up to 5MB)
- No special privileges required
- Attack is repeatable

**Economic Rationality:** 
Transaction fees in AElf consist of method fees (fixed) and size fees (transaction size-based), charged through pre-execution plugins: [9](#0-8) 

Since fees are not proportional to the number of cross-contract calls or computational complexity, an attacker can impose computational costs on the network that exceed the transaction fees paid. The attack becomes economically viable if the cost to congest the network is less than the value gained from preventing fee updates or disrupting governance.

**Feasibility:** Highly feasible - requires only the ability to submit transactions with crafted input parameters.

### Recommendation

**Immediate Fix - Move Authorization Check Before Validation Loop:**

Restructure `SetMethodFee()` to check authorization before any expensive operations:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    State.TransactionFees[input.MethodName] = input;
    
    return new Empty();
}
```

**Defense in Depth - Add Array Size Limit:**

Add validation similar to ProfitContract:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    Assert(input.Fees.Count <= MaxMethodFeesCount, "Too many fees.");
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    State.TransactionFees[input.MethodName] = input;
    
    return new Empty();
}
```

Where `MaxMethodFeesCount` is a reasonable limit (e.g., 5-10 fee tokens per method).

**Apply Fix Across All System Contracts:** The same pattern exists in Parliament, Association, MultiToken, CrossChain, Economic, Election, Vote, Referendum, TokenHolder, Configuration, Consensus, Profit, TokenConverter, and Treasury contracts.

**Test Cases:**
1. Test unauthorized SetMethodFee() with large arrays (should fail immediately at authorization)
2. Test authorized SetMethodFee() with array exceeding size limit (should fail at validation)
3. Test authorized SetMethodFee() with valid array (should succeed)
4. Benchmark gas consumption before and after fix to verify mitigation

### Proof of Concept

**Initial State:**
- BasicContractZero contract deployed on test network
- Default MethodFeeController set to Parliament default organization
- Attacker has a standard account with no special privileges

**Attack Steps:**

1. **Craft malicious transaction:**
   ```
   MethodFees input = new MethodFees {
       MethodName = "SomeMethod",
       Fees = { /* Array of 100,000 MethodFee entries with valid token symbols */ }
   };
   ```

2. **Submit transaction:**
   ```
   Call BasicContractZero.SetMethodFee(input)
   ```

3. **Expected behavior:** Transaction should fail immediately with "Unauthorized to set method fee."

4. **Actual behavior:** 
   - Node processes entire foreach loop (100,000 iterations)
   - Each iteration calls AssertValidToken() making cross-contract call to TokenContract
   - 100,000 state reads from TokenContract.GetTokenInfo()
   - Only AFTER all this computation does authorization check fail
   - Transaction fails but computational damage is done

5. **Repeat attack:** Submit multiple such transactions to congest network and prevent legitimate fee updates

**Success Condition:** Attacker can force network nodes to perform O(n) expensive operations where n is controlled by the attacker (up to ~100,000), before authorization rejection occurs. This allows practical DOS of the fee management system.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L9-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);

        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L73-82)
```csharp
    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L252-257)
```csharp
    private bool IsTokenAvailableForMethodFee(string symbol)
    {
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null) throw new AssertionException("Token is not found.");
        return tokenInfo.IsBurnable;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L11-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L8-8)
```csharp
    public const int TokenAmountLimit = 5;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** protobuf/basic_contract_zero_impl.proto (L6-6)
```text
 * Implement AElf Standards ACS0 and ACS1.
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/FeeChargePreExecutionPlugin.cs (L31-61)
```csharp
    }

    protected override Transaction GetTransaction(TokenContractImplContainer.TokenContractImplStub tokenStub,
        ChargeTransactionFeesInput chargeTransactionFeesInput)
    {
        return tokenStub.ChargeTransactionFees.GetTransaction(chargeTransactionFeesInput);
    }
}

```
