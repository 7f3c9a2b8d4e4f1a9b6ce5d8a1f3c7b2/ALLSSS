### Title
Uninitialized TokenHolderContract Reference Causes Side Chain Dividend Pool DoS

### Summary
The `InitialProfitSchemeForSideChain()` function returns early without throwing an exception when the TokenHolder contract is not found, leaving `State.TokenHolderContract.Value` uninitialized. This causes all subsequent `Donate()` calls and related view methods to fail with a `NullReferenceException`, completely disabling the side chain dividend pool functionality.

### Finding Description

**Exact Code Locations:**

The vulnerability exists in the initialization flow where `InitialProfitSchemeForSideChain()` is called during side chain consensus contract initialization. [1](#0-0) 

When `Context.GetContractAddressByName` returns null (indicating TokenHolder contract is not deployed), the function logs a debug message and returns early without setting `State.TokenHolderContract.Value` or throwing an exception. [2](#0-1) 

The `State.TokenHolderContract.Value` is only set when the TokenHolder contract address is successfully retrieved. [3](#0-2) 

**Root Cause:**

The `Donate()` public method uses `State.TokenHolderContract.Value` in two critical places without any null check:
1. As the `Spender` parameter in the Approve call
2. In the `ContributeProfits.Send()` call [4](#0-3) 

When `State.TokenHolderContract.Value` is null, attempting to use it as a contract reference will throw a `NullReferenceException`, causing the transaction to fail.

**Why Protections Fail:**

The contract has inconsistent null checking. The `Donate()` method only calls `EnsureTokenContractAddressSet()` to lazily initialize the Token contract reference, [5](#0-4)  but there is no equivalent `EnsureTokenHolderContractAddressSet()` method. [6](#0-5) 

In contrast, the `Release()` method properly checks for null before using `State.TokenHolderContract.Value`. [7](#0-6) 

Additionally, the private `GetSideChainDividendPoolScheme()` method also lacks null checking before calling `State.TokenHolderContract.GetScheme.Call()`, [8](#0-7)  affecting view methods `GetSymbolList()` and `GetUndistributedDividends()`.

### Impact Explanation

**Concrete Harm:**
- Complete denial-of-service of the side chain dividend pool functionality
- All `Donate()` calls will fail with `NullReferenceException`
- View methods `GetSymbolList()` and `GetUndistributedDividends()` will also fail
- The dividend pool becomes permanently unusable until contract reinitialization or upgrade

**Who Is Affected:**
- All side chains where TokenHolder contract is not deployed during consensus contract initialization
- Users attempting to donate to the dividend pool
- Applications querying dividend pool information

**Severity Justification (Medium):**
- **No direct fund loss**: Transactions fail before any token transfers complete
- **Complete functional DoS**: The entire dividend pool mechanism is disabled
- **Configuration-dependent**: Only affects side chains with missing TokenHolder contract deployment
- **Permanent until upgrade**: Cannot be fixed without contract upgrade or redeployment

### Likelihood Explanation

**Attacker Capabilities:**
- No special privileges required - any user can call the public `Donate()` method

**Attack Complexity:**
- Trivial - simply call `Donate()` with valid parameters
- No complex transaction sequencing required

**Feasibility Conditions:**
- The side chain must have been initialized with `IsSideChain = true`
- TokenHolder contract was not deployed or `GetContractAddressByName` returned null during initialization
- The code comment explicitly acknowledges this scenario: "No need to continue if Token Holder Contract didn't deployed" [9](#0-8) 

**Detection/Operational Constraints:**
- This is a deployment/configuration issue, not runtime exploitation
- Would be immediately detected on first `Donate()` call attempt
- Likelihood depends on side chain deployment practices

### Recommendation

**Code-Level Mitigation:**

1. Add a null check at the beginning of `Donate()` method:
```csharp
public override Empty Donate(DonateInput input)
{
    if (State.TokenHolderContract.Value == null)
    {
        return new Empty(); // or throw assertion
    }
    // ... rest of method
}
```

2. Add similar null checks in `GetSideChainDividendPoolScheme()`:
```csharp
private Scheme GetSideChainDividendPoolScheme()
{
    if (State.TokenHolderContract.Value == null)
    {
        return new Scheme(); // or handle appropriately
    }
    // ... rest of method
}
```

3. Alternatively, create an `EnsureTokenHolderContractAddressSet()` helper method similar to `EnsureTokenContractAddressSet()` and call it in `Donate()` for lazy initialization.

4. Consider throwing an assertion in `InitialProfitSchemeForSideChain()` instead of silently returning, if TokenHolder contract is required for side chain operation.

**Invariant Checks:**
- Ensure `State.TokenHolderContract.Value` is null-checked before any `.Send()` or `.Call()` operations
- Maintain consistency: if `Release()` checks for null, all other methods should too

**Test Cases:**
- Test side chain initialization with missing TokenHolder contract
- Verify `Donate()` either fails gracefully or throws explicit error (not NullReferenceException)
- Verify view methods return empty/default values rather than crashing
- Test lazy initialization if that approach is chosen

### Proof of Concept

**Required Initial State:**
1. Deploy AEDPoS consensus contract on a side chain
2. Do NOT deploy TokenHolder contract before consensus initialization
3. Call `InitialAElfConsensusContract` with `IsSideChain = true`
4. `GetContractAddressByName(TokenHolderContractSystemName)` returns null
5. `InitialProfitSchemeForSideChain()` returns early, leaving `State.TokenHolderContract.Value = null`

**Transaction Steps:**
1. Any user calls `Donate(symbol: "ELF", amount: 1000)`
2. Method reaches line 56: `Spender = State.TokenHolderContract.Value` (null)
3. Method reaches line 59: `State.TokenHolderContract.ContributeProfits.Send(...)`

**Expected vs Actual Result:**
- **Expected**: Graceful handling or explicit error message
- **Actual**: `NullReferenceException` thrown, transaction fails, dividend pool is unusable

**Success Condition:**
Transaction failure with NullReferenceException when attempting to call methods on null contract reference, demonstrating complete DoS of dividend pool functionality.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L35-35)
```csharp
        if (input.IsSideChain) InitialProfitSchemeForSideChain(input.PeriodSeconds);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L18-25)
```csharp
        var tokenHolderContractAddress =
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName);
        // No need to continue if Token Holder Contract didn't deployed.
        if (tokenHolderContractAddress == null)
        {
            Context.LogDebug(() => "Token Holder Contract not found, so won't initial side chain dividends pool.");
            return;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L27-27)
```csharp
        State.TokenHolderContract.Value = tokenHolderContractAddress;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L39-39)
```csharp
        EnsureTokenContractAddressSet();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L52-64)
```csharp
        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            Spender = State.TokenHolderContract.Value
        });

        State.TokenHolderContract.ContributeProfits.Send(new ContributeProfitsInput
        {
            SchemeManager = Context.Self,
            Symbol = input.Symbol,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L104-104)
```csharp
        if (State.TokenHolderContract.Value == null) return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L167-167)
```csharp
            var tokenHolderScheme = State.TokenHolderContract.GetScheme.Call(Context.Self);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L140-145)
```csharp
    private void EnsureTokenContractAddressSet()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
    }
```
