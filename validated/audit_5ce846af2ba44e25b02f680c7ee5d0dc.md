# Audit Report

## Title
Period Desynchronization Between TokenHolder and Profit Contracts Causes DOS in RegisterForProfits

## Summary
The TokenHolder contract maintains a local `Period` counter that becomes permanently desynchronized from the ProfitContract's `CurrentPeriod` when a scheme manager calls `ProfitContract.DistributeProfits` directly. This causes `RegisterForProfits` to fail when auto-distribute is triggered, creating a permanent DOS condition for new user registrations.

## Finding Description

The vulnerability exists in the period synchronization mechanism between TokenHolder and Profit contracts, involving three critical issues:

**Issue 1: Direct ProfitContract Invocation**

The ProfitContract explicitly allows scheme managers to call `DistributeProfits` directly, bypassing TokenHolder. [1](#0-0) 

When this occurs, ProfitContract increments its `CurrentPeriod`. [2](#0-1) 

However, TokenHolder's local `Period` field remains unchanged, creating permanent desynchronization.

**Issue 2: No Period Synchronization in RegisterForProfits**

The `RegisterForProfits` method retrieves the scheme without period synchronization. [3](#0-2) 

The `GetValidScheme` method has an `updateSchemePeriod` parameter that defaults to `false`. [4](#0-3) 

When `false`, `UpdateTokenHolderProfitScheme` returns early without synchronization if the SchemeId is already set. [5](#0-4) 

When auto-distribute is triggered, the stale period value is used. [6](#0-5) [7](#0-6) 

The ProfitContract then validates this period strictly and reverts when there's a mismatch. [8](#0-7) 

**Issue 3: Storage Corruption Bug**

The `UpdateTokenHolderProfitScheme` method contains a critical storage bug where it saves to `Context.Sender` instead of the `manager` parameter. [9](#0-8) 

When `RegisterForProfits` calls this function, `Context.Sender` is the user (not the manager), causing period synchronization (when it does occur) to be saved to the wrong address.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes complete denial of service for the core `RegisterForProfits` functionality when auto-distribute thresholds are configured:

1. **Operational DOS**: Users cannot register for profits when the auto-distribute threshold is met, preventing them from staking tokens and receiving dividends
2. **Permanent Condition**: The desynchronization persists indefinitely until manual recovery through calling `TokenHolder.DistributeProfits` to resynchronize
3. **Fundamental Functionality**: Token staking and dividend distribution are core economic mechanisms in the AElf ecosystem
4. **No Automatic Recovery**: There is no built-in mechanism to detect or prevent this desynchronization
5. **Widespread Impact**: Any TokenHolder scheme with auto-distribute thresholds (a common configuration) is vulnerable

The storage bug compounds the issue by potentially corrupting period updates when they do occur, making even manual recovery unreliable.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability has a very high probability of occurrence:

1. **Low Complexity**: The manager only needs to call `ProfitContract.DistributeProfits` directly - a single transaction with publicly accessible methods
2. **Legitimate Access Pattern**: The ProfitContract explicitly permits managers to call this method directly, making this a valid operation that can happen in normal usage
3. **No Cost Barrier**: No economic cost beyond normal transaction fees
4. **Accidental Occurrence**: This can happen unintentionally if a manager doesn't understand the dual-contract architecture and calls ProfitContract directly thinking it's equivalent to calling TokenHolder
5. **Difficult Detection**: The desynchronization is not visible without querying both contracts' state separately, and users see generic "Invalid period" errors without understanding the root cause
6. **Common Configuration**: Auto-distribute thresholds are a standard feature for automated profit distribution schemes
7. **No Warnings**: Neither contract emits events or provides warnings about period desynchronization

## Recommendation

**Fix 1: Enforce Period Synchronization in RegisterForProfits**

Change line 152 in `RegisterForProfits` to always synchronize the period:
```csharp
var scheme = GetValidScheme(input.SchemeManager, true); // Force period sync
```

**Fix 2: Correct Storage Bug in UpdateTokenHolderProfitScheme**

Change line 298 to save to the correct address:
```csharp
State.TokenHolderProfitSchemes[manager] = scheme; // Use manager parameter instead of Context.Sender
```

**Fix 3: Add Period Validation (Defense in Depth)**

Before triggering auto-distribute in `RegisterForProfits`, add validation:
```csharp
var currentProfitPeriod = State.ProfitContract.GetScheme.Call(scheme.SchemeId).CurrentPeriod;
Assert(scheme.Period == currentProfitPeriod, "Period desynchronization detected");
```

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_Period_Desynchronization_DOS_Test()
{
    // Setup: Create scheme with auto-distribute threshold
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        AutoDistributeThreshold = { { "ELF", 1000 } }
    });
    
    // Contribute profits to initialize scheme
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = 1000,
        Symbol = "ELF"
    });
    
    // Get scheme IDs
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var schemeId = schemeIds.SchemeIds.First();
    
    // Verify initial period synchronization
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    tokenHolderScheme.Period.ShouldBe(0); // Not distributed yet
    profitScheme.CurrentPeriod.ShouldBe(1); // Initial period
    
    // VULNERABILITY TRIGGER: Manager calls ProfitContract.DistributeProfits directly
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1
    });
    
    // Now periods are desynchronized
    profitScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    profitScheme.CurrentPeriod.ShouldBe(2); // Incremented by direct call
    tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    tokenHolderScheme.Period.ShouldBe(0); // Still unchanged!
    
    // Contribute more profits to meet auto-distribute threshold
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = 1000,
        Symbol = "ELF"
    });
    
    // DOS DEMONSTRATED: RegisterForProfits fails when auto-distribute is triggered
    var result = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = 10,
            SchemeManager = Starter
        });
    
    // Verify DOS - transaction fails with period mismatch error
    result.TransactionResult.Error.ShouldContain("Invalid period");
}
```

**Notes**

The vulnerability is valid and affects production code. The key issue is that `RegisterForProfits` uses `updateSchemePeriod=false` by default, while `DistributeProfits` in TokenHolder correctly uses `updateSchemePeriod=true`. This asymmetry, combined with ProfitContract allowing direct manager invocation, creates the desynchronization condition. The storage bug at line 298 further compounds the issue by saving synchronized periods to the wrong address when synchronization does occur.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L479-480)
```csharp
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L193-197)
```csharp
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L203-203)
```csharp
            State.ProfitContract.DistributeProfits.Send(distributedInput);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-278)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L289-289)
```csharp
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L298-298)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
```
