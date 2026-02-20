# Audit Report

## Title
Period Desynchronization Causes DoS in RegisterForProfits Auto-Distribution

## Summary
The TokenHolderContract maintains a local period counter that becomes desynchronized from the Profit contract's authoritative CurrentPeriod when scheme managers call `Profit.DistributeProfits` directly. This causes subsequent `RegisterForProfits` calls with auto-distribution to fail with an "Invalid period" assertion error, creating a complete denial-of-service for new user registrations.

## Finding Description

The TokenHolderContract wraps the Profit contract and caches the current distribution period locally in `scheme.Period`. This cache must remain synchronized with the Profit contract's `CurrentPeriod` for distributions to succeed. However, the synchronization logic has a critical flaw.

When `RegisterForProfits` is called with auto-distribution enabled, it retrieves the scheme without forcing period synchronization: [1](#0-0) 

This triggers an early return in `UpdateTokenHolderProfitScheme` that skips the period synchronization logic: [2](#0-1) 

The early return prevents execution from reaching the synchronization code that updates the local period from the Profit contract's authoritative CurrentPeriod: [3](#0-2) 

When the auto-distribution threshold is met, `RegisterForProfits` creates a distribution request using the stale local period: [4](#0-3) 

The Profit contract strictly validates that the provided period matches its current period: [5](#0-4) 

The desynchronization occurs because the Profit contract authorizes both the TokenHolder contract AND the scheme manager to call `DistributeProfits` directly: [6](#0-5) 

When the scheme manager calls `Profit.DistributeProfits` directly, it increments the Profit contract's `CurrentPeriod`: [7](#0-6) 

However, the TokenHolder's local cache remains stale because the direct call bypassed the TokenHolder wrapper.

In contrast, the manual `DistributeProfits` method correctly forces period synchronization by passing `updateSchemePeriod = true`: [8](#0-7) 

## Impact Explanation

This vulnerability causes **HIGH severity** denial-of-service on the `RegisterForProfits` function:

1. **Complete functionality loss**: Once desynchronization occurs, ALL users attempting to call `RegisterForProfits` will experience transaction failure during auto-distribution. The function becomes completely unusable for new registrations.

2. **Affects core user functionality**: `RegisterForProfits` is the primary entry point for users to participate in profit schemes. This is not an administrative function but a critical user-facing operation.

3. **Auto-distribution is intended behavior**: The auto-distribution feature is explicitly implemented and tested, making this a failure of documented functionality, not an edge case: [9](#0-8) 

4. **Requires manual intervention**: Recovery requires someone with appropriate permissions to call `TokenHolder.DistributeProfits` to force period resynchronization, creating operational overhead and potential confusion.

5. **Systemic vulnerability**: All TokenHolder schemes with `AutoDistributeThreshold` configured are vulnerable to this issue, potentially affecting multiple profit distribution schemes across the protocol.

## Likelihood Explanation

The likelihood of this vulnerability being triggered is **HIGH**:

1. **Legitimate access**: The scheme manager who created the TokenHolder profit scheme has legitimate authorization to call `Profit.DistributeProfits` directly. The scheme manager is set as the caller during scheme creation: [10](#0-9) 

2. **Minimal attack complexity**: The trigger requires only a single direct call to `Profit.DistributeProfits`, bypassing the TokenHolder wrapper. This is trivial to execute.

3. **Dual authorization design**: The Profit contract explicitly allows both the scheme manager and TokenHolder contract to distribute profits, suggesting direct calls are an intended use case rather than a security violation.

4. **Accidental triggers**: This can occur accidentally during normal operations if a scheme manager is unaware they should only distribute through the TokenHolder wrapper, or if they use the Profit contract directly for convenience.

5. **No protective restrictions**: There is no documentation, code comment, or runtime check preventing scheme managers from calling `Profit.DistributeProfits` directly. The authorization model actively enables this pattern.

## Recommendation

Implement one of the following fixes:

**Option 1: Always Force Period Synchronization in RegisterForProfits**
Modify the `RegisterForProfits` method to always update the scheme period before checking auto-distribution thresholds. Change line 152 to pass `true` for the `updateSchemePeriod` parameter:

```csharp
var scheme = GetValidScheme(input.SchemeManager, true);
```

**Option 2: Remove Dual Authorization**
Restrict `Profit.DistributeProfits` to only be callable by the TokenHolder contract for schemes managed through TokenHolder. Modify the authorization check in ProfitContract to remove the scheme manager authorization when the scheme is managed by TokenHolder.

**Option 3: Add Period Synchronization Check**
Add an explicit period synchronization step in the auto-distribution logic before creating the distribution request, ensuring the local cache is always current.

The recommended approach is **Option 1** as it is the simplest fix with minimal code changes and preserves the existing authorization model while ensuring consistency.

## Proof of Concept

```csharp
[Fact]
public async Task PeriodDesynchronization_DoS_Test()
{
    // Setup: Create scheme with auto-distribution
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        AutoDistributeThreshold = { { "ELF", 1000 } }
    });
    
    // Get the profit scheme ID
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    var schemeId = schemeIds.SchemeIds.First();
    
    // Contribute profits to meet auto-distribution threshold
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = 1000,
        Symbol = "ELF"
    });
    
    // Trigger desynchronization: Scheme manager calls Profit.DistributeProfits directly
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1,
        AmountsMap = { { "ELF", 0 } }
    });
    
    // Now Profit.CurrentPeriod = 2, but TokenHolder.scheme.Period = 1
    
    // Verify: RegisterForProfits with auto-distribution now fails
    var result = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = 100,
            SchemeManager = Starter
        });
    
    // Assert the DoS condition
    result.TransactionResult.Error.ShouldContain("Invalid period");
}
```

---

## Notes

This vulnerability represents a state synchronization failure between two contracts where the wrapper (TokenHolder) maintains a cached copy of state from the wrapped contract (Profit). The root cause is the conditional synchronization logic that assumes the cache only needs updating during explicit distribution calls, but fails to account for direct calls to the underlying contract that are authorized by the dual-authorization model. The fix requires either eliminating the dual authorization or ensuring synchronization occurs before every use of the cached period value.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L31-31)
```csharp
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L133-133)
```csharp
        var scheme = GetValidScheme(input.SchemeManager, true);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L193-196)
```csharp
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L289-289)
```csharp
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L297-297)
```csharp
        scheme.Period = originScheme.CurrentPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L478-480)
```csharp
        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```
