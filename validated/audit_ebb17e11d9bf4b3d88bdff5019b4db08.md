# Audit Report

## Title
Stale Period Cache Causes RegisterForProfits Auto-Distribution Failure After Direct ProfitContract Calls

## Summary
The TokenHolderContract maintains a cached period that can become desynchronized from the ProfitContract's authoritative CurrentPeriod due to an early return in `UpdateTokenHolderProfitScheme()`. When a scheme manager legitimately calls ProfitContract.DistributeProfits directly, the period mismatch causes all subsequent RegisterForProfits operations with auto-distribution to fail, resulting in a complete denial of service for new token holder registrations.

## Finding Description

The vulnerability stems from a period synchronization failure in the TokenHolderContract. The contract maintains a cached `Period` field in `TokenHolderProfitScheme` that should always match the ProfitContract's `CurrentPeriod`. However, an early return condition prevents this synchronization: [1](#0-0) 

When this early return executes (because `scheme.SchemeId` exists and `updateSchemePeriod` is false), the function skips the period synchronization logic that would update the cached period from ProfitContract's current state.

The problem manifests when:

1. **Manager calls ProfitContract.DistributeProfits directly** - The ProfitContract allows scheme managers to call DistributeProfits directly: [2](#0-1) 

This increments the ProfitContract's CurrentPeriod: [3](#0-2) 

2. **TokenHolder's cached period becomes stale** - When RegisterForProfits is called, it invokes `GetValidScheme()` with `updateSchemePeriod = false`: [4](#0-3) 

This triggers the early return, preventing period synchronization: [5](#0-4) 

3. **Auto-distribute uses stale period** - The auto-distribute logic fetches the latest scheme but only extracts the VirtualAddress: [6](#0-5) 

It then creates a DistributeProfitsInput using the stale cached period: [7](#0-6) 

4. **ProfitContract validation fails** - When the DistributeProfits call reaches ProfitContract, the strict period validation fails: [8](#0-7) 

The assertion fails because the input period (N) doesn't match the current period (N+1), causing the transaction to revert with the error message: "Invalid period. When release scheme... of period N. Current period is N+1".

## Impact Explanation

**Denial of Service Impact:**
- **Complete DoS of RegisterForProfits**: When auto-distribute is configured and the period mismatch occurs, all users attempting to register for profits will have their transactions fail
- **Affects all new registrations**: Until the periods are manually re-synchronized by calling TokenHolder.DistributeProfits, no new users can join the scheme
- **Operational disruption**: The TokenHolder scheme becomes non-functional for new participant onboarding

**Severity Justification (Medium):**
- The vulnerability causes operational DoS but does not result in fund loss
- It breaks core dividend registration functionality
- Recovery requires manual intervention (someone must call TokenHolder.DistributeProfits to re-sync periods)
- Affects all users during the desynchronized state
- Does not compromise funds or allow unauthorized access

## Likelihood Explanation

**High Likelihood:**

This vulnerability will naturally occur in normal operations because:

1. **Legitimate manager behavior**: Scheme managers calling ProfitContract.DistributeProfits directly is an intended and authorized operation, not an attack
2. **Common configuration**: Auto-distribute thresholds are a standard feature that many schemes will configure
3. **No special privileges required**: The scenario only requires normal operational actions
4. **Low complexity**: The issue triggers with just two sequential operations:
   - Manager calls ProfitContract.DistributeProfits (normal operation)
   - User calls RegisterForProfits with auto-distribute threshold met (normal operation)

**Operational Rationality:**
Managers may legitimately prefer calling ProfitContract directly for:
- Integration with other smart contracts
- Custom distribution logic requirements
- Access to ProfitContract-specific features
- Batch operations across multiple schemes

## Recommendation

Fix the `UpdateTokenHolderProfitScheme()` function to always synchronize the period when the scheme exists, regardless of the `updateSchemePeriod` flag. The early return should only apply when the `SchemeId` is null (scheme not yet initialized).

**Recommended Fix:**
```csharp
private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
    bool updateSchemePeriod)
{
    if (scheme.SchemeId == null)
    {
        // Only skip if scheme doesn't exist yet
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        scheme.SchemeId = originSchemeId;
    }
    
    // Always synchronize period when scheme exists
    var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
    scheme.Period = originScheme.CurrentPeriod;
    State.TokenHolderProfitSchemes[manager] = scheme;
}
```

This ensures the cached period is always synchronized with ProfitContract's authoritative CurrentPeriod, preventing the desynchronization issue.

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_FailsAfterDirectProfitContractCall()
{
    // Setup: Create scheme with auto-distribute threshold
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        AutoDistributeThreshold = { { "ELF", 1000 } }
    });
    
    // Contribute profits to initialize the scheme
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 10000
    });
    
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    
    // Verify initial state: periods are synchronized
    scheme.Period.ShouldBe(profitScheme.CurrentPeriod);
    
    // Manager calls ProfitContract.DistributeProfits directly (legitimate action)
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = scheme.SchemeId,
        Period = profitScheme.CurrentPeriod,
        AmountsMap = { { "ELF", 0 } }
    });
    
    // Verify ProfitContract period incremented
    profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    profitScheme.CurrentPeriod.ShouldBe(scheme.Period + 1);
    
    // TokenHolder's cached period is now stale
    scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    scheme.Period.ShouldBe(profitScheme.CurrentPeriod - 1); // Stale!
    
    // User attempts RegisterForProfits with auto-distribute threshold met
    var registerResult = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = 100,
            SchemeManager = Starter
        });
    
    // Verify the transaction fails with period mismatch error
    registerResult.TransactionResult.Error.ShouldContain("Invalid period");
    registerResult.TransactionResult.Error.ShouldContain("Current period is");
}
```

**Notes:**
- This vulnerability represents a legitimate operational scenario, not a malicious attack
- The issue occurs due to period cache desynchronization between TokenHolderContract and ProfitContract
- The fix should ensure period synchronization happens consistently to maintain the invariant that both contracts track the same period
- Recovery requires manual intervention to call TokenHolder.DistributeProfits, which updates the cached period

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L181-182)
```csharp
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L193-197)
```csharp
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-283)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
    {
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-289)
```csharp
    private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
        bool updateSchemePeriod)
    {
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
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
