# Audit Report

## Title
Period Desynchronization Causes RegisterForProfits Denial of Service

## Summary
The TokenHolder contract caches the Period field from the underlying Profit contract but fails to update it when the scheme manager calls `DistributeProfits` directly on the Profit contract. This causes period desynchronization, resulting in complete denial of service for `RegisterForProfits` when auto-distribute thresholds are enabled.

## Finding Description

The vulnerability stems from an optimization in the `UpdateTokenHolderProfitScheme()` method that prevents Period synchronization with the underlying Profit contract. [1](#0-0) 

When a TokenHolder scheme has been initialized (`scheme.SchemeId != null`) and `updateSchemePeriod` is false, the function returns early without fetching the current Period from the Profit contract. [2](#0-1) 

Most TokenHolder functions call `GetValidScheme()` with the default parameter `updateSchemePeriod = false`. [3](#0-2)  For example, `RegisterForProfits` uses this default parameter. [4](#0-3) 

The Profit contract's access control explicitly allows both the scheme manager AND the TokenHolder contract to call `DistributeProfits`. [5](#0-4) 

When the scheme manager calls `DistributeProfits` directly on the Profit contract (bypassing TokenHolder), the Profit contract's `CurrentPeriod` advances. [6](#0-5) 

However, the TokenHolder's cached Period remains stale. The Profit contract strictly validates that the input period matches its current period. [7](#0-6) 

In `RegisterForProfits`, when auto-distribute thresholds are met, the function triggers distribution using the stale Period from the TokenHolder scheme. [8](#0-7)  Specifically, it creates a `DistributeProfitsInput` with the cached period. [9](#0-8) 

This causes the Profit contract's assertion to fail when the periods don't match, reverting the entire `RegisterForProfits` transaction.

## Impact Explanation

**Operational Impact - Complete Denial of Service**: Users cannot register for profits when auto-distribute is enabled and the period has become desynchronized. The `RegisterForProfits` function becomes completely unusable, preventing:
- New users from staking tokens and joining the profit scheme
- Existing users from increasing their stakes  
- The profit distribution system from functioning as intended

**Affected Users**: All users attempting to register for profits in a TokenHolder scheme where:
1. Auto-distribute thresholds are configured (`AutoDistributeThreshold` is set)
2. The period has become desynchronized (scheme manager called Profit contract directly)
3. The threshold balance has been reached (triggering auto-distribute)

**Severity**: High. This breaks a core invariant of the TokenHolder contract - that users can always register for profits when they meet the locking requirements. The DoS persists until someone calls `DistributeProfits` through the TokenHolder contract with `updateSchemePeriod = true` to resynchronize. [10](#0-9) 

## Likelihood Explanation

**Attacker Capabilities**: The scheme manager (who created the TokenHolder scheme via `CreateScheme`) has direct access to call `DistributeProfits` on the Profit contract. This is explicitly allowed by the Profit contract's access control. [5](#0-4) 

**Attack Complexity**: Low. The scheme manager only needs to:
1. Call `DistributeProfits` directly on the Profit contract (rather than through the TokenHolder wrapper)
2. This can be done intentionally to cause DoS, or unintentionally if using automation scripts or direct Profit contract interfaces

**Feasibility**: The attack requires the scheme to have been initialized (SchemeId set to non-null) through at least one operation like `ContributeProfits` or `RegisterForProfits`. Tests confirm that after `CreateScheme`, SchemeId is null, but becomes non-null after the first operation. [11](#0-10)  After initialization, any direct call to Profit.DistributeProfits causes desynchronization.

**Probability**: Medium to High. Scheme managers may legitimately use direct Profit contract calls for various operational reasons (gas optimization, batch operations, automation), making unintentional desynchronization likely in production environments.

## Recommendation

Modify the `UpdateTokenHolderProfitScheme()` method to always synchronize the Period when the scheme has been initialized, regardless of the `updateSchemePeriod` parameter:

```csharp
private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
    bool updateSchemePeriod)
{
    if (scheme.SchemeId != null && !updateSchemePeriod) 
    {
        // Still need to sync Period even when not updating full scheme
        var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[manager] = scheme;
        return;
    }
    
    var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
    {
        Manager = manager
    }).SchemeIds.FirstOrDefault();
    Assert(originSchemeId != null, "Origin scheme not found.");
    var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
    scheme.SchemeId = originScheme.SchemeId;
    scheme.Period = originScheme.CurrentPeriod;
    State.TokenHolderProfitSchemes[manager] = scheme;
}
```

Alternatively, always pass `updateSchemePeriod = true` when calling `GetValidScheme()` from functions that may trigger distribution operations.

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_PeriodDesynchronization_DoS_Test()
{
    // Setup: Create scheme with auto-distribute
    var amount = 1000L;
    var tokenSymbol = "ELF";
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = tokenSymbol,
        AutoDistributeThreshold = { { tokenSymbol, amount } }
    });
    
    // Initialize scheme by contributing profits
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = amount,
        Symbol = tokenSymbol
    });
    
    // Get scheme IDs
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    var schemeId = schemeIds.SchemeIds.First();
    
    // Verify periods are synchronized (both at 1)
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    profitScheme.CurrentPeriod.ShouldBe(1);
    tokenHolderScheme.Period.ShouldBe(1);
    
    // ATTACK: Scheme manager calls DistributeProfits directly on Profit contract
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1,
        AmountsMap = { { tokenSymbol, 0 } }
    });
    
    // Profit contract's period advances to 2
    profitScheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    profitScheme.CurrentPeriod.ShouldBe(2);
    
    // TokenHolder's cached period remains at 1 (stale)
    tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    tokenHolderScheme.Period.ShouldBe(1); // Still stale!
    
    // Contribute more to meet auto-distribute threshold again
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = amount,
        Symbol = tokenSymbol
    });
    
    // EXPLOIT: RegisterForProfits fails due to period mismatch
    var result = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            Amount = amount,
            SchemeManager = Starter
        });
    
    // Transaction reverts with period mismatch error
    result.TransactionResult.Error.ShouldContain("Invalid period");
}
```

## Notes

This vulnerability requires the scheme manager to call the Profit contract directly, which is a legitimate operation by design. The issue is that TokenHolder's caching mechanism doesn't account for this valid usage pattern. The fix should ensure Period synchronization on every access, not just during full scheme updates.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L133-133)
```csharp
        var scheme = GetValidScheme(input.SchemeManager, true);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L179-206)
```csharp
        if (scheme.AutoDistributeThreshold != null && scheme.AutoDistributeThreshold.Any())
        {
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
            Profit.DistributeProfitsInput distributedInput = null;
            foreach (var threshold in scheme.AutoDistributeThreshold)
            {
                var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = virtualAddress,
                    Symbol = threshold.Key
                }).Balance;
                if (balance < threshold.Value) continue;
                if (distributedInput == null)
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
                distributedInput.AmountsMap[threshold.Key] = 0;
                break;
            }

            if (distributedInput == null) return new Empty();
            State.ProfitContract.DistributeProfits.Send(distributedInput);
            scheme.Period = scheme.Period.Add(1);
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-278)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-299)
```csharp
    private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
        bool updateSchemePeriod)
    {
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
    }
```

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

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L43-57)
```csharp
            tokenHolderProfitScheme.Period.ShouldBe(0);
            tokenHolderProfitScheme.Symbol.ShouldBe("APP");
            tokenHolderProfitScheme.SchemeId.ShouldBeNull();
        }

        await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeManager = Starter,
            Symbol = "ELF",
            Amount = 1
        });

        {
            var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
            tokenHolderProfitScheme.SchemeId.ShouldNotBeNull();
```
