# Audit Report

## Title
Period Desynchronization Causes RegisterForProfits Denial of Service

## Summary
The TokenHolder contract caches the Period field from the underlying Profit contract, but fails to update it when the scheme manager calls `DistributeProfits` directly on the Profit contract. This causes period desynchronization, resulting in complete denial of service for `RegisterForProfits` when auto-distribute thresholds are enabled.

## Finding Description

The vulnerability exists due to an early return optimization in `UpdateTokenHolderProfitScheme()` that prevents Period synchronization with the underlying Profit contract. [1](#0-0) 

When `scheme.SchemeId != null` and `updateSchemePeriod` is false, the function returns at line 289 without fetching the current Period from the Profit contract (which would happen at line 297). Most TokenHolder functions call `GetValidScheme()` with the default parameter `updateSchemePeriod = false`: [2](#0-1) 

The Profit contract allows both the scheme manager AND the TokenHolder contract to call `DistributeProfits`: [3](#0-2) 

When the scheme manager calls `DistributeProfits` directly on the Profit contract (bypassing the TokenHolder wrapper), the Profit contract's `CurrentPeriod` advances: [4](#0-3) 

However, the TokenHolder's cached Period remains stale. The Profit contract strictly validates that the input period matches its current period: [5](#0-4) 

In `RegisterForProfits`, when auto-distribute thresholds are met, the function triggers distribution using the stale Period from the TokenHolder scheme: [6](#0-5) 

This causes the Profit contract's assertion to fail when the periods don't match, reverting the entire `RegisterForProfits` transaction and creating a complete denial of service condition.

## Impact Explanation

**Operational Impact - Complete Denial of Service**: Users cannot register for profits when auto-distribute is enabled and the period has become desynchronized. The `RegisterForProfits` function becomes completely unusable, preventing:
- New users from staking tokens and joining the profit scheme
- Existing users from increasing their stakes
- The profit distribution system from functioning as intended

**Affected Users**: All users attempting to register for profits in a TokenHolder scheme where:
1. Auto-distribute thresholds are configured (`AutoDistributeThreshold` is set)
2. The period has become desynchronized (scheme manager called Profit contract directly)
3. The threshold balance has been reached (triggering auto-distribute at lines 179-206)

**Severity**: High. This breaks a core invariant of the TokenHolder contract - that users can always register for profits when they meet the locking requirements. The DoS persists until someone calls `DistributeProfits` through the TokenHolder contract with `updateSchemePeriod = true` to resynchronize. [7](#0-6) 

## Likelihood Explanation

**Attacker Capabilities**: The scheme manager (who created the TokenHolder scheme via `CreateScheme`) has direct access to call `DistributeProfits` on the Profit contract. This is explicitly allowed by the Profit contract's access control. [8](#0-7) 

**Attack Complexity**: Low. The scheme manager only needs to:
1. Call `DistributeProfits` directly on the Profit contract (rather than through the TokenHolder wrapper)
2. This can be done intentionally to cause DoS, or unintentionally if using automation scripts or direct Profit contract interfaces

**Feasibility**: The attack requires the scheme to have been initialized (SchemeId set to non-null) through at least one operation like `AddBeneficiary`, `ContributeProfits`, or `RegisterForProfits`. After initialization, any direct call to Profit.DistributeProfits causes desynchronization.

**Probability**: Medium to High. Scheme managers may legitimately use direct Profit contract calls for various operational reasons (gas optimization, batch operations, automation), making unintentional desynchronization likely in production environments.

## Recommendation

Modify `UpdateTokenHolderProfitScheme()` to always update the Period from the Profit contract, regardless of the `updateSchemePeriod` parameter. The early return should only skip initialization when SchemeId is already set, but should always synchronize the Period to prevent desynchronization:

```csharp
private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
    bool updateSchemePeriod)
{
    if (scheme.SchemeId != null && !updateSchemePeriod) 
    {
        // Still update the Period to prevent desynchronization
        var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
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
    State.TokenHolderProfitSchemes[Context.Sender] = scheme;
}
```

Alternatively, remove the early return entirely and always fetch fresh data from the Profit contract to ensure consistency.

## Proof of Concept

```csharp
[Fact]
public async Task PeriodDesynchronization_CausesRegisterForProfitsDoS()
{
    // 1. Setup: Create TokenHolder scheme with auto-distribute threshold
    var schemeManager = Accounts[0].Address;
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1,
        AutoDistributeThreshold = { { "ELF", 100 } }
    });

    // 2. Initialize the scheme by calling AddBeneficiary (sets SchemeId to non-null)
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Accounts[1].Address,
        Shares = 100
    });

    // 3. Get the underlying Profit scheme ID
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(schemeManager);
    var profitSchemeId = scheme.SchemeId;

    // 4. Scheme manager calls DistributeProfits DIRECTLY on Profit contract
    // This advances the Profit contract's CurrentPeriod but leaves TokenHolder's Period stale
    await ProfitContractStub.DistributeProfits.SendAsync(new Profit.DistributeProfitsInput
    {
        SchemeId = profitSchemeId,
        Period = 1,
        AmountsMap = { { "ELF", 0 } }
    });

    // 5. Contribute profits to meet auto-distribute threshold
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = TokenHolderContractAddress,
        Symbol = "ELF",
        Amount = 200
    });
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = schemeManager,
        Symbol = "ELF",
        Amount = 200
    });

    // 6. User attempts to RegisterForProfits with auto-distribute enabled
    // This should FAIL due to period mismatch
    var result = await TokenHolderContractStub.RegisterForProfits.SendWithExceptionAsync(
        new RegisterForProfitsInput
        {
            SchemeManager = schemeManager,
            Amount = 100
        });

    // 7. Verify DoS: Transaction reverts with period assertion failure
    result.TransactionResult.Error.ShouldContain("Invalid period");
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });

        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-147)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
        var distributeProfitsInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
        scheme.Period = scheme.Period.Add(1);
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L193-203)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-284)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
    {
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
    }
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
