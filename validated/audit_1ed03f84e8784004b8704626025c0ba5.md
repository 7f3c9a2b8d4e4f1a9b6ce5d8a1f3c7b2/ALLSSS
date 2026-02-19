# Audit Report

## Title
Permanent DOS of TokenHolder Operations Due to ProfitContract Manager Reset

## Summary

The TokenHolderContract contains a critical state management bug where `UpdateTokenHolderProfitScheme` saves the scheme to the wrong state location. When combined with ProfitContract's `ResetManager` function, this creates a permanent denial-of-service condition that locks users' funds and prevents all scheme operations.

## Finding Description

The vulnerability stems from a state storage bug in `UpdateTokenHolderProfitScheme` combined with cross-contract state dependency.

When a TokenHolder scheme is created, it stores the scheme data without a `SchemeId` field. [1](#0-0)  The scheme is simultaneously registered in ProfitContract with the manager's address tracked in `ManagingSchemeIds`. [2](#0-1) 

When any TokenHolder operation calls `GetValidScheme` with a manager address different from `Context.Sender`, the function loads the scheme from `State.TokenHolderProfitSchemes[manager]` [3](#0-2)  and calls `UpdateTokenHolderProfitScheme` to populate the `SchemeId`. 

The critical bug occurs at the end of `UpdateTokenHolderProfitScheme`: it queries `GetManagingSchemeIds` using the `manager` parameter to find the scheme ID, but then saves the updated scheme to `State.TokenHolderProfitSchemes[Context.Sender]` instead of `State.TokenHolderProfitSchemes[manager]`. [4](#0-3)  This means the original manager's scheme entry never gets its `SchemeId` populated in persistent storage.

When the scheme manager later calls ProfitContract's `ResetManager` to transfer management, the scheme ID is removed from the original manager's `ManagingSchemeIds` list. [5](#0-4) 

Subsequently, any attempt to call TokenHolder operations for that manager fails because `UpdateTokenHolderProfitScheme` queries `GetManagingSchemeIds` which now returns an empty list. [6](#0-5)  The `FirstOrDefault()` returns null, triggering an assertion failure. [7](#0-6) 

## Impact Explanation

**HIGH severity** - This vulnerability causes permanent fund lockup with no recovery mechanism:

1. **Direct Fund Loss**: Users who registered for profits via `RegisterForProfits` locked their tokens using the MultiToken contract's lock mechanism. [8](#0-7)  After `ResetManager` is called, these users cannot withdraw their locked tokens because `Withdraw` requires a successful `GetValidScheme` call. [9](#0-8) 

2. **Complete Scheme Failure**: All seven functions that depend on `GetValidScheme` become permanently inaccessible: `AddBeneficiary`, `RemoveBeneficiary`, `ContributeProfits`, `DistributeProfits`, `RegisterForProfits`, `Withdraw`, and `ClaimProfits`.

3. **No Recovery Path**: There is no administrative function to manually fix the `SchemeId` or bypass the validation. The locked tokens remain permanently inaccessible.

## Likelihood Explanation

**MEDIUM-HIGH likelihood** - This can occur through legitimate operations:

1. **Public Entry Point**: `ResetManager` is a public method in ProfitContract callable by any scheme manager without special privileges. [10](#0-9) 

2. **Realistic Scenario**: Scheme managers commonly transfer management to multi-signature wallets, DAOs, or organizational addresses for security/governance purposes. This is a legitimate use case that unknowingly triggers the vulnerability.

3. **Simple Preconditions**: Only requires (1) scheme creation, (2) users registering for profits, and (3) manager calling `ResetManager` - all normal operations requiring no coordination or special privileges.

4. **Accidental Trigger**: The manager has no indication this operation will break TokenHolder functionality, making accidental triggering highly likely during routine management transfers.

## Recommendation

Fix the state storage bug in `UpdateTokenHolderProfitScheme` by changing line 298 to save to the correct state location:

```csharp
// INCORRECT (current):
State.TokenHolderProfitSchemes[Context.Sender] = scheme;

// CORRECT (fixed):
State.TokenHolderProfitSchemes[manager] = scheme;
```

This ensures the scheme's `SchemeId` is properly saved to the original manager's state entry, preventing the state mismatch that causes the vulnerability.

Additionally, consider implementing a recovery mechanism that allows the new manager to update the TokenHolder scheme reference, or add warnings in documentation about the cross-contract dependencies when calling `ResetManager`.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task TestPermanentDOSAfterResetManager()
{
    // Setup: Manager A creates TokenHolder scheme
    var managerA = Accounts[0].Address;
    var userB = Accounts[1].Address;
    var newManagerC = Accounts[2].Address;
    
    // Step 1: Create TokenHolder scheme (Context.Sender = managerA)
    var createResult = await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    // Step 2: User B registers and locks tokens (Context.Sender = userB, SchemeManager = managerA)
    var registerResult = await TokenHolderContractStubUserB.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = managerA,
        Amount = 1000
    });
    registerResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Manager A calls ResetManager on ProfitContract
    var schemeId = /* get scheme ID from ProfitContract */;
    var resetResult = await ProfitContractStubManagerA.ResetManager.SendAsync(new ResetManagerInput
    {
        SchemeId = schemeId,
        NewManager = newManagerC
    });
    resetResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: User B tries to withdraw - THIS FAILS PERMANENTLY
    var withdrawResult = await TokenHolderContractStubUserB.Withdraw.SendAsync(managerA);
    
    // Assertion: Transaction fails with "Origin scheme not found."
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.TransactionResult.Error.ShouldContain("Origin scheme not found.");
    
    // User B's tokens are permanently locked with no recovery mechanism
}
```

## Notes

The vulnerability requires two components to trigger: (1) the state storage bug where `SchemeId` never gets saved to the correct location, and (2) the `ResetManager` call that removes the scheme from the original manager's `ManagingSchemeIds`. Neither alone causes the issue, but together they create permanent fund lockup. The bug is particularly dangerous because it can be triggered accidentally during legitimate management transfers without any indication of the consequences.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-165)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-244)
```csharp
        var scheme = GetValidScheme(input);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = State.LockIds[input][Context.Sender];
        Assert(lockId != null, "Sender didn't register for profits.");
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");

        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });

        State.LockIds[input].Remove(Context.Sender);
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = Context.Sender
        });
        return new Empty();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L280-283)
```csharp
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-298)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L723-730)
```csharp
    public override Empty ResetManager(ResetManagerInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L733-738)
```csharp
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
        var newManagerSchemeIds = State.ManagingSchemeIds[input.NewManager] ?? new CreatedSchemeIds();
        newManagerSchemeIds.SchemeIds.Add(input.SchemeId);
        State.ManagingSchemeIds[input.NewManager] = newManagerSchemeIds;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```
