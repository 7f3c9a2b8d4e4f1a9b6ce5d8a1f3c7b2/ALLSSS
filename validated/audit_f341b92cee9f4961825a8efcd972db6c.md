# Audit Report

## Title
Permanent DOS of TokenHolder Operations Due to State Storage Bug in UpdateTokenHolderProfitScheme

## Summary

The TokenHolderContract contains a critical state management bug where `UpdateTokenHolderProfitScheme` saves scheme data to the wrong state location. When combined with ProfitContract's `ResetManager` function, this creates a permanent denial-of-service condition that locks users' funds and prevents all scheme operations.

## Finding Description

The vulnerability stems from a state storage bug in `UpdateTokenHolderProfitScheme` that writes to an incorrect state key, combined with cross-contract state dependency on ProfitContract's `ManagingSchemeIds`.

When a TokenHolder scheme is created, the scheme data is stored without a `SchemeId` field. [1](#0-0)  The scheme is simultaneously registered in ProfitContract, with the manager's address tracked in `ManagingSchemeIds`. [2](#0-1) 

When any TokenHolder operation calls `GetValidScheme` with a manager address different from `Context.Sender`, the function loads the scheme from `State.TokenHolderProfitSchemes[manager]` [3](#0-2)  and calls `UpdateTokenHolderProfitScheme` to populate the `SchemeId`. [4](#0-3) 

The critical bug occurs in `UpdateTokenHolderProfitScheme`: it queries `GetManagingSchemeIds` using the `manager` parameter to find the scheme ID [5](#0-4) , populates the scheme's `SchemeId` field [6](#0-5) , but then saves the updated scheme to `State.TokenHolderProfitSchemes[Context.Sender]` instead of `State.TokenHolderProfitSchemes[manager]`. [7](#0-6)  This means the original manager's scheme entry never gets its `SchemeId` populated in persistent storage.

When the scheme manager later calls ProfitContract's `ResetManager` to transfer management, the scheme ID is removed from the original manager's `ManagingSchemeIds` list. [8](#0-7) 

Subsequently, any attempt to call TokenHolder operations for that manager fails because `UpdateTokenHolderProfitScheme` queries `GetManagingSchemeIds` [9](#0-8)  which now returns an empty list. The `FirstOrDefault()` returns null [10](#0-9) , triggering an assertion failure. [11](#0-10) 

## Impact Explanation

**HIGH severity** - This vulnerability causes permanent fund lockup with no recovery mechanism:

1. **Direct Fund Loss**: Users who registered for profits via `RegisterForProfits` locked their tokens using the MultiToken contract's lock mechanism. [12](#0-11)  After `ResetManager` is called, these users cannot withdraw their locked tokens because `Withdraw` requires a successful `GetValidScheme` call. [13](#0-12) 

2. **Complete Scheme Failure**: All functions that depend on `GetValidScheme` become permanently inaccessible: `AddBeneficiary` [14](#0-13) , `RemoveBeneficiary` [15](#0-14) , `ContributeProfits` [16](#0-15) , `DistributeProfits` [17](#0-16) , `RegisterForProfits` [18](#0-17) , `Withdraw` [13](#0-12) , and `ClaimProfits` [19](#0-18) .

3. **No Recovery Path**: There is no administrative function to manually fix the `SchemeId` or bypass the validation. The locked tokens remain permanently inaccessible.

## Likelihood Explanation

**MEDIUM-HIGH likelihood** - This can occur through legitimate operations:

1. **Public Entry Point**: `ResetManager` is a public method in ProfitContract callable by any scheme manager without special privileges. [20](#0-19) 

2. **Realistic Scenario**: Scheme managers commonly transfer management to multi-signature wallets, DAOs, or organizational addresses for security/governance purposes. This is a legitimate use case that unknowingly triggers the vulnerability.

3. **Simple Preconditions**: Only requires (1) scheme creation, (2) users registering for profits, and (3) manager calling `ResetManager` - all normal operations requiring no coordination or special privileges.

4. **Accidental Trigger**: The manager has no indication this operation will break TokenHolder functionality, making accidental triggering highly likely during routine management transfers.

## Recommendation

Fix the state storage bug in `UpdateTokenHolderProfitScheme` by saving to the correct state location:

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
    State.TokenHolderProfitSchemes[manager] = scheme;  // FIX: Use manager instead of Context.Sender
}
```

## Proof of Concept

```csharp
[Fact]
public async Task PermanentDOS_After_ResetManager()
{
    // Setup: Manager creates TokenHolder scheme
    var manager = Accounts[0].Address;
    var user = Accounts[1].Address;
    
    await TokenHolderStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    // User registers for profits (locks tokens)
    await TokenHolderStub_User.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager,
        Amount = 1000
    });
    
    // Manager transfers management using ResetManager
    var schemeId = (await ProfitStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = manager })).SchemeIds.First();
    
    await ProfitStub.ResetManager.SendAsync(new ResetManagerInput
    {
        SchemeId = schemeId,
        NewManager = Accounts[2].Address
    });
    
    // User attempts to withdraw - this will fail permanently
    var withdrawResult = await TokenHolderStub_User.Withdraw.SendWithExceptionAsync(manager);
    withdrawResult.TransactionResult.Error.ShouldContain("Origin scheme not found.");
}
```

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L39-39)
```csharp
        var scheme = GetValidScheme(Context.Sender);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L72-72)
```csharp
        var scheme = GetValidScheme(Context.Sender);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L102-102)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L133-133)
```csharp
        var scheme = GetValidScheme(input.SchemeManager, true);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-213)
```csharp
        var scheme = GetValidScheme(input);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L249-249)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L280-280)
```csharp
        var scheme = State.TokenHolderProfitSchemes[manager];
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L282-282)
```csharp
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-293)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L294-294)
```csharp
        Assert(originSchemeId != null, "Origin scheme not found.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L296-297)
```csharp
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L298-298)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L729-729)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L733-735)
```csharp
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```
