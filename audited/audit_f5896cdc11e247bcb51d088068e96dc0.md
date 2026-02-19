# Audit Report

## Title 
Scheme Manager Can Modify Critical Parameters After User Registration, Breaking Withdrawal and Lock Period Expectations

## Summary
The TokenHolder contract's `CreateScheme` method allows scheme managers to overwrite critical scheme parameters (Symbol, MinimumLockMinutes, AutoDistributeThreshold) after users have already registered and locked tokens. This creates a parameter mismatch where users lock tokens under one set of conditions but must withdraw under different conditions, potentially causing permanent fund lockup or indefinite lock period extensions.

## Finding Description

The vulnerability arises from the interaction between three components:

1. **Unconditional State Overwrite**: The `CreateScheme` method in TokenHolderContract directly overwrites the scheme state without validation [1](#0-0) . There is no check to prevent a manager from calling this method multiple times, and no verification that users have already registered under the existing parameters.

2. **Multiple Profit Schemes Created**: Each call to `CreateScheme` creates a NEW scheme in the underlying Profit contract with a different scheme ID [2](#0-1) . The scheme ID is generated based on the manager's scheme count, so the first call creates hash(0), the second creates hash(1), etc.

3. **Parameter Mismatch During Withdrawal**: When users register, they lock tokens based on the current scheme parameters [3](#0-2) . However, during withdrawal, the contract retrieves the OVERWRITTEN scheme parameters from state [4](#0-3) , while the SchemeId is updated to the FIRST scheme [5](#0-4) . This creates a hybrid scheme object with SchemeId from the original scheme but parameters from the overwritten state.

The critical issue is in the withdrawal flow where the scheme Symbol is used to query locked amounts [6](#0-5)  and unlock tokens [7](#0-6) . Since MultiToken's lock/unlock operations are symbol-specific [8](#0-7) [9](#0-8) , attempting to unlock "BTC" when tokens were locked as "ELF" will fail. The GetLockedAmount query will also return 0 [10](#0-9)  because it queries the virtual address balance for the wrong symbol.

## Impact Explanation

This vulnerability has severe impact on user funds:

**Symbol Modification Attack**: If the manager changes the Symbol from "ELF" to "BTC" after users have locked ELF tokens, the withdrawal function will query locked amounts for "BTC" (returning 0) and attempt to unlock "BTC" tokens from a virtual address that holds "ELF" tokens. This causes withdrawal failures and permanent fund lockup, as there is no mechanism for users to unlock their original "ELF" tokens once the scheme parameters have been overwritten.

**MinimumLockMinutes Extension Attack**: If the manager increases MinimumLockMinutes from 1440 minutes (1 day) to 43200 minutes (30 days) after users have registered, users who expected to withdraw after 1 day will fail the time validation check. The manager can repeatedly call `CreateScheme` with increasing lock periods, indefinitely trapping user funds by constantly extending the withdrawal timelock.

**AutoDistributeThreshold Manipulation**: Changing the threshold affects when profits are automatically distributed, altering dividend distribution behavior for existing participants who registered under different expectations.

All registered users are affected - they either lose access to their locked funds completely (symbol mismatch) or face arbitrary extensions of lock periods (time manipulation). This represents direct fund seizure by scheme managers, violating the core security invariant that locked tokens must be unlockable by their rightful owners.

## Likelihood Explanation

The likelihood of this vulnerability being exploited is HIGH:

**Reachable Entry Point**: `CreateScheme` is a public method callable by any address without authorization restrictions [11](#0-10) . There is no check preventing the same manager from calling it multiple times.

**Feasible Preconditions**: The attacker only needs to be the scheme manager, which is simply the address that called `CreateScheme` initially. This is not a privileged admin role requiring governance approval - any user can create a scheme and become its manager. Malicious scheme creators or compromised scheme manager accounts can trivially execute this attack.

**Execution Practicality**: The attack requires only two simple transactions:
1. Initial `CreateScheme` call with legitimate-looking parameters (e.g., Symbol: "ELF", MinimumLockMinutes: 1440)
2. Wait for users to register and lock their tokens
3. Second `CreateScheme` call with modified parameters (e.g., Symbol: "BTC", MinimumLockMinutes: 43200)

No complex contract interactions, timing constraints, or special conditions are required. The attack is straightforward and deterministic.

**Economic Rationality**: The attack costs minimal gas fees (two CreateScheme transactions) but can trap arbitrary amounts of user funds. A malicious scheme manager could profit by collecting contributions via `ContributeProfits` while preventing users from withdrawing their stake, effectively stealing user funds.

## Recommendation

Add a guard to prevent `CreateScheme` from being called multiple times by the same manager:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add this check at the beginning
    var existingScheme = State.TokenHolderProfitSchemes[Context.Sender];
    Assert(existingScheme == null, "Scheme already exists for this manager. Cannot recreate scheme.");
    
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

Alternatively, if scheme parameter updates are a legitimate requirement, create a separate `UpdateScheme` method that:
1. Verifies no users have active registrations
2. Or requires all users to explicitly re-register with new parameters
3. Or ensures locked tokens are migrated correctly to match new parameters

## Proof of Concept

```csharp
[Fact]
public async Task SchemeManager_CanTrapUserFundsByModifyingParameters()
{
    // Setup: Manager creates initial scheme with ELF symbol and 1 day lock
    var manager = Accounts[0];
    var user = Accounts[1];
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1440 // 1 day
    });
    
    // User registers and locks 1000 ELF tokens
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager,
        Amount = 1000
    });
    
    // Verify tokens are locked
    var lockId = await GetUserLockId(manager, user);
    var lockedAmount = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = user,
        LockId = lockId,
        Symbol = "ELF"
    });
    lockedAmount.Amount.ShouldBe(1000);
    
    // ATTACK: Manager calls CreateScheme again with different symbol and extended lock
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "BTC",
        MinimumLockMinutes = 43200 // 30 days
    });
    
    // Fast forward 2 days (past original 1 day lock period)
    await BlockTimeProvider.SetBlockTime(Timestamp.FromDateTime(DateTime.UtcNow.AddDays(2)));
    
    // User attempts to withdraw - this should FAIL due to parameter mismatch
    var withdrawResult = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(manager);
    
    // The withdrawal fails because:
    // 1. GetLockedAmount queries for "BTC" symbol (returns 0) when tokens are locked as "ELF"
    // 2. MinimumLockMinutes check requires 30 days (43200 min) instead of original 1 day
    // 3. User's funds are permanently trapped
    
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    
    // Verify user's ELF tokens remain locked and inaccessible
    var stillLocked = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = user,
        LockId = lockId,
        Symbol = "ELF"
    });
    stillLocked.Amount.ShouldBe(1000); // Funds still trapped
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-14)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-167)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L220-225)
```csharp
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-236)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L280-283)
```csharp
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-297)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-71)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
        State.SchemeInfos[schemeId] = scheme;

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L208-212)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-242)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        Context.SendVirtualInline(fromVirtualAddress, Context.Self, nameof(Transfer), new TransferInput
        {
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-115)
```csharp
    public override GetLockedAmountOutput GetLockedAmount(GetLockedAmountInput input)
    {
        Assert(input.LockId != null, "Lock id cannot be null.");
        var virtualAddress = GetVirtualAddressForLocking(new GetVirtualAddressForLockingInput
        {
            Address = input.Address,
            LockId = input.LockId
        });
        return new GetLockedAmountOutput
        {
            Symbol = input.Symbol,
            Address = input.Address,
            LockId = input.LockId,
            Amount = GetBalance(virtualAddress, input.Symbol)
        };
```
