# Audit Report

## Title
Scheme Manager Can Retroactively Increase MinimumLockMinutes to Prevent User Withdrawals

## Summary
The `CreateScheme` function in TokenHolder contract lacks protection against multiple invocations, allowing a malicious scheme manager to overwrite the `TokenHolderProfitScheme` with a new `MinimumLockMinutes` value. This retroactively applies to existing users who registered under the original scheme, permanently trapping their locked tokens.

## Finding Description

The vulnerability exists because `CreateScheme` unconditionally overwrites the scheme parameters without checking if a scheme already exists. [1](#0-0) 

When users register for profits, their lock timestamp is recorded separately from the scheme parameters. [2](#0-1) 

During withdrawal, the system retrieves the current scheme (which may have been replaced) and uses its `MinimumLockMinutes` to validate against the original lock timestamp. [3](#0-2) 

The root cause involves three critical design flaws:
1. Lock timestamps persist separately and are not tied to specific scheme versions
2. Withdrawal validation uses the CURRENT scheme's `MinimumLockMinutes` against the ORIGINAL lock timestamp  
3. The Profit contract allows multiple scheme creations via count-based scheme ID generation [4](#0-3) 

Each `CreateScheme` call creates a new profit scheme with a different ID, so the "Already exists" check never prevents overwriting. [5](#0-4) 

The `UpdateTokenHolderProfitScheme` helper only updates the `SchemeId` and `Period` fields but leaves `MinimumLockMinutes` unchanged from the overwritten scheme. [6](#0-5) 

**Attack Scenario:**
1. Manager creates scheme with `MinimumLockMinutes = 1`
2. User registers and locks 10,000 ELF at timestamp T0
3. Manager calls `CreateScheme` again with `MinimumLockMinutes = 100000000` (~190 years)
4. User attempts withdrawal but check fails: `T0 + 100000000 minutes < CurrentTime` returns false
5. User's 10,000 ELF is permanently locked

## Impact Explanation

**HIGH Severity** - This vulnerability enables complete freezing of user funds:

- **Direct Fund Impact**: Users' locked tokens become permanently inaccessible. A user who locks 10,000 ELF expecting a 1-minute lock period can have it changed to 100,000,000 minutes (~190 years), making funds unrecoverable during the user's lifetime.

- **Affected Parties**: All users who have registered for profits in TokenHolder schemes, including individual token holders, DApp staking contracts, and side chain dividend participants.

- **No Recourse**: Once the scheme parameters are overwritten, there is no mechanism for users to recover their funds. The lock is enforced by the MultiToken contract and cannot be bypassed.

- **Unilateral Execution**: Unlike governance attacks requiring consensus, this can be executed instantly by any scheme manager with a single transaction.

## Likelihood Explanation

**HIGH Likelihood** - The attack is trivial to execute:

- **Attacker Capabilities**: Anyone can become a scheme manager by calling `CreateScheme`. The barrier to entry is minimal - only transaction gas costs.

- **Attack Complexity**: Trivial - requires only one additional `CreateScheme` transaction with modified parameters. No special timing, coordination, or technical sophistication needed.

- **Detection**: Silent attack - no events indicate scheme parameter changes. Users only discover the issue when attempting withdrawal, by which point their funds are already trapped.

- **Economic Rationality**: Highly favorable for malicious actors - single transaction cost versus potential to lock millions in user funds. Can be combined with social engineering (advertise high yields with short lock periods to attract deposits, then change parameters).

- **Preconditions**: Only requires that users have registered for profits, which is normal operation of the contract.

## Recommendation

Add validation to prevent scheme recreation:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add check to prevent overwriting existing scheme
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
        "Scheme already exists for this manager.");
    
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

Alternatively, store scheme parameters versioned by scheme ID rather than by manager address, and record which scheme ID each lock was created under.

## Proof of Concept

```csharp
[Fact]
public async Task SchemeManager_Can_Freeze_User_Funds_By_Changing_MinimumLockMinutes()
{
    // Setup: Manager creates scheme with 1 minute lock
    var manager = Accounts[0].Address;
    var user = Accounts[1].Address;
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 1
    });
    
    // User registers and locks 10000 ELF
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager,
        Amount = 10000
    });
    
    // Advance time by 2 minutes - user should be able to withdraw
    BlockTimeProvider.SetBlockTime(BlockTimeProvider.GetBlockTime().AddMinutes(2));
    
    // Attack: Manager recreates scheme with 100000000 minute lock (~190 years)
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100000000
    });
    
    // User attempts withdrawal - should fail despite time elapsed
    var result = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(manager);
    
    // Assert: Withdrawal fails with "Cannot withdraw" even though original lock period expired
    result.TransactionResult.Error.ShouldContain("Cannot withdraw");
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L167-167)
```csharp
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-228)
```csharp
    public override Empty Withdraw(Address input)
    {
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L59-59)
```csharp
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L964-971)
```csharp
    private Hash GenerateSchemeId(CreateSchemeInput createSchemeInput)
    {
        var manager = createSchemeInput.Manager ?? Context.Sender;
        if (createSchemeInput.Token != null)
            return Context.GenerateId(Context.Self, createSchemeInput.Token);
        var createdSchemeCount = State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0;
        return Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false));
    }
```
