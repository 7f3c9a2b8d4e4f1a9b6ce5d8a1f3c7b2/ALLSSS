### Title
Permanent DOS of TokenHolder Operations Due to ProfitContract Manager Reset

### Summary
The TokenHolderContract's `GetValidScheme` function can permanently fail when the underlying ProfitContract scheme manager is changed via `ResetManager`, causing a state mismatch between contracts. This prevents users from withdrawing locked tokens, claiming profits, and executing any operations dependent on the scheme, resulting in permanent fund lockup.

### Finding Description

The vulnerability exists in the interaction between TokenHolderContract's `GetValidScheme` function and ProfitContract's `ResetManager` function. [1](#0-0) 

When a TokenHolder scheme is created, the `CreateScheme` function stores scheme data in `State.TokenHolderProfitSchemes[Context.Sender]` but notably does NOT set the `SchemeId` field: [2](#0-1) 

It also creates a corresponding scheme in ProfitContract with the sender as manager: [3](#0-2) 

Later, when functions like `Withdraw` call `GetValidScheme`, the function attempts to retrieve the scheme ID via `UpdateTokenHolderProfitScheme`: [4](#0-3) 

The critical issue is that `UpdateTokenHolderProfitScheme` queries `GetManagingSchemeIds` from ProfitContract to find the scheme ID. However, if the scheme manager calls ProfitContract's `ResetManager`, the scheme ID is removed from the original manager's `ManagingSchemeIds`: [5](#0-4) 

This causes `GetManagingSchemeIds` to return an empty list for the original manager: [6](#0-5) 

When `FirstOrDefault()` returns null at line 293 of TokenHolderContract, the assertion at line 294 fails with "Origin scheme not found", causing the transaction to revert.

### Impact Explanation

**Direct Fund Impact**: Users who registered for profits by locking tokens via `RegisterForProfits` cannot withdraw their locked tokens: [7](#0-6) 

The `Withdraw` function requires calling `GetValidScheme(input)` where `input` is the original scheme manager address. After the manager calls `ResetManager`, this call permanently fails, preventing token unlock.

**Affected Operations**: All functions depending on `GetValidScheme` become permanently inaccessible for the original manager:
- `AddBeneficiary` (line 39)
- `RemoveBeneficiary` (line 72)
- `ContributeProfits` (line 102)
- `DistributeProfits` (line 133)
- `RegisterForProfits` (line 152)
- `Withdraw` (line 213)
- `ClaimProfits` (line 249)

**Severity Justification**: HIGH - Users' tokens are permanently locked with no recovery mechanism. The original scheme manager loses all ability to manage the scheme through TokenHolder functions. Any user who registered for profits cannot access their locked funds or accumulated profits.

### Likelihood Explanation

**Reachable Entry Point**: The ProfitContract's `ResetManager` function is a public method callable by any scheme manager: [8](#0-7) 

**Feasible Preconditions**: 
1. A user creates a TokenHolder scheme (publicly accessible)
2. Other users register for profits and lock tokens (publicly accessible)
3. The scheme manager calls `ResetManager` in ProfitContract (legitimate operation, no special privileges required beyond being the manager)

**Execution Practicality**: The exploit requires no complex setup or coordination. A scheme manager might legitimately transfer management to another address (e.g., to a multi-sig wallet or DAO) without realizing it breaks TokenHolder functionality. The operation executes under normal AElf contract semantics.

**Attack Complexity**: LOW - Single transaction by the scheme manager. The manager may not even intend to cause harm; this could happen accidentally during legitimate management transfer.

**Economic Rationality**: The manager has no direct incentive to execute this, but it can happen through:
- Legitimate management transfer without understanding the consequences
- Malicious manager wanting to prevent users from withdrawing
- Accidental call during contract upgrades or reorganization

### Recommendation

**Code-Level Mitigation**:
1. Store the `SchemeId` during `CreateScheme` in TokenHolderContract instead of querying it dynamically:
   - Modify line 27-32 to include `SchemeId` from the ProfitContract's return value
   - This eliminates the need for `GetManagingSchemeIds` lookup

2. Add synchronization mechanism:
   - Either prevent `ResetManager` calls for TokenHolder-managed schemes
   - Or add a function in TokenHolderContract to update the stored manager address when ProfitContract manager changes

3. Alternative: Query schemes by `SchemeId` directly rather than by manager address:
   - Modify `GetValidScheme` to use the stored `SchemeId` to call `GetScheme` directly
   - Remove dependency on `GetManagingSchemeIds`

**Invariant Checks**:
- Add assertion in `UpdateTokenHolderProfitScheme` to verify scheme consistency before querying `GetManagingSchemeIds`
- Add check in ProfitContract's `ResetManager` to verify if the scheme is managed by TokenHolder and emit warning event

**Test Cases**:
1. Test scenario where manager calls `ResetManager` after users lock tokens, then verify users can still withdraw
2. Test that TokenHolder operations remain functional across manager transfers
3. Test that `GetValidScheme` handles manager changes gracefully

### Proof of Concept

**Initial State**:
1. Alice creates a TokenHolder scheme by calling `CreateScheme(symbol="ELF", minimumLockMinutes=100)`
2. This creates entry in `State.TokenHolderProfitSchemes[Alice]` (without SchemeId set)
3. ProfitContract creates scheme with Alice as manager, scheme added to `State.ManagingSchemeIds[Alice]`

**Exploit Steps**:
1. Bob calls `RegisterForProfits(schemeManager=Alice, amount=1000)` 
   - Locks 1000 tokens
   - Gets added as beneficiary with shares=1000
   - LockId stored in `State.LockIds[Alice][Bob]`

2. Alice calls `ResetManager` in ProfitContract with `newManager=Charlie`
   - ProfitContract removes schemeId from `State.ManagingSchemeIds[Alice]`
   - ProfitContract adds schemeId to `State.ManagingSchemeIds[Charlie]`
   - TokenHolderContract state unchanged

3. Bob attempts to call `Withdraw(input=Alice)` after lock period expires
   - Calls `GetValidScheme(Alice)` at line 213
   - Gets scheme from `State.TokenHolderProfitSchemes[Alice]` (not null, passes line 281)
   - Calls `UpdateTokenHolderProfitScheme` at line 282
   - `scheme.SchemeId` is null, so doesn't return at line 289
   - Calls `GetManagingSchemeIds(Alice)` at line 290-293
   - Returns empty list (scheme moved to Charlie)
   - `FirstOrDefault()` returns null
   - **Assertion fails at line 294: "Origin scheme not found"**
   - **Transaction reverts**

**Expected Result**: Bob should be able to withdraw his 1000 locked tokens after the minimum lock period.

**Actual Result**: Transaction permanently reverts. Bob's tokens remain locked indefinitely with no recovery mechanism.

**Success Condition**: The vulnerability is confirmed when users cannot withdraw tokens after the scheme manager calls `ResetManager`, despite the lock period being satisfied.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-245)
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
    }
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L723-743)
```csharp
    public override Empty ResetManager(ResetManagerInput input)
    {
        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
        Assert(input.NewManager.Value.Any(), "Invalid new sponsor.");

        // Transfer managing scheme id.
        var oldManagerSchemeIds = State.ManagingSchemeIds[scheme.Manager];
        oldManagerSchemeIds.SchemeIds.Remove(input.SchemeId);
        State.ManagingSchemeIds[scheme.Manager] = oldManagerSchemeIds;
        var newManagerSchemeIds = State.ManagingSchemeIds[input.NewManager] ?? new CreatedSchemeIds();
        newManagerSchemeIds.SchemeIds.Add(input.SchemeId);
        State.ManagingSchemeIds[input.NewManager] = newManagerSchemeIds;

        scheme.Manager = input.NewManager;
        State.SchemeInfos[input.SchemeId] = scheme;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```
