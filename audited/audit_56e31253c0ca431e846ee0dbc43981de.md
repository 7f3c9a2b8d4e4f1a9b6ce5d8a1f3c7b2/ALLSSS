### Title
Permanent Token Lock Due to State Corruption Bug and Manager Transfer

### Summary
Users who register for profits in a TokenHolder scheme can have their tokens permanently locked if the scheme manager transfers ownership via the Profit contract's `ResetManager` method. This occurs due to a state corruption bug in `UpdateTokenHolderProfitScheme` that stores scheme updates to the wrong address, preventing withdrawal when the manager no longer owns the scheme.

### Finding Description

**Root Cause - State Corruption Bug:**

The `UpdateTokenHolderProfitScheme` method contains a critical bug where it stores the updated scheme to `Context.Sender` instead of the `manager` parameter: [1](#0-0) 

This causes the populated `SchemeId` to be stored at the caller's address rather than the manager's address. When combined with the Profit contract's `ResetManager` functionality, this creates a permanent lock scenario.

**Exploitation Path:**

1. **Scheme Creation**: Manager M creates a TokenHolder scheme via `CreateScheme`, which initializes `State.TokenHolderProfitSchemes[M]` with `SchemeId = null`: [2](#0-1) 

2. **User Registration**: User A registers via `RegisterForProfits(schemeManager=M, amount)`, which locks tokens and stores the lockId: [3](#0-2) 

During registration, `GetValidScheme(M)` is called, which populates the `SchemeId` but stores it to `State.TokenHolderProfitSchemes[UserA]` instead of `State.TokenHolderProfitSchemes[M]` due to the bug. Unless auto-distribute triggers (which updates the state correctly at lines 204-205), the manager's scheme state remains with `SchemeId = null`.

3. **Manager Transfer**: Manager M calls `ResetManager` in the Profit contract to transfer ownership to address N: [4](#0-3) 

This removes the scheme from M's `ManagingSchemeIds` (lines 733-735) and adds it to N's list.

4. **Failed Withdrawal**: User A attempts to withdraw by calling `Withdraw(M)`: [5](#0-4) 

The withdrawal fails because:
- `GetValidScheme(M)` retrieves `State.TokenHolderProfitSchemes[M]` which still has `SchemeId = null`
- `UpdateTokenHolderProfitScheme` is called to fetch the scheme
- `GetManagingSchemeIds` for manager M returns an empty list (scheme was transferred)
- `FirstOrDefault()` returns null
- The assertion at line 294 fails: "Origin scheme not found" [6](#0-5) 

**Why Existing Protections Fail:**

The assertion at line 281 checks if the scheme object is null, which it is not—it exists but has an unpopulated `SchemeId`. The actual failure occurs in `UpdateTokenHolderProfitScheme` at line 294 when trying to resolve the scheme ID from a manager who no longer owns any schemes.

### Impact Explanation

**Direct Fund Impact:**
- Users' locked tokens become permanently inaccessible with no recovery mechanism
- The `Withdraw` method is the only way to unlock tokens, and it becomes permanently blocked
- All tokens locked by any user of a scheme whose manager transfers ownership are affected

**Affected Parties:**
- All users who registered to the scheme before the manager transfer
- Amount equals the sum of all locked tokens across affected users

**Severity Justification:**
Critical severity due to:
- Permanent and irreversible loss of user funds
- No administrative recovery function exists
- Violation of the fundamental invariant: "lock/unlock correctness"
- Users have no warning or protection against this scenario

### Likelihood Explanation

**Attacker Capabilities:**
The scheme manager must have:
- Created a TokenHolder scheme (legitimate operation)
- Had users register and lock tokens (normal protocol usage)
- Access to call `ResetManager` on the Profit contract (available to any scheme manager)

**Attack Complexity:**
Low complexity—requires only a single call to `ResetManager`: [7](#0-6) 

**Feasibility Conditions:**
- Manager transfers ownership intentionally (malicious) or accidentally (operational error)
- Users registered without triggering auto-distribute, or auto-distribute threshold not configured
- Realistic in normal protocol operations

**Probability Assessment:**
Medium-to-high probability:
- `ResetManager` is a legitimate function managers may use for operational reasons
- No warnings or safeguards prevent managers from calling it
- Users have no visibility or control over manager actions
- The state corruption bug affects all registrations where auto-distribute doesn't trigger

### Recommendation

**Code-Level Mitigation:**

1. **Fix the state corruption bug** at line 298 to use the `manager` parameter instead of `Context.Sender`:

```csharp
// Line 298: Change from
State.TokenHolderProfitSchemes[Context.Sender] = scheme;
// To
State.TokenHolderProfitSchemes[manager] = scheme;
```

2. **Add scheme validation** in the `Withdraw` method to handle manager transfers gracefully. Store the original scheme ID when users register:

```csharp
// Store scheme ID with lockId during registration
State.LockSchemeIds[input.SchemeManager][Context.Sender] = scheme.SchemeId;

// In Withdraw, use stored scheme ID instead of re-fetching
var originalSchemeId = State.LockSchemeIds[input][Context.Sender];
```

3. **Add invariant check** to prevent `ResetManager` when TokenHolder beneficiaries exist, or implement a migration path for locked tokens.

**Test Cases:**
1. Test registration followed by manager transfer and attempted withdrawal
2. Test that scheme state is correctly updated for the manager address after any operation
3. Test withdrawal after manager transfer with the proposed fix
4. Test that all state writes to `TokenHolderProfitSchemes` use the correct address key

### Proof of Concept

**Initial State:**
- Manager M has created a TokenHolder profit scheme
- Profit scheme created with M as manager
- Auto-distribute not configured or threshold not met

**Attack Sequence:**

1. **User A registers:**
   ```
   TokenHolderContract.RegisterForProfits({
     SchemeManager: M,
     Amount: 1000 ELF
   })
   ```
   - Result: 1000 ELF locked, lockId stored at `State.LockIds[M][UserA]`
   - Bug: Scheme update stored at `State.TokenHolderProfitSchemes[UserA]`
   - State: `State.TokenHolderProfitSchemes[M].SchemeId` remains null

2. **Manager M transfers ownership:**
   ```
   ProfitContract.ResetManager({
     SchemeId: <scheme_id>,
     NewManager: N
   })
   ```
   - Result: Scheme removed from M's `ManagingSchemeIds`, added to N's

3. **User A attempts withdrawal:**
   ```
   TokenHolderContract.Withdraw(M)
   ```
   - Expected: Tokens unlocked and returned to User A
   - Actual: Transaction fails with "Origin scheme not found"
   - Result: 1000 ELF permanently locked

**Success Condition:**
The vulnerability is confirmed when step 3 fails with assertion error at line 294, preventing User A from withdrawing their locked tokens despite having waited past the minimum lock period and meeting all other withdrawal conditions.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-177)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = input.Amount
            }
        });

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
