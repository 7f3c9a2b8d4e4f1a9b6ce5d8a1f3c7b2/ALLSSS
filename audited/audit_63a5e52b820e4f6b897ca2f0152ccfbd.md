# Audit Report

## Title
Permanent Token Lock Due to State Corruption Bug and Manager Transfer

## Summary
Users who register for profits in a TokenHolder scheme can have their tokens permanently locked if the scheme manager transfers ownership via the Profit contract's `ResetManager` method. This occurs due to a state corruption bug in `UpdateTokenHolderProfitScheme` that stores scheme updates to the wrong address, preventing withdrawal when the manager no longer owns the scheme.

## Finding Description

The TokenHolder contract contains a critical state corruption bug that, when combined with legitimate manager operations, causes permanent token locks for users.

**Root Cause - State Corruption Bug:**

The `UpdateTokenHolderProfitScheme` method incorrectly stores the updated scheme to `Context.Sender` instead of the `manager` parameter. [1](#0-0) 

This causes the populated `SchemeId` to be stored at the caller's address rather than the manager's address.

**Execution Flow:**

1. **Scheme Creation**: Manager M creates a TokenHolder scheme, which initializes the scheme with `SchemeId = null` at the manager's address. [2](#0-1) 

2. **User Registration**: User A registers via `RegisterForProfits(schemeManager=M, amount)`. During registration, tokens are locked via the MultiToken contract. [3](#0-2) 

   The critical issue occurs when `GetValidScheme(M)` is called at line 152, which invokes `UpdateTokenHolderProfitScheme`. This method fetches the scheme ID from the Profit contract but stores it to `State.TokenHolderProfitSchemes[Context.Sender]` (User A's address) instead of the manager's address. [4](#0-3) 

   Unless auto-distribute triggers (which correctly stores to `input.SchemeManager` at lines 204-205), the manager's scheme state remains with `SchemeId = null`.

3. **Manager Transfer**: Manager M calls `ResetManager` in the Profit contract to transfer ownership to address N. [5](#0-4) 

   This operation removes the scheme from M's `ManagingSchemeIds` list (lines 733-735) and adds it to the new manager's list.

4. **Failed Withdrawal**: User A attempts to withdraw by calling `Withdraw(M)`. [6](#0-5) 

   The withdrawal fails because:
   - `GetValidScheme(M)` retrieves `State.TokenHolderProfitSchemes[M]` which still has `SchemeId = null`
   - `UpdateTokenHolderProfitScheme` attempts to populate it by calling `GetManagingSchemeIds` for manager M
   - This returns an empty list because the scheme was transferred to the new manager [7](#0-6) 
   - `FirstOrDefault()` returns null, causing the assertion at line 294 to fail with "Origin scheme not found"

## Impact Explanation

This vulnerability results in **permanent and irreversible loss of user funds**:

- Users' locked tokens become permanently inaccessible with no recovery mechanism
- The `Withdraw` method is the only way to unlock tokens [8](#0-7) , and it becomes permanently blocked after manager transfer
- All tokens locked by any user of a scheme whose manager transfers ownership are affected
- No administrative function exists to unlock tokens or fix the corrupted state
- The fundamental invariant "lock/unlock correctness" is violated

The severity is **Critical** because:
- It causes permanent, irreversible loss of user funds
- Users have no control, warning, or protection against this scenario
- The impact scales with all users registered to affected schemes
- There is no recovery path

## Likelihood Explanation

The likelihood is **Medium-to-High** because:

**Attacker Requirements:**
- Create a TokenHolder scheme (public operation)
- Have users register and lock tokens (normal protocol usage)
- Call `ResetManager` on the Profit contract (available to any scheme manager)

**Complexity:**
The attack requires only a single call to `ResetManager`. [5](#0-4) 

**Feasibility:**
- Manager transfers are legitimate operations that managers may perform for operational reasons (restructuring, upgrading, delegation)
- No warnings, validations, or safeguards prevent managers from calling `ResetManager`
- Users have no visibility or control over manager actions
- The state corruption affects all registrations where auto-distribute doesn't trigger, which depends on threshold configuration

**Realistic Scenarios:**
- Malicious manager intentionally locks user funds before transferring
- Honest manager accidentally triggers the bug during legitimate operational transfer
- Manager unaware that users will be affected by ownership transfer

## Recommendation

Fix the state corruption bug by storing the updated scheme to the correct address:

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
    // FIX: Store to manager address instead of Context.Sender
    State.TokenHolderProfitSchemes[manager] = scheme;
}
```

**Additional Recommendations:**

1. **Migration Plan**: Implement an administrative function to fix existing corrupted state for affected users
2. **Withdrawal Enhancement**: Modify `Withdraw` to handle scheme transfers by checking both old and new manager addresses
3. **ResetManager Validation**: Add checks in `ResetManager` to prevent transfer if there are active beneficiaries in dependent TokenHolder schemes
4. **Event Emission**: Emit events when managers transfer schemes to warn users

## Proof of Concept

```csharp
[Fact]
public async Task Test_PermanentTokenLock_AfterManagerTransfer()
{
    // Setup: Manager creates TokenHolder scheme
    var manager = Accounts[0].Address;
    var user = Accounts[1].Address;
    var newManager = Accounts[2].Address;
    
    // Step 1: Manager creates scheme
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    // Step 2: User registers and locks tokens (without auto-distribute trigger)
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager,
        Amount = 1000
    });
    
    // Verify tokens are locked
    var lockId = await TokenHolderContractStub.LockIds[manager][user].GetAsync();
    Assert.NotNull(lockId);
    
    // Step 3: Manager transfers scheme ownership
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(manager);
    await ProfitContractStub.ResetManager.SendAsync(new ResetManagerInput
    {
        SchemeId = scheme.SchemeId,
        NewManager = newManager
    });
    
    // Step 4: User attempts withdrawal - THIS WILL FAIL
    var withdrawResult = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(manager);
    
    // Assertion: Withdrawal fails with "Origin scheme not found"
    Assert.Contains("Origin scheme not found", withdrawResult.TransactionResult.Error);
    
    // Verify tokens remain permanently locked
    var lockedAmount = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = user,
        LockId = lockId,
        Symbol = "ELF"
    });
    Assert.Equal(1000, lockedAmount.Amount);
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-209)
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

        // Check auto-distribute threshold.
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

        return new Empty();
    }
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
