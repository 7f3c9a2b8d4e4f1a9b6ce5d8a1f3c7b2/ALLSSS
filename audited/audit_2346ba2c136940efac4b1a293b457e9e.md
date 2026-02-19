### Title
Scheme Manager Can Modify Critical Parameters After User Registration, Breaking Withdrawal and Lock Period Expectations

### Summary
The TokenHolder contract's `CreateScheme` method lacks protection against repeated invocation by the same manager, allowing scheme parameters (Symbol, MinimumLockMinutes, AutoDistributeThreshold) to be overwritten after users have already registered and locked tokens. This breaks user expectations and can prevent withdrawals or indefinitely trap user funds with extended lock periods.

### Finding Description

The `CreateScheme` method in TokenHolderContract.cs unconditionally overwrites the scheme parameters without checking if a scheme already exists or if users have already registered: [1](#0-0) 

The method directly assigns a new `TokenHolderProfitScheme` to `State.TokenHolderProfitSchemes[Context.Sender]` without any validation. The underlying Profit contract allows the same manager to create multiple schemes: [2](#0-1) 

When users register for profits, they lock tokens based on the current scheme parameters: [3](#0-2) 

The tokens are locked with the scheme's Symbol (line 162), and the lock timestamp is recorded (line 167). However, when users attempt to withdraw, the contract uses the CURRENT scheme parameters, not the ones at registration time: [4](#0-3) 

The withdrawal logic queries the locked amount using `scheme.Symbol` (line 224), validates against `scheme.MinimumLockMinutes` (line 227), and unlocks using `scheme.Symbol` (line 235). If these parameters have been modified via a second `CreateScheme` call, the operations will fail or behave incorrectly.

The MultiToken contract's lock/unlock operations are symbol-specific - tokens locked with symbol "ELF" must be unlocked with the same symbol: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Symbol Modification Attack**: If the manager changes Symbol from "ELF" to "BTC" after users have locked ELF tokens, the `Withdraw` function will query locked amounts for "BTC" (returning 0) and attempt to unlock "BTC" tokens instead of the user's locked "ELF" tokens, causing withdrawal failures and permanent fund lockup.

**MinimumLockMinutes Extension Attack**: If the manager increases MinimumLockMinutes from 1440 (1 day) to 43200 (30 days) after users have registered, users who expected to withdraw after 1 day will be unable to withdraw for 30 days. This can be repeated indefinitely to trap user funds permanently.

**AutoDistributeThreshold Manipulation**: Changing the threshold alters dividend distribution behavior, affecting when and how profits are distributed to existing participants who registered under different expectations.

All registered users are affected - they lose access to their locked funds or face arbitrary extension of lock periods. This represents direct fund theft/seizure by scheme managers, violating the core invariant that "lock/unlock correctness" must be maintained.

### Likelihood Explanation

**Reachable Entry Point**: `CreateScheme` is a public method callable by any address without restriction. No authorization check prevents the manager from calling it multiple times.

**Feasible Preconditions**: The attacker must be the scheme manager (the address that called `CreateScheme` initially). This is not a privileged admin role but simply the creator of the scheme. Malicious scheme managers or compromised scheme manager accounts can trivially execute this attack.

**Execution Practicality**: The attack requires only two transactions: (1) Initial `CreateScheme` call to establish the scheme, wait for users to register, then (2) Second `CreateScheme` call with modified parameters. No complex contract interactions or timing requirements exist.

**Economic Rationality**: The attack costs minimal gas fees (two CreateScheme transactions) but can trap arbitrary amounts of user funds. A malicious scheme manager could profit by collecting profits/contributions while preventing users from withdrawing their stake.

The vulnerability is straightforward to exploit and has already been demonstrated in the codebase structure - there are no tests verifying that `CreateScheme` cannot be called twice, suggesting this attack vector was not considered during development.

### Recommendation

**Immediate Fix**: Add a check in `CreateScheme` to prevent re-creation of schemes:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
           "Scheme already exists. Cannot modify scheme parameters after creation.");
    
    // ... rest of the method
}
```

**Enhanced Solution**: Implement a dedicated `UpdateScheme` method with strict validation:
- Only allow updates when no users are currently registered (total shares == 0)
- Or require all registered users to explicitly approve parameter changes
- Or maintain parameter history per registration, checking parameters at registration time during withdrawal

**State Validation**: Store the scheme parameters (Symbol, MinimumLockMinutes) in the lock state itself during `RegisterForProfits`, and use those stored parameters during `Withdraw` rather than the current scheme state.

**Test Cases**: Add regression tests:
- Test that `CreateScheme` fails when called twice by the same manager
- Test that parameter modifications (if allowed in future) do not affect existing registered users
- Test withdrawal with original parameters remains functional regardless of scheme state changes

### Proof of Concept

**Initial State**: Manager deploys TokenHolder scheme

**Step 1**: Manager calls `CreateScheme`
```
CreateScheme({
    Symbol: "ELF",
    MinimumLockMinutes: 1440,  // 1 day
    AutoDistributeThreshold: {}
})
```

**Step 2**: User registers and locks 10,000 ELF tokens
```
RegisterForProfits({
    SchemeManager: <manager_address>,
    Amount: 10000
})
```
- Tokens are locked with Symbol="ELF"
- LockTimestamp recorded = T0

**Step 3**: Manager calls `CreateScheme` again (malicious)
```
CreateScheme({
    Symbol: "BTC",
    MinimumLockMinutes: 43200,  // 30 days
    AutoDistributeThreshold: {}
})
```
- State.TokenHolderProfitSchemes[manager] is overwritten

**Step 4**: After 2 days (T0 + 2880 minutes), user attempts withdrawal
```
Withdraw(<manager_address>)
```

**Expected Result**: User withdraws 10,000 ELF tokens successfully (lock period was 1 day)

**Actual Result**: Transaction fails with "Cannot withdraw" because:
- Line 227 checks: LockTimestamp (T0) + MinimumLockMinutes (43200) < CurrentBlockTime (T0 + 2880)
- This evaluates to FALSE (T0 + 43200 > T0 + 2880)
- User must wait 30 days instead of the originally agreed 1 day

**Alternate Failure**: If user waits 30 days and tries again, withdrawal attempts to unlock "BTC" tokens but user locked "ELF" tokens, causing unlock operation to fail or return zero balance.

**Success Condition**: User funds are trapped and withdrawal is blocked, demonstrating complete parameter modification attack.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L44-84)
```csharp
    public override Hash CreateScheme(CreateSchemeInput input)
    {
        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");

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

        Context.LogDebug(() => $"Created scheme {State.SchemeInfos[schemeId]}");

        Context.Fire(new SchemeCreated
        {
            SchemeId = scheme.SchemeId,
            Manager = scheme.Manager,
            IsReleaseAllBalanceEveryTimeByDefault = scheme.IsReleaseAllBalanceEveryTimeByDefault,
            ProfitReceivingDuePeriodCount = scheme.ProfitReceivingDuePeriodCount,
            VirtualAddress = scheme.VirtualAddress
        });
        return schemeId;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L101-116)
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
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L224-252)
```csharp
    public override Empty Unlock(UnlockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Unlock behaviour should be initialed by origin address.");

        AssertValidToken(input.Symbol, input.Amount);
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        Context.SendVirtualInline(fromVirtualAddress, Context.Self, nameof(Transfer), new TransferInput
        {
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        DealWithExternalInfoDuringUnlock(new TransferFromInput
        {
            From = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress),
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
    }
```
