### Title
TokenHolder Scheme Overwrite Causes Permanent Token Lock for Registered Users

### Summary
The `CreateScheme` method in TokenHolderContract does not validate if a scheme already exists for a manager address, allowing scheme state to be overwritten. When a manager creates a second scheme with a different token symbol, all users who registered under the first scheme become unable to withdraw their locked tokens, as the withdrawal logic uses the new scheme's symbol with lockIds from the old scheme, causing permanent fund loss.

### Finding Description

The vulnerability exists in the interaction between `CreateScheme`, `RegisterForProfits`, and `Withdraw` methods: [1](#0-0) 

The `CreateScheme` method unconditionally overwrites `State.TokenHolderProfitSchemes[Context.Sender]` without checking if a scheme already exists. The underlying Profit contract allows managers to create multiple schemes with different IDs based on a counter. [2](#0-1) 

When users register for profits, their lockIds are stored per manager address: [3](#0-2) 

The lockId is deterministic based on the manager and user address, but the locked tokens are associated with the scheme's symbol at registration time.

When the manager creates a second scheme with a different symbol, the withdrawal process fails: [4](#0-3) 

The `Withdraw` method retrieves the current scheme (with the new symbol), but uses the old lockId. When `GetLockedAmount` is called with the new symbol and the old lockId (which locked tokens of the original symbol), it returns 0. The subsequent `Unlock` call unlocks 0 tokens, leaving the user's original tokens permanently locked. The lockId mapping is then removed, preventing any future withdrawal attempts.

### Impact Explanation

**Direct Fund Impact**: All users who registered under the original scheme lose access to their locked tokens permanently. For example:
- User locks 1,000 ELF tokens under Scheme A (Symbol: "ELF")
- Manager creates Scheme B (Symbol: "USDT"), overwriting Scheme A's metadata
- User's 1,000 ELF remains locked but withdrawal attempts fail because the contract queries for locked USDT instead of ELF
- The lockId is deleted from state after the failed withdrawal, making recovery impossible

**Affected Parties**: All users who called `RegisterForProfits` before the manager creates a new scheme lose their funds. This could affect hundreds or thousands of users if the scheme is popular.

**Severity Justification**: HIGH - Complete and permanent loss of user funds with no recovery mechanism. The vulnerability breaks the fundamental token locking invariant and violates user expectations that locked tokens can be withdrawn after the lock period.

### Likelihood Explanation

**Reachable Entry Point**: `CreateScheme` is a public method callable by any address to create their own scheme. No special permissions required.

**Feasible Preconditions**: 
- Manager creates an initial scheme (normal operation)
- Users register and lock tokens (normal operation)
- Manager calls `CreateScheme` again with different parameters (could be accidental during contract upgrades or intentional)

**Execution Practicality**: The attack requires only two simple transactions:
1. Call `CreateScheme` with new Symbol parameter
2. Users' subsequent `Withdraw` calls automatically fail

**Attack Complexity**: VERY LOW - No sophisticated manipulation required. Can occur accidentally if a manager tries to "update" their scheme configuration by calling `CreateScheme` again.

**Economic Rationality**: Zero cost to execute. Could be accidental (manager attempting to modify scheme parameters) or malicious (rug pull by locking all user funds).

**Detection Constraints**: Users would only discover the issue when attempting to withdraw, by which point their funds are already permanently locked.

### Recommendation

**Immediate Fix**: Add validation to prevent scheme overwrites:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add this check
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
           "Scheme already exists for this manager. Cannot create multiple schemes.");
    
    // ... rest of existing code
}
```

**Enhanced Fix**: If supporting multiple schemes per manager is desired:
1. Change the state mapping structure to include scheme ID: `MappedState<Address, Hash, Address, Hash> LockIds` (Manager -> SchemeId -> User -> LockId)
2. Modify `RegisterForProfits` to specify and store the scheme ID
3. Update `Withdraw` to require scheme ID parameter
4. Ensure lockIds are unique per manager-scheme-user combination

**Invariant Checks**:
- Assert in `CreateScheme`: `State.TokenHolderProfitSchemes[Context.Sender] == null`
- Assert in `Withdraw`: `scheme.Symbol` matches the symbol of the locked tokens for the given lockId

**Test Cases**:
- Test that `CreateScheme` called twice by the same manager reverts
- Test that users can successfully withdraw after lock period with original scheme
- Test that attempting to create a second scheme fails with clear error message

### Proof of Concept

**Initial State**:
- Manager address: `0xManager`
- User address: `0xUser1`
- User has 1,000 ELF tokens approved for TokenHolder contract

**Transaction Sequence**:

1. **Manager creates Scheme A**:
   - Call: `CreateScheme({Symbol: "ELF", MinimumLockMinutes: 1})`
   - Result: `TokenHolderProfitSchemes[0xManager] = {Symbol: "ELF", MinimumLockMinutes: 1}`

2. **User registers and locks tokens**:
   - Call: `RegisterForProfits({SchemeManager: 0xManager, Amount: 1000})`
   - Result: 1,000 ELF locked, `LockIds[0xManager][0xUser1] = lockIdA`

3. **Manager creates Scheme B (overwrites Scheme A)**:
   - Call: `CreateScheme({Symbol: "USDT", MinimumLockMinutes: 100})`
   - Result: `TokenHolderProfitSchemes[0xManager] = {Symbol: "USDT", MinimumLockMinutes: 100}` (OVERWRITTEN)

4. **User attempts withdrawal** (after 1 minute):
   - Call: `Withdraw(0xManager)`
   - Expected: Unlock 1,000 ELF tokens
   - Actual: 
     - `GetLockedAmount(0xUser1, lockIdA, "USDT")` returns 0 (lockIdA has ELF, not USDT)
     - `Unlock(0xUser1, lockIdA, 0, "USDT")` unlocks 0 tokens
     - User's 1,000 ELF remains locked forever
     - `LockIds[0xManager][0xUser1]` is deleted, preventing retry

**Success Condition of Attack**: User's tokens remain locked in the contract but cannot be withdrawn. `GetBalance` shows locked balance but withdrawal fails or unlocks 0 tokens.

### Notes

There is an additional bug discovered at line 298 in `UpdateTokenHolderProfitScheme` where `State.TokenHolderProfitSchemes[Context.Sender]` should be `State.TokenHolderProfitSchemes[manager]`, but this secondary bug does not prevent the primary vulnerability from occurring. [5](#0-4)

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L157-166)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-236)
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
