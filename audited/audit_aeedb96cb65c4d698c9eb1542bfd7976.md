### Title
Scheme Manager Can Arbitrarily Modify Scheme Parameters After User Registration, Breaking Lock Guarantees

### Summary
The `CreateScheme` method lacks protection against re-invocation, allowing scheme managers to overwrite existing scheme parameters (Symbol, MinimumLockMinutes, AutoDistributeThreshold) after users have registered and locked tokens. This breaks user expectations and can extend lock periods indefinitely or prevent withdrawals entirely.

### Finding Description

The vulnerability exists in the `CreateScheme` method which directly overwrites the scheme state without checking if a scheme already exists: [1](#0-0) 

**Root Cause**: There is no assertion or check preventing multiple calls to `CreateScheme` by the same manager address. The method unconditionally stores new parameters to `State.TokenHolderProfitSchemes[Context.Sender]`, overwriting any existing scheme.

**Why Protections Fail**: No protections exist. The protobuf service definition shows `CreateScheme` as a normal RPC method without any constraints: [2](#0-1) 

**Execution Path**:
1. When users call `RegisterForProfits`, they lock tokens based on current scheme parameters (Symbol for the lock, MinimumLockMinutes for expected unlock time): [3](#0-2) 

2. The lock timestamp is recorded: [4](#0-3) 

3. When users attempt to `Withdraw`, the contract retrieves the CURRENT scheme parameters (which may have been modified) and enforces the NEW MinimumLockMinutes: [5](#0-4) 

4. If the manager called `CreateScheme` again with modified parameters, the assertion at line 227 now checks against the NEW MinimumLockMinutes value, not the original value users agreed to.

### Impact Explanation

**Direct Fund Impact**: Users' tokens can be locked indefinitely beyond their original agreement. Example scenario:
- Manager creates scheme with MinimumLockMinutes=60 (1 hour)
- User locks 1,000,000 ELF tokens expecting 1-hour lock
- Manager calls `CreateScheme` again with MinimumLockMinutes=525,600 (1 year)
- User cannot withdraw for 1 year instead of 1 hour - effective theft through time-locking

**Symbol Modification Impact**: If Symbol is changed from "ELF" to "USDT", the `Withdraw` function will call `GetLockedAmount` with the wrong symbol, returning 0 and preventing withdrawal entirely: [6](#0-5) 

**AutoDistributeThreshold Impact**: Users registered expecting specific auto-distribution behavior. Changing thresholds can prevent expected distributions or trigger unexpected ones: [7](#0-6) 

**Who is Affected**: All users who registered for profits in any scheme where the manager acts maliciously or makes an honest mistake by reconfiguring.

**Severity Justification**: HIGH - Direct user fund lock-up with no recourse, breaking the fundamental lock/unlock invariant.

### Likelihood Explanation

**Attacker Capabilities**: Only requires scheme manager privileges - the legitimate manager who created the scheme. No special attack vectors or exploits needed.

**Attack Complexity**: Trivial - single transaction calling `CreateScheme` with modified parameters.

**Feasibility Conditions**: 
- Scheme must exist (manager already called `CreateScheme` once)
- Users must have registered (called `RegisterForProfits`)
- Manager simply calls `CreateScheme` again

**Economic Rationality**: 
- Zero cost attack for malicious manager
- High value extraction through extended lock periods
- Enables "rug pull" scenarios where manager attracts users with favorable terms then changes them

**Detection Constraints**: Changes are immediate and irreversible. Users only discover the issue when attempting withdrawal.

**Probability**: MODERATE to HIGH - While requires manager to act maliciously or make an error, the ease of execution and lack of safeguards makes this practical.

### Recommendation

**Code-Level Mitigation**: Add assertion in `CreateScheme` to prevent re-creation:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
           "Scheme already exists for this manager.");
    
    // ... rest of existing code
}
```

**Alternative Mitigation**: If scheme updates are intentionally needed, create a separate `UpdateScheme` method with:
- Explicit authorization checks
- Restrictions on which parameters can be updated
- Protection against reducing MinimumLockMinutes (only allow increases with user consent)
- Event emission for parameter changes
- Timelock/governance control for sensitive changes

**Invariant Checks to Add**:
1. Scheme creation is immutable OR
2. Scheme updates only through governed process with constraints
3. User lock parameters cannot be retroactively made more restrictive

**Test Cases**:
1. Test that second `CreateScheme` call by same manager fails
2. Test that users can withdraw after original MinimumLockMinutes even if manager attempts modification
3. Test that Symbol changes don't affect existing user locks

### Proof of Concept

**Initial State**:
- Manager address: `ManagerAddr`
- User address: `UserAddr`
- User has 1,000,000 ELF tokens

**Transaction Sequence**:

1. Manager creates scheme (T=0):
   ```
   CreateScheme({
     Symbol: "ELF",
     MinimumLockMinutes: 60,
     AutoDistributeThreshold: {}
   })
   ```
   State: `TokenHolderProfitSchemes[ManagerAddr] = {Symbol:"ELF", MinimumLockMinutes:60, ...}`

2. User registers for profits (T=5 minutes):
   ```
   RegisterForProfits({
     SchemeManager: ManagerAddr,
     Amount: 1000000
   })
   ```
   State: User's 1M ELF locked, `LockTimestamp[lockId] = T+5`
   Expected unlock: T+65 minutes

3. Manager modifies scheme (T=30 minutes):
   ```
   CreateScheme({
     Symbol: "ELF",
     MinimumLockMinutes: 525600,  // 1 year!
     AutoDistributeThreshold: {}
   })
   ```
   State: `TokenHolderProfitSchemes[ManagerAddr] = {Symbol:"ELF", MinimumLockMinutes:525600, ...}`

4. User attempts withdrawal (T=70 minutes):
   ```
   Withdraw(ManagerAddr)
   ```
   **Expected**: Success (60 minutes passed since lock)
   **Actual**: FAILURE - Assert fails because `LockTimestamp[lockId].AddMinutes(525600) < CurrentBlockTime` is FALSE
   
   User must now wait until T+525605 minutes (nearly 1 year) to withdraw.

**Success Condition**: User cannot withdraw at expected time, demonstrating broken lock guarantee.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L167-167)
```csharp
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L178-206)
```csharp
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L213-228)
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
```

**File:** protobuf/token_holder_contract.proto (L19-21)
```text
    // Create a scheme for distributing bonus.
    rpc CreateScheme (CreateTokenHolderProfitSchemeInput) returns (google.protobuf.Empty) {
    }
```
