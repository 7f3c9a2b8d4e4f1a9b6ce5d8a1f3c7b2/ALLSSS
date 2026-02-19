### Title
Symbol Mismatch Causes Permanent Token Lock When Scheme is Recreated

### Summary
The TokenHolder contract allows scheme managers to recreate profit schemes with different token symbols, causing users' previously locked tokens to become permanently inaccessible. When users register for profits by locking tokens of one symbol, and the manager subsequently recreates the scheme with a different symbol, withdrawal operations fail because the contract queries for the new symbol's balance while the actual locked tokens remain under the original symbol.

### Finding Description

**Exact Code Locations:**
- `CreateScheme()` function [1](#0-0) 
- `RegisterForProfits()` function [2](#0-1) 
- `Withdraw()` function [3](#0-2) 

**Root Cause:**

The `CreateScheme()` function has no protection against overwriting existing schemes. When a manager calls `CreateScheme()`, it unconditionally overwrites the scheme stored at `State.TokenHolderProfitSchemes[Context.Sender]`, including the `Symbol` field. [4](#0-3) 

During registration, users lock tokens using the scheme's symbol retrieved at that moment. [5](#0-4) 

During withdrawal, the contract retrieves the current scheme and queries the locked amount using `scheme.Symbol`. [6](#0-5) 

**Why Protections Fail:**

The `GetLockedAmount` function computes the virtual address based on the lockId and queries the balance for the specified symbol. [7](#0-6)  If the symbol parameter differs from the actually locked symbol, it returns the balance of that different symbol (typically 0), not the locked tokens.

When the withdrawal attempts to unlock 0 amount, the `AssertValidSymbolAndAmount` validation fails with "Invalid amount." [8](#0-7) 

The user cannot re-register because the "Already registered" check prevents it. [9](#0-8) 

### Impact Explanation

**Direct Fund Impact:**
- Users' locked tokens become permanently inaccessible, representing complete loss of funds
- All users who registered before scheme recreation are affected simultaneously
- The tokens remain locked in virtual addresses with no recovery mechanism

**Affected Parties:**
- Users who locked tokens under the original scheme symbol
- The funds cannot be recovered through any contract function
- `RemoveBeneficiary` only removes profit distribution rights but doesn't unlock tokens [10](#0-9) 

**Severity Justification:**
This is a HIGH severity vulnerability due to:
1. Complete loss of user funds (permanent lock)
2. Affects all registered users of a scheme
3. No recovery mechanism exists
4. Simple execution by scheme manager

### Likelihood Explanation

**Attacker Capabilities:**
- Any scheme manager can trigger this vulnerability
- Requires only calling `CreateScheme()` twice with different symbols
- No special permissions beyond being a scheme creator

**Attack Complexity:**
- Trivial: Single transaction to recreate scheme
- Can be intentional (malicious manager) or accidental (manager updating scheme parameters)
- Immediate effect on all registered users

**Feasibility Conditions:**
- Users must have already registered for profits (normal usage)
- Manager calls `CreateScheme()` again with different symbol
- Both actions are standard contract operations requiring no special setup

**Detection/Operational Constraints:**
- No on-chain prevention mechanism
- Users discover the issue only when attempting withdrawal
- By then, funds are already permanently locked

**Probability:**
HIGH - The attack can be executed by any scheme manager with minimal effort, and the contract provides no safeguards against scheme recreation.

### Recommendation

**Immediate Fixes:**

1. **Prevent Scheme Overwriting**: Add validation in `CreateScheme()` to prevent recreation if the scheme already exists:
```
Assert(State.TokenHolderProfitSchemes[Context.Sender] == null || 
       State.TokenHolderProfitSchemes[Context.Sender].SchemeId == null, 
       "Scheme already exists. Cannot recreate.");
```

2. **Symbol Immutability**: Once a scheme is created with beneficiaries, the symbol should be immutable. Check if beneficiaries exist before allowing any scheme modifications.

3. **Recovery Mechanism**: Add an emergency unlock function that allows users to withdraw based on the actual locked symbol in the virtual address, rather than relying solely on the scheme's current symbol.

**Invariant Checks:**
- Scheme symbol must remain constant after first user registration
- Virtual address token balances must match withdrawal queries
- GetLockedAmount symbol parameter must match originally locked symbol

**Test Cases:**
- Test that CreateScheme fails when called twice
- Test that withdrawal succeeds after scheme recreation attempt is blocked
- Test recovery mechanism with mismatched symbols
- Test multiple users with different registration times

### Proof of Concept

**Initial State:**
- Manager address: `0xManager`
- User address: `0xUser`
- User has balance: 100 ELF

**Attack Sequence:**

**Step 1**: Manager creates scheme with Symbol "ELF"
```
CreateScheme(symbol: "ELF", minimum_lock_minutes: 1440)
// State.TokenHolderProfitSchemes[0xManager] = {Symbol: "ELF", ...}
```

**Step 2**: User registers for profits
```
RegisterForProfits(scheme_manager: 0xManager, amount: 100)
// Locks 100 ELF to virtual address
// Virtual address = Hash(TokenHolderContract + 0xUser + lockId)
// Virtual address balance: {ELF: 100}
```

**Step 3**: Manager recreates scheme with Symbol "TOKEN"
```
CreateScheme(symbol: "TOKEN", minimum_lock_minutes: 1440)
// State.TokenHolderProfitSchemes[0xManager] = {Symbol: "TOKEN", ...}
// Overwrites previous scheme
```

**Step 4**: User attempts withdrawal (after lock period)
```
Withdraw(0xManager)
// Gets scheme.Symbol = "TOKEN"
// Calls GetLockedAmount(Address: 0xUser, LockId: lockId, Symbol: "TOKEN")
// Returns amount = 0 (virtual address has ELF, not TOKEN)
// Attempts Unlock(amount: 0, symbol: "TOKEN")
// FAILS: "Invalid amount" error
```

**Expected Result**: User successfully withdraws 100 ELF

**Actual Result**: Withdrawal fails with "Invalid amount" error. User's 100 ELF tokens remain permanently locked in the virtual address with no way to recover them.

**Success Condition for Attack**: User's funds are locked and withdrawal fails, which is successfully demonstrated by the above sequence.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-98)
```csharp
    public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);

        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
            State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = input.Beneficiary,
                    Shares = lockedAmount.Sub(input.Amount)
                }
            });

        return new Empty();
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```
