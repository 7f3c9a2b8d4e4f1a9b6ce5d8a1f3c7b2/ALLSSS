### Title
Scheme Manager Can Remove Self-Registered Token Holders Without Unlocking Tokens, Causing Loss of Expected Dividends

### Summary
Users who lock tokens via `RegisterForProfits` to participate in profit distribution can be unilaterally removed by the scheme manager using `RemoveBeneficiary`, which removes their beneficiary status but leaves their tokens locked. This creates an inconsistent state where users cannot earn dividends but their capital remains locked until the minimum lock period expires, resulting in lost opportunity costs and violation of the lock-for-profit contract.

### Finding Description

The TokenHolder contract provides two distinct flows for beneficiary management that fail to coordinate:

**Flow 1: Manager-Controlled Beneficiaries**
- `AddBeneficiary` [1](#0-0)  allows the scheme manager to add beneficiaries with specified shares
- `RemoveBeneficiary` [2](#0-1)  allows the scheme manager to remove these beneficiaries
- No tokens are locked in this flow

**Flow 2: User Self-Registration**
- `RegisterForProfits` [3](#0-2)  allows users to lock their tokens and register as beneficiaries
- Tokens are locked via the Token contract [4](#0-3) 
- Lock ID is stored in state [5](#0-4) 
- `Withdraw` [6](#0-5)  allows users to unlock and withdraw after minimum lock period

**Root Cause:**
`RemoveBeneficiary` validates only that the caller is the scheme manager [7](#0-6)  but does NOT check whether the beneficiary has locked tokens via `RegisterForProfits`. The function removes the beneficiary from the Profit contract [8](#0-7)  but does NOT unlock tokens or remove the lock ID from `State.LockIds` [9](#0-8) .

When `RemoveBeneficiary` is called on a user who registered via `RegisterForProfits`, the Profit contract removes their beneficiary status immediately or shortens their profit period [10](#0-9) , terminating future profit distributions while their tokens remain locked.

### Impact Explanation

**Direct Financial Harm:**
1. Users lock tokens expecting continuous profit distributions until withdrawal
2. Scheme manager removes them as beneficiaries, immediately terminating profit rights
3. Tokens remain locked in Token contract and cannot be used
4. Users must wait until `MinimumLockMinutes` expires before calling `Withdraw` [11](#0-10) 
5. All profits distributed during this remaining lock period are lost

**Quantified Impact:**
- If user locks X tokens for Y days minimum period
- Manager removes them after Z days (where Z < Y)
- User loses (Y - Z) days of dividend distributions
- With substantial profit pools, this represents significant value loss
- User capital is effectively "dead" - locked but earning nothing

**Affected Parties:**
- Token holders who use `RegisterForProfits` to stake tokens for dividends
- Particularly harmful in schemes with long `MinimumLockMinutes` and high profit volumes

**Severity Justification:**
This violates the core invariant that locked tokens earn profit distributions. Users suffer forced opportunity cost - their capital is locked but generates zero return, while they could have used those tokens elsewhere or participated in other schemes.

### Likelihood Explanation

**Attacker Capabilities:**
The "attacker" is the scheme manager, a privileged role. However, this is not necessarily malicious - the manager may legitimately want to remove beneficiaries without understanding the implications for users who locked tokens themselves.

**Attack Complexity:**
Simple execution - scheme manager calls `RemoveBeneficiary` with the user's address. No special conditions or sophisticated attacks required.

**Feasibility Conditions:**
1. User has called `RegisterForProfits` and locked tokens
2. Scheme manager has authority (by design) to call `RemoveBeneficiary`
3. No technical barriers prevent this action
4. No test coverage exists for this scenario [12](#0-11) 

**Detection/Operational Constraints:**
The scheme is created with `CanRemoveBeneficiaryDirectly = true` [13](#0-12) , explicitly granting this capability. There are no warnings or checks to alert the manager about locked tokens.

**Probability:**
HIGH - This can occur in any TokenHolder scheme where users lock tokens and the manager later decides to rebalance beneficiaries without awareness of the coordination issue.

### Recommendation

**Code-Level Mitigation:**
Add a check in `RemoveBeneficiary` to prevent removing beneficiaries who have locked tokens:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // NEW: Check if beneficiary has locked tokens via RegisterForProfits
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    Assert(lockId == null, 
        "Cannot remove beneficiary with locked tokens. User must withdraw first.");
    
    // ... existing logic
}
```

**Alternative Approach:**
Modify `RemoveBeneficiary` to automatically unlock tokens if a lock ID exists:

```csharp
if (lockId != null) {
    var lockedAmount = State.TokenContract.GetLockedAmount.Call(...).Amount;
    State.TokenContract.Unlock.Send(...);
    State.LockIds[Context.Sender].Remove(input.Beneficiary);
}
```

**Invariant to Add:**
Document and enforce: "Beneficiaries with locked tokens (registered via RegisterForProfits) cannot be removed via RemoveBeneficiary until they withdraw."

**Test Cases:**
Add test: `RemoveBeneficiary_After_RegisterForProfits_Should_Fail` to verify the protection works correctly.

### Proof of Concept

**Initial State:**
1. Scheme manager creates TokenHolder profit scheme with `MinimumLockMinutes = 1440` (1 day)
2. Scheme has 10,000 ELF in profit pool ready for distribution
3. User has 1,000 ELF tokens available

**Exploitation Steps:**

**Step 1:** User registers for profits
```
User calls: RegisterForProfits(amount=1000, schemeManager=Manager)
Result: 1,000 ELF locked, user becomes beneficiary with 1000 shares
State: LockIds[Manager][User] = lockId123
```

**Step 2:** Scheme manager removes user (10 minutes later)
```
Manager calls: RemoveBeneficiary(beneficiary=User, amount=0)
Result: User removed from Profit contract beneficiary list
State: User no longer has profit rights
State: LockIds[Manager][User] = lockId123 (STILL EXISTS)
State: 1,000 ELF remain locked in Token contract
```

**Step 3:** Profits distributed while user is locked out
```
Manager calls: DistributeProfits(amountsMap={"ELF": 10000})
Result: 10,000 ELF distributed to remaining beneficiaries
User receives: 0 ELF (not a beneficiary anymore)
State: User's 1,000 ELF still locked
```

**Step 4:** User can only withdraw after minimum period
```
User calls: Withdraw(Manager) after 1430 minutes
Result: FAILS - "Cannot withdraw" (minimum 1440 minutes not met)

User calls: Withdraw(Manager) after 1440 minutes  
Result: SUCCESS - 1,000 ELF unlocked and returned
```

**Expected vs Actual:**
- **Expected:** User locks tokens → earns dividends until voluntary withdrawal
- **Actual:** User locks tokens → manager forcibly removes → tokens locked but zero dividends → forced wait until minimum period → significant profit loss

**Success Condition:**
User's tokens are locked without profit rights, causing measurable financial loss equal to the dividends that would have been earned during the remaining lock period.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L24-24)
```csharp
            CanRemoveBeneficiaryDirectly = true
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L37-68)
```csharp
    public override Empty AddBeneficiary(AddTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        var shares = input.Shares;
        if (detail.Details.Any())
        {
            // Only keep one detail.

            State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
            {
                SchemeId = scheme.SchemeId,
                Beneficiary = input.Beneficiary
            });
            shares.Add(detail.Details.Single().Shares);
        }

        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = input.Beneficiary,
                Shares = shares
            }
        });
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L15-15)
```csharp
    public MappedState<Address, Address, Hash> LockIds { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-356)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
        //id == null
        if (scheme.CanRemoveBeneficiaryDirectly && profitDetailId != null)
        {
            detailsCanBeRemoved = detailsCanBeRemoved.All(d => d.Id != profitDetailId)
                ? detailsCanBeRemoved.Where(d => d.Id == null).ToList()
                : detailsCanBeRemoved.Where(d => d.Id == profitDetailId).ToList();
        }

        // remove the profitDetail with the profitDetailId, and de-duplicate it before involving.
        if (profitDetailId != null && profitDetails.Details.Any(d => d.Id == profitDetailId) &&
            detailsCanBeRemoved.All(d => d.Id != profitDetailId))
        {
            detailsCanBeRemoved.Add(profitDetails.Details.Single(d => d.Id == profitDetailId));
        }

        if (detailsCanBeRemoved.Any())
        {
            foreach (var profitDetail in detailsCanBeRemoved)
            {
                // set remove sign
                profitDetail.IsWeightRemoved = true;
                if (profitDetail.LastProfitPeriod >= scheme.CurrentPeriod)
                {
                    // remove those profits claimed
                    profitDetails.Details.Remove(profitDetail);
                }
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L138-153)
```csharp
    public async Task RemoveBeneficiaryTest()
    {
        await AddBeneficiaryTest();

        var tokenHolderProfitScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);

        await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
        {
            Beneficiary = UserAddresses.First()
        });

        {
            var originScheme = await ProfitContractStub.GetScheme.CallAsync(tokenHolderProfitScheme.SchemeId);
            originScheme.TotalShares.ShouldBe(0);
        }
    }
```
