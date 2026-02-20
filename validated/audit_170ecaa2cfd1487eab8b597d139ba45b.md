# Audit Report

## Title
TokenHolder Lock-Beneficiary State Desynchronization Allows Capital Lockup Without Profit Accrual

## Summary
The `RemoveBeneficiary` function in TokenHolderContract can remove a user's beneficiary status from the profit scheme without unlocking their tokens, creating a state where users' capital remains locked but earns no profits. This violates the core TokenHolder contract invariant that locked tokens should always earn proportional profit shares.

## Finding Description

When a user calls `RegisterForProfits`, three state changes occur atomically: tokens are locked via TokenContract, a lockId mapping is stored, and the user is added as a beneficiary to the profit scheme. [1](#0-0) 

However, when the scheme manager calls `RemoveBeneficiary`, only the beneficiary status is removed from the Profit contract. The function does NOT unlock the tokens from the Token contract, remove the `State.LockIds` mapping, or clear the `State.LockTimestamp` entry. [2](#0-1) 

This creates a desynchronization where the beneficiary status is removed but the token lock state remains unchanged. Users cannot withdraw until the minimum lock period expires, as enforced by the check in the `Withdraw` function. [3](#0-2) 

The scheme is created with `CanRemoveBeneficiaryDirectly = true`, explicitly allowing immediate beneficiary removal by the manager. [4](#0-3) 

In the Profit contract, when a beneficiary has already been removed, subsequent calls to `RemoveBeneficiary` return gracefully without error, allowing the `Withdraw` function to succeed even after premature beneficiary removal. [5](#0-4) 

The design clearly shows atomic coupling: `RegisterForProfits` couples locking with beneficiary addition, and `Withdraw` couples unlocking with beneficiary removal. [6](#0-5) 

However, `RemoveBeneficiary` breaks this coupling by only affecting beneficiary status without synchronizing the token lock state.

## Impact Explanation

**Direct Financial Impact:**
- Users lose expected profit distributions during the remaining lock period. For example, if a scheme distributes 10% APY and tokens remain locked for 30 days after `RemoveBeneficiary` is called, users lose approximately 0.83% of their locked capital value in missed profits.
- Opportunity cost: Users cannot deploy their capital elsewhere (staking, liquidity provision, trading) during the forced lock period without profit accrual.

**Operational Impact:**
- Violates the fundamental TokenHolder contract invariant that locked tokens should always earn profit shares proportional to their locked amount.
- Undermines user trust in the staking mechanism as capital can be locked without compensation.

**Who is Affected:**
- Any user who has called `RegisterForProfits` and can be arbitrarily removed by the scheme manager before their minimum lock period expires.
- Impact is particularly severe for schemes with long `MinimumLockMinutes` values as defined in the scheme configuration. [7](#0-6) 

## Likelihood Explanation

**Attacker Capabilities:**
- Requires scheme manager privileges, which is a realistic role as all TokenHolder profit schemes have managers by design.
- Single function call execution with no additional preconditions or complex setup required.

**Attack Complexity:**
- Trivial: One transaction calling `RemoveBeneficiary(beneficiary=victim, amount=0)` as documented in the protobuf definition. [8](#0-7) 

- Can be executed against any registered user at any time.

**Feasibility Conditions:**
- Scheme must exist (normal operation)
- User must be registered via `RegisterForProfits` (normal operation)  
- Caller must be the scheme manager (by design, enforced by `GetValidScheme(Context.Sender)`) [9](#0-8) 

**Probability Assessment:**
- Malicious scenario: Scheme manager can directly execute this attack with immediate effect.
- Accidental scenario: Scheme managers may not realize that calling `RemoveBeneficiary` on users who registered via `RegisterForProfits` leaves their tokens locked.
- Either scenario results in the same harmful outcome for users.

This is a high-probability vulnerability given the low barriers to exploitation and realistic attacker model (scheme managers are not listed as trusted roles in the threat model).

## Recommendation

Modify the `RemoveBeneficiary` function to maintain state synchronization. When removing a beneficiary who registered via `RegisterForProfits`, the function should:

1. Check if the beneficiary has locked tokens via `State.LockIds`
2. If tokens are locked, either:
   - Option A: Automatically unlock the tokens and clear all associated state
   - Option B: Prevent beneficiary removal if tokens are still locked (require user to withdraw first)

Recommended fix (Option A):

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
    
    // Check if tokens are locked via RegisterForProfits
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    if (lockId != null && input.Amount == 0)
    {
        // Unlock tokens when fully removing beneficiary
        if (State.TokenContract.Value == null)
            State.TokenContract.Value = Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
            
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = input.Beneficiary,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
        
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = input.Beneficiary,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
        
        State.LockIds[Context.Sender].Remove(input.Beneficiary);
        State.LockTimestamp.Remove(lockId);
    }
    
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    
    if (lockedAmount > input.Amount && input.Amount != 0)
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

## Proof of Concept

```csharp
[Fact]
public async Task TokenHolder_LockBeneficiary_Desynchronization_Vulnerability()
{
    // Setup: Create scheme with minimum lock period
    var minimumLockMinutes = 1440; // 1 day
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = minimumLockMinutes
    });

    // User registers and locks tokens
    var lockAmount = 1000L;
    var userStub = GetTokenHolderContractTester(UserKeyPairs.First());
    await userStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });

    // Verify tokens are locked
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var lockedBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddresses.First(),
        Symbol = "ELF"
    });
    
    // Manager removes beneficiary (amount=0 means full removal)
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = UserAddresses.First(),
        Amount = 0
    });

    // Verify beneficiary status removed
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        Beneficiary = UserAddresses.First(),
        SchemeId = scheme.SchemeId
    });
    profitDetails.Details.Count.ShouldBe(0); // No longer beneficiary

    // Verify tokens still locked (vulnerability)
    var lockedAmount = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddresses.First(),
        Symbol = "ELF"
    });
    lockedBalance.Balance.ShouldBe(lockedAmount.Balance); // Tokens still locked

    // User cannot withdraw because minimum lock period not expired
    var withdrawResult = await userStub.Withdraw.SendWithExceptionAsync(Starter);
    withdrawResult.TransactionResult.Error.ShouldContain("Cannot withdraw");
    
    // VULNERABILITY CONFIRMED:
    // 1. User's tokens remain locked
    // 2. User is no longer a beneficiary (no profit accrual)
    // 3. User cannot withdraw until minimum lock period expires
    // Result: Capital locked without earning profits
}
```

## Notes

This vulnerability represents a critical state desynchronization issue in the TokenHolder contract. The atomic coupling established by `RegisterForProfits` (lock + add beneficiary) is not mirrored in `RemoveBeneficiary`, which only removes beneficiary status without unlocking tokens. This asymmetry creates an exploitable state where users' capital can be locked without compensation, violating the fundamental contract invariant.

The issue is particularly severe because:
1. Scheme managers are not trusted roles per the threat model
2. The attack requires only a single function call with no complex setup
3. Users have no recourse until the minimum lock period expires
4. The financial impact scales with both the lock amount and the lock duration

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-176)
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-243)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L233-235)
```csharp
        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();
```

**File:** protobuf/token_holder_contract.proto (L27-30)
```text
    // Removes a beneficiary from a scheme.
    // Note: amount > 0: update the weight of the beneficiary, amount = 0: remove the beneficiary.
    rpc RemoveBeneficiary (RemoveTokenHolderBeneficiaryInput) returns (google.protobuf.Empty) {
    }
```
