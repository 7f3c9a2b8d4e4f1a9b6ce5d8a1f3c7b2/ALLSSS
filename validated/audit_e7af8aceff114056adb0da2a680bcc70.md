# Audit Report

## Title
Scheme Manager Can Steal Profit Shares from Locked Token Holders via RemoveBeneficiary

## Summary
The TokenHolder contract's `RemoveBeneficiary` function allows a scheme manager to remove profit shares from users who registered via `RegisterForProfits` with locked tokens, while those tokens remain locked. This enables theft of future profit distributions that should belong to locked token holders.

## Finding Description

The vulnerability exists in the authorization model of the `RemoveBeneficiary` function, which fails to distinguish between two types of beneficiaries:

1. **Manager-added beneficiaries** (via `AddBeneficiary`) - no tokens locked
2. **Self-registered beneficiaries** (via `RegisterForProfits`) - tokens locked as collateral

**Attack Execution Path:**

When a user registers for profits, their tokens are locked and a lock ID is stored [1](#0-0) , and they receive profit shares [2](#0-1) .

However, the scheme manager can call `RemoveBeneficiary`, which only validates that the caller is the scheme manager [3](#0-2) . This function removes the user's profit shares [4](#0-3)  but **does not unlock their tokens** - there is no call to `State.TokenContract.Unlock` in the entire RemoveBeneficiary function [5](#0-4) .

The removal propagates to the Profit contract, which sets the beneficiary's `EndPeriod` to `CurrentPeriod - 1` for active beneficiaries [6](#0-5) , preventing them from receiving any future profits. The scheme is created with `CanRemoveBeneficiaryDirectly = true` [7](#0-6) , which enables immediate removal of active beneficiaries [8](#0-7) .

The legitimate `Withdraw` function shows the proper flow: it unlocks tokens after the minimum lock period expires [9](#0-8) , but users whose shares were removed cannot receive profits during the lock period, even though their capital remains locked.

## Impact Explanation

**Critical - Direct Financial Theft:**

Users who lock tokens via `RegisterForProfits` have an economic expectation: locked capital guarantees proportional profit share. This vulnerability breaks that invariant by allowing managers to:

1. Remove user profit shares while tokens remain locked
2. Redistribute those shares to other beneficiaries (including the manager)
3. Force users to wait for the minimum lock period before recovering their capital via `Withdraw`

**Quantified Example:**
- User locks 10,000 tokens for 30-day minimum lock period
- Manager has 10,000 shares (total: 20,000 shares)
- Manager calls `RemoveBeneficiary` on the user
- New total shares: 10,000 (only manager)
- If 10,000 tokens profit distributed: Manager receives 10,000 (100%) instead of 5,000 (50%)
- User receives 0 while their 10,000 tokens remain locked for 30 days
- **Net theft: 5,000 tokens per distribution period**

This affects all users who register via `RegisterForProfits` and is particularly severe for users with large lock amounts or long minimum lock periods.

## Likelihood Explanation

**High Likelihood:**

**Attacker Capabilities:**
- Attacker must be a scheme manager (achieved by calling `CreateScheme` - permissionless)
- No additional privileges required

**Attack Complexity:**
- Single function call to `RemoveBeneficiary`
- No timing constraints or complex state manipulation
- Works immediately after users register

**Feasibility:**
- Users registering via `RegisterForProfits` is expected normal usage
- No preconditions beyond normal scheme operation
- Works on any TokenHolder scheme

**Detection:**
- Appears as legitimate manager function
- No on-chain validation prevents this
- Users only discover after attempting to claim profits

**Economic Rationality:**
- Zero cost to execute
- Direct profit theft with no risk
- Highly profitable even for small amounts

## Recommendation

Add a check in `RemoveBeneficiary` to distinguish between manager-added and self-registered beneficiaries. Only allow removal of self-registered beneficiaries if their tokens are unlocked first, or prevent removal entirely for users who registered via `RegisterForProfits`:

```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // Check if beneficiary has locked tokens
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    if (lockId != null)
    {
        // Either unlock tokens first or prevent removal
        Assert(false, "Cannot remove beneficiary with locked tokens. Beneficiary must call Withdraw first.");
    }
    
    // Rest of the function...
}
```

Alternatively, modify `RemoveBeneficiary` to automatically unlock tokens when removing self-registered beneficiaries.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_StealsLockedTokenHolderProfits_Test()
{
    var lockAmount = 10000L;
    var profitAmount = 10000L;
    
    // Manager creates scheme
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 43200 // 30 days
    });
    
    // Manager adds themselves as beneficiary with shares
    await TokenHolderContractStub.AddBeneficiary.SendAsync(new AddTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Shares = lockAmount
    });
    
    // User locks tokens and registers for profits
    var userStub = GetTester<TokenHolderContractImplContainer.TokenHolderContractImplStub>(
        TokenHolderContractAddress, UserKeyPairs.First());
    await userStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });
    
    // Verify user's tokens are locked
    var userBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = UserAddresses.First(),
        Symbol = "ELF"
    })).Balance;
    
    var scheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    profitScheme.TotalShares.ShouldBe(lockAmount * 2); // Manager + User
    
    // Manager removes user's profit shares while tokens remain locked
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = UserAddresses.First()
    });
    
    // Verify user lost profit shares
    profitScheme = await ProfitContractStub.GetScheme.CallAsync(scheme.SchemeId);
    profitScheme.TotalShares.ShouldBe(lockAmount); // Only manager now
    
    // Distribute profits
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = profitAmount
    });
    await TokenHolderContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeManager = Starter
    });
    
    // Manager can claim all profits
    var managerBalanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Starter,
        Symbol = "ELF"
    })).Balance;
    
    await TokenHolderContractStub.ClaimProfits.SendAsync(new ClaimProfitsInput
    {
        SchemeManager = Starter
    });
    
    var managerBalanceAfter = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Starter,
        Symbol = "ELF"
    })).Balance;
    
    // Manager received all profits (should have been 50/50)
    (managerBalanceAfter - managerBalanceBefore).ShouldBe(profitAmount);
    
    // User cannot claim any profits despite locked tokens
    var userProfits = await ProfitContractStub.GetProfitsMap.CallAsync(new Profit.ClaimProfitsInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = UserAddresses.First()
    });
    userProfits.Value.Count.ShouldBe(0);
    
    // User's tokens remain locked - cannot withdraw immediately
    var withdrawResult = await userStub.Withdraw.SendWithExceptionAsync(Starter);
    withdrawResult.TransactionResult.Error.ShouldContain("Cannot withdraw");
}
```

## Notes

This vulnerability represents a fundamental design flaw in the TokenHolder contract where economic invariants (locked capital → guaranteed profit share) are not enforced. The permissionless nature of scheme creation combined with the ability to remove locked token holders makes this a high-severity issue affecting all TokenHolder schemes.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-24)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-166)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L168-176)
```csharp
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-236)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L351-356)
```csharp
                else if (profitDetail.EndPeriod >= scheme.CurrentPeriod)
                {
                    // No profit can be here, except the scheme is cancellable.
                    // shorten profit.
                    profitDetail.EndPeriod = scheme.CurrentPeriod.Sub(1);
                }
```
