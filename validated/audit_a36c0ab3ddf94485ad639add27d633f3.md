# Audit Report

## Title
Scheme Manager Can Steal Profit Shares from Locked Token Holders via RemoveBeneficiary

## Summary
The TokenHolder contract's `RemoveBeneficiary` function allows a scheme manager to remove profit shares from users who locked tokens via `RegisterForProfits`, while their tokens remain locked. This violates the core invariant that locked tokens guarantee proportional profit participation, enabling direct theft of expected profit distributions.

## Finding Description

The vulnerability exists in the `RemoveBeneficiary` function which fails to distinguish between two types of beneficiaries:
1. Manager-added beneficiaries (via `AddBeneficiary`) - no tokens locked
2. Self-registered beneficiaries (via `RegisterForProfits`) - tokens locked

When users call `RegisterForProfits`, their tokens are locked and stored in the `LockIds` mapping [1](#0-0) . They receive profit shares equal to their locked amount [2](#0-1) .

However, `RemoveBeneficiary` only validates that the caller is the scheme manager [3](#0-2) . It removes or reduces the beneficiary's shares in the Profit contract **without unlocking their tokens**. The function has no call to `State.TokenContract.Unlock`, meaning locked tokens remain inaccessible while profit rights are stripped.

The legitimate withdrawal path shows the correct behavior: it checks the lock period, unlocks tokens, then removes the beneficiary [4](#0-3) .

When the Profit contract processes the removal with `CanRemoveBeneficiaryDirectly = true` [5](#0-4) , it sets the beneficiary's `EndPeriod` to the past [6](#0-5) , preventing all future profit claims.

## Impact Explanation

This enables **direct financial theft** of profit distributions:

**Quantified Scenario:**
- User locks 10,000 tokens (receives 10,000 shares)
- Manager has 10,000 shares
- During distribution: 10,000 profit tokens → User gets 5,000, Manager gets 5,000
- Manager calls `RemoveBeneficiary` on user
- User's shares removed, total shares now 10,000 (manager only)
- Next distribution: 10,000 profit tokens → User gets 0, Manager gets 10,000
- User's capital remains locked until minimum lock period expires
- **Net theft: ~5,000 tokens per distribution period**

The "stolen" shares effectively redistribute to remaining beneficiaries. If the manager added themselves as a beneficiary, they directly receive the victim's profit allocation. This violates the fundamental guarantee that locked tokens ensure proportional profit participation for the lock duration.

**Affected Parties:**
- All users who lock tokens via `RegisterForProfits`
- Particularly severe for large amounts and long lock periods
- Affects any TokenHolder profit scheme since scheme creation is permissionless

## Likelihood Explanation

**High Likelihood:**

**Attacker Capabilities:**
- Any user can become a scheme manager by calling `CreateScheme`
- No special privileges beyond scheme creation required
- Attack is permissionless once scheme exists

**Attack Complexity:**
- Extremely low: single function call to `RemoveBeneficiary`
- No timing constraints or complex state manipulation
- Can execute immediately after users register

**Preconditions:**
- Users must register via `RegisterForProfits` (normal expected behavior)
- No unusual state requirements
- Works on any TokenHolder scheme

**Detection Difficulty:**
- Appears as legitimate scheme management action
- No on-chain warnings or validation prevents execution
- Users discover only after noticing reduced profit claims while tokens remain locked

**Economic Rationality:**
- Highly profitable: steal 100% of profit allocation at zero cost
- Risk-free since it appears as authorized manager action
- Rational for any profit-maximizing malicious manager

## Recommendation

Add a check in `RemoveBeneficiary` to verify whether the beneficiary has locked tokens, and if so, either:
1. Reject the removal and require the beneficiary to use `Withdraw` after the lock period
2. Automatically unlock the tokens when removing the beneficiary

**Recommended Fix:**
```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // Check if beneficiary has locked tokens
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    Assert(lockId == null, "Cannot remove beneficiary with locked tokens. Beneficiary must call Withdraw after lock period expires.");
    
    // ... rest of existing logic
}
```

Alternatively, add automatic unlock:
```csharp
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // Check and unlock if tokens are locked
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    if (lockId != null)
    {
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = input.Beneficiary,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;
        
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address: input.Beneficiary,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
        
        State.LockIds[Context.Sender].Remove(input.Beneficiary);
    }
    
    // ... rest of existing logic
}
```

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_StealsShares_WhileTokensRemainLocked()
{
    // Setup: Create scheme
    var manager = Accounts[0];
    var victim = Accounts[1];
    await TokenHolderStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 43200 // 30 days
    });
    
    // Victim locks tokens and registers for profits
    await TokenStub.Approve.SendAsync(new ApproveInput { Spender = TokenHolderAddress, Symbol = "ELF", Amount = 10000 });
    await TokenHolderStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = manager.Address,
        Amount = 10000
    });
    
    // Verify tokens are locked
    var lockedAmount = await TokenStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = victim.Address,
        Symbol = "ELF",
        LockId = ComputeLockId(manager.Address, victim.Address)
    });
    Assert.Equal(10000, lockedAmount.Amount);
    
    // Verify victim has profit shares
    var details = await ProfitStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = GetSchemeId(manager.Address),
        Beneficiary = victim.Address
    });
    Assert.Equal(10000, details.Details[0].Shares);
    
    // Manager removes victim's shares
    await TokenHolderStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = victim.Address,
        Amount = 10000
    });
    
    // Tokens still locked!
    lockedAmount = await TokenStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = victim.Address,
        Symbol = "ELF",
        LockId = ComputeLockId(manager.Address, victim.Address)
    });
    Assert.Equal(10000, lockedAmount.Amount); // Still locked
    
    // But shares removed!
    details = await ProfitStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = GetSchemeId(manager.Address),
        Beneficiary = victim.Address
    });
    Assert.Empty(details.Details); // No shares
    
    // Victim cannot withdraw (lock period not expired) but has no profit rights
    // This is the vulnerability: locked capital with zero profit participation
}
```

## Notes

This vulnerability specifically impacts the **TokenHolder profit distribution mechanism**. The issue arises from a missing distinction between beneficiary types in the authorization logic. The `CanRemoveBeneficiaryDirectly = true` setting [5](#0-4)  enables immediate removal in the Profit contract [7](#0-6) , but the TokenHolder contract fails to protect users who have locked tokens.

The vulnerability is particularly severe because:
1. Scheme creation is permissionless (anyone can call `CreateScheme`)
2. The attack is undetectable until execution
3. Users have no recourse until the lock period expires
4. The manager can repeatedly exploit this against multiple users

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L24-24)
```csharp
            CanRemoveBeneficiaryDirectly = true
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-84)
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-243)
```csharp
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
