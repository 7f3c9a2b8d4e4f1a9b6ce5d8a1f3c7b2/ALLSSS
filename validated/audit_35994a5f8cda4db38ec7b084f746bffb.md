# Audit Report

## Title
TokenHolder Lock-Beneficiary State Desynchronization Allows Capital Lockup Without Profit Accrual

## Summary
The `RemoveBeneficiary` function in TokenHolderContract creates a critical state desynchronization by removing users from profit schemes without unlocking their tokens. This forces users into a "dead zone" where their capital remains locked but earns zero profits until the minimum lock period expires, violating the fundamental TokenHolder contract invariant that locked tokens must earn proportional rewards.

## Finding Description

The vulnerability stems from inconsistent state synchronization across three operations:

**RegisterForProfits atomically couples three state changes:** [1](#0-0) 

When users register, tokens are locked in TokenContract, the lockId mapping is stored, and beneficiary status is granted in ProfitContract—all three happen together.

**RemoveBeneficiary breaks this coupling:** [2](#0-1) 

The scheme manager can remove beneficiary status from ProfitContract (lines 80-84) but this function does NOT unlock tokens from TokenContract, does NOT remove the `State.LockIds` mapping, and does NOT clear the `State.LockTimestamp` entry. This creates a desynchronized state.

**Withdraw enforces minimum lock period:** [3](#0-2) 

Users cannot withdraw until `MinimumLockMinutes` expires, creating a forced gap period where tokens are locked without earning any profit distributions.

**The scheme explicitly allows immediate removal:** [4](#0-3) 

Schemes are created with `CanRemoveBeneficiaryDirectly = true`, explicitly permitting managers to remove beneficiaries at any time.

**Graceful handling enables the vulnerability:** [5](#0-4) 

When Withdraw eventually calls RemoveBeneficiary on an already-removed user, ProfitContract returns Empty gracefully without error, allowing the operation to complete.

**Configuration parameter defines lock duration:** [6](#0-5) 

The `minimum_lock_minutes` field in scheme configuration determines how long users remain trapped in the "locked but unprofitable" state.

## Impact Explanation

**Direct Financial Loss:**
Users lose all profit distributions during the gap between RemoveBeneficiary and when MinimumLockMinutes expires. For a scheme distributing 10% APY, a 30-day forced lock period without profits represents approximately 0.83% capital value loss. For large token holders or high-APY schemes, this becomes significant.

**Opportunity Cost:**
During the forced lock period, users cannot redeploy capital to other opportunities (alternative staking, liquidity provision, trading), compounding the financial impact beyond just missed profit distributions.

**Protocol Invariant Violation:**
The TokenHolder contract's fundamental guarantee—that locked tokens earn proportional profit shares—is broken. This undermines user trust in the entire profit distribution mechanism.

**Affected Users:**
Any user who calls RegisterForProfits can be arbitrarily victimized by the scheme manager before their minimum lock period expires. Schemes with longer MinimumLockMinutes values (e.g., 30-90 days) create larger attack windows and greater financial impact.

## Likelihood Explanation

**Attacker Profile:**
The scheme manager role is NOT a trusted system role—it's simply any address that calls CreateScheme. Scheme managers are untrusted regular users, making this a realistic threat actor.

**Attack Complexity:**
Trivial single-transaction exploit: `RemoveBeneficiary(beneficiary=victim_address, amount=0)` as documented in the protobuf definition. [7](#0-6) 

**Feasibility:**
- No special preconditions required beyond normal operation
- Scheme manager authority is obtained by design (calling CreateScheme)
- Can target any registered user at any time
- No rate limits or cooldown periods prevent execution

**Probability Assessment:**
High probability for both malicious and accidental scenarios:
- **Malicious:** Rogue scheme managers can directly execute this to extract value from locked users
- **Accidental:** Well-intentioned managers may call RemoveBeneficiary on RegisterForProfits users without realizing tokens remain locked

## Recommendation

Modify `RemoveBeneficiary` to synchronize token lock state when removing users who registered via RegisterForProfits:

**Option 1 - Unlock tokens when removing beneficiary:**
Add token unlock logic in RemoveBeneficiary when the lockId exists: [2](#0-1) 

After line 84, add:
```csharp
// Check if beneficiary registered via RegisterForProfits
var lockId = State.LockIds[Context.Sender][input.Beneficiary];
if (lockId != null)
{
    // Unlock tokens
    var lockedAmount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
    {
        Address = input.Beneficiary,
        LockId = lockId,
        Symbol = scheme.Symbol
    }).Amount;
    
    if (lockedAmount > 0)
    {
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = input.Beneficiary,
            LockId = lockId,
            Amount = lockedAmount,
            Symbol = scheme.Symbol
        });
    }
    
    State.LockIds[Context.Sender].Remove(input.Beneficiary);
    State.LockTimestamp.Remove(lockId);
}
```

**Option 2 - Prevent RemoveBeneficiary for locked users:**
Add assertion to prevent removal while tokens are locked:
```csharp
var lockId = State.LockIds[Context.Sender][input.Beneficiary];
Assert(lockId == null, "Cannot remove beneficiary with locked tokens. User must call Withdraw first.");
```

**Preferred Solution:** Option 1 maintains manager flexibility while ensuring state consistency. Option 2 is simpler but forces users to wait until MinimumLockMinutes expires.

## Proof of Concept

```csharp
[Fact]
public async Task RemoveBeneficiary_Leaves_Tokens_Locked_Vulnerability_Test()
{
    // Setup: Create scheme with 30-day minimum lock period
    var lockPeriodMinutes = 43200; // 30 days
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = lockPeriodMinutes
    });

    // User registers and locks 1000 tokens
    var lockAmount = 1000L;
    var userBalanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = "ELF",
        Owner = Starter
    })).Balance;
    
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = lockAmount,
        SchemeManager = Starter
    });

    // Verify tokens are locked
    var userBalanceAfterLock = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = "ELF",
        Owner = Starter
    })).Balance;
    userBalanceAfterLock.ShouldBe(userBalanceBefore - lockAmount);

    // Manager removes beneficiary (VULNERABILITY: doesn't unlock tokens)
    await TokenHolderContractStub.RemoveBeneficiary.SendAsync(new RemoveTokenHolderBeneficiaryInput
    {
        Beneficiary = Starter,
        Amount = 0 // Complete removal
    });

    // Verify user is removed from profit scheme
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = Starter
    });
    var profitDetails = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
    {
        SchemeId = schemeIds.SchemeIds.First(),
        Beneficiary = Starter
    });
    profitDetails.Details.Count.ShouldBe(0); // Beneficiary removed

    // VULNERABILITY: Tokens still locked but user earns no profits
    var userBalanceAfterRemoval = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = "ELF",
        Owner = Starter
    })).Balance;
    userBalanceAfterRemoval.ShouldBe(userBalanceBefore - lockAmount); // Still locked!

    // User cannot withdraw (blocked by minimum lock period)
    var withdrawResult = await TokenHolderContractStub.Withdraw.SendWithExceptionAsync(Starter);
    withdrawResult.TransactionResult.Error.ShouldContain("Cannot withdraw");

    // IMPACT: User has locked capital earning ZERO profits until MinimumLockMinutes expires
    // This violates the core TokenHolder invariant that locked tokens earn proportional profits
}
```

**Notes:**
1. The scheme manager is NOT a trusted role in AElf's threat model—any user can become a scheme manager by calling CreateScheme
2. The vulnerability affects the Economics & Rewards domain by breaking the fundamental coupling between token locks and profit beneficiary status
3. No test in the existing test suite validates this cross-cutting concern between RemoveBeneficiary and RegisterForProfits users
4. The issue has both malicious (rogue managers) and accidental (uninformed managers) attack vectors with identical harmful outcomes

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L24-24)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L233-235)
```csharp
        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();
```

**File:** protobuf/token_holder_contract.proto (L63-70)
```text
message CreateTokenHolderProfitSchemeInput {
    // The token symbol.
    string symbol = 1;
    // Minimum lock time for holding token.
    int64 minimum_lock_minutes = 2;
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
}
```

**File:** protobuf/token_holder_contract.proto (L79-84)
```text
message RemoveTokenHolderBeneficiaryInput {
    // Beneficiary's address.
    aelf.Address beneficiary = 1;
    // The amount of weights to remove.
    int64 amount = 2;
}
```
