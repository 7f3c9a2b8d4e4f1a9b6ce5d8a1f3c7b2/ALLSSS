### Title
Scheme Manager Can Steal Profit Shares from Locked Token Holders via RemoveBeneficiary

### Summary
The TokenHolder contract's `RemoveBeneficiary` function allows a scheme manager to remove or reduce shares of beneficiaries who registered via `RegisterForProfits` with locked tokens, while their tokens remain locked. This enables the manager to effectively steal future profit distributions that should belong to locked token holders, redistributing those profits to themselves or other beneficiaries.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**
The `RemoveBeneficiary` function only validates that the caller is the scheme manager but does not distinguish between two types of beneficiaries:
1. Manager-added beneficiaries (via `AddBeneficiary`) - no tokens locked
2. Self-registered beneficiaries (via `RegisterForProfits`) - tokens locked [2](#0-1) 

The authorization check at line 72 only calls `GetValidScheme(Context.Sender)`, which verifies the sender is a valid scheme manager, but provides no protection for users who have locked tokens.

**Why Protections Fail:**

When a user registers via `RegisterForProfits`, tokens are locked and a lock ID is stored: [3](#0-2) 

However, `RemoveBeneficiary` removes/reduces the user's shares in the Profit contract without unlocking their tokens: [4](#0-3) 

The function has no call to `State.TokenContract.Unlock`, meaning the user's tokens remain locked while their profit shares are stolen.

**Execution Path:**
When a beneficiary is removed from the Profit contract, their `EndPeriod` is set to `CurrentPeriod - 1`, preventing them from receiving any future profits: [5](#0-4) 

The scheme is created with `CanRemoveBeneficiaryDirectly = true`, allowing immediate removal: [6](#0-5) 

### Impact Explanation

**Direct Financial Theft:**
- Users who lock tokens via `RegisterForProfits` expect to receive profit distributions proportional to their locked tokens for the duration of the lock period
- A malicious scheme manager can remove or reduce their shares while tokens remain locked
- The "stolen" shares are effectively redistributed to other beneficiaries (including the manager themselves if they added themselves as a beneficiary)

**Quantified Impact:**
Example: User locks 10,000 tokens for a 30-day minimum lock period. Manager removes 9,999 shares, leaving user with 1 share. During 30 days, if 10,000 tokens profit is distributed and manager has equal shares, the manager receives ~99.99% (9,999 tokens) instead of 50% (5,000 tokens). The user loses ~4,999 tokens of profit while their capital remains locked.

**Affected Parties:**
- All users who register via `RegisterForProfits` and lock tokens
- Particularly severe for users with large lock amounts or long minimum lock periods

**Severity Justification:**
Critical - This violates the core invariant that locked tokens should guarantee proportional profit share. It enables direct theft of user funds (profits) through an authorization bypass where the manager has unauthorized power over user-locked capital.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be a scheme manager (achieved by calling `CreateScheme`)
- No additional privileges required beyond scheme creation
- Attack is completely permissionless once a scheme is created

**Attack Complexity:**
- Low complexity: single function call to `RemoveBeneficiary`
- No timing constraints or complex state manipulation required
- Can be executed immediately after users register

**Feasibility Conditions:**
- Users must first register via `RegisterForProfits` (expected normal usage)
- No preconditions beyond normal scheme operation
- Works on any TokenHolder scheme

**Detection Constraints:**
- Difficult to detect before execution as it's a "legitimate" manager function
- Once executed, user sees reduced shares but tokens remain locked
- No on-chain warning or validation prevents this

**Economic Rationality:**
- Highly rational for malicious manager: steal profits at zero cost
- Profitable even for small amounts due to zero execution cost
- Risk-reward strongly favors attacker since it appears as legitimate scheme management

### Recommendation

**Immediate Fix:**
Add a state mapping to track whether a beneficiary was added via `RegisterForProfits` and prevent managers from removing such beneficiaries while tokens are locked:

```csharp
// In TokenHolderContractState.cs
public MappedState<Address, Address, bool> IsRegisteredForProfits { get; set; }

// In RemoveBeneficiary
public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
{
    var scheme = GetValidScheme(Context.Sender);
    
    // NEW: Check if beneficiary registered via RegisterForProfits
    var lockId = State.LockIds[Context.Sender][input.Beneficiary];
    Assert(lockId == null || input.Beneficiary == Context.Sender, 
        "Cannot remove beneficiary with locked tokens.");
    
    // ... rest of function
}
```

**Invariant Checks:**
1. Beneficiaries with locked tokens (non-null lock ID) cannot be removed by managers
2. Only the beneficiary themselves can remove their registration via `Withdraw`
3. `RemoveBeneficiary` should only work on beneficiaries added via `AddBeneficiary`

**Test Cases:**
1. Test that manager cannot call `RemoveBeneficiary` on user who called `RegisterForProfits`
2. Test that user can still `Withdraw` after minimum lock period
3. Test that manager can still remove beneficiaries added via `AddBeneficiary`
4. Test partial removal attempts on locked beneficiaries fail

### Proof of Concept

**Initial State:**
- Alice creates a TokenHolder scheme with 30-day minimum lock
- Bob has 10,000 ELF tokens
- Alice adds herself as beneficiary with 10,000 shares via `AddBeneficiary`

**Attack Steps:**

1. **Bob registers for profits:**
   - Bob calls `RegisterForProfits(Alice, 10000)`
   - 10,000 ELF locked for 30 days
   - Bob receives 10,000 shares
   - Total shares: 20,000 (Alice: 10,000, Bob: 10,000)

2. **Alice contributes profits:**
   - Alice calls `ContributeProfits(10000 ELF)`
   - Virtual address receives 10,000 ELF

3. **Alice steals Bob's shares:**
   - Alice calls `RemoveBeneficiary(Bob, 9999)`
   - Bob's shares reduced to 1
   - Total shares: 10,001 (Alice: 10,000, Bob: 1)

4. **Profit distribution:**
   - Alice calls `DistributeProfits`
   - Alice receives: 10,000 / 10,001 * 10,000 = 9,999 ELF
   - Bob receives: 1 / 10,001 * 10,000 = 1 ELF

**Expected vs Actual Result:**
- **Expected:** Bob receives 5,000 ELF (50% of profits for his 10,000 locked tokens)
- **Actual:** Bob receives 1 ELF (0.01% of profits despite 10,000 tokens locked)
- **Alice's gain:** 9,999 ELF instead of 5,000 ELF (4,999 ELF stolen)

**Success Condition:**
Bob's tokens remain locked (verifiable via `GetLockedAmount`), but his profit share is reduced from 10,000 to 1, enabling Alice to claim profits that should belong to Bob.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-167)
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
