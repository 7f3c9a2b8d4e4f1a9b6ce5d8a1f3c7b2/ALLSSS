### Title
Manager Can Steal Locked Users' Profit Share by Removing Beneficiaries Before Distribution

### Summary
The `RemoveBeneficiary` function allows the scheme manager to remove beneficiaries with `Amount=0` at any time, immediately reducing `TotalShares` in the Profit contract. If the manager removes beneficiaries after profits are contributed but before `DistributeProfits` is called, the removed beneficiaries lose their entire profit share for that period while their tokens remain locked. The remaining beneficiaries (potentially including the manager) receive inflated profit shares, effectively stealing the removed users' profit entitlement.

### Finding Description

The vulnerability exists in the interaction between `TokenHolderContract.RemoveBeneficiary` and the Profit contract's distribution mechanism.

**Root Cause:**

When `RemoveBeneficiary` is called with `input.Amount == 0`, the function completely removes the beneficiary from the profit scheme: [1](#0-0) 

This triggers the Profit contract's `RemoveBeneficiary`, which immediately executes `RemoveProfitDetails`: [2](#0-1) 

The Profit contract's `RemoveProfitDetails` function sets the beneficiary's `EndPeriod` to `CurrentPeriod - 1` when `CanRemoveBeneficiaryDirectly` is true (which it always is for TokenHolder schemes): [3](#0-2) 

And critically, the beneficiary's shares are immediately subtracted from `scheme.TotalShares`: [4](#0-3) 

**Why Existing Protections Fail:**

The TokenHolder scheme is created with `CanRemoveBeneficiaryDirectly = true`, enabling immediate removal: [5](#0-4) 

When profits are distributed, the function uses the **current** `scheme.TotalShares` (after removal): [6](#0-5) 

The removed beneficiary can only claim profits up to their `EndPeriod`, which was set to `CurrentPeriod - 1`: [7](#0-6) 

Meanwhile, the removed beneficiary's tokens **remain locked** and cannot be withdrawn until `MinimumLockMinutes` passes: [8](#0-7) 

### Impact Explanation

**Direct Fund Impact:**
- Removed beneficiaries lose their entire profit share for the current distribution period
- Their locked tokens earn zero returns despite being locked
- Remaining beneficiaries receive inflated profit shares proportional to the stolen amount
- If 2 users each lock 100 tokens and 1000 tokens are to be distributed, removing 1 user before distribution gives the remaining user 1000 tokens instead of 500 tokens - a theft of 500 tokens

**Who Is Affected:**
- Victim: Any user who has locked tokens via `RegisterForProfits` and is removed before distribution
- Beneficiary: Remaining beneficiaries in the scheme, potentially including the manager if they registered themselves

**Severity Justification:**
This is a **CRITICAL** vulnerability because:
1. Users' locked tokens become worthless (no profit generation) without their consent
2. The manager can execute this attack repeatedly across multiple distribution periods
3. Users cannot immediately withdraw due to the lock period requirement
4. The economic damage scales with the amount of locked tokens and profit contributions
5. The attack is completely undetectable to users until after distribution occurs

### Likelihood Explanation

**Attacker Capabilities:**
The attacker must be the scheme manager, which is a legitimate privileged role obtained through `CreateScheme`. The manager can also register as a beneficiary themselves to directly profit from the theft. [9](#0-8) 

**Attack Complexity:**
The attack requires only 2 simple function calls:
1. `RemoveBeneficiary(victim_address, Amount=0)` - removes victim's shares
2. `DistributeProfits(current_period)` - distributes profits to remaining beneficiaries only

**Feasibility Conditions:**
- Profits must be contributed to the scheme (via `ContributeProfits`)
- Distribution must not have occurred yet for the current period
- Victims' tokens must still be within the lock period

**Economic Rationality:**
The attack is highly profitable with minimal cost:
- No transaction cost beyond gas fees
- Direct profit proportional to removed beneficiaries' shares
- Can be repeated across multiple periods
- Example: Removing a beneficiary with 50% of shares doubles the manager's profit share

**Detection/Operational Constraints:**
The attack is difficult to detect because:
- `RemoveBeneficiary` appears to be a legitimate management function
- The theft only becomes apparent after distribution occurs
- Users cannot prevent it due to locked tokens
- No on-chain event explicitly warns users of impending profit loss

### Recommendation

**Immediate Mitigation:**

1. **Prevent removal when undistributed profits exist:**
   Add a check in `TokenHolderContract.RemoveBeneficiary` to ensure no pending profits exist in the scheme's VirtualAddress before allowing removal:
   
   ```csharp
   // Check that scheme has no undistributed profits
   var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput {
       Owner = scheme.VirtualAddress,
       Symbol = scheme.Symbol
   }).Balance;
   Assert(balance == 0, "Cannot remove beneficiary with pending undistributed profits.");
   ```

2. **Require profit claim before removal:**
   Force the beneficiary to claim all available profits before removal:
   
   ```csharp
   // Ensure beneficiary has claimed all available profits
   State.ProfitContract.ClaimProfits.Send(new ClaimProfitsInput {
       SchemeId = scheme.SchemeId,
       Beneficiary = input.Beneficiary
   });
   ```

3. **Alternative approach - proportional refund:**
   When removing a beneficiary with `Amount=0`, calculate and immediately transfer their proportional share of any undistributed profits in the VirtualAddress.

**Invariant Checks to Add:**

- Assert that removing a beneficiary does not reduce their claimable profit amount for already-contributed periods
- Verify that `TotalShares` used for distribution equals the sum of all active beneficiaries' shares at the time profits were contributed
- Track the period when profits are contributed and lock beneficiary list at that time

**Test Cases:**

1. Test that removal with pending profits in VirtualAddress is rejected
2. Test that beneficiary receives correct profit share if removed after all profits are claimed
3. Test that concurrent removal + distribution transactions are properly ordered
4. Test that a removed beneficiary with Amount>0 maintains proportional shares

### Proof of Concept

**Initial State:**
- Manager creates TokenHolder scheme with Symbol="ELF", MinimumLockMinutes=1440
- Alice calls `RegisterForProfits(manager_address, 100 ELF)` → locks 100 ELF, receives 100 shares
- Bob calls `RegisterForProfits(manager_address, 100 ELF)` → locks 100 ELF, receives 100 shares
- Current state: TotalShares = 200, CurrentPeriod = 1

**Attack Sequence:**

**Step 1 - Profits Contributed:**
- Contributor calls `ContributeProfits(manager_address, "ELF", 1000)` 
- 1000 ELF transferred to scheme.VirtualAddress
- Profits not yet distributed (still in Period 1)

**Step 2 - Manager Removes Alice:**
- Manager calls `RemoveBeneficiary(Alice, Amount=0)`
- Alice's EndPeriod set to 0 (CurrentPeriod - 1 = 1 - 1 = 0)
- TotalShares reduced to 100 (only Bob's shares remain)
- Alice's 100 ELF remains locked

**Step 3 - Manager Distributes Profits:**
- Manager calls `DistributeProfits(manager_address, Period=1)`
- Distribution uses TotalShares = 100
- Bob receives: (100/100) × 1000 = 1000 ELF
- Alice receives: 0 ELF (EndPeriod=0 < CurrentPeriod=1)

**Expected vs Actual Result:**
- **Expected:** Alice gets 500 ELF, Bob gets 500 ELF (50/50 split)
- **Actual:** Alice gets 0 ELF, Bob gets 1000 ELF (Manager stole Alice's 500 ELF share)

**Success Condition:**
The attack succeeds when Bob's profit balance equals 1000 ELF and Alice's claimable profits equal 0 ELF, despite both having locked 100 ELF tokens during the contribution period.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L24-24)
```csharp
            CanRemoveBeneficiaryDirectly = true
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L72-72)
```csharp
        var scheme = GetValidScheme(Context.Sender);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L80-84)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L85-87)
```csharp
        if (lockedAmount > input.Amount &&
            input.Amount != 0) // If input.Amount == 0, means just remove this beneficiary.
            State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L260-260)
```csharp
        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L462-462)
```csharp
        var totalShares = scheme.TotalShares;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L856-856)
```csharp
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
```
