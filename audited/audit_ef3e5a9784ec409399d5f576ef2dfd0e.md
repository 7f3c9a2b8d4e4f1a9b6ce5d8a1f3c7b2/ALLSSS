### Title
Stale Period Cache Causes RegisterForProfits Auto-Distribution Failure After Direct ProfitContract Calls

### Summary
The `UpdateTokenHolderProfitScheme()` function contains an early return that prevents period synchronization when `SchemeId` exists and `updateSchemePeriod` is false. This allows the TokenHolder contract's cached period to become desynchronized from the ProfitContract's actual `CurrentPeriod`, causing RegisterForProfits with auto-distribution to fail when the scheme manager legitimately calls ProfitContract.DistributeProfits directly.

### Finding Description

The vulnerability exists in the `UpdateTokenHolderProfitScheme()` function at the early return condition: [1](#0-0) 

When this early return executes, the function skips synchronizing the cached `scheme.Period` with the ProfitContract's authoritative `CurrentPeriod`, preventing lines 290-298 from executing.

The root cause is that:

1. **TokenHolder maintains a cached period**: The TokenHolderProfitScheme stores a local `Period` field that should match ProfitContract's `CurrentPeriod`.

2. **ProfitContract allows direct manager calls**: The scheme manager can legitimately call ProfitContract.DistributeProfits directly: [2](#0-1) 

3. **Period validation is strict**: ProfitContract enforces exact period matching: [3](#0-2) 

4. **RegisterForProfits uses stale period**: When auto-distribute triggers, it uses the cached period without synchronization: [4](#0-3) [5](#0-4) 

Notably, the auto-distribute code fetches the latest scheme but only uses its `VirtualAddress`, ignoring the up-to-date `CurrentPeriod`: [6](#0-5) 

### Impact Explanation

**Operational DoS Impact:**

When the scheme manager calls ProfitContract.DistributeProfits directly (incrementing ProfitContract's `CurrentPeriod` to N+1), but TokenHolder's cached period remains at N, subsequent RegisterForProfits calls with auto-distribution enabled will fail with the assertion error: "Invalid period. When release scheme... of period N. Current period is N+1".

**Affected Operations:**
- All users attempting to register for profits when auto-distribute threshold is met
- The TokenHolder scheme becomes non-functional for new registrations until TokenHolder.DistributeProfits is called to re-sync

**Severity Justification (Medium):**
- Complete DoS of RegisterForProfits when auto-distribute is configured
- Requires manual intervention (calling TokenHolder.DistributeProfits) to restore functionality
- Does not result in fund loss, but breaks core dividend registration functionality
- Affects all users trying to stake tokens during the desynchronized state

### Likelihood Explanation

**Realistic Exploitability:**

This is not an "attack" but a legitimate operational scenario with high likelihood:

1. **No special attacker capabilities needed**: The scheme manager using their legitimate authority to call ProfitContract directly is a normal operational action.

2. **Low complexity**: The scenario requires only two sequential operations:
   - Manager calls ProfitContract.DistributeProfits directly
   - Any user attempts RegisterForProfits with auto-distribute threshold met

3. **Feasible preconditions**: 
   - Scheme has auto-distribute threshold configured (common feature)
   - Manager performs profit distribution through ProfitContract interface (legitimate)
   - No special state manipulation required

4. **Operational rationality**: Managers may prefer calling ProfitContract directly for:
   - Integration with other contracts
   - Custom distribution logic
   - Bypassing TokenHolder restrictions

**Probability: High** - This represents a legitimate usage pattern that will naturally occur in production when managers interact with both contract interfaces.

### Recommendation

**Immediate Fix:**

Modify `UpdateTokenHolderProfitScheme()` to always synchronize the period from ProfitContract, or synchronize it specifically before DistributeProfits calls: [7](#0-6) 

**Option 1 - Remove early return for period sync:**
```csharp
private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
    bool updateSchemePeriod)
{
    // Always sync SchemeId if null
    if (scheme.SchemeId == null)
    {
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        scheme.SchemeId = originSchemeId;
    }
    
    // Always sync period when updateSchemePeriod is true, or before critical operations
    if (updateSchemePeriod || scheme.SchemeId != null)
    {
        var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[manager] = scheme;
    }
}
```

**Option 2 - Sync period in RegisterForProfits before auto-distribute:**

In RegisterForProfits, use the already-fetched `originScheme.CurrentPeriod` instead of cached `scheme.Period`: [8](#0-7) 

Replace line 196 to use `originScheme.CurrentPeriod` instead of `scheme.Period`.

**Test Case:**
Add regression test simulating direct ProfitContract calls:
1. Create TokenHolder scheme
2. Manager calls ProfitContract.DistributeProfits directly
3. User calls RegisterForProfits with auto-distribute threshold met
4. Verify no assertion failure and successful registration

### Proof of Concept

**Initial State:**
- TokenHolder scheme created with auto-distribute threshold = 1000 ELF
- Scheme manager is Alice
- ProfitContract.CurrentPeriod = 1
- TokenHolder cached scheme.Period = 1

**Exploitation Steps:**

1. **Alice contributes 1000 ELF to ProfitContract** (via ContributeProfits)
   - ProfitContract scheme virtual address balance = 1000 ELF
   - ProfitContract.CurrentPeriod = 1

2. **Alice calls ProfitContract.DistributeProfits directly** with period = 1
   - Authorization check passes (Alice is scheme manager)
   - ProfitContract.CurrentPeriod increments to 2
   - TokenHolder cached scheme.Period remains at 1 (desynchronized)

3. **Bob calls TokenHolder.RegisterForProfits** to stake 100 ELF
   - GetValidScheme called with updateSchemePeriod = false
   - Early return executes at line 289
   - Auto-distribute check: balance (1000 ELF) >= threshold (1000 ELF) ✓
   - Creates DistributeProfitsInput with Period = 1 (stale)
   - Calls ProfitContract.DistributeProfits with period = 1
   - **Assertion fails**: "Invalid period. When release scheme... of period 1. Current period is 2"
   - Transaction reverts

**Expected Result:** RegisterForProfits succeeds with auto-distribution

**Actual Result:** Transaction fails with period mismatch assertion

**Success Condition for Exploit:** RegisterForProfits becomes unusable until someone calls TokenHolder.DistributeProfits to re-sync the period.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L478-480)
```csharp
        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```
