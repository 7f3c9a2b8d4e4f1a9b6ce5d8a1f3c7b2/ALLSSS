### Title
Period Desynchronization Causes DoS in RegisterForProfits Auto-Distribution

### Summary
The TokenHolderContract maintains a local period counter that can become desynchronized from the Profit contract's authoritative CurrentPeriod. When the scheme manager distributes profits directly through the Profit contract, the TokenHolder's local period becomes stale. Subsequent RegisterForProfits calls with auto-distribution enabled will fail with an "Invalid period" assertion error, creating a denial-of-service condition for new user registrations.

### Finding Description

The TokenHolderContract stores a local period counter in `scheme.Period` that must match the Profit contract's `CurrentPeriod` for distributions to succeed. However, the period synchronization logic is inconsistent across different code paths:

**RegisterForProfits with auto-distribution** (lines 149-209):
- Calls `GetValidScheme(input.SchemeManager)` with default `updateSchemePeriod = false` [1](#0-0) 
- The `UpdateTokenHolderProfitScheme` method returns early when `updateSchemePeriod = false`, skipping period synchronization [2](#0-1) 
- Uses the potentially stale local period for auto-distribution [3](#0-2) 
- Increments the local period after distribution [4](#0-3) 

**Manual DistributeProfits** (lines 131-147):
- Calls `GetValidScheme(input.SchemeManager, true)` with `updateSchemePeriod = true` [5](#0-4) 
- This forces period synchronization from the Profit contract [6](#0-5) 

**Profit contract validation**:
- Strictly validates that `input.Period == scheme.CurrentPeriod` [7](#0-6) 
- Increments its own `CurrentPeriod` after each distribution [8](#0-7) 

**Authorization bypass**:
- The Profit contract allows both the TokenHolder contract AND the scheme manager to call DistributeProfits directly [9](#0-8) 

The root cause is that RegisterForProfits assumes the local period is always synchronized, but this assumption breaks when the scheme manager distributes profits directly through the Profit contract, bypassing the TokenHolder wrapper.

### Impact Explanation

**Operational Impact**: 
When periods become desynchronized, any user attempting to call RegisterForProfits will encounter an assertion failure during auto-distribution. The Profit contract will reject the distribution with the error message: "Invalid period. When release scheme {schemeId} of period {stalePeriod}. Current period is {actualPeriod}".

**Who is affected**:
- All new users attempting to register for profits when auto-distribution is enabled
- Existing scheme functionality becomes unusable for new registrations
- The scheme remains in a broken state until someone manually calls TokenHolder.DistributeProfits to resync the period

**Severity justification**:
This is HIGH severity because:
1. It causes complete denial-of-service for the RegisterForProfits function
2. Auto-distribution is a documented, intended feature, not an edge case
3. The vulnerability affects core user-facing functionality
4. It requires manual intervention to recover
5. All schemes with auto-distribution enabled are vulnerable

### Likelihood Explanation

**Attacker capabilities**:
The scheme manager (who created the TokenHolder profit scheme) has legitimate access to call Profit.DistributeProfits directly. No privilege escalation or unauthorized access is required.

**Attack complexity**:
Extremely simple - the scheme manager only needs to call `Profit.DistributeProfits` directly instead of calling it through the TokenHolder wrapper. This can happen accidentally during normal operations or intentionally.

**Feasibility conditions**:
- Scheme must be created with auto-distribution enabled (AutoDistributeThreshold set)
- Scheme manager calls Profit.DistributeProfits directly at least once
- A user then attempts to call RegisterForProfits, triggering auto-distribution

**Probability**:
HIGH - The authorization model explicitly allows scheme managers to call Profit.DistributeProfits directly. There is no documentation or restriction preventing direct calls. In fact, the dual authorization suggests direct calls are an intended use case, making accidental desynchronization likely during normal operations.

### Recommendation

**Immediate fix**:
Modify RegisterForProfits to synchronize the period before auto-distribution by changing line 152 to call `GetValidScheme` with `updateSchemePeriod = true`:

```csharp
// Line 152: Change from
var scheme = GetValidScheme(input.SchemeManager);
// To
var scheme = GetValidScheme(input.SchemeManager, true);
```

This ensures the period is always synchronized from the Profit contract before attempting auto-distribution, matching the behavior of manual DistributeProfits.

**Additional safeguards**:
1. Add a state invariant check that validates `TokenHolder.Period == Profit.CurrentPeriod` before any distribution
2. Consider making TokenHolder the exclusive distributor by removing scheme manager authorization from Profit.DistributeProfits
3. Add comprehensive integration tests that verify period synchronization across all distribution paths

**Test cases to prevent regression**:
1. Test RegisterForProfits after direct Profit.DistributeProfits call by scheme manager
2. Test alternating direct and wrapped distribution calls
3. Test auto-distribution trigger after period desynchronization
4. Verify period synchronization in all GetValidScheme call sites

### Proof of Concept

**Initial state**:
1. TokenHolder scheme created with AutoDistributeThreshold = {{"ELF", 1000}}
2. Profits contributed to reach threshold (1000 ELF in scheme virtual address)
3. TokenHolder.Period = 1
4. Profit.CurrentPeriod = 1

**Exploitation steps**:

**Step 1**: Scheme manager calls Profit.DistributeProfits directly (bypassing TokenHolder)
- Input: `SchemeId = tokenHolderSchemeId, Period = 1`
- Profit contract validates: Period (1) == CurrentPeriod (1) ✓
- Profit contract increments: CurrentPeriod = 2
- TokenHolder.Period remains: 1

**Step 2**: User calls TokenHolder.RegisterForProfits
- Input: `Amount = 100, SchemeManager = schemeManager`
- RegisterForProfits calls GetValidScheme WITHOUT period sync (updateSchemePeriod = false) [1](#0-0) 
- Auto-distribution triggers (balance >= threshold) [10](#0-9) 
- Uses stale TokenHolder.Period = 1 [3](#0-2) 
- Calls Profit.DistributeProfits with Period = 1 [11](#0-10) 

**Step 3**: Profit contract rejects the call
- Validates: Period (1) == CurrentPeriod (2) ✗
- Assertion fails with error: "Invalid period. When release scheme ... of period 1. Current period is 2" [7](#0-6) 
- RegisterForProfits transaction reverts
- User cannot register for profits

**Expected result**: RegisterForProfits succeeds and auto-distribution completes

**Actual result**: RegisterForProfits fails with "Invalid period" assertion error, denying service to users attempting to register for profits

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L133-133)
```csharp
        var scheme = GetValidScheme(input.SchemeManager, true);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L179-206)
```csharp
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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L289-289)
```csharp
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L297-297)
```csharp
        scheme.Period = originScheme.CurrentPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L426-428)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L479-480)
```csharp
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```
