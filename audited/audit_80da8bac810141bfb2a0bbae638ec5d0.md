### Title
Period Desynchronization Between TokenHolder and Profit Contracts Causes DOS in RegisterForProfits

### Summary
The TokenHolder contract maintains a local `Period` counter that can become permanently desynchronized from the ProfitContract's `CurrentPeriod`. When a scheme manager calls `ProfitContract.DistributeProfits` directly, the ProfitContract's period advances but TokenHolder's does not. Subsequently, when users call `TokenHolder.RegisterForProfits` with auto-distribute enabled, it uses the stale period value, causing the ProfitContract's period validation to fail and the transaction to revert. This creates a permanent DOS condition preventing users from registering for profits.

### Finding Description

The vulnerability exists in the period synchronization mechanism between TokenHolder and Profit contracts. The root cause involves two issues:

**Issue 1: Direct ProfitContract Invocation**

The ProfitContract allows the scheme manager to call `DistributeProfits` directly: [1](#0-0) 

When called directly, the ProfitContract increments its `CurrentPeriod`: [2](#0-1) 

However, the TokenHolder contract's local `Period` field remains unchanged, creating desynchronization.

**Issue 2: No Period Sync in RegisterForProfits**

The `RegisterForProfits` function retrieves the scheme without period synchronization: [3](#0-2) 

The `GetValidScheme` function calls `UpdateTokenHolderProfitScheme` with `updateSchemePeriod = false` (default): [4](#0-3) 

This causes an early return without synchronization when the SchemeId is already set: [5](#0-4) 

When auto-distribute is triggered, the stale period is used: [6](#0-5) 

The ProfitContract then validates this period and fails when it doesn't match: [7](#0-6) 

**Issue 3: Storage Corruption Bug**

Additionally, `UpdateTokenHolderProfitScheme` contains a storage bug where it saves to `Context.Sender` instead of the `manager` parameter: [8](#0-7) 

This means period syncs (when they do occur) may be saved to the wrong address, further compounding desynchronization issues.

### Impact Explanation

**Operational Impact - DOS Attack:**
- Users cannot execute `RegisterForProfits` when the auto-distribute threshold is met
- This is a core functionality for token holders to stake tokens and receive dividends
- The DOS is permanent and repeatable - the manager can continuously call ProfitContract directly to maintain desynchronization

**Affected Parties:**
- All users attempting to register for profits in schemes with auto-distribute thresholds
- The scheme becomes functionally broken for new registrations
- Existing beneficiaries can still claim, but new participants cannot join

**Severity: HIGH**
- Complete loss of core contract functionality
- No recovery mechanism exists without contract upgrade
- Affects fundamental economic mechanism (staking/dividends)

### Likelihood Explanation

**Attacker Capabilities:**
- The "attacker" is the scheme manager (legitimate role)
- Manager only needs to call `ProfitContract.DistributeProfits` directly, which is explicitly allowed
- No special privileges beyond being scheme creator required

**Attack Complexity: LOW**
1. Create TokenHolder scheme with auto-distribute threshold
2. Call `ProfitContract.DistributeProfits` directly (bypassing TokenHolder)
3. Wait for users to call `RegisterForProfits` when threshold is met
4. Transaction automatically reverts due to period mismatch

**Feasibility: HIGH**
- Entry points are public methods
- No economic cost to the attacker (just normal transaction fees)
- ProfitContract explicitly permits this access pattern
- Auto-distribute thresholds are common configurations

**Detection: DIFFICULT**
- The desync is not visible without checking both contracts' state
- Users see transaction failures but may not understand the root cause
- No events or logs indicate the period desync

**Probability: VERY HIGH**
- This can occur accidentally if a manager uses both interfaces
- Once desync occurs, it persists indefinitely
- Any scheme with auto-distribute threshold is vulnerable

### Recommendation

**Fix 1: Always Sync Period in RegisterForProfits**

Modify `RegisterForProfits` to sync the period before use:
```csharp
var scheme = GetValidScheme(input.SchemeManager, true); // Pass updateSchemePeriod = true
```

**Fix 2: Correct Storage Bug in UpdateTokenHolderProfitScheme**

Change line 298 to save to the correct address:
```csharp
State.TokenHolderProfitSchemes[manager] = scheme; // Use manager parameter, not Context.Sender
```

**Fix 3: Add Period Sync to All Public Functions**

Ensure all functions that use `scheme.Period` sync before use:
- `ContributeProfits`: Change to `GetValidScheme(input.SchemeManager, true)`
- `ClaimProfits`: Change to `GetValidScheme(input.SchemeManager, true)`
- `Withdraw`: Change to `GetValidScheme(input, true)`

**Fix 4: Add Invariant Check**

Add validation that catches period mismatches early:
```csharp
var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
Assert(scheme.Period == originScheme.CurrentPeriod || 
       scheme.Period == originScheme.CurrentPeriod - 1, 
       "Period desync detected");
```

**Test Cases:**
1. Test direct ProfitContract.DistributeProfits followed by RegisterForProfits
2. Test auto-distribute with desynced periods
3. Test period sync occurs in all public functions
4. Test storage correctness when Context.Sender != manager

### Proof of Concept

**Initial State:**
- Alice creates a TokenHolder scheme with auto-distribute threshold of 1000 ELF
- Initial: ProfitContract.CurrentPeriod = 1, TokenHolder.Period = 1

**Step 1: Create Desynchronization**
```
Transaction: Alice calls ProfitContract.DistributeProfits(schemeId, period=1)
- ProfitContract.CurrentPeriod increments to 2
- TokenHolder.Period remains at 1
- Result: Desynchronization created (ProfitContract=2, TokenHolder=1)
```

**Step 2: Trigger DOS**
```
Transaction: Bob calls TokenHolder.RegisterForProfits(schemeManager=Alice, amount=100)
- Line 152: Gets scheme with Period=1 (stale value)
- Line 289: Returns early without sync (SchemeId is set, updateSchemePeriod=false)
- Lines 186-190: Auto-distribute threshold met (balance >= 1000 ELF)
- Line 196: Creates DistributeProfitsInput with Period=1
- Line 203: Calls ProfitContract.DistributeProfits(period=1)
- ProfitContract line 478-480: Assert fails (1 != 2)
- Transaction REVERTS with "Invalid period" error
```

**Expected Result:** Bob successfully registers and receives profit shares

**Actual Result:** Transaction reverts with assertion failure, DOS condition achieved

**Success Condition for Exploit:** 
- Bob cannot complete RegisterForProfits
- Alice can repeat Step 1 indefinitely to maintain DOS
- All future RegisterForProfits attempts with auto-distribute will fail

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L193-197)
```csharp
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L278-283)
```csharp
    private TokenHolderProfitScheme GetValidScheme(Address manager, bool updateSchemePeriod = false)
    {
        var scheme = State.TokenHolderProfitSchemes[manager];
        Assert(scheme != null, "Token holder profit scheme not found.");
        UpdateTokenHolderProfitScheme(ref scheme, manager, updateSchemePeriod);
        return scheme;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-298)
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
```
