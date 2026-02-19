### Title
Period Desynchronization Between TokenHolder and Profit Contracts Causes DoS in RegisterForProfits

### Summary
The TokenHolder contract maintains a local `Period` counter that should remain synchronized with the Profit contract's `CurrentPeriod`. However, when a scheme manager calls `Profit.DistributeProfits` directly (bypassing TokenHolder), the periods desynchronize. This causes `RegisterForProfits` with auto-distribute enabled to revert, creating a permanent DoS condition that prevents users from registering for profit schemes.

### Finding Description

The TokenHolder contract tracks profit distribution periods locally in `TokenHolderProfitScheme.Period` [1](#0-0) , which should stay synchronized with the underlying Profit contract's `Scheme.CurrentPeriod` [2](#0-1) .

The synchronization mechanism is implemented in `UpdateTokenHolderProfitScheme` [3](#0-2) , which updates the local Period from the Profit contract's CurrentPeriod. However, this function has an early-exit condition [4](#0-3)  that prevents synchronization when `SchemeId != null` and `updateSchemePeriod=false`.

The vulnerability occurs in `RegisterForProfits` when auto-distribute is triggered. The function calls `GetValidScheme` with `updateSchemePeriod=false` [5](#0-4) , which prevents period synchronization. Although the function fetches `originScheme` from the Profit contract [6](#0-5) , it uses the stale local `scheme.Period` for auto-distribute [7](#0-6)  instead of `originScheme.CurrentPeriod`.

The Profit contract allows both the scheme manager AND the TokenHolder contract to call `DistributeProfits` [8](#0-7) . When the manager calls it directly, the Profit contract increments its `CurrentPeriod` [9](#0-8)  but TokenHolder's local Period remains unchanged.

Subsequently, when `RegisterForProfits` triggers auto-distribute with the stale Period, the Profit contract enforces that the input Period must equal CurrentPeriod [10](#0-9) , causing the transaction to revert with "Invalid period" error.

### Impact Explanation

**Operational Impact - Complete DoS of RegisterForProfits:**
- When periods desynchronize, `RegisterForProfits` with auto-distribute enabled permanently fails for ALL users
- Users cannot lock tokens or register as beneficiaries in the profit scheme
- The staking/dividend system becomes non-functional for new participants
- Existing beneficiaries are unaffected but no new users can join

**Scope of Damage:**
- Affects ALL TokenHolder schemes where auto-distribute thresholds are configured [11](#0-10) 
- The DoS is permanent until someone successfully calls `TokenHolder.DistributeProfits` (which may also fail due to desync)
- No fund loss occurs, but protocol functionality is severely degraded

**Who is Affected:**
- Users attempting to register for profits (cannot stake tokens)
- Scheme managers (reduced participation in their profit schemes)
- Overall protocol adoption and utility

### Likelihood Explanation

**Attacker Capabilities Required:**
- Attacker must be the scheme manager (trusted role)
- OR exploit occurs through legitimate manager operations
- No special privileges beyond being the scheme creator

**Attack Complexity:**
- Very simple: Single transaction calling `Profit.DistributeProfits` directly
- No coordination or timing requirements needed
- Permanent effect from single action

**Feasibility Conditions:**
- Manager has legitimate reasons to call `Profit.DistributeProfits` directly (e.g., distributing profits without going through TokenHolder)
- Auto-distribute thresholds must be configured in the TokenHolder scheme
- Once triggered, affects all subsequent `RegisterForProfits` calls

**Probability Assessment:**
- HIGH: Direct calls to `Profit.DistributeProfits` are valid operations that managers might perform
- The test suite shows expected behavior when TokenHolder calls are used [12](#0-11) , but doesn't cover the desync scenario
- No detection mechanism exists to warn about period desynchronization

### Recommendation

**Immediate Fix:**
In `RegisterForProfits` auto-distribute logic, use the already-fetched `originScheme.CurrentPeriod` instead of the local `scheme.Period`:

Change line 196 from using `scheme.Period` to using `originScheme.CurrentPeriod` when creating the `DistributeProfitsInput` [7](#0-6) .

**Alternative Fix:**
Call `GetValidScheme` with `updateSchemePeriod=true` at line 152 [5](#0-4)  to force period synchronization before auto-distribute.

**Invariant Check to Add:**
Before calling auto-distribute, assert that `scheme.Period == originScheme.CurrentPeriod` to detect and prevent desynchronization.

**Test Case to Prevent Regression:**
Add test where:
1. Manager calls `Profit.DistributeProfits` directly
2. Verify TokenHolder period becomes stale
3. Call `RegisterForProfits` with auto-distribute
4. Verify it either succeeds (after fix) or fails gracefully

### Proof of Concept

**Initial State:**
- Manager creates TokenHolder scheme with auto-distribute threshold configured
- Both `TokenHolder.Period = 1` and `Profit.CurrentPeriod = 1`

**Exploitation Steps:**
1. Manager calls `ProfitContract.DistributeProfits(SchemeId=X, Period=1)` directly (valid operation per authorization check [8](#0-7) )
2. Profit contract increments `CurrentPeriod` to 2 [9](#0-8) 
3. TokenHolder's local `Period` remains at 1 (no update mechanism triggered)
4. User calls `TokenHolder.RegisterForProfits(SchemeManager=Manager, Amount=1000)` with sufficient balance to trigger auto-distribute
5. RegisterForProfits locks tokens and checks auto-distribute thresholds [13](#0-12) 
6. Auto-distribute creates `DistributeProfitsInput` with `Period=1` (stale value) [7](#0-6) 
7. Calls `Profit.DistributeProfits(SchemeId=X, Period=1)` [14](#0-13) 
8. Profit contract checks `input.Period (1) == releasingPeriod (2)` [10](#0-9) 

**Expected vs Actual Result:**
- **Expected:** User successfully registers for profits, auto-distribute executes with correct period
- **Actual:** Transaction reverts with "Invalid period. When release scheme ... of period 1. Current period is 2"

**Success Condition:**
All subsequent `RegisterForProfits` calls fail with period mismatch error until manual period resynchronization occurs.

### Citations

**File:** protobuf/token_holder_contract.proto (L68-69)
```text
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
```

**File:** protobuf/token_holder_contract.proto (L116-127)
```text
message TokenHolderProfitScheme {
    // The token symbol.
    string symbol = 1;
    // The scheme id.
    aelf.Hash scheme_id = 2;
    // The current dividend period.
    int64 period = 3;
    // Minimum lock time for holding token.
    int64 minimum_lock_minutes = 4;
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 5;
}
```

**File:** protobuf/profit_contract.proto (L135-160)
```text
message Scheme {
    // The virtual address of the scheme.
    aelf.Address virtual_address = 1;
    // The total weight of the scheme.
    int64 total_shares = 2;
    // The manager of the scheme.
    aelf.Address manager = 3;
    // The current period.
    int64 current_period = 4;
    // Sub schemes information.
    repeated SchemeBeneficiaryShare sub_schemes = 5;
    // Whether you can directly remove the beneficiary.
    bool can_remove_beneficiary_directly = 6;
    // Period of profit distribution.
    int64 profit_receiving_due_period_count = 7;
    // Whether all the schemes balance will be distributed during distribution each period.
    bool is_release_all_balance_every_time_by_default = 8;
    // The is of the scheme.
    aelf.Hash scheme_id = 9;
    // Delay distribute period.
    int32 delay_distribute_period_count = 10;
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
    // The received token symbols.
    repeated string received_token_symbols = 12;
}
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L152-152)
```csharp
        var scheme = GetValidScheme(input.SchemeManager);
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L178-200)
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
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L203-203)
```csharp
            State.ProfitContract.DistributeProfits.Send(distributedInput);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L415-418)
```csharp
        var schemeInfoInProfit = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        var schemeInfoInTokenHolder = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
        schemeInfoInProfit.CurrentPeriod.ShouldBe(2);
        schemeInfoInTokenHolder.Period.ShouldBe(2);
```
