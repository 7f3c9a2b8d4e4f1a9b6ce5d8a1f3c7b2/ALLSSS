### Title
Off-by-One Error in Profit Detail Cleanup Causes Permanent Loss of Unclaimed Profits

### Summary
The `AddBeneficiary` method uses an incorrect comparison operator (`>=` instead of `>`) when determining which profit details to clean up, causing beneficiaries to lose their final period's unclaimed profits. When a beneficiary's `LastProfitPeriod` equals their `EndPeriod`, they still have one period to claim, but the cleanup logic erroneously removes their profit detail, permanently preventing them from claiming those funds.

### Finding Description
The root cause is in the cleanup logic within the `AddBeneficiary` method. [1](#0-0) 

The cleanup condition checks `d.LastProfitPeriod >= d.EndPeriod`, but this is incorrect because `LastProfitPeriod` represents the **next** period to claim, not the last claimed period. When claiming profits, the `ProfitAllPeriods` function updates `LastProfitPeriod` to `period + 1` after processing each period. [2](#0-1) 

The claiming loop iterates from `LastProfitPeriod` to `maxProfitPeriod` (inclusive). [3](#0-2) 

This means if `LastProfitPeriod = 10` and `EndPeriod = 10`, the beneficiary can still claim period 10, but the cleanup condition `10 >= 10` evaluates to true and removes the detail prematurely.

Notably, the `ClaimProfits` method correctly uses the strict inequality `>` for its cleanup logic. [4](#0-3) 

The default `ProfitReceivingDuePeriodCount` of 10 is used when schemes don't specify this value. [5](#0-4) [6](#0-5) 

### Impact Explanation
**Direct Fund Loss**: Beneficiaries permanently lose their unclaimed profits for the final period of their participation. For example, if a beneficiary is entitled to 1000 ELF across 10 periods (100 ELF per period), they could lose the final 100 ELF.

**Affected Users**: Any beneficiary with a time-limited participation (`EndPeriod != long.MaxValue`), which is common for:
- Temporary staking rewards
- Time-limited voting dividends
- Campaign-based profit distribution schemes
- Short-term liquidity mining programs

**Severity Justification**: HIGH severity because:
1. Guaranteed loss of funds when conditions are met
2. Affects legitimate users who claim profits regularly but not every single period
3. Default grace period of only 10 periods can pass quickly in active schemes
4. No warning or recovery mechanism once detail is deleted

### Likelihood Explanation
**Reachable Entry Point**: The cleanup executes automatically during `AddBeneficiary` calls, which are routine operations in profit schemes as new participants join.

**Attack Complexity**: No malicious actor needed—this is a logic bug that triggers during normal operations:
1. User is added as beneficiary with finite `EndPeriod`
2. User claims profits but not for the final period (due to timing—profits can only be claimed up to `CurrentPeriod - 1`)
3. Time passes beyond `EndPeriod + ProfitReceivingDuePeriodCount`
4. Any `AddBeneficiary` call triggers cleanup

**Feasibility Conditions**: Highly likely in practice:
- Users often claim profits periodically (e.g., weekly) rather than daily
- The 10-period grace window can expire quickly (e.g., 10 days for daily distribution schemes)
- Beneficiaries might not realize they have one final period to claim after `EndPeriod`
- `AddBeneficiary` is frequently called in active schemes

**Probability**: HIGH—occurs naturally whenever a beneficiary's participation ends and they haven't claimed their absolute final period before new beneficiaries are added after the grace period.

### Recommendation
Change the cleanup comparison operator from `>=` to `>` in the `AddBeneficiary` method to match the logic used in `ClaimProfits`:

```csharp
// Line 205 - Change from:
d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&

// To:
d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod > d.EndPeriod &&
```

**Additional safeguards**:
1. Add integration tests that verify beneficiaries can claim all periods up to and including `EndPeriod`
2. Add a test case where beneficiary claims at `CurrentPeriod = EndPeriod` (getting up to `EndPeriod - 1`), then claims again at `CurrentPeriod = EndPeriod + 1` to get the final period
3. Document that `LastProfitPeriod` represents the next unclaimed period, not the last claimed period

### Proof of Concept
**Initial State**:
- Scheme created with `ProfitReceivingDuePeriodCount = 10` (default)
- Beneficiary Alice added at period 1 with `StartPeriod = 1`, `EndPeriod = 10`, `Shares = 100`
- Profits of 1000 ELF distributed for periods 1-10 (100 ELF per period)

**Exploitation Steps**:
1. At `CurrentPeriod = 10`: Alice calls `ClaimProfits`
   - She receives periods 1-9 (900 ELF total) because claims are limited to `CurrentPeriod - 1`
   - Her `LastProfitPeriod` is updated to 10
   - Period 10's profit (100 ELF) remains unclaimed

2. At `CurrentPeriod = 11`: Profits distributed for period 11
   - Alice could now claim period 10, but doesn't immediately

3. Time passes: `CurrentPeriod` reaches 21

4. At `CurrentPeriod = 21`: New beneficiary Bob is added via `AddBeneficiary`
   - Cleanup logic evaluates Alice's detail:
     - `EndPeriod (10) != long.MaxValue` ✓
     - `LastProfitPeriod (10) >= EndPeriod (10)` ✓ [BUG: should be `>`]
     - `EndPeriod + ProfitReceivingDuePeriodCount (20) < CurrentPeriod (21)` ✓
   - Alice's profit detail is **deleted**

5. Alice attempts to claim her remaining profits
   - **Result**: Transaction fails or returns 0—her detail no longer exists
   - **Expected**: Alice should receive 100 ELF for period 10
   - **Actual**: 100 ELF permanently lost, stuck in the period 10 virtual address

**Success Condition**: Alice's unclaimed 100 ELF from period 10 is permanently inaccessible, demonstrating the off-by-one error causes real fund loss.

### Notes
The inconsistency between `AddBeneficiary` using `>=` and `ClaimProfits` using `>` for the same semantic check strongly suggests this is an unintentional bug rather than intended behavior. The default 10-period grace window, while seemingly generous, can expire quickly in schemes with frequent distributions, making this a practical concern for real-world deployments.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L48-49)
```csharp
        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L204-207)
```csharp
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-789)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-860)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L908-908)
```csharp
                    lastProfitPeriod = period + 1;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L6-6)
```csharp
    public const int DefaultProfitReceivingDuePeriodCount = 10;
```
