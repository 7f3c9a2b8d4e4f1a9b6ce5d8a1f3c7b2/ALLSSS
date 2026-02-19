### Title
Rounding Errors in Profit Distribution Cause Inaccessible Dust Accumulation in Period Virtual Addresses

### Summary
The `SafeCalculateProfits` function uses truncating division that rounds down each beneficiary's profit share, causing dust to remain in period-specific virtual addresses after all claims are made. Over many distribution periods, this dust accumulates to significant amounts that become permanently inaccessible, as no mechanism exists for scheme managers to recover remaining tokens from period virtual addresses.

### Finding Description

**Root Cause:**
The profit calculation function performs decimal arithmetic then casts to long, which truncates fractional amounts: [1](#0-0) 

This truncation guarantees that when `totalAmount` is not evenly divisible by `totalShares`, each beneficiary receives a rounded-down amount, leaving remainder tokens (dust) unclaimed.

**Distribution Flow:**
When profits are distributed, the total amount is transferred to a period-specific virtual address and stored in `DistributedProfitsMap`: [2](#0-1) 

The `AmountsMap` stores the original distributed amount but is never updated as claims occur.

**Claiming Flow:**
When beneficiaries claim profits, their share is calculated using the same truncating function: [3](#0-2) 

After all beneficiaries claim their rounded-down shares, dust remains in the period virtual address.

**Why Dust is Inaccessible:**
Period virtual addresses are generated deterministically from the scheme ID and period number: [4](#0-3) 

Only the contract can use `SendVirtualInline` with these hashes to transfer tokens. The profit contract provides no public method for scheme managers to withdraw remaining balances from period virtual addresses after all claims are completed. Managers only have control over the scheme's main virtual address, not individual period addresses.

**Evidence of Known Issue:**
Test cases explicitly expect and tolerate rounding errors, confirming developers are aware but haven't addressed dust recovery: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Concrete Impact:**
- **Per-Period Loss:** For each distribution period, dust ranges from 0 to (totalShares - 1) tokens per symbol
- **Cumulative Loss:** Over 1,000 distribution periods with average 10 shares, up to 10,000 tokens could become permanently locked
- **Example:** Distributing 100 tokens among 3 equal beneficiaries results in each claiming 33 tokens (total 99), leaving 1 token permanently locked
- **Affected Parties:** All profit schemes using the contract, including consensus rewards, token holder dividends, and treasury distributions

**Severity Justification (Medium):**
- Not direct theft or malicious exploitation
- Funds are locked rather than stolen
- Impact grows linearly with number of periods
- Represents genuine economic loss that reduces protocol efficiency
- Affects critical economic infrastructure (consensus rewards, token holder benefits)

### Likelihood Explanation

**Deterministic Occurrence:**
- Happens automatically whenever `totalAmount % totalShares ≠ 0`
- No attacker action required - occurs during normal operations
- Affects every profit distribution with non-divisible amounts
- Mathematical certainty: probability = 100% for typical distributions

**No Special Preconditions:**
- Any authorized manager can trigger via normal `DistributeProfits` call
- No special state setup required
- Works with standard AElf contract execution model
- Beneficiaries claim normally via `ClaimProfits`

**Operational Reality:**
- Most token amounts won't divide evenly by share counts
- Schemes run for hundreds or thousands of periods
- Each period creates new uncollectable dust
- Compound effect across all active schemes protocol-wide

### Recommendation

**Immediate Mitigation:**
1. Add a `WithdrawPeriodDust` method accessible only to scheme managers:
   - Takes scheme ID and period as parameters
   - Calculates remaining balance in period virtual address
   - Transfers remainder back to scheme's main virtual address
   - Can only be called after sufficient time has passed (e.g., after period + grace period)

2. Modify `UpdateDistributedProfits` to track claimed amounts:
   - Add `ClaimedAmountsMap` to `DistributedProfitsInfo` message
   - Update claimed amounts when `ClaimProfits` executes
   - Allow managers to withdraw `AmountsMap - ClaimedAmountsMap` after all claims

3. Alternative: Implement dust redistribution:
   - Track cumulative dust per scheme
   - Automatically include accumulated dust in next period's distribution
   - Requires adding `AccumulatedDust` mapping to scheme state

**Test Cases:**
- Test distribution with prime-number shares (e.g., 7, 11, 13) to maximize dust
- Verify dust recovery after all beneficiaries claim
- Test multi-period accumulation and batch recovery
- Ensure manager-only access to dust withdrawal

### Proof of Concept

**Initial State:**
1. Create profit scheme with scheme manager Alice
2. Add 3 beneficiaries (Bob, Carol, Dave) each with 1 share (total: 3 shares)
3. Period 1: Distribute 100 tokens

**Execution Steps:**
1. Alice calls `DistributeProfits` with 100 tokens for period 1
   - 100 tokens transferred to period 1 virtual address
   - `DistributedProfitsMap[period1Address].AmountsMap["ELF"] = 100`

2. Bob claims profits via `ClaimProfits`:
   - Calculation: `SafeCalculateProfits(1, 100, 3)` = `(long)(33.333...)` = 33
   - Receives 33 tokens

3. Carol claims profits:
   - Calculation: `SafeCalculateProfits(1, 100, 3)` = 33
   - Receives 33 tokens

4. Dave claims profits:
   - Calculation: `SafeCalculateProfits(1, 100, 3)` = 33
   - Receives 33 tokens

**Expected vs Actual Result:**
- **Expected:** All 100 tokens distributed to beneficiaries
- **Actual:** 99 tokens claimed (33 × 3), 1 token remains in period 1 virtual address
- **Success Condition:** Query balance of period 1 virtual address shows 1 token permanently locked with no method to recover it

**Accumulation Example:**
Repeat for 1,000 periods with same parameters:
- Total dust accumulated: ~1,000 tokens
- All permanently inaccessible
- No cleanup mechanism available

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L560-583)
```csharp
    private void UpdateDistributedProfits(Dictionary<string, long> profitsMap,
        Address profitsReceivingVirtualAddress, long totalShares)
    {
        var distributedProfitsInformation =
            State.DistributedProfitsMap[profitsReceivingVirtualAddress] ??
            new DistributedProfitsInfo();

        distributedProfitsInformation.TotalShares = totalShares;
        distributedProfitsInformation.IsReleased = true;

        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var balanceOfVirtualAddressForCurrentPeriod = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = profitsReceivingVirtualAddress,
                Symbol = symbol
            }).Balance;
            distributedProfitsInformation.AmountsMap[symbol] = amount.Add(balanceOfVirtualAddressForCurrentPeriod);
        }

        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInformation;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L873-874)
```csharp
                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L956-962)
```csharp
    private static long SafeCalculateProfits(long totalAmount, long shares, long totalShares)
    {
        var decimalTotalAmount = (decimal)totalAmount;
        var decimalShares = (decimal)shares;
        var decimalTotalShares = (decimal)totalShares;
        return (long)(decimalTotalAmount * decimalShares / decimalTotalShares);
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L57-60)
```csharp
    private Hash GeneratePeriodVirtualAddressFromHash(Hash schemeId, long period)
    {
        return HashHelper.XorAndCompute(schemeId, HashHelper.ComputeFrom(period));
    }
```

**File:** test/AElf.Contracts.Election.Tests/Full/CitizenWelfareTests.cs (L716-716)
```csharp
            actualClaimed.ShouldBeInRange(shouldClaimed - 2, shouldClaimed);
```

**File:** test/AElf.Contracts.Election.Tests/Full/CitizenWelfareTests.cs (L724-724)
```csharp
        profitsList.Sum().ShouldBeInRange(totalAmount - 6, totalAmount);
```
