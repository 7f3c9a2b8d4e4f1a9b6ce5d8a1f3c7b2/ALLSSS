### Title
Scheme Manager Can DOS Profit Claiming Through Unlimited Empty Period Creation

### Summary
A malicious scheme manager can repeatedly call `DistributeProfits` with empty `AmountsMap`, causing periods to increment indefinitely without distributing any profits. This forces beneficiaries to iterate through potentially millions of empty periods when claiming profits, making profit claiming economically infeasible due to excessive gas costs and transaction requirements.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The `DistributeProfits` function unconditionally increments the period counter without validating that actual profit distribution occurred. [2](#0-1) 

The code only adds `AmountsMap` if it is non-null AND non-empty. When these conditions fail, an empty `AmountsMap` is passed to the Profit contract. [3](#0-2) 

The period is incremented unconditionally, regardless of whether any profits were distributed.

**Authorization Check**: [4](#0-3) 

The scheme manager is authorized to call this function, making this a legitimate but abusable capability.

**Profit Contract Behavior**: [5](#0-4) 

The only protection checks if period is negative OR totalShares is zero. If a scheme has beneficiaries (totalShares > 0), the function proceeds. [6](#0-5) 

The Profit contract also unconditionally increments `CurrentPeriod`, even when no profits are distributed.

**Impact on Claiming**: [7](#0-6) 

When users claim profits, they must iterate from `LastProfitPeriod` to `CurrentPeriod-1`. Empty periods are skipped but still consume gas during iteration. [8](#0-7) 

Each claim transaction can process a maximum of approximately 100 periods (divided by the number of profitable details), as defined by the constant limit.

### Impact Explanation

**Who is Affected**: All beneficiaries of the TokenHolder profit scheme become victims of this DOS attack.

**Harm Mechanism**:
1. Attacker creates N empty periods (e.g., 1,000,000 periods)
2. Each beneficiary must call `ClaimProfits` approximately N/100 times (10,000+ transactions)
3. Each transaction costs gas fees
4. Total cost to claim may exceed the value of profits, making them economically unclaimed

**Quantified Damage**:
- If 1,000,000 empty periods are created, users need ~10,000 claim transactions
- At reasonable gas costs, this could cost hundreds of dollars per user
- Small profit amounts become permanently trapped as claiming costs exceed profit value
- Protocol reputation severely damaged

**Severity Justification**: High severity because:
- Affects all protocol participants in the scheme
- Legitimate profits become inaccessible
- Attack cost is minimal (just transaction fees for the manager)
- No recovery mechanism exists for trapped periods
- Economic denial of service with permanent effect

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be the scheme manager, which is a legitimate role obtained during scheme creation. This is not a privilege escalation - it's abuse of existing authority.

**Attack Complexity**: Extremely low - just repeatedly call the same function with empty input:
```
DistributeProfits({ SchemeManager: <address>, AmountsMap: {} })
```

**Feasibility Conditions**:
- Scheme must have at least one beneficiary (totalShares > 0) - this is the normal case
- No additional preconditions required
- No time locks or cooldown periods exist

**Detection Constraints**: 
- Attack is immediately visible on-chain (period increments without profit events)
- However, damage is already done once periods are created
- No on-chain mechanism to reverse or skip empty periods

**Probability**: HIGH - Any malicious or compromised scheme manager can execute this attack at will with minimal cost and maximum impact.

### Recommendation

**Code-Level Mitigation**:

Add validation in `TokenHolderContract.DistributeProfits` to ensure profits are actually being distributed:

```csharp
public override Empty DistributeProfits(DistributeProfitsInput input)
{
    var scheme = GetValidScheme(input.SchemeManager, true);
    Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
           Context.Sender == input.SchemeManager, "No permission to distribute profits.");
    
    // NEW: Require non-empty AmountsMap OR IsReleaseAllBalanceEveryTimeByDefault mode
    Assert(
        (input.AmountsMap != null && input.AmountsMap.Any()) ||
        scheme.IsReleaseAllBalanceEveryTimeByDefault,
        "Cannot distribute without specifying amounts unless auto-release is enabled."
    );
    
    var distributeProfitsInput = new Profit.DistributeProfitsInput
    {
        SchemeId = scheme.SchemeId,
        Period = scheme.Period
    };
    if (input.AmountsMap != null && input.AmountsMap.Any()) 
        distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

    State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
    scheme.Period = scheme.Period.Add(1);
    State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
    return new Empty();
}
```

**Alternative/Additional Protection** in `ProfitContract.DistributeProfits`:

```csharp
// After building profitsMap (line 460), add:
Assert(
    profitsMap.Any() || input.Period < 0 || totalShares <= 0,
    "Cannot increment period without distributing profits."
);
```

**Test Cases**:
1. Test that calling `DistributeProfits` with empty `AmountsMap` is rejected
2. Test that auto-release mode still works when enabled
3. Test that beneficiaries can claim after legitimate distributions
4. Test gas consumption limits for claim operations

### Proof of Concept

**Initial State**:
1. Scheme manager creates a TokenHolder profit scheme
2. At least one user registers as beneficiary (e.g., locks 1000 tokens)
3. Someone contributes 1000 ELF to the scheme for future distribution
4. Current period is 1

**Attack Execution**:
1. Malicious scheme manager calls `DistributeProfits({ SchemeManager: <manager_address>, AmountsMap: {} })` 
2. Period increments to 2 with no profit distribution
3. Repeat step 1 for 10,000 times
4. Period is now 10,002

**Expected vs Actual Result**:
- **Expected**: Period should only increment when profits are actually distributed
- **Actual**: Period increments to 10,002 without any profit distribution

**Impact Verification**:
1. Beneficiary attempts to claim profits by calling `ClaimProfits`
2. Function must iterate through periods 1-10,001
3. With limit of ~100 periods per transaction, beneficiary needs 100+ transactions
4. Each transaction costs gas, making the 1000 ELF profit economically inaccessible if gas costs exceed profit value

**Success Condition**: The attack succeeds if:
- Period counter reaches 10,000+ with zero actual profit distributions
- Beneficiaries cannot claim their legitimate profits without excessive transaction costs
- Total claiming cost approaches or exceeds the profit value

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L131-147)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        var scheme = GetValidScheme(input.SchemeManager, true);
        Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName) ||
               Context.Sender == input.SchemeManager, "No permission to distribute profits.");
        var distributeProfitsInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
        scheme.Period = scheme.Period.Add(1);
        State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-494)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-871)
```csharp
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
            {
                var periodToPrint = period;
                var detailToPrint = profitDetail;
                var distributedPeriodProfitsVirtualAddress =
                    GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, period);
                var distributedProfitsInformation =
                    State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
                if (distributedProfitsInformation == null || distributedProfitsInformation.TotalShares == 0 ||
                    !distributedProfitsInformation.AmountsMap.Any() ||
                    !distributedProfitsInformation.AmountsMap.ContainsKey(symbol))
                    continue;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L9-9)
```csharp
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
```
