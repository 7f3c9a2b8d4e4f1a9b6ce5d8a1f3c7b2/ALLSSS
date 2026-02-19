### Title
Cumulative Rounding Errors in Sub-Scheme Profit Distribution Cause Systematic Underpayment

### Summary
The `PerformDistributeProfits` function suffers from cumulative rounding errors when distributing profits to multiple sub-schemes. The `SafeCalculateProfits` function truncates decimal results to integers, causing each sub-scheme to lose up to 1 smallest token unit. With many sub-schemes, these losses accumulate, causing `remainAmount` (allocated to individual beneficiaries) to be systematically larger than the mathematically correct value, resulting in unfair distribution where sub-schemes are underpaid and individuals are overpaid.

### Finding Description

The vulnerability exists in the profit distribution mechanism across three key locations: [1](#0-0) [2](#0-1) [3](#0-2) 

**Root Cause**: The `SafeCalculateProfits` function converts integers to decimals for calculation but then casts the result back to `long`, which truncates (rounds down) any fractional part. This means each calculation: `(long)(totalAmount * shares / totalShares)` loses up to 0.999... units.

**Accumulation Mechanism**: In `DistributeProfitsForSubSchemes`, the function:
1. Starts with `remainAmount = totalAmount`
2. For each sub-scheme, calculates `distributeAmount = SafeCalculateProfits(...)` which rounds down
3. Subtracts: `remainAmount = remainAmount.Sub(distributeAmount)`
4. Returns the remainder to be allocated to individual beneficiaries

With N sub-schemes, the cumulative rounding loss can reach N smallest token units. This means:
- remainAmount = totalAmount - Σ(floor(shares_i × totalAmount / totalShares))
- remainAmount ≈ (expected individual allocation) + (N × rounding error per sub-scheme)

**Why Existing Protections Fail**: There are no checks or compensatory mechanisms to prevent or correct rounding error accumulation. The only validation in `AddSubScheme` is that shares must be greater than 0, which doesn't address the mathematical precision issue. [4](#0-3) 

### Impact Explanation

**Direct Fund Impact**: This causes systematic reward misallocation between sub-schemes and individual beneficiaries. The severity depends on three factors:

1. **Number of sub-schemes (N)**: More sub-schemes = more accumulated error
2. **Distribution amount relative to shares**: When `(shares_i × totalAmount / totalShares) < 1`, severe underpayment occurs
3. **Token decimals**: Tokens with fewer decimal places experience larger percentage errors

**Worst-Case Scenario**:
- Distributing 999 smallest units across 1,000 total shares
- 500 sub-schemes with 1 share each
- Each sub-scheme expected: 999 × 1 / 1,000 = 0.999 units
- Each sub-scheme receives: floor(0.999) = 0 units
- Total expected for sub-schemes: 499.5 units
- Total received by sub-schemes: 0 units
- Individual beneficiaries receive: 999 units instead of 499.5 units (nearly double)

**Who Is Affected**: The Treasury contract uses this pattern to distribute mining rewards across sub-schemes (Mining Reward, Subsidy, Welfare), making this a real-world concern. [5](#0-4) [6](#0-5) 

**Severity Justification**: Medium severity because while typical scenarios have small absolute impact, edge cases with many sub-schemes or low-decimal tokens can result in sub-schemes receiving 0-10% of their entitled allocation. Over multiple distribution periods, the cumulative unfairness becomes significant.

### Likelihood Explanation

**Reachable Entry Point**: The `DistributeProfits` function is publicly callable by scheme managers. [7](#0-6) 

**Execution Practicality**: This occurs during normal profit distribution operations whenever a scheme has sub-schemes. No special conditions or malicious actions are required - the mathematical flaw is inherent in the implementation.

**Feasible Preconditions**: 
- A profit scheme with multiple sub-schemes exists (common in Treasury)
- Profits are distributed (happens every consensus term)
- The impact severity increases when:
  - Many sub-schemes exist (easily achievable)
  - Distribution amounts are small relative to total shares
  - Tokens have low decimal precision

**Probability**: High likelihood of occurrence (happens on every distribution with sub-schemes), but impact severity varies. The unfairness is systematic and accumulates over time.

**Not an Active Exploit**: This is not exploitable by external attackers since only scheme managers can create sub-schemes and distribute profits. However, it represents a fundamental flaw in the distribution algorithm that systematically favors individual beneficiaries over sub-schemes.

### Recommendation

**Code-Level Mitigation**:

1. **Track and redistribute rounding errors**: Modify the distribution logic to track accumulated rounding errors and add them to the final sub-scheme's allocation or distribute them proportionally.

2. **Use higher precision arithmetic**: Consider using a library for higher-precision decimal arithmetic that doesn't truncate until the final distribution.

3. **Reverse the calculation order**: Calculate individual allocations first using the same rounding method, then give the remainder to sub-schemes, ensuring consistency.

4. **Add explicit rounding strategy**: Implement a configurable rounding strategy (e.g., round to nearest, banker's rounding) rather than always rounding down.

**Recommended Implementation**:
```
In DistributeProfitsForSubSchemes:
- Track total distributed
- For last sub-scheme, assign: remainingAmount instead of calculated amount
- This ensures: sum(distributions) = totalAmount exactly

Or alternatively:
- Calculate distributions for all but one sub-scheme
- Give remainder to the largest sub-scheme or split proportionally
```

**Invariant Checks**:
- Assert that sum of all distributions equals total amount
- Log warnings when rounding errors exceed threshold
- Add tests with edge cases (many sub-schemes, small amounts)

**Test Cases**:
- Test with 100+ sub-schemes and small distribution amounts
- Test with tokens of varying decimal places (0, 2, 8, 18)
- Test cumulative distribution over many periods
- Verify sub-schemes receive at least floor(expected amount)

### Proof of Concept

**Initial State**:
- Create a profit scheme with SchemeId = SCHEME_A
- Add 500 sub-schemes, each with 1 share
- Add individual beneficiaries with total 500 shares
- Total shares in scheme: 1,000

**Transaction Steps**:
1. Manager calls `ContributeProfits(schemeId: SCHEME_A, amount: 999, symbol: "ELF", period: 1)`
2. Manager calls `DistributeProfits(schemeId: SCHEME_A, period: 1, amountsMap: {"ELF": 999})`

**Expected Result** (mathematically correct):
- Each sub-scheme should receive: 999 × 1 / 1,000 = 0.999 ≈ 1 unit
- Total for 500 sub-schemes: ~500 units
- Individual beneficiaries: ~499 units

**Actual Result**:
- Each sub-scheme receives: floor(999 × 1 / 1,000) = floor(0.999) = 0 units
- Total for 500 sub-schemes: 500 × 0 = 0 units
- remainAmount transferred to individuals: 999 - 0 = 999 units

**Success Condition**:
- Query sub-scheme balances: All show 0 tokens
- Query individual beneficiaries' claimable amount: Shows 999 tokens total
- Demonstrate that 999 ≠ 499.5 (expected), proving individuals received nearly double their fair share while sub-schemes received nothing

This demonstrates a severe distribution unfairness where sub-schemes are completely deprived of their entitled rewards due to cumulative rounding errors.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L91-128)
```csharp
    public override Empty AddSubScheme(AddSubSchemeInput input)
    {
        Assert(input.SchemeId != input.SubSchemeId, "Two schemes cannot be same.");
        Assert(input.SubSchemeShares > 0, "Shares of sub scheme should greater than 0.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");
        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only manager can add sub-scheme.");
        Assert(scheme.SubSchemes.All(s => s.SchemeId != input.SubSchemeId),
            $"Sub scheme {input.SubSchemeId} already exist.");

        var subSchemeId = input.SubSchemeId;
        var subScheme = State.SchemeInfos[subSchemeId];
        Assert(subScheme != null, "Sub scheme not found.");

        var subSchemeVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeId);
        // Add profit details and total shares of the father scheme.
        AddBeneficiary(new AddBeneficiaryInput
        {
            SchemeId = input.SchemeId,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = subSchemeVirtualAddress,
                Shares = input.SubSchemeShares
            },
            EndPeriod = long.MaxValue
        });

        // Add a sub profit scheme.
        scheme.SubSchemes.Add(new SchemeBeneficiaryShare
        {
            SchemeId = input.SubSchemeId,
            Shares = input.SubSchemeShares
        });
        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L417-499)
```csharp
    public override Empty DistributeProfits(DistributeProfitsInput input)
    {
        if (input.AmountsMap.Any())
            Assert(input.AmountsMap.All(a => !string.IsNullOrEmpty(a.Key)), "Invalid token symbol.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can distribute profits.");

        ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

        var profitsMap = new Dictionary<string, long>();
        if (input.AmountsMap.Any())
        {
            foreach (var amount in input.AmountsMap)
            {
                var actualAmount = amount.Value == 0
                    ? State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = amount.Key
                    }).Balance
                    : amount.Value;
                profitsMap.Add(amount.Key, actualAmount);
            }
        }
        else
        {
            if (scheme.IsReleaseAllBalanceEveryTimeByDefault && scheme.ReceivedTokenSymbols.Any())
                // Prepare to distribute all from general ledger.
                foreach (var symbol in scheme.ReceivedTokenSymbols)
                {
                    var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = symbol
                    }).Balance;
                    profitsMap.Add(symbol, balance);
                }
        }

        var totalShares = scheme.TotalShares;

        if (scheme.DelayDistributePeriodCount > 0)
        {
            scheme.CachedDelayTotalShares.Add(input.Period.Add(scheme.DelayDistributePeriodCount), totalShares);
            if (scheme.CachedDelayTotalShares.ContainsKey(input.Period))
            {
                totalShares = scheme.CachedDelayTotalShares[input.Period];
                scheme.CachedDelayTotalShares.Remove(input.Period);
            }
            else
            {
                totalShares = 0;
            }
        }

        var releasingPeriod = scheme.CurrentPeriod;
        Assert(input.Period == releasingPeriod,
            $"Invalid period. When release scheme {input.SchemeId.ToHex()} of period {input.Period}. Current period is {releasingPeriod}");

        var profitsReceivingVirtualAddress =
            GetDistributedPeriodProfitsVirtualAddress(scheme.SchemeId, releasingPeriod);

        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);

        Context.LogDebug(() => $"Receiving virtual address: {profitsReceivingVirtualAddress}");

        UpdateDistributedProfits(profitsMap, profitsReceivingVirtualAddress, totalShares);

        PerformDistributeProfits(profitsMap, scheme, totalShares, profitsReceivingVirtualAddress);

        scheme.CurrentPeriod = input.Period.Add(1);

        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L585-604)
```csharp
    private void PerformDistributeProfits(Dictionary<string, long> profitsMap, Scheme scheme, long totalShares,
        Address profitsReceivingVirtualAddress)
    {
        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var remainAmount = DistributeProfitsForSubSchemes(symbol, amount, scheme, totalShares);
            Context.LogDebug(() => $"Distributing {remainAmount} {symbol} tokens.");
            // Transfer remain amount to individuals' receiving profits address.
            if (remainAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = profitsReceivingVirtualAddress,
                        Amount = remainAmount,
                        Symbol = symbol
                    }.ToByteString());
        }
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L606-649)
```csharp
    private long DistributeProfitsForSubSchemes(string symbol, long totalAmount, Scheme scheme, long totalShares)
    {
        Context.LogDebug(() => $"Sub schemes count: {scheme.SubSchemes.Count}");
        var remainAmount = totalAmount;
        foreach (var subSchemeShares in scheme.SubSchemes)
        {
            Context.LogDebug(() => $"Releasing {subSchemeShares.SchemeId}");

            // General ledger of this sub profit scheme.
            var subItemVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeShares.SchemeId);

            if (State.TokenContract.Value == null)
                State.TokenContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

            var distributeAmount = SafeCalculateProfits(subSchemeShares.Shares, totalAmount, totalShares);
            if (distributeAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = subItemVirtualAddress,
                        Amount = distributeAmount,
                        Symbol = symbol
                    }.ToByteString());

            remainAmount = remainAmount.Sub(distributeAmount);

            // Update current_period of detail of sub profit scheme.
            var subItemDetail = State.ProfitDetailsMap[scheme.SchemeId][subItemVirtualAddress];
            foreach (var detail in subItemDetail.Details) detail.LastProfitPeriod = scheme.CurrentPeriod;

            State.ProfitDetailsMap[scheme.SchemeId][subItemVirtualAddress] = subItemDetail;

            // Update sub scheme.
            var subScheme = State.SchemeInfos[subSchemeShares.SchemeId];
            if (!subScheme.ReceivedTokenSymbols.Contains(symbol))
            {
                subScheme.ReceivedTokenSymbols.Add(symbol);
                State.SchemeInfos[subSchemeShares.SchemeId] = subScheme;
            }
        }

        return remainAmount;
    }
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L884-890)
```csharp
            State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                SubSchemeId = State.BasicRewardHash.Value,
                SubSchemeShares = 1
            });
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L919-935)
```csharp
            State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
            {
                SchemeId = State.ReElectionRewardHash.Value,
                SubSchemeId = State.WelfareHash.Value,
                SubSchemeShares = 1
            });
        }
        else
        {
            Context.LogDebug(() => "Flexible reward will go to Basic Reward.");
            State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
            {
                SchemeId = State.ReElectionRewardHash.Value,
                SubSchemeId = State.BasicRewardHash.Value,
                SubSchemeShares = 1
            });
        }
```
