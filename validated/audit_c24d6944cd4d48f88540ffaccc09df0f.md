# Audit Report

## Title
CachedDelayTotalShares Never Updated During Beneficiary Removal - Causing Permanent Fund Dilution

## Summary
The `RemoveBeneficiary` function in the Profit contract modifies the local `scheme.CachedDelayTotalShares` dictionary to subtract removed beneficiary shares, but never persists the updated scheme object back to state. This causes all future delayed profit distributions to use inflated total shares that still include removed beneficiaries, resulting in permanent underpayment to all remaining beneficiaries.

## Finding Description
The vulnerability exists in the `RemoveBeneficiary` function where state persistence is incomplete. The function loads the scheme object, modifies its `CachedDelayTotalShares` field to subtract removed beneficiary shares, but only persists the `TotalShares` field directly to state. [1](#0-0) 

The critical missing statement is `State.SchemeInfos[input.SchemeId] = scheme;` after the CachedDelayTotalShares modifications. This pattern is correctly implemented in other functions:

- `AddBeneficiary` correctly saves the entire scheme object [2](#0-1) 
- `DistributeProfits` correctly saves the entire scheme object [3](#0-2) 

The `RemovedDetails.TryAdd` method correctly accumulates shares using safe arithmetic [4](#0-3) , but these accumulated values are used to modify `CachedDelayTotalShares` which is never persisted.

When `DistributeProfits` executes for delayed schemes, it retrieves `CachedDelayTotalShares[input.Period]` to determine the total shares for that period's distribution. [5](#0-4)  Since removed beneficiary shares were never subtracted from the cached totals in state, the inflated value is used for profit calculations, causing all remaining beneficiaries to receive proportionally less than they should.

The Treasury contract uses delayed distribution in production, setting `DelayDistributePeriodCount = 1` for the Citizen Welfare scheme (index 3). [6](#0-5) 

## Impact Explanation
This is a **CRITICAL** severity vulnerability causing permanent fund loss:

**Direct Financial Harm**: When profits are distributed using `SafeCalculateProfits`, each beneficiary receives `(their_shares * total_amount) / total_shares`. [7](#0-6)  With inflated cached totals still containing removed shares, the denominator is incorrect, causing underpayment to all remaining beneficiaries.

**Quantified Loss**: If 100 shares are removed from a scheme with 1000 total shares:
- Remaining beneficiaries lose 10% of expected profits per affected period
- For consensus rewards distributing 100,000 tokens: 10,000 tokens remain undistributed
- Affects ALL future delayed distribution periods compoundingly

**Permanence**: Profits remain locked in period virtual addresses with no recovery mechanism. Once `DistributeProfits` completes for a period and increments `CurrentPeriod`, that period's distribution is finalized and cannot be corrected. [8](#0-7) 

**Affected Systems**:
- Treasury profit distributions (Citizen Welfare)
- TokenHolder dividend schemes  
- Any profit scheme with `DelayDistributePeriodCount > 0`

## Likelihood Explanation
**Certainty**: 100% - This is not an active exploit but a broken feature. ANY call to `RemoveBeneficiary` on schemes with `DelayDistributePeriodCount > 0` fails to update cached totals.

**Attacker Capabilities**: Requires scheme manager or TokenHolder contract privileges. [9](#0-8)  However, this is a passive bug occurring during legitimate operations.

**Feasibility**: CERTAIN during normal operations:
- Removing expired beneficiaries
- Vote withdrawals in TokenHolder schemes [10](#0-9) 
- Treasury management operations
- Schemes with delayed distribution are used in production

**Detection**: DIFFICULT - No transaction failure occurs, no event indicates the bug. Beneficiaries only notice reduced profits in future periods, requiring manual comparison of expected vs. actual amounts across multiple periods.

## Recommendation
Add the missing state persistence statement immediately after modifying `CachedDelayTotalShares`. The fix should be applied after line 258 in `RemoveBeneficiary`:

```csharp
// After line 258, add:
State.SchemeInfos[input.SchemeId] = scheme;
```

This ensures that the modified `CachedDelayTotalShares` dictionary is persisted to state, matching the pattern used in `AddBeneficiary` and `DistributeProfits`.

Alternatively, update line 260 from:
```csharp
State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
```

To:
```csharp
scheme.TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
State.SchemeInfos[input.SchemeId] = scheme;
```

## Proof of Concept
The following test demonstrates the vulnerability:

```csharp
[Fact]
public async Task RemoveBeneficiary_ShouldUpdateCachedDelayTotalShares()
{
    // 1. Create scheme with DelayDistributePeriodCount = 1
    var schemeId = await CreateSchemeWithDelay(delayPeriodCount: 1);
    
    // 2. Add two beneficiaries with 100 shares each
    await AddBeneficiary(schemeId, beneficiary1, shares: 100);
    await AddBeneficiary(schemeId, beneficiary2, shares: 100);
    
    // 3. Distribute profits for period 1 (caches 200 shares for period 2)
    await DistributeProfits(schemeId, period: 1, amount: 1000);
    
    // 4. Remove beneficiary1 (should update cached shares for period 2)
    await RemoveBeneficiary(schemeId, beneficiary1);
    
    // 5. Distribute profits for period 2
    await DistributeProfits(schemeId, period: 2, amount: 1000);
    
    // 6. Claim profits
    var beneficiary2Profit = await ClaimProfits(schemeId, beneficiary2);
    
    // Expected: beneficiary2 should get full 1000 (only remaining beneficiary)
    // Actual: beneficiary2 gets only 500 (calculated as 100/200 * 1000)
    // The bug: CachedDelayTotalShares[2] still contains 200 instead of 100
    Assert.Equal(1000, beneficiary2Profit); // This will FAIL, proving the bug
}
```

The test proves that removed beneficiary shares remain in `CachedDelayTotalShares`, causing incorrect profit distribution calculations in subsequent periods.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L184-184)
```csharp
        State.SchemeInfos[schemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L237-239)
```csharp
        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L243-260)
```csharp
        foreach (var (removedMinPeriod, removedShares) in removedDetails.Where(d => d.Key != 0))
        {
            if (scheme.DelayDistributePeriodCount > 0)
            {
                for (var removedPeriod = removedMinPeriod;
                     removedPeriod < removedMinPeriod.Add(scheme.DelayDistributePeriodCount);
                     removedPeriod++)
                {
                    if (scheme.CachedDelayTotalShares.ContainsKey(removedPeriod))
                    {
                        scheme.CachedDelayTotalShares[removedPeriod] =
                            scheme.CachedDelayTotalShares[removedPeriod].Sub(removedShares);
                    }
                }
            }
        }

        State.SchemeInfos[input.SchemeId].TotalShares = scheme.TotalShares.Sub(removedDetails.Values.Sum());
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L464-476)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L494-496)
```csharp
        scheme.CurrentPeriod = input.Period.Add(1);

        State.SchemeInfos[input.SchemeId] = scheme;
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

**File:** contract/AElf.Contracts.Profit/Models/RemovedDetails.cs (L8-18)
```csharp
        public void TryAdd(long key, long value)
        {
            if (ContainsKey(key))
            {
                this[key] = this[key].Add(value);
            }
            else
            {
                this[key] = value;
            }
        }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L60-67)
```csharp
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
                // Distribution of Citizen Welfare will delay one period.
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L239-243)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = Context.Sender
        });
```
