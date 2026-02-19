### Title
New Miners Lose Welcome Rewards Due to Premature Beneficiary Removal

### Summary
New miners receive welcome reward beneficiary entries with `EndPeriod = termNumber + 1`, intending to provide rewards for two consecutive terms. However, the `UpdateWelcomeRewardWeights` function prematurely removes these beneficiaries at the start of term N+1's distribution, shortening their `EndPeriod` to N before period N+1 profits are distributed. This causes new miners to lose 50% of their intended welcome rewards.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:**

When a new miner is detected at the end of term N, they are added as a welcome reward beneficiary with `EndPeriod = termNumber + 1` (N+1). [2](#0-1) 

The beneficiary's `StartPeriod` is set to the scheme's `CurrentPeriod` (which is N at this point) by the Profit contract. [3](#0-2) 

This should allow the miner to claim rewards for both period N and period N+1 based on the claiming logic. [4](#0-3) 

However, at the end of term N+1, `UpdateWelcomeRewardWeights` is called again and removes ALL previous miners as beneficiaries. [5](#0-4) 

The Welcome Reward scheme has `CanRemoveBeneficiaryDirectly = true` (it's scheme index 6 in the initialization). [6](#0-5) 

This allows the `RemoveProfitDetails` function to forcibly shorten any beneficiary's `EndPeriod` where `EndPeriod >= scheme.CurrentPeriod`. [7](#0-6) 

Since at the end of term N+1, the scheme's `CurrentPeriod` is N+1 (updated from the previous term's distribution), and the miner's `EndPeriod` is also N+1, the condition triggers and `EndPeriod` is shortened to N.

**Why Protections Fail:**

The `UpdateWelcomeRewardWeights` function is called in `UpdateStateBeforeDistribution`, which executes BEFORE `ReleaseTreasurySubProfitItems`. [8](#0-7) 

This timing means the beneficiary removal happens before period N+1's profits are actually distributed, yet after the scheme's `CurrentPeriod` was already incremented to N+1 (from the previous term's distribution).

The removal logic in `RemoveProfitDetails` doesn't distinguish between:
- Beneficiaries who should still receive rewards for the current period being distributed
- Beneficiaries whose reward period has truly expired

### Impact Explanation

**Direct Fund Impact - Reward Misallocation:**

New miners lose welcome rewards for one full term (period N+1), representing 50% of their intended welcome rewards since they were supposed to receive rewards for two periods (N and N+1).

The welcome reward pool share is defined by the `MinerRewardWeightSetting.WelcomeRewardWeight` (default weight of 1 out of total miner reward weight of 4). [9](#0-8) 

When new miners are removed prematurely, these welcome rewards don't disappear - they are instead redistributed to the Basic Reward scheme. [10](#0-9) 

**Who Is Affected:**

Every new miner (those entering the consensus for the first time) loses half of their welcome rewards. This affects network decentralization incentives as new validators receive less than the intended economic benefit for joining.

**Severity Justification:**

Medium severity because:
- Direct, deterministic loss of intended rewards
- Affects all new miners automatically
- Undermines the economic design of welcome rewards
- However, it's a partial loss (50%), not total loss, and doesn't affect the security of existing miners or consensus operation

### Likelihood Explanation

**Exploitation Practicality:**

This is an automatic vulnerability that triggers without any attacker action:
1. When any new miner joins the network
2. They are correctly identified and added as welcome reward beneficiaries
3. At the next term's distribution, they are automatically removed prematurely
4. No special conditions or attacker capabilities required

**Probability:** 

100% probability - this occurs for EVERY new miner that remains active for more than one term. The vulnerability is in the core logic flow, not in edge cases.

**Detection:**

The issue is masked because:
- The profits still get distributed (to Basic Reward instead)
- New miners can still claim for period N successfully
- Only when trying to claim for period N+1 would they notice the missing EndPeriod

### Recommendation

**Code-Level Mitigation:**

Modify `UpdateWelcomeRewardWeights` to NOT remove beneficiaries whose `EndPeriod` is equal to the current period being distributed. The removal should only target beneficiaries whose `EndPeriod` is strictly less than the current period.

Option 1: Filter the removal list:
```csharp
var previousMinerAddresses = 
    GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);

// Only remove beneficiaries whose EndPeriod < CurrentPeriod
var beneficiariesToRemove = previousMinerAddresses
    .Where(addr => ShouldRemoveBeneficiary(addr, State.VotesWeightRewardHash.Value))
    .ToList();

if (beneficiariesToRemove.Any())
{
    State.ProfitContract.RemoveBeneficiaries.Send(new RemoveBeneficiariesInput
    {
        SchemeId = State.VotesWeightRewardHash.Value,
        Beneficiaries = { beneficiariesToRemove }
    });
}
```

Option 2: Adjust EndPeriod to `termNumber + 2` to account for the removal timing, ensuring beneficiaries can claim for both terms: [2](#0-1) 
Change to: `EndPeriod = previousTermInformation.TermNumber.Add(2)`

**Invariant Check:**

Add assertion: Before removing a welcome reward beneficiary, verify that `beneficiary.EndPeriod < scheme.CurrentPeriod` OR that the current distribution has completed for the period matching the beneficiary's EndPeriod.

**Test Cases:**

1. Test that a new miner joining in term N can claim welcome rewards for both period N and period N+1
2. Test that EndPeriod is not shortened when CurrentPeriod equals EndPeriod
3. Test the total amount of welcome rewards distributed matches expected calculations

### Proof of Concept

**Initial State:**
- Network is at end of term N
- Miner A is elected for the first time (never mined before)
- `State.LatestMinedTerm[A] = 0`
- Welcome Reward scheme's `CurrentPeriod = N`

**Transaction Sequence:**

**Step 1 - End of Term N:**
- Consensus contract calls `Treasury.Release(N)`
- `UpdateWelcomeRewardWeights` executes:
  - Miner A is in `newElectedMiners` list
  - `AddBeneficiaries` called with `EndPeriod = N + 1`
  - Profit contract creates `ProfitDetail{StartPeriod: N, EndPeriod: N+1, Shares: 1}`
- `ReleaseTreasurySubProfitItems(N)` distributes profits
- Scheme's `CurrentPeriod` becomes N+1
- `State.LatestMinedTerm[A] = N`

**Step 2 - End of Term N+1:**
- Consensus contract calls `Treasury.Release(N+1)`
- `UpdateWelcomeRewardWeights` executes:
  - Miner A NOT in `newElectedMiners` (LatestMinedTerm ≠ 0)
  - `RemoveBeneficiaries` called for all term N miners including A
  - `RemoveProfitDetails` executes with `scheme.CurrentPeriod = N+1`
  - Miner A's detail: `EndPeriod (N+1) >= CurrentPeriod (N+1)` → TRUE
  - **EndPeriod shortened from N+1 to N** [7](#0-6) 
- `ReleaseTreasurySubProfitItems(N+1)` distributes profits (but A already removed)

**Step 3 - Claiming:**
- Miner A calls `Profit.ClaimProfits` for Welcome Reward scheme
- Claim logic: `targetPeriod = Min(CurrentPeriod - 1, EndPeriod) = Min(N+1, N) = N`
- Miner A can only claim for period N

**Expected vs Actual:**
- **Expected:** Miner A claims rewards for both period N and period N+1 (EndPeriod was N+1)
- **Actual:** Miner A can only claim for period N (EndPeriod was shortened to N)
- **Loss:** 50% of intended welcome rewards (1 out of 2 periods)

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L64-67)
```csharp
                DelayDistributePeriodCount = i == 3 ? 1 : 0,
                // Subsidy, Flexible Reward and Welcome Reward can remove beneficiary directly (due to replaceable.)
                CanRemoveBeneficiaryDirectly = new List<int> { 2, 5, 6 }.Contains(i)
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L162-163)
```csharp
        UpdateStateBeforeDistribution(previousTermInformation, maybeNewElectedMiners);
        ReleaseTreasurySubProfitItems(input.PeriodNumber);
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L480-487)
```csharp
    private MinerRewardWeightSetting GetDefaultMinerRewardWeightSetting()
    {
        return new MinerRewardWeightSetting
        {
            BasicMinerRewardWeight = 2,
            WelcomeRewardWeight = 1,
            FlexibleRewardWeight = 1
        };
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L848-891)
```csharp
    private void UpdateWelcomeRewardWeights(Round previousTermInformation, List<string> newElectedMiners)
    {
        var previousMinerAddresses =
            GetAddressesFromCandidatePubkeys(previousTermInformation.RealTimeMinersInformation.Keys);
        var possibleWelcomeBeneficiaries = new RemoveBeneficiariesInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            Beneficiaries = { previousMinerAddresses }
        };
        State.ProfitContract.RemoveBeneficiaries.Send(possibleWelcomeBeneficiaries);
        State.ProfitContract.RemoveSubScheme.Send(new RemoveSubSchemeInput
        {
            SchemeId = State.VotesWeightRewardHash.Value,
            SubSchemeId = State.BasicRewardHash.Value
        });

        if (newElectedMiners.Any())
        {
            Context.LogDebug(() => "Welcome reward will go to new miners.");
            var newBeneficiaries = new AddBeneficiariesInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                EndPeriod = previousTermInformation.TermNumber.Add(1)
            };
            foreach (var minerAddress in newElectedMiners.Select(GetProfitsReceiver))
                newBeneficiaries.BeneficiaryShares.Add(new BeneficiaryShare
                {
                    Beneficiary = minerAddress,
                    Shares = 1
                });

            if (newBeneficiaries.BeneficiaryShares.Any()) State.ProfitContract.AddBeneficiaries.Send(newBeneficiaries);
        }
        else
        {
            Context.LogDebug(() => "Welcome reward will go to Basic Reward.");
            State.ProfitContract.AddSubScheme.Send(new AddSubSchemeInput
            {
                SchemeId = State.VotesWeightRewardHash.Value,
                SubSchemeId = State.BasicRewardHash.Value,
                SubSchemeShares = 1
            });
        }
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-191)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L856-860)
```csharp
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```
