# Audit Report

## Title
FixProfitDetail Allows Retroactive Profit Claims Through Unconstrained StartPeriod Modification

## Summary
The `FixProfitDetail` method in the Profit contract permits scheme managers to arbitrarily modify a beneficiary's `StartPeriod` to any historical value without validation. This enables beneficiaries to retroactively claim profits from periods before they were added to the scheme, violating the fundamental profit distribution invariant and diluting legitimate beneficiaries' shares.

## Finding Description

The vulnerability exists in the `FixProfitDetail` method which lacks validation on the `StartPeriod` value being set. [1](#0-0) 

When a beneficiary is legitimately added via `AddBeneficiary`, their `StartPeriod` is correctly initialized to `scheme.CurrentPeriod + DelayDistributePeriodCount`, ensuring they only receive profits from when they joined onwards. [2](#0-1) 

However, `FixProfitDetail` allows the manager to replace this value with any period through a simple conditional assignment, with only authorization checks but no validation that the new `StartPeriod` is greater than or equal to the original value, or that it falls within valid scheme distribution periods. [3](#0-2) 

When `ClaimProfits` is called for the first time (when `LastProfitPeriod == 0`), it initializes `LastProfitPeriod` to the manipulated `StartPeriod`. [4](#0-3) 

The `ProfitAllPeriods` method then iterates from this manipulated starting period, calculating and transferring tokens from historical period virtual addresses. [5](#0-4) 

**Evidence of Design Intent:**

Test expectations explicitly verify that `StartPeriod` should remain unchanged after legitimate `FixProfitDetail` usage. [6](#0-5) 

The only production usage in the Election contract never modifies `StartPeriod` - it explicitly relies on the default value (0) to preserve the original, with a comment confirming this intent. [7](#0-6) 

The Treasury contract demonstrates that important schemes like CitizenWelfare are managed by the Election contract, which receives manager authority through the initialization process. [8](#0-7) 

## Impact Explanation

**Direct Fund Theft**: A malicious or compromised scheme manager can:
1. Add a beneficiary at period N with legitimate `StartPeriod = N`
2. Before the beneficiary claims, call `FixProfitDetail` to set `StartPeriod = 1`
3. The beneficiary claims and receives profits from periods 1 through N-1

**Share Dilution**: When a beneficiary claims retroactive profits using shares that didn't exist in those historical periods, they receive a portion calculated against the `TotalShares` from those earlier periods. This directly reduces the remaining tokens available for legitimate beneficiaries who were actually present during those periods. The profit calculation uses the beneficiary's shares against historical `TotalShares` values. [9](#0-8) 

**Governance Bypass**: For DAO-controlled schemes like Treasury CitizenWelfare managed by Parliament through the Election contract, the manager can unilaterally redistribute historical profits without governance approval, bypassing intended control mechanisms. While Treasury parameter changes require Parliament authorization, [10](#0-9)  the `FixProfitDetail` method only requires manager authorization. [11](#0-10) 

**Value at Risk**: All historical accumulated profits in any scheme are vulnerable. For major schemes like Treasury citizen welfare distributions, this represents significant token amounts accumulated over many periods.

## Likelihood Explanation

**Attack Complexity**: Extremely simple - requires only a single `FixProfitDetail` transaction with a modified `StartPeriod` parameter.

**Attacker Capabilities**: Requires scheme manager access. However, the critical issue is that even legitimate managers have MORE power than the design intends:
- For DAO-managed schemes, this bypasses governance controls
- For any scheme, this violates the expected invariant that beneficiaries only receive profits from their participation period
- Compromised manager keys enable direct exploitation

**Feasibility Conditions**: 
- Scheme must have distributed profits in historical periods
- Beneficiary must not have claimed yet (common for newly added beneficiaries)
- Manager retains access
- No additional preconditions required

**Detection Difficulty**: The modification is a permanent state change. After claiming, profits are transferred and cannot be recovered. On-chain events show the claim but may not reveal the period manipulation.

## Recommendation

Add validation in the `FixProfitDetail` method to ensure that:

1. If `input.StartPeriod` is non-zero, it must be greater than or equal to the original `fixingDetail.StartPeriod`
2. The new `StartPeriod` must be less than or equal to the current scheme period
3. The new `StartPeriod` must be less than or equal to `EndPeriod`

```csharp
// After line 298, add validation:
if (input.StartPeriod != 0)
{
    Assert(input.StartPeriod >= fixingDetail.StartPeriod, 
        "Cannot set StartPeriod earlier than original value.");
    Assert(input.StartPeriod <= scheme.CurrentPeriod, 
        "StartPeriod cannot be later than current period.");
}

if (input.EndPeriod != 0)
{
    var effectiveStartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
    Assert(input.EndPeriod >= effectiveStartPeriod, 
        "EndPeriod must be greater than or equal to StartPeriod.");
}
```

## Proof of Concept

A test demonstrating the vulnerability would:

1. Create a profit scheme with multiple distributed periods (e.g., periods 1-5)
2. Add a beneficiary at period 5 with legitimate `StartPeriod = 5`
3. Call `FixProfitDetail` with `StartPeriod = 1` (no validation prevents this)
4. Call `ClaimProfits` for the beneficiary
5. Verify the beneficiary receives profits from periods 1-4 (which they should not receive)
6. Verify this dilutes the shares of legitimate beneficiaries who were present in periods 1-4

The test would prove that the lack of validation in `FixProfitDetail` allows retroactive profit claims, violating the fundamental invariant that beneficiaries only receive profits from periods they participated in.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-192)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L265-306)
```csharp
    public override Empty FixProfitDetail(FixProfitDetailInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        var scheme = State.SchemeInfos[input.SchemeId];
        if (Context.Sender != scheme.Manager && Context.Sender !=
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName))
        {
            throw new AssertionException("Only manager or token holder contract can add beneficiary.");
        }

        // Try to get profitDetails by Id
        var profitDetails = State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary];
        ProfitDetail fixingDetail = null;
        if (input.ProfitDetailId != null)
        {
            // In new rules, rofitDetail.Id equals to its vote id.
            fixingDetail = profitDetails.Details.SingleOrDefault(d => d.Id == input.ProfitDetailId);
        }

        if (fixingDetail == null)
        {
            // However, in the old time, profitDetail.Id is null, so use Shares.
            fixingDetail = profitDetails.Details.OrderBy(d => d.StartPeriod)
                .FirstOrDefault(d => d.Shares == input.BeneficiaryShare.Shares);
        }

        if (fixingDetail == null)
        {
            throw new AssertionException("Cannot find proper profit detail to fix.");
        }

        // Clone the old one to a new one, remove the old, and add the new.
        var newDetail = fixingDetail.Clone();
        // The startPeriod is 0, so use the original one.
        newDetail.StartPeriod = input.StartPeriod == 0 ? fixingDetail.StartPeriod : input.StartPeriod;
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
        profitDetails.Details.Remove(fixingDetail);
        profitDetails.Details.Add(newDetail);
        State.ProfitDetailsMap[input.SchemeId][input.BeneficiaryShare.Beneficiary] = profitDetails;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L780-782)
```csharp
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-875)
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

                var amount = SafeCalculateProfits(profitDetail.Shares,
                    distributedProfitsInformation.AmountsMap[symbol], distributedProfitsInformation.TotalShares);

```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L830-830)
```csharp
        profitDetail.StartPeriod.ShouldBe(originProfitDetail.Details.First().StartPeriod);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L143-154)
```csharp
            // The endPeriod is updated and startPeriod is 0, others stay still.
            State.ProfitContract.FixProfitDetail.Send(new FixProfitDetailInput
            {
                SchemeId = State.WelfareHash.Value,
                BeneficiaryShare = new BeneficiaryShare
                {
                    Beneficiary = electionVotingRecord.Voter,
                    Shares = electionVotingRecord.Weight
                },
                EndPeriod = endPeriod,
                ProfitDetailId = voteId
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L102-111)
```csharp
            State.ProfitContract.ResetManager.Send(new ResetManagerInput
            {
                SchemeId = managingSchemeIds[2],
                NewManager = electionContractAddress
            });
            State.ProfitContract.ResetManager.Send(new ResetManagerInput
            {
                SchemeId = managingSchemeIds[3],
                NewManager = electionContractAddress
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L312-322)
```csharp
    public override Empty SetDividendPoolWeightSetting(DividendPoolWeightSetting input)
    {
        AssertPerformedByTreasuryController();
        Assert(
            input.CitizenWelfareWeight > 0 && input.BackupSubsidyWeight > 0 &&
            input.MinerRewardWeight > 0,
            "invalid input");
        ResetSubSchemeToTreasury(input);
        State.DividendPoolWeightSetting.Value = input;
        return new Empty();
    }
```
