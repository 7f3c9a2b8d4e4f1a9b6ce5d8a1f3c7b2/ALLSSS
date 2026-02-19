### Title
FixProfitDetail Allows Retroactive Profit Claims Through Unconstrained StartPeriod Modification

### Summary
The `FixProfitDetail` method allows the scheme manager to arbitrarily modify a beneficiary's `StartPeriod` to any value, including periods before the beneficiary was added to the scheme. This enables retroactive claims of historical profits that were distributed before the beneficiary's participation, violating the fundamental profit distribution invariant and enabling fund theft from legitimate beneficiaries.

### Finding Description

The vulnerability exists in the `FixProfitDetail` method which lacks validation on the `StartPeriod` value being set. [1](#0-0) 

When a beneficiary is added via `AddBeneficiary`, their `StartPeriod` is correctly set to `scheme.CurrentPeriod + DelayDistributePeriodCount`, ensuring they only receive profits from when they joined onwards: [2](#0-1) 

However, `FixProfitDetail` allows the manager to replace this value with any period (lines 299-301), with only authorization checks but no validation that:
- The new `StartPeriod` >= original `StartPeriod`
- The new `StartPeriod` >= the period when the beneficiary was actually added
- The new `StartPeriod` is not earlier than when the scheme started distributing

When `ClaimProfits` is called for the first time (`LastProfitPeriod == 0`), it sets `LastProfitPeriod = StartPeriod`: [3](#0-2) 

The `ProfitAllPeriods` method then iterates from this manipulated `StartPeriod`, allowing the beneficiary to claim profits from periods before they existed as a beneficiary: [4](#0-3) 

Test expectations confirm that `StartPeriod` should NOT be modified when `FixProfitDetail` is legitimately used: [5](#0-4) 

The only production usage in the Election contract never modifies `StartPeriod` (sets it to 0, meaning keep original): [6](#0-5) 

### Impact Explanation

**Direct Fund Theft**: A malicious or compromised scheme manager can:
1. Add a beneficiary at period N with legitimate `StartPeriod = N`
2. Call `FixProfitDetail` to set `StartPeriod = 1` (or any earlier period)
3. The beneficiary claims profits from periods 1 through N-1, stealing historical distributions

**Dilution of Legitimate Shares**: When a beneficiary claims retroactive profits, they receive shares of distributions that occurred when they weren't participating. This directly reduces what legitimate beneficiaries who were actually present during those periods receive, violating the share-based distribution model.

**Governance Bypass**: For DAO-controlled schemes (Treasury, Election welfare schemes managed by Parliament), the manager can unilaterally redistribute historical profits without governance approval, bypassing the intended control mechanisms.

**Value at Risk**: All historical accumulated profits in a scheme are vulnerable. For major schemes like Treasury citizen welfare distributions, this could represent significant token amounts distributed over many periods.

### Likelihood Explanation

**Attack Complexity**: Extremely simple - requires only a single `FixProfitDetail` transaction with modified `StartPeriod` parameter.

**Attacker Capabilities**: Requires scheme manager access. While this is a privileged role, the issue is that even legitimate managers have MORE power than intended:
- For DAO-managed schemes, this bypasses governance controls
- For any scheme, this violates the expected invariant that beneficiaries only receive profits from their participation period
- Compromised manager keys or malicious managers can exploit this

**Feasibility Conditions**: 
- Scheme must have distributed profits in historical periods
- Manager must have maintained access
- No additional preconditions or complex state requirements

**Detection Constraints**: The modification is permanent state change. Post-claim, profits are transferred to the beneficiary and cannot be recovered. On-chain events would show the claim but not necessarily reveal the period manipulation.

**Probability**: High for schemes with:
- Significant historical accumulated profits
- DAO/multi-sig managers that could be compromised
- Long operational history with many distribution periods

### Recommendation

Add validation in `FixProfitDetail` to ensure `StartPeriod` can only be increased or kept the same, never decreased:

```csharp
// After line 297, before line 299:
if (input.StartPeriod != 0 && input.StartPeriod < fixingDetail.StartPeriod)
{
    throw new AssertionException(
        $"Cannot decrease StartPeriod. Current: {fixingDetail.StartPeriod}, Requested: {input.StartPeriod}");
}
```

Additional invariant checks:
1. Validate `newStartPeriod <= newEndPeriod`
2. Validate `newStartPeriod >= 1` (must be valid period)
3. Consider adding an optional maximum allowed extension for `EndPeriod` to prevent indefinite future claims

Test cases to add:
1. Test that `FixProfitDetail` with `StartPeriod < original.StartPeriod` fails
2. Test that claims after period modification only cover valid participation periods
3. Test that legitimate `EndPeriod` extension (Election use case) continues to work

### Proof of Concept

**Initial State:**
1. Scheme created at period 1 with `CurrentPeriod = 1`
2. `DistributeProfits` called for periods 1-9, distributing 1000 ELF each period
3. At period 10, beneficiary Alice added with `StartPeriod = 10`, `Shares = 100`
4. Other beneficiaries have `Shares = 900` total, were present since period 1
5. `DistributeProfits` called for period 10, `CurrentPeriod = 11`

**Exploitation Steps:**
1. Manager calls `FixProfitDetail`:
   - `SchemeId`: target scheme
   - `BeneficiaryShare.Beneficiary`: Alice
   - `BeneficiaryShare.Shares`: 100
   - `StartPeriod`: 1 (manipulated from original 10)
   - `EndPeriod`: 0 (keep original)

2. Alice calls `ClaimProfits`:
   - Since `LastProfitPeriod == 0`, it sets `LastProfitPeriod = StartPeriod = 1`
   - `ProfitAllPeriods` iterates from period 1 to 10
   - For each period, Alice receives `100/(100+900) * 1000 = 100 ELF`
   - Total claim: 1000 ELF from periods 1-10

**Expected vs Actual:**
- **Expected**: Alice should only receive profits from period 10 onwards (100 ELF)
- **Actual**: Alice receives profits from periods 1-10 (1000 ELF)
- **Damage**: Alice steals 900 ELF from historical distributions, diluting legitimate beneficiaries who were actually present during periods 1-9

**Success Condition**: Alice's balance increases by 1000 ELF instead of the legitimate 100 ELF, with 900 ELF stolen from historical period allocations.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L845-920)
```csharp
    private Dictionary<string, long> ProfitAllPeriods(Scheme scheme, ProfitDetail profitDetail, Address beneficiary, long maxProfitReceivingPeriodCount,
        bool isView = false, string targetSymbol = null)
    {
        var profitsMap = new Dictionary<string, long>();
        var lastProfitPeriod = profitDetail.LastProfitPeriod;

        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
        {
            var totalAmount = 0L;
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
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

                if (!isView)
                {
                    Context.LogDebug(() =>
                        $"{beneficiary} is profiting {amount} {symbol} tokens from {scheme.SchemeId.ToHex()} in period {periodToPrint}." +
                        $"Sender's Shares: {detailToPrint.Shares}, total Shares: {distributedProfitsInformation.TotalShares}");
                    if (distributedProfitsInformation.IsReleased && amount > 0)
                    {
                        if (State.TokenContract.Value == null)
                            State.TokenContract.Value =
                                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

                        Context.SendVirtualInline(
                            GeneratePeriodVirtualAddressFromHash(scheme.SchemeId, period),
                            State.TokenContract.Value,
                            nameof(State.TokenContract.Transfer), new TransferInput
                            {
                                To = beneficiary,
                                Symbol = symbol,
                                Amount = amount
                            }.ToByteString());

                        Context.Fire(new ProfitsClaimed
                        {
                            Beneficiary = beneficiary,
                            Symbol = symbol,
                            Amount = amount,
                            ClaimerShares = detailToPrint.Shares,
                            TotalShares = distributedProfitsInformation.TotalShares,
                            Period = periodToPrint
                        });
                    }

                    lastProfitPeriod = period + 1;
                }

                totalAmount = totalAmount.Add(amount);
            }

            profitsMap.Add(symbol, totalAmount);
        }

        profitDetail.LastProfitPeriod = lastProfitPeriod;

        return profitsMap;
    }
```

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L830-830)
```csharp
        profitDetail.StartPeriod.ShouldBe(originProfitDetail.Details.First().StartPeriod);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L144-154)
```csharp
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
