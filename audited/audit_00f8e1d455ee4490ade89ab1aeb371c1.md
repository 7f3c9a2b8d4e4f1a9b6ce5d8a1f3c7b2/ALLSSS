### Title
Negative TotalShares via Double-Subtraction in RemoveSubScheme Causes Permanent DoS of Profit Distribution

### Summary
The `RemoveSubScheme` function lacks validation to ensure `scheme.TotalShares >= shares.Shares` before subtraction at line 152. If prior operations (RemoveBeneficiary or ClaimProfits) already reduced TotalShares for a sub-scheme without updating the SubSchemes list, calling RemoveSubScheme subtracts the shares again, causing TotalShares to become negative. This triggers a permanent DoS where all future profit distributions are burned instead of distributed. [1](#0-0) 

### Finding Description

**Root Cause**: Lack of synchronization between `scheme.TotalShares` and `scheme.SubSchemes` state, combined with missing validation in RemoveSubScheme.

**Code Locations**:
1. **Vulnerable subtraction** at line 152: `scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares)` with no check that `TotalShares >= shares.Shares` [2](#0-1) 

2. **RemoveBeneficiary** at line 260 subtracts from TotalShares but doesn't update SubSchemes list [3](#0-2) 

3. **ClaimProfits** at line 792 subtracts expired shares from TotalShares but doesn't update SubSchemes list [4](#0-3) 

**The Sub() Method Behavior**: The SafeMath `Sub()` method uses C#'s `checked` keyword, which only throws OverflowException when results exceed `long` type bounds. A subtraction like `100 - 150 = -50` is valid and produces a negative number without exception. [5](#0-4) 

**Why Protection Fails**: The question's premise about "wrapping to a massive value" is incorrect—TotalShares becomes **negative**, not wrapped. However, this is still critical because at line 485 of DistributeProfits, when `totalShares <= 0`, all profits are burned via `BurnProfits` instead of distributed. [6](#0-5) 

**Exploitation Paths**:

**Path 1 - Via RemoveBeneficiary** (Requires `CanRemoveBeneficiaryDirectly = true`):
1. AddSubScheme adds sub-scheme B with 100 shares to scheme A (TotalShares += 100, SubSchemes adds entry) [7](#0-6) 

2. Manager calls RemoveBeneficiary for sub-scheme B's virtual address. Since `CanRemoveBeneficiaryDirectly = true`, RemoveProfitDetails removes the beneficiary details [8](#0-7) 

3. Line 260 subtracts shares from TotalShares (TotalShares -= 100), but SubSchemes still contains the entry {B, 100}

4. Manager calls RemoveSubScheme for B. Line 152 subtracts 100 again. If TotalShares < 100, it becomes negative.

**Path 2 - Via ClaimProfits and FixProfitDetail**:
1. AddSubScheme initially creates profit detail with EndPeriod = long.MaxValue [9](#0-8) 

2. Manager uses FixProfitDetail to change EndPeriod to a finite value [10](#0-9) 

3. After period expires, ClaimProfits is called. Lines 787-792 identify expired details and subtract their shares from TotalShares, but don't update SubSchemes

4. RemoveSubScheme subtracts the shares again, potentially making TotalShares negative

### Impact Explanation

**Direct Harm**: Permanent DoS of the profit distribution mechanism for the affected scheme.

**Mechanism**: When TotalShares becomes negative and DistributeProfits is called, the check at line 485 (`totalShares <= 0`) causes all contributed profits to be burned via the `BurnProfits` function instead of being distributed to beneficiaries. This destroys value for all legitimate beneficiaries. [11](#0-10) 

**Affected Parties**: 
- All beneficiaries of the scheme lose their entitled profit distributions
- The scheme becomes permanently broken until TotalShares is corrected by adding new beneficiaries with sufficient shares
- Treasury and reward distribution systems relying on this scheme are disrupted

**Severity**: HIGH - Complete loss of profit distribution functionality violates the critical invariant of "dividend distribution and settlement accuracy" in the Economics & Treasury category.

### Likelihood Explanation

**Attacker Capabilities**: Requires manager role, but exploitation can occur through legitimate operational mistakes rather than malicious intent.

**Attack Complexity**: LOW for Path 1:
- Manager creates scheme with `CanRemoveBeneficiaryDirectly = true` (line 130 in CreateSchemeInput) [12](#0-11) 
- Manager adds sub-scheme
- Manager calls RemoveBeneficiary on sub-scheme's virtual address (perhaps unaware it's a sub-scheme)
- Manager later calls RemoveSubScheme for cleanup

**Feasibility Conditions**: 
- Path 1 requires scheme configured with `CanRemoveBeneficiaryDirectly = true` (a legitimate configuration option)
- Path 2 requires manager to use FixProfitDetail (a provided function for legitimate profit detail management)
- Both paths arise from normal contract operations, not adversarial behavior

**Detection**: Difficult - TotalShares becoming negative is stored silently in contract state without events or assertions

**Economic Rationality**: N/A - occurs through operational mistakes rather than economic incentives

**Probability**: MEDIUM-HIGH - The lack of awareness that sub-scheme virtual addresses are also tracked in SubSchemes makes accidental triggering likely.

### Recommendation

**Immediate Fix**: Add validation in RemoveSubScheme before subtraction:

```csharp
// At line 152, replace:
scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares);

// With:
Assert(scheme.TotalShares >= shares.Shares, 
    $"Insufficient total shares. Cannot subtract {shares.Shares} from {scheme.TotalShares}");
scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares);
```

**Comprehensive Fix**: Ensure state consistency by making RemoveBeneficiary aware of SubSchemes:

```csharp
// In RemoveBeneficiary, before line 260, add:
// Check if beneficiary is a sub-scheme and prevent direct removal
var isSubScheme = scheme.SubSchemes.Any(s => 
    Context.ConvertVirtualAddressToContractAddress(s.SchemeId) == input.Beneficiary);
Assert(!isSubScheme, 
    "Cannot directly remove sub-scheme beneficiary. Use RemoveSubScheme instead.");
```

**Additional Safeguard**: Add invariant check in DistributeProfits:
```csharp
// At line 462, after getting totalShares:
Assert(totalShares >= 0, 
    $"Invalid state: TotalShares is negative ({totalShares})");
```

**Test Cases**:
1. Test RemoveSubScheme with TotalShares < shares.Shares (should revert)
2. Test RemoveBeneficiary for sub-scheme virtual address (should revert)
3. Test full cycle: AddSubScheme → RemoveBeneficiary → RemoveSubScheme (should revert on second step)
4. Test ClaimProfits with expired sub-scheme details after FixProfitDetail modification

### Proof of Concept

**Initial State**:
- Scheme A exists with TotalShares = 50 from other beneficiaries
- Scheme A configured with CanRemoveBeneficiaryDirectly = true

**Transaction Sequence**:

1. **Manager calls AddSubScheme**:
   - Input: {schemeId: A, subSchemeId: B, subSchemeShares: 100}
   - Result: Scheme A has TotalShares = 150, SubSchemes = [{B, 100}]

2. **Manager calls RemoveBeneficiary**:
   - Input: {schemeId: A, beneficiary: ConvertVirtualAddressToContractAddress(B)}
   - Result: Scheme A has TotalShares = 50, but SubSchemes STILL = [{B, 100}]

3. **Manager calls RemoveSubScheme**:
   - Input: {schemeId: A, subSchemeId: B}
   - Line 141: Gets shares = 100 from SubSchemes
   - Line 152: TotalShares = 50 - 100 = **-50**
   - Result: Scheme A has TotalShares = -50 (NEGATIVE!)

4. **Anyone calls DistributeProfits**:
   - Line 485 check: totalShares (-50) <= 0 → TRUE
   - Line 486: Calls BurnProfits, destroying all contributed profits
   - Result: All profits are burned instead of distributed

**Success Condition**: TotalShares becomes negative, and subsequent DistributeProfits calls burn profits instead of distributing them, confirmed by checking scheme state and observing burn events instead of transfer events.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L109-126)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L131-156)
```csharp
    public override Empty RemoveSubScheme(RemoveSubSchemeInput input)
    {
        Assert(input.SchemeId != input.SubSchemeId, "Two schemes cannot be same.");

        var scheme = State.SchemeInfos[input.SchemeId];
        Assert(scheme != null, "Scheme not found.");

        // ReSharper disable once PossibleNullReferenceException
        Assert(Context.Sender == scheme.Manager, "Only manager can remove sub-scheme.");

        var shares = scheme.SubSchemes.SingleOrDefault(d => d.SchemeId == input.SubSchemeId);
        if (shares == null) return new Empty();

        var subSchemeId = input.SubSchemeId;
        var subScheme = State.SchemeInfos[subSchemeId];
        Assert(subScheme != null, "Sub scheme not found.");

        var subSchemeVirtualAddress = Context.ConvertVirtualAddressToContractAddress(subSchemeId);
        // Remove profit details
        State.ProfitDetailsMap[input.SchemeId][subSchemeVirtualAddress] = new ProfitDetails();
        scheme.SubSchemes.Remove(shares);
        scheme.TotalShares = scheme.TotalShares.Sub(shares.Shares);
        State.SchemeInfos[input.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L224-263)
```csharp
    public override Empty RemoveBeneficiary(RemoveBeneficiaryInput input)
    {
        Assert(input.SchemeId != null, "Invalid scheme id.");
        Assert(input.Beneficiary != null, "Invalid Beneficiary address.");

        var scheme = State.SchemeInfos[input.SchemeId];

        Assert(scheme != null, "Scheme not found.");

        var currentDetail = State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];

        if (scheme == null || currentDetail == null) return new Empty();

        Assert(Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager or token holder contract can add beneficiary.");

        var removedDetails = RemoveProfitDetails(scheme, input.Beneficiary, input.ProfitDetailId);

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

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L300-301)
```csharp
        // The endPeriod is set, so use the inputted one.
        newDetail.EndPeriod = input.EndPeriod == 0 ? fixingDetail.EndPeriod : input.EndPeriod;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L321-324)
```csharp
        var detailsCanBeRemoved = scheme.CanRemoveBeneficiaryDirectly
            ? profitDetails.Details.Where(d => !d.IsWeightRemoved).ToList()
            : profitDetails.Details
                .Where(d => d.EndPeriod < scheme.CurrentPeriod && !d.IsWeightRemoved).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L517-557)
```csharp
    private Empty BurnProfits(long period, Dictionary<string, long> profitsMap, Scheme scheme,
        Address profitsReceivingVirtualAddress)
    {
        scheme.CurrentPeriod = period.Add(1);

        var distributedProfitsInfo = new DistributedProfitsInfo
        {
            IsReleased = true
        };
        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            if (amount > 0)
            {
                var balanceOfToken = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = symbol
                });
                if (balanceOfToken.Balance < amount)
                    continue;
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = Context.Self,
                        Amount = amount,
                        Symbol = symbol
                    }.ToByteString());
                State.TokenContract.Burn.Send(new BurnInput
                {
                    Amount = amount,
                    Symbol = symbol
                });
                distributedProfitsInfo.AmountsMap.Add(symbol, -amount);
            }
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;
        State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInfo;
        return new Empty();
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L787-799)
```csharp
        var profitDetailsToRemove = profitableDetails
            .Where(profitDetail =>
                profitDetail.LastProfitPeriod > profitDetail.EndPeriod && !profitDetail.IsWeightRemoved).ToList();
        var sharesToRemove =
            profitDetailsToRemove.Aggregate(0L, (current, profitDetail) => current.Add(profitDetail.Shares));
        scheme.TotalShares = scheme.TotalShares.Sub(sharesToRemove);
        foreach (var delayToPeriod in scheme.CachedDelayTotalShares.Keys)
        {
            scheme.CachedDelayTotalShares[delayToPeriod] =
                scheme.CachedDelayTotalShares[delayToPeriod].Sub(sharesToRemove);
        }

        State.SchemeInfos[scheme.SchemeId] = scheme;
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-98)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
    }
```

**File:** protobuf/profit_contract.proto (L129-130)
```text
    // Whether you can directly remove the beneficiary.
    bool can_remove_beneficiary_directly = 5;
```
