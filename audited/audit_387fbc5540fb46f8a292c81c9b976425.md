### Title
BurnProfits Unconditionally Overwrites DistributedProfitsMap Causing Loss of Pre-Contributed Profits

### Summary
The `BurnProfits` function creates a new `DistributedProfitsInfo` object and unconditionally overwrites any existing `DistributedProfitsMap` entry for a period without preserving pre-contributed profits. When users contribute profits to future periods via `ContributeProfits`, and the scheme later has zero `totalShares` when that period arrives, `BurnProfits` destroys the accounting record while the contributed tokens remain locked in the period-specific virtual address, making them permanently unclaimable.

### Finding Description

The vulnerability exists in the interaction between `ContributeProfits` and `BurnProfits` functions: [1](#0-0) 

`ContributeProfits` allows users to contribute tokens to future periods (period > currentPeriod), as validated at line 684. These tokens are transferred to period-specific virtual addresses: [2](#0-1) 

The contribution is recorded in `DistributedProfitsMap[distributedPeriodProfitsVirtualAddress]` at line 712.

When `DistributeProfits` is called for a period where `totalShares <= 0` (or `period < 0`), it invokes `BurnProfits`: [3](#0-2) 

The critical flaw is in `BurnProfits` implementation: [4](#0-3) 

At line 522, `BurnProfits` creates a **new** `DistributedProfitsInfo` object without reading any existing state. It then burns tokens from the scheme's general ledger (lines 532-550), not from the period-specific address where pre-contributions were deposited. Finally, at line 556, it unconditionally overwrites `DistributedProfitsMap[profitsReceivingVirtualAddress]`, destroying any record of previously contributed profits.

The period-specific virtual address is generated consistently: [5](#0-4) 

After `BurnProfits` executes, `IsReleased=true` prevents any further contributions to that period: [6](#0-5) 

The `DistributedProfitsMap` state is defined as: [7](#0-6) 

### Impact Explanation

**Direct Fund Impact - Permanent Loss of Contributed Profits:**

1. **Loss of Funds:** Tokens contributed to future periods become permanently locked in the period-specific virtual address with no way to retrieve them. The accounting in `DistributedProfitsMap` is overwritten, and `ClaimProfits` cannot recover these funds.

2. **Quantified Damage:** The impact scales with the contribution amount. For example, if 10,000 ELF tokens are contributed to period 5, and the scheme has zero beneficiaries when period 5 arrives, all 10,000 ELF become permanently locked.

3. **Who is Affected:** 
   - Users who contribute profits to future periods expecting normal distribution
   - Scheme managers who may inadvertently trigger this by removing all beneficiaries
   - The overall protocol, as tokens become permanently stuck

4. **Severity Justification (Medium):** While this requires specific conditions (future period contribution + zero totalShares at distribution time), it represents a complete loss of the contributed funds. The likelihood is elevated because removing beneficiaries is a legitimate operation when winding down schemes. [8](#0-7) 

### Likelihood Explanation

**Attack Complexity: Medium**

The vulnerability can be triggered through normal operations without requiring privileged access beyond what's needed to contribute profits:

1. **Reachable Entry Point:** `ContributeProfits` is a public method callable by any user with token allowance.

2. **Feasible Preconditions:**
   - Scheme exists and accepts contributions
   - User contributes to a future period (e.g., period 5 when current period is 1)
   - By the time period 5 arrives, all beneficiaries have been removed via `RemoveBeneficiary`, resulting in `totalShares = 0`
   - Scheme manager calls `DistributeProfits` for period 5

3. **Execution Practicality:** This scenario naturally occurs when:
   - A scheme is being wound down and beneficiaries are removed
   - Users contributed to future periods expecting normal operation
   - The timing gap between contribution and distribution allows beneficiary changes

4. **Economic Rationality:** No attack cost beyond the contribution itself. An attacker could even grief others by contributing on their behalf to future periods, then removing beneficiaries.

5. **Detection Constraints:** The issue is not easily detectable as both `ContributeProfits` and `RemoveBeneficiary` are legitimate operations. The loss only becomes apparent when attempting to claim profits.

### Recommendation

**Immediate Fix:**

Modify `BurnProfits` to preserve existing `DistributedProfitsInfo` when it exists:

```csharp
private Empty BurnProfits(long period, Dictionary<string, long> profitsMap, Scheme scheme,
    Address profitsReceivingVirtualAddress)
{
    scheme.CurrentPeriod = period.Add(1);

    // READ existing DistributedProfitsInfo instead of creating new
    var distributedProfitsInfo = State.DistributedProfitsMap[profitsReceivingVirtualAddress] 
        ?? new DistributedProfitsInfo();
    
    distributedProfitsInfo.IsReleased = true;
    
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
            // UPDATE existing amounts instead of replacing
            var currentAmount = distributedProfitsInfo.AmountsMap.ContainsKey(symbol) 
                ? distributedProfitsInfo.AmountsMap[symbol] 
                : 0;
            distributedProfitsInfo.AmountsMap[symbol] = currentAmount.Sub(amount);
        }
    }

    State.SchemeInfos[scheme.SchemeId] = scheme;
    State.DistributedProfitsMap[profitsReceivingVirtualAddress] = distributedProfitsInfo;
    return new Empty();
}
```

**Additional Invariant Checks:**

1. Add validation in `ContributeProfits` to warn or prevent contributions to schemes with declining totalShares
2. Emit an event when `BurnProfits` is called on periods with existing contributions
3. Add a recovery mechanism for stuck funds in period-specific addresses

**Test Cases to Add:**

1. Contribute to future period → Remove all beneficiaries → Distribute with burn → Verify contributions are preserved or recoverable
2. Contribute to period N → Burn in period N → Verify `DistributedProfitsInfo.AmountsMap` correctly reflects both contributions and burns
3. Test sequential contribution → burn → contribution scenarios

### Proof of Concept

**Initial State:**
- Scheme X exists with schemeId = SCHEME_ID
- Current period = 1
- TotalShares = 100 (some beneficiaries exist)
- User A has 10,000 ELF tokens with approval to ProfitContract

**Exploit Steps:**

1. **User A contributes to future period:**
   ```
   ContributeProfits(
       SchemeId: SCHEME_ID,
       Period: 5,
       Symbol: "ELF",
       Amount: 10000
   )
   ```
   - 10,000 ELF transferred to period-5-virtual-address
   - `DistributedProfitsMap[period-5-virtual-address] = {AmountsMap: {"ELF": 10000}, IsReleased: false}`

2. **Advance to period 5 and remove all beneficiaries:**
   ```
   // Manager removes all beneficiaries via RemoveBeneficiary calls
   // scheme.TotalShares becomes 0
   ```

3. **Manager distributes profits for period 5:**
   ```
   DistributeProfits(
       SchemeId: SCHEME_ID,
       Period: 5,
       AmountsMap: {"ELF": 0}  // or empty, uses general ledger balance
   )
   ```
   - Since `totalShares = 0`, `BurnProfits` is called
   - `BurnProfits` creates NEW `DistributedProfitsInfo` with `IsReleased=true`
   - May burn 0 ELF from general ledger (or whatever balance exists there)
   - **OVERWRITES** `DistributedProfitsMap[period-5-virtual-address]`
   - Original contribution record of 10,000 ELF is lost

4. **Attempt to claim:**
   ```
   ClaimProfits(SchemeId: SCHEME_ID, Beneficiary: USER_A)
   ```
   - `DistributedProfitsMap[period-5-virtual-address]` no longer shows the 10,000 ELF
   - `IsReleased=true` prevents new contributions
   - Funds are permanently stuck in period-5-virtual-address

**Expected Result:** User A should be able to claim or recover the 10,000 ELF contributed to period 5.

**Actual Result:** The 10,000 ELF remains in period-5-virtual-address but is unclaimable. `DistributedProfitsMap` shows incorrect/negative amounts or empty state. User A has permanently lost access to the contributed funds.

**Success Condition for Exploit:** Query balance of period-5-virtual-address shows 10,000 ELF, but `GetDistributedProfitsInfo(SCHEME_ID, 5)` does not reflect this amount or shows negative values, and `ClaimProfits` fails or transfers 0 tokens.

### Citations

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L485-486)
```csharp
        if (input.Period < 0 || totalShares <= 0)
            return BurnProfits(input.Period, profitsMap, scheme, profitsReceivingVirtualAddress);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L517-558)
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
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L651-721)
```csharp
    public override Empty ContributeProfits(ContributeProfitsInput input)
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        AssertTokenExists(input.Symbol);
        if (input.Amount <= 0)
        {
            throw new AssertionException("Amount need to greater than 0.");
        }

        var scheme = State.SchemeInfos[input.SchemeId];
        if (scheme == null)
        {
            throw new AssertionException("Scheme not found.");
        }
        // ReSharper disable once PossibleNullReferenceException
        var virtualAddress = scheme.VirtualAddress;

        if (input.Period == 0)
        {

            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = virtualAddress,
                Symbol = input.Symbol,
                Amount = input.Amount,
                Memo = $"Add {input.Amount} dividends."
            });
        }
        else
        {
            Assert(input.Period >= scheme.CurrentPeriod, "Invalid contributing period.");
            var distributedPeriodProfitsVirtualAddress =
                GetDistributedPeriodProfitsVirtualAddress(input.SchemeId, input.Period);

            var distributedProfitsInformation = State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress];
            if (distributedProfitsInformation == null)
            {
                distributedProfitsInformation = new DistributedProfitsInfo
                {
                    AmountsMap = { { input.Symbol, input.Amount } }
                };
            }
            else
            {
                Assert(!distributedProfitsInformation.IsReleased,
                    $"Scheme of period {input.Period} already released.");
                distributedProfitsInformation.AmountsMap[input.Symbol] =
                    distributedProfitsInformation.AmountsMap[input.Symbol].Add(input.Amount);
            }

            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = distributedPeriodProfitsVirtualAddress,
                Symbol = input.Symbol,
                Amount = input.Amount
            });

            State.DistributedProfitsMap[distributedPeriodProfitsVirtualAddress] = distributedProfitsInformation;
        }

        // If someone directly use virtual address to do the contribution, won't sense the token symbol he was using.
        if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol)) scheme.ReceivedTokenSymbols.Add(input.Symbol);

        State.SchemeInfos[scheme.SchemeId] = scheme;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L51-60)
```csharp
    private Address GetDistributedPeriodProfitsVirtualAddress(Hash schemeId, long period)
    {
        return Context.ConvertVirtualAddressToContractAddress(
            GeneratePeriodVirtualAddressFromHash(schemeId, period));
    }

    private Hash GeneratePeriodVirtualAddressFromHash(Hash schemeId, long period)
    {
        return HashHelper.XorAndCompute(schemeId, HashHelper.ComputeFrom(period));
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L11-11)
```csharp
    public MappedState<Address, DistributedProfitsInfo> DistributedProfitsMap { get; set; }
```
