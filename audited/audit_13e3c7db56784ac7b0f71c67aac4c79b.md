### Title
Unbounded Token Symbol Accumulation Causes DOS in Profit Claiming

### Summary
The Profit contract's `ReceivedTokenSymbols` list has no size limit, allowing unlimited token types to accumulate in a scheme. When beneficiaries claim profits via `ClaimProfits`, the nested iteration through all symbols and periods can cause transaction complexity to exceed practical execution limits, resulting in denial of service for legitimate profit claims.

### Finding Description

The vulnerability exists in the profit claiming mechanism where multiple token types accumulate without bounds:

**Root Cause - Unbounded Symbol Accumulation:**

The `Scheme` structure tracks all received token symbols in `ReceivedTokenSymbols` with no maximum limit. [1](#0-0) 

Symbols are added in two locations without any validation:
- In `DistributeProfitsForSubSchemes` when distributing to sub-schemes [2](#0-1) 
- In `ContributeProfits` when anyone contributes profits (no manager restriction) [3](#0-2) 

**Claiming Complexity Issue:**

When `ClaimProfits` is called, it processes up to 10 profit details, with each calling `ProfitAllPeriods` [4](#0-3) 

The `ProfitAllPeriods` method creates a nested loop structure that iterates through ALL symbols in `ReceivedTokenSymbols` (unbounded), and for each symbol, loops through periods up to `maxProfitReceivingPeriodCount` [5](#0-4) 

**Execution Path:**
```
ClaimProfits 
  → Loop: 10 profit details
    → ProfitAllPeriods
      → Loop: ALL symbols in ReceivedTokenSymbols (no limit)
        → Loop: up to maxProfitReceivingPeriodCount periods (default 100)
          → State read + potential inline transfer
```

Total complexity: **10 × N_symbols × 100 = 1,000 × N_symbols iterations**

Each iteration performs state reads to get `DistributedProfitsInfo` and may generate inline transactions. [6](#0-5) 

**Why Protections Fail:**

The constant `TokenAmountLimit = 5` only applies to method fee configuration, not to `ReceivedTokenSymbols`. [7](#0-6) 

### Impact Explanation

**Direct Impact:**
- Beneficiaries cannot claim their legitimate profits when the number of accumulated token symbols becomes large
- Transaction execution time grows linearly with the number of token symbols
- With 100+ different token types, a single claim could require 100,000+ loop iterations

**Who is Affected:**
- All beneficiaries of schemes that have accumulated many different token types
- More severe for long-running schemes or treasury schemes that accept diverse tokens

**Operational Damage:**
- Legitimate profit claims fail due to transaction timeout or resource limits
- Users must potentially split claims or wait, creating poor UX
- In extreme cases, profits may become permanently unclaimable if the complexity grows beyond transaction limits

**Severity Justification (Low):**
- No direct fund theft or permanent loss
- Funds remain in the contract and are not stolen
- DOS is operational rather than complete system failure
- Can be mitigated through scheme design choices
- Attack cost is non-trivial (requires owning/creating many different tokens and actually transferring them)

### Likelihood Explanation

**Attacker Capabilities:**
Any user can call `ContributeProfits` to add new token symbols to a scheme. [8](#0-7) 

**Attack Complexity:**
1. Attacker identifies a target profit scheme
2. Creates or obtains many different token types (has a cost)
3. Calls `ContributeProfits` repeatedly with minimal amounts of each different token
4. Each call adds a new symbol to `ReceivedTokenSymbols` if not already present
5. Over time or in bulk, accumulates hundreds of different token symbols
6. When beneficiaries call `ClaimProfits`, they hit complexity limits

**Feasibility Conditions:**
- **Natural Occurrence**: In multi-token DeFi ecosystems, treasury schemes or reward distribution schemes can legitimately accumulate dozens of different tokens over time through normal operations
- **Accelerated Attack**: Malicious actor can speed up accumulation by deliberately contributing many token types
- **Economic Cost**: Attacker must own tokens and pay for transfers, but minimal amounts suffice (1 token of each type)

**Detection/Constraints:**
- No on-chain detection of this attack vector
- AElf's transaction limits based on execution time/resources will eventually reject the transaction
- No explicit circuit breaker for number of symbols

**Probability**: Medium-High for natural occurrence in active schemes; Low-Medium for deliberate attack due to economic costs of creating/obtaining many different tokens.

### Recommendation

**Immediate Mitigation:**

1. **Add Maximum Token Symbol Limit**: Enforce a reasonable upper bound on `ReceivedTokenSymbols` size (e.g., 20-50 token types per scheme):

```csharp
// In DistributeProfitsForSubSchemes and ContributeProfits
if (!scheme.ReceivedTokenSymbols.Contains(symbol))
{
    Assert(scheme.ReceivedTokenSymbols.Count < ProfitContractConstants.MaxReceivedTokenSymbolCount, 
           "Scheme has reached maximum token type limit");
    scheme.ReceivedTokenSymbols.Add(symbol);
}
```

Add constant: `public const int MaxReceivedTokenSymbolCount = 50;` [9](#0-8) 

2. **Implement Symbol Filtering in ClaimProfits**: Allow beneficiaries to claim specific token symbols rather than all at once:

```csharp
// Add optional parameter to ClaimProfitsInput
message ClaimProfitsInput {
    aelf.Hash scheme_id = 1;
    aelf.Address beneficiary = 2;
    repeated string symbols = 3; // Optional: specific symbols to claim
}
```

Modify `ProfitAllPeriods` to only process specified symbols when provided.

3. **Add Invariant Check**: In `DistributeProfits` and `ContributeProfits`, validate the total symbol count before adding.

**Testing:**
- Test claiming with 100+ different token symbols to verify failure
- Test symbol limit enforcement in contribute and distribute paths
- Test selective symbol claiming functionality
- Regression test: ensure existing single-token and multi-token (2-10) scenarios still work

### Proof of Concept

**Initial State:**
- Profit scheme exists with scheme_id = SCHEME_X
- Beneficiary has shares in the scheme
- Scheme has distributed profits over 100 periods

**Attack Steps:**

1. Attacker creates or obtains 200 different token types (TOKEN_001 through TOKEN_200)

2. For each token i from 1 to 200:
   ```
   ContributeProfits(
       scheme_id: SCHEME_X,
       symbol: TOKEN_i,
       amount: 1,
       period: current_period
   )
   ```
   This adds TOKEN_i to `scheme.ReceivedTokenSymbols`

3. Victim beneficiary attempts to claim profits:
   ```
   ClaimProfits(
       scheme_id: SCHEME_X,
       beneficiary: VICTIM_ADDRESS
   )
   ```

**Expected Result:**
Beneficiary successfully claims profits for all token types across all periods.

**Actual Result:**
Transaction fails or times out due to executing:
- 10 profit details × 200 symbols × 100 periods = **200,000 loop iterations**
- Each iteration performs state reads and potential inline transactions
- Transaction exceeds AElf's practical execution limits

**Success Condition:**
The `ClaimProfits` transaction reverts or times out, preventing the beneficiary from claiming their legitimate profits, demonstrating operational DOS.

**Notes:**

This vulnerability arises from the design choice to track all received token symbols without bounds. While mixing ELF and non-ELF tokens specifically doesn't create a unique vulnerability (any token types create the same issue), the unbounded accumulation of diverse token types in a scheme creates a quadratic-to-cubic complexity growth in the claiming mechanism. The issue is exacerbated in ecosystems with many different tokens or in treasury/reward schemes designed to accept multiple asset types. The recommended mitigations balance functionality (supporting multiple tokens) with security (preventing DOS through complexity explosion).

### Citations

**File:** protobuf/profit_contract.proto (L159-159)
```text
    repeated string received_token_symbols = 12;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L641-645)
```csharp
            if (!subScheme.ReceivedTokenSymbols.Contains(symbol))
            {
                subScheme.ReceivedTokenSymbols.Add(symbol);
                State.SchemeInfos[subSchemeShares.SchemeId] = subScheme;
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L773-784)
```csharp
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
        // Only can get profit from last profit period to actual last period (profit.CurrentPeriod - 1),
        // because current period not released yet.
        for (var i = 0; i < profitableDetailCount; i++)
        {
            var profitDetail = profitableDetails[i];
            if (profitDetail.LastProfitPeriod == 0)
                // This detail never performed profit before.
                profitDetail.LastProfitPeriod = profitDetail.StartPeriod;

            ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-860)
```csharp
        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
        {
            var totalAmount = 0L;
            var targetPeriod = Math.Min(scheme.CurrentPeriod - 1, profitDetail.EndPeriod);
            var maxProfitPeriod = profitDetail.EndPeriod == long.MaxValue
                ? Math.Min(scheme.CurrentPeriod - 1, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount))
                : Math.Min(targetPeriod, profitDetail.LastProfitPeriod.Add(maxProfitReceivingPeriodCount));
            for (var period = profitDetail.LastProfitPeriod; period <= maxProfitPeriod; period++)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L864-895)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L3-10)
```csharp
public class ProfitContractConstants
{
    public const int ProfitReceivingLimitForEachTime = 10;
    public const int DefaultProfitReceivingDuePeriodCount = 10;
    public const int MaximumProfitReceivingDuePeriodCount = 1024;
    public const int TokenAmountLimit = 5;
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
}
```
