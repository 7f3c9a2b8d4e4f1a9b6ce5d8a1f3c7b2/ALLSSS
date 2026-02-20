# Audit Report

## Title
Unbounded Token Symbol Accumulation Causes DOS in Profit Claiming

## Summary
The Profit contract's `ReceivedTokenSymbols` list lacks size limits, allowing unlimited token types to accumulate. When beneficiaries claim profits via `ClaimProfits`, nested iteration through all symbols and periods causes transaction complexity to exceed execution limits, resulting in denial of service for legitimate profit claims.

## Finding Description

The vulnerability exists in the profit claiming mechanism where token symbols accumulate without bounds in the `Scheme` structure. The `ReceivedTokenSymbols` field is defined as an unbounded repeated string in the protobuf definition. [1](#0-0) 

Symbols are added without size validation in two locations:

1. **In `DistributeProfitsForSubSchemes`**: When distributing to sub-schemes, the method unconditionally adds new token symbols to `ReceivedTokenSymbols` if not already present, with no size validation. [2](#0-1) 

2. **In `ContributeProfits`**: This is a public method with no access control restrictions. Any user can contribute profits with any valid token symbol, and the method adds new symbols without size limits. [3](#0-2)  The specific symbol addition occurs without bounds checking. [4](#0-3) 

When `ClaimProfits` is called, it processes up to 10 profit details at a time, limited by `ProfitReceivingLimitForEachTime`. [5](#0-4) 

The `ProfitAllPeriods` method creates a nested loop structure that iterates through ALL symbols in the unbounded `ReceivedTokenSymbols` list. [6](#0-5)  For each symbol, it loops through periods up to a maximum count. [7](#0-6) 

Each iteration performs state reads to retrieve `DistributedProfitsInfo` and may generate inline token transfers. [8](#0-7) 

The constant `TokenAmountLimit = 5` only applies to method fee configuration in `SetMethodFee`, not to `ReceivedTokenSymbols`. [9](#0-8) [10](#0-9) 

The maximum period count defaults to 100. [11](#0-10)  This period budget is divided among profit details, so with 10 details, each processes approximately 10 periods. [12](#0-11) 

## Impact Explanation

**Direct Impact:**
- Beneficiaries cannot claim their legitimate profits when many token symbols accumulate in a scheme
- Transaction complexity grows as: profit details (up to 10) × N symbols × periods per detail, resulting in approximately 100N total iterations with state reads
- With 100+ accumulated token types, a single `ClaimProfits` call requires 10,000+ loop iterations with state reads and potential transfers
- Transactions will timeout or exceed AElf's resource/execution limits, causing reverts

**Who is Affected:**
- All beneficiaries of schemes with many accumulated token types
- Particularly severe for long-running treasury or reward schemes that naturally accept diverse tokens
- Sub-schemes that inherit token symbols from parent distributions

**Operational Damage:**
- Legitimate profit claims fail due to transaction resource exhaustion
- Users unable to access earned rewards, causing poor user experience
- No alternative claiming mechanism exists when symbol count is too high
- In extreme cases with hundreds of symbols, profits become practically unclaimable

**Severity Justification (Low):**
- No direct fund theft or permanent loss of funds
- Funds remain securely in the contract addresses
- DOS is operational rather than complete protocol failure  
- Can be mitigated through careful scheme design and token acceptance policies
- Attack requires non-trivial economic cost (creating/obtaining many different tokens and paying transaction fees for each contribution)
- Natural accumulation is also possible through legitimate multi-token operations

## Likelihood Explanation

**Attacker Capabilities:**
Any user can call `ContributeProfits` to add new token symbols to any scheme without requiring manager permissions or special privileges. The method only validates token existence, not caller authorization.

**Attack Complexity:**
1. Attacker identifies target profit scheme ID
2. Creates or obtains many different token types (each token creation incurs cost)
3. Calls `ContributeProfits` repeatedly with minimal amounts of each different token symbol
4. Each call adds a new symbol to `ReceivedTokenSymbols` if not already present
5. Accumulates hundreds of different token symbols over time
6. Beneficiaries calling `ClaimProfits` hit computational complexity limits causing transaction failures

**Feasibility:**
- **Natural Occurrence**: Multi-token treasury or reward schemes can legitimately accumulate dozens of different tokens through normal operations (Medium-High probability over long timeframes)
- **Accelerated Attack**: Malicious actor can deliberately speed up symbol accumulation (Low-Medium probability due to economic costs of creating tokens and transaction fees)
- **Economic Barrier**: Attacker must own tokens and pay transaction fees for each contribution, but minimal token amounts suffice for the attack

**Detection/Constraints:**
- No on-chain detection mechanism prevents excessive symbol accumulation
- AElf transaction execution limits will eventually reject overly complex transactions
- No circuit breaker or maximum limit enforced on scheme's symbol count
- Attack is detectable through monitoring scheme state, but no automated prevention exists

## Recommendation

Implement a maximum limit on the number of token symbols that can be accumulated in a scheme's `ReceivedTokenSymbols` list:

1. **Add Symbol Limit Constant**: Define a reasonable maximum (e.g., 50-100 symbols) in `ProfitContractConstants.cs`

2. **Enforce Limit in ContributeProfits**: Before adding a new symbol, check if the limit would be exceeded and revert if so

3. **Enforce Limit in DistributeProfitsForSubSchemes**: Apply the same validation when distributing to sub-schemes

4. **Alternative Approach**: Implement pagination or batching in `ClaimProfits` to process symbols in chunks across multiple transactions, though this adds complexity

5. **Governance Control**: Allow the limit to be adjustable via governance to balance flexibility with DOS protection

The fix should be applied to both locations where symbols are added to maintain consistency and prevent bypass.

## Proof of Concept

```csharp
// Test demonstrating DOS via symbol accumulation
[Fact]
public async Task ContributeProfits_UnboundedSymbols_CausesClaimDOS()
{
    // Setup: Create a profit scheme
    var schemeId = await CreateTestScheme();
    var beneficiary = await AddBeneficiaryToScheme(schemeId);
    
    // Attack: Add many different token symbols
    for (int i = 0; i < 150; i++)
    {
        var tokenSymbol = $"TOKEN{i}";
        await CreateToken(tokenSymbol);
        
        // Any user can contribute with new token symbol
        await ProfitContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId,
            Amount = 1, // Minimal amount
            Symbol = tokenSymbol,
            Period = 0
        });
    }
    
    // Distribute profits to activate the scheme
    await DistributeProfits(schemeId);
    
    // Verify: ClaimProfits fails due to excessive computational complexity
    var claimResult = await ProfitContractStub.ClaimProfits.SendWithExceptionAsync(
        new ClaimProfitsInput
        {
            SchemeId = schemeId,
            Beneficiary = beneficiary
        }
    );
    
    // Transaction should fail/timeout due to nested loops: 
    // 10 details × 150 symbols × ~10 periods = 15,000+ iterations
    claimResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    claimResult.TransactionResult.Error.ShouldContain("resource limit"); // Or timeout error
}
```

## Notes

The vulnerability represents a legitimate DOS vector where the unbounded accumulation of token symbols creates computational complexity that exceeds transaction execution limits. While the attack has economic costs (token creation fees and transaction fees), the impact on legitimate users is real when schemes accumulate many tokens either through attack or natural multi-token operations. The LOW severity rating is appropriate because funds are not at risk of theft, only accessibility, and the issue can be mitigated through careful scheme design and governance policies limiting accepted token types.

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L772-774)
```csharp
        var profitableDetailCount =
            Math.Min(ProfitContractConstants.ProfitReceivingLimitForEachTime, profitableDetails.Count);
        var maxProfitReceivingPeriodCount = GetMaximumPeriodCountForProfitableDetail(profitableDetailCount);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L822-833)
```csharp
    private int GetMaximumPeriodCountForProfitableDetail(int profitableDetailCount)
    {
        // Get the maximum profit receiving period count
        var maxPeriodCount = GetMaximumProfitReceivingPeriodCount();
        // Check if the maximum period count is greater than the profitable detail count
        // and if the profitable detail count is greater than 0
        return maxPeriodCount > profitableDetailCount && profitableDetailCount > 0
            // Divide the maximum period count by the profitable detail count
            ? maxPeriodCount.Div(profitableDetailCount)
            // If the conditions are not met, return 1 as the maximum period count
            : 1;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-851)
```csharp
        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-911)
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L8-8)
```csharp
    public const int TokenAmountLimit = 5;
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L9-9)
```csharp
    public const int DefaultMaximumProfitReceivingPeriodCountOfOneTime = 100;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```
