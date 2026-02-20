# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables State Bloat and Iteration DoS on Profit Schemes

## Summary
The `ReceivedTokenSymbols` list in profit schemes has no size limit and can be populated by any user through unrestricted `ContributeProfits()` calls. When this list grows large, critical operations that iterate over all symbols—including `DistributeProfits()`, `ClaimProfits()`, and `GetUndistributedDividends()`—will perform excessive external contract calls, causing denial-of-service for scheme managers and beneficiaries, particularly affecting critical infrastructure like TokenHolder schemes, Treasury, and consensus dividend pools.

## Finding Description

**Root Cause - Unbounded List Definition:**

The `ReceivedTokenSymbols` field is defined as an unbounded `repeated string` in the Scheme message structure without any maximum size constraint. [1](#0-0) 

**Population Without Access Control:**

The `ContributeProfits()` method is publicly accessible and allows any user to contribute tokens to any profit scheme. [2](#0-1)  The only validations are token existence and positive amount checks. [3](#0-2)  When a new symbol is contributed, it's automatically added to `ReceivedTokenSymbols` without any bound check. [4](#0-3) 

Symbols are also added during sub-scheme distribution without bounds. [5](#0-4) 

**TokenAmountLimit Is Unrelated:**

The `TokenAmountLimit` constant exists but only applies to method fee configuration, [6](#0-5)  not to `ReceivedTokenSymbols`. [7](#0-6) 

**DoS Attack Vectors:**

1. **DistributeProfits() Full Iteration:** When `IsReleaseAllBalanceEveryTimeByDefault` is true and no specific amounts are provided, the function iterates over ALL symbols in `ReceivedTokenSymbols` and makes external `GetBalance` calls for each. [8](#0-7)  TokenHolderContract ALWAYS sets this flag to true, [9](#0-8)  as does Treasury. [10](#0-9) 

2. **ProfitAllPeriods() Nested Loops:** This function iterates over symbols (or all symbols if no target specified) [11](#0-10)  and then iterates over periods for each symbol, [12](#0-11)  creating nested loops with external calls.

3. **GetUndistributedDividends() in AEDPoS:** The consensus dividend pool view method iterates all `ReceivedTokenSymbols` and makes external `GetBalance` calls. [13](#0-12) 

4. **Automatic Distribution Trigger:** The AEDPoS side chain dividends pool can automatically trigger distribution with empty AmountsMap, [14](#0-13)  which would iterate all symbols when the scheme has `IsReleaseAllBalanceEveryTimeByDefault=true`.

## Impact Explanation

**Operational Denial-of-Service:**
- Scheme managers cannot successfully distribute profits when schemes have `IsReleaseAllBalanceEveryTimeByDefault = true` (default for TokenHolder and Treasury schemes)
- Beneficiaries cannot claim their profits through `ClaimProfits()` due to excessive gas consumption
- Critical infrastructure like consensus dividend pools become non-operational, potentially halting validator reward distributions
- View methods timeout, preventing monitoring and accounting

**Permanent State Bloat:**
- Each added symbol permanently increases Scheme object storage size
- No removal mechanism exists
- Storage costs compound indefinitely

**Affected Critical Systems:**
- TokenHolder schemes (staking rewards) - always vulnerable due to default flag
- Treasury schemes (protocol revenue) - always vulnerable due to default flag  
- Consensus dividend pools (validator rewards) - critical infrastructure
- Any profit scheme can be targeted

The severity is assessed as **Medium** due to economic cost barriers (~1000 ELF for 1000 symbols), but the impact on consensus/treasury infrastructure is severe and permanent.

## Likelihood Explanation

**Attack Feasibility:**
- **Technical Complexity:** Very low - simply call `ContributeProfits()` repeatedly with different symbols
- **Permissions Required:** None - method is public
- **Economic Cost:** For 1000 symbols at ~1 ELF per transaction = ~1000 ELF, plus minimal token contributions
- **Detection:** Visible on-chain but difficult to prevent without protocol changes

**Attack Conditions:**
- Chains with many existing tokens are more vulnerable
- Schemes with `IsReleaseAllBalanceEveryTimeByDefault = true` (TokenHolder/Treasury) are immediately impacted
- Can be executed gradually over time
- Most dangerous when targeting critical protocol infrastructure

**Probability:** **Medium-Low** overall. While technically trivial and economically feasible for motivated attackers, the upfront cost (~1000 ELF) and sustained effort reduce probability for casual attacks.

## Recommendation

Implement a maximum size limit for `ReceivedTokenSymbols`:

1. **Add constant limit:** Define `public const int MaxReceivedTokenSymbols = 100;` in `ProfitContractConstants`

2. **Enforce in ContributeProfits:**
```csharp
if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol))
{
    Assert(scheme.ReceivedTokenSymbols.Count < ProfitContractConstants.MaxReceivedTokenSymbols,
        $"Maximum token symbols limit ({ProfitContractConstants.MaxReceivedTokenSymbols}) reached.");
    scheme.ReceivedTokenSymbols.Add(input.Symbol);
}
```

3. **Enforce in sub-scheme distribution:** Apply same check before adding symbols in `DistributeProfitsForSubSchemes()`

4. **Add removal mechanism:** Implement a manager-only method to remove unused symbols with zero balance

5. **Alternative mitigation:** For critical schemes, use explicit AmountsMap in `DistributeProfits()` calls instead of relying on full iteration

## Proof of Concept

```csharp
// Test demonstrating ReceivedTokenSymbols DoS attack
public async Task ReceivedTokenSymbols_DoS_Attack()
{
    // Create profit scheme with IsReleaseAllBalanceEveryTimeByDefault = true
    var schemeId = await CreateTokenHolderScheme();
    
    // Attacker adds many token symbols
    for (int i = 0; i < 1000; i++)
    {
        var symbol = $"TOKEN{i}";
        await CreateToken(symbol);
        await ContributeProfits(schemeId, symbol, amount: 1);
    }
    
    // Verify ReceivedTokenSymbols has 1000 entries
    var scheme = await GetScheme(schemeId);
    Assert.Equal(1000, scheme.ReceivedTokenSymbols.Count);
    
    // Attempt to distribute profits - will fail/timeout due to 1000+ external calls
    var exception = await Assert.ThrowsAsync<Exception>(() => 
        DistributeProfits(schemeId, period: 1, amountsMap: null));
    
    // Verify operation fails (gas limit exceeded or timeout)
    Assert.Contains("gas", exception.Message.ToLower());
}
```

### Citations

**File:** protobuf/profit_contract.proto (L159-159)
```text
    repeated string received_token_symbols = 12;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L447-459)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L640-645)
```csharp
            var subScheme = State.SchemeInfos[subSchemeShares.SchemeId];
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-851)
```csharp
        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L853-915)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L8-8)
```csharp
    public const int TokenAmountLimit = 5;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L23-23)
```csharp
            IsReleaseAllBalanceEveryTimeByDefault = true,
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L62-62)
```csharp
                IsReleaseAllBalanceEveryTimeByDefault = true,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L117-120)
```csharp
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L147-161)
```csharp
    public override Dividends GetUndistributedDividends(Empty input)
    {
        var scheme = GetSideChainDividendPoolScheme();
        return new Dividends
        {
            Value =
            {
                scheme.ReceivedTokenSymbols.Select(s => State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = s
                })).ToDictionary(b => b.Symbol, b => b.Balance)
            }
        };
    }
```
