# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables State Bloat and Iteration DoS on Profit Schemes

## Summary
The `ReceivedTokenSymbols` field in profit schemes has no size limit and can be populated by any user contributing arbitrary token types to any scheme. When this list grows large, operations that iterate over all symbols—such as profit distribution and claiming—will exceed gas limits or become prohibitively expensive, causing operational DoS for scheme managers and beneficiaries, including critical infrastructure like the consensus dividend pool.

## Finding Description

The `ReceivedTokenSymbols` field is defined as an unbounded repeated string field in the Scheme structure with no maximum size constraint: [1](#0-0) 

This list is populated in `DistributeProfitsForSubSchemes()` when distributing to sub-schemes without any bound validation: [2](#0-1) 

And in `ContributeProfits()` when anyone contributes tokens: [3](#0-2) 

The critical vulnerability is that `ContributeProfits()` has no access control. The only validation performed is checking that the token exists and the amount is positive: [4](#0-3) 

Any user can call this function to contribute dust amounts of any valid token to any profit scheme, causing that token symbol to be permanently added to `ReceivedTokenSymbols`.

The `TokenAmountLimit` constant is unrelated to this vulnerability—it only applies to method fee configuration: [5](#0-4) 

Once the list grows large, three critical DoS vectors emerge:

**DoS Vector 1**: `DistributeProfits()` when `IsReleaseAllBalanceEveryTimeByDefault` is true and no specific amounts are provided—it iterates over ALL symbols making external `GetBalance` calls for each: [6](#0-5) 

**DoS Vector 2**: `ProfitAllPeriods()` when calculating profits for beneficiaries iterates over all symbols: [7](#0-6) 

**DoS Vector 3**: `GetUndistributedDividends()` in the AEDPoS consensus contract iterates all symbols to calculate undistributed dividends for the consensus dividend pool: [8](#0-7) 

Each iteration involves expensive external contract calls to the Token contract, causing gas consumption to scale linearly with the number of symbols.

## Impact Explanation

**Operational DoS:**
- Scheme managers (especially for the consensus dividend pool) become unable to call `DistributeProfits()` if the gas cost of iterating 1000+ symbols exceeds block gas limits or becomes prohibitively expensive
- Beneficiaries become unable to claim profits via `ClaimProfits()` when calculation functions timeout or exceed gas limits
- The consensus dividend pool could become completely non-operational, disrupting validator reward distributions

**State Bloat:**
- Each token symbol added increases the state size of the Scheme object permanently
- No mechanism exists to remove symbols from the list
- Storage costs accumulate over time

**Affected Parties:**
- Scheme managers needing to distribute profits
- Beneficiaries attempting to claim their profits
- The protocol's consensus dividend pool infrastructure
- Any high-value profit scheme targeted by attackers

This breaks the operational availability guarantee of the profit distribution system, which is critical infrastructure for AElf's economic model.

## Likelihood Explanation

**Attack Feasibility:**
- **Attacker Capabilities**: Needs access to multiple token types (can use existing tokens or create new ones) and must pay transaction fees for each contribution
- **Technical Complexity**: Low—simply call `ContributeProfits()` repeatedly with different token symbols and minimal amounts (1 unit)
- **Economic Rationality**: For N=1000 symbols, cost = N × (transaction_fee + 1_token_unit), which is economically feasible for motivated attackers targeting critical infrastructure

**Execution Characteristics:**
- Can be executed gradually over time to avoid detection
- No special permissions or exploitation techniques required
- Attack is detectable through monitoring but difficult to prevent without access control changes
- No automatic cleanup mechanism exists

**Probability Assessment**: Medium-Low. While technically simple and economically feasible for high-value targets, it requires sustained effort and upfront costs. The attack is more likely against critical infrastructure schemes (consensus dividend pool, treasury) where DoS disrupts network operations.

## Recommendation

Implement a maximum size limit for `ReceivedTokenSymbols` and add validation in both `ContributeProfits()` and `DistributeProfitsForSubSchemes()`:

1. Define a constant maximum symbol count (e.g., 50-100 symbols per scheme)
2. Add validation before adding new symbols to reject contributions if limit is reached
3. Consider adding access control or a whitelist mechanism for which tokens can be contributed to critical schemes
4. Add a cleanup mechanism to remove symbols with zero balance during distribution operations

## Proof of Concept

A proof of concept would involve:
1. Creating multiple token types (or using existing ones)
2. Repeatedly calling `ContributeProfits()` with minimal amounts (1 unit) of each different token symbol targeting a profit scheme
3. Verifying that `ReceivedTokenSymbols` grows unbounded
4. Attempting to call `DistributeProfits()` or `ClaimProfits()` and observing increased gas consumption or transaction failure as the symbol count reaches 100s or 1000s

The test would demonstrate that after adding sufficient symbols, legitimate operations on the scheme become economically infeasible or exceed gas limits.

### Citations

**File:** protobuf/profit_contract.proto (L159-159)
```text
    repeated string received_token_symbols = 12;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L449-459)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L641-645)
```csharp
            if (!subScheme.ReceivedTokenSymbols.Contains(symbol))
            {
                subScheme.ReceivedTokenSymbols.Add(symbol);
                State.SchemeInfos[subSchemeShares.SchemeId] = subScheme;
            }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L656-660)
```csharp
        AssertTokenExists(input.Symbol);
        if (input.Amount <= 0)
        {
            throw new AssertionException("Amount need to greater than 0.");
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L716-716)
```csharp
        if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol)) scheme.ReceivedTokenSymbols.Add(input.Symbol);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L851-853)
```csharp
        var symbols = targetSymbol == null ? scheme.ReceivedTokenSymbols.ToList() : new List<string> { targetSymbol };

        foreach (var symbol in symbols)
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L154-158)
```csharp
                scheme.ReceivedTokenSymbols.Select(s => State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = s
                })).ToDictionary(b => b.Symbol, b => b.Balance)
```
