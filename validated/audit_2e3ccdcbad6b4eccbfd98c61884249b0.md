# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables State Bloat and Iteration DoS on Profit Schemes

## Summary
The `ReceivedTokenSymbols` list in profit schemes lacks a size limit and can be populated by any user through unrestricted token contributions. When this list grows large (1000+ symbols), critical operations that iterate over all symbols—such as `DistributeProfits()`, `ClaimProfits()`, and `GetUndistributedDividends()`—will make excessive external contract calls that can exceed gas limits, causing operational denial-of-service for scheme managers and beneficiaries, particularly affecting critical infrastructure like the consensus dividend pool.

## Finding Description

**Root Cause - Unbounded List Definition:**

The `ReceivedTokenSymbols` field is defined as an unbounded repeated string field in the Scheme message structure. [1](#0-0)  This design allows unlimited symbol accumulation without any maximum size constraint.

**Population Without Access Control:**

The `ContributeProfits()` method allows any user to contribute tokens to any profit scheme. [2](#0-1)  The only validation performed is `AssertTokenExists()` to verify the token exists. [3](#0-2)  When a new token symbol is contributed, it's automatically added to `ReceivedTokenSymbols` without any bound check. [4](#0-3) 

The list is also populated during sub-scheme distribution without bound checks. [5](#0-4) 

**Incorrect Assumption About TokenAmountLimit:**

The `TokenAmountLimit` constant exists in the codebase [6](#0-5)  but it only applies to method fee configuration, not to `ReceivedTokenSymbols`. [7](#0-6) 

**DoS Attack Vectors:**

1. **DistributeProfits() Iteration:** When `IsReleaseAllBalanceEveryTimeByDefault` is true and no specific amounts are provided, the function iterates over ALL symbols in `ReceivedTokenSymbols` and makes external `GetBalance` calls for each. [8](#0-7)  With 1000+ symbols, this creates 1000+ external contract calls that can exceed block gas limits.

2. **ProfitAllPeriods() Nested Loops:** This internal function iterates over symbols (or all symbols if no target specified) [9](#0-8)  and then iterates over periods for each symbol. [10](#0-9)  This creates nested loops with external calls that become prohibitively expensive.

3. **GetUndistributedDividends() in AEDPoS:** The consensus dividend pool's view method iterates all `ReceivedTokenSymbols` and makes external `GetBalance` calls for each. [11](#0-10)  This can timeout or fail with large symbol lists.

**Attack Execution Path:**

1. Attacker identifies target profit scheme (schemeId)
2. For each unique token symbol available on chain:
   - Call `ContributeProfits(schemeId, amount: 1, period: 0, symbol)`
   - Pay transaction fee (~1 ELF default) + minimal token amount
3. `ReceivedTokenSymbols` grows without limit
4. Legitimate scheme operations fail due to gas exhaustion

## Impact Explanation

**Operational Denial-of-Service:**
- Scheme managers cannot successfully call `DistributeProfits()` when schemes have `IsReleaseAllBalanceEveryTimeByDefault = true`, as the transaction will exceed gas limits
- Beneficiaries cannot claim their profits through `ClaimProfits()` when the calculation functions consume excessive gas
- Critical infrastructure like the consensus dividend pool becomes non-operational, potentially halting reward distributions
- View methods like `GetUndistributedDividends()` timeout, preventing monitoring and accounting

**Permanent State Bloat:**
- Each added symbol permanently increases the Scheme object's storage size
- No removal mechanism exists to clean up the symbol list
- Storage costs compound over time as more symbols are added

**Affected Systems:**
- Any profit scheme, but especially critical for:
  - Consensus dividend pools (disrupts validator rewards)
  - Treasury profit schemes (disrupts protocol revenue distribution)
  - TokenHolder schemes (disrupts staking rewards)

The severity is assessed as **Low-to-Medium** due to the economic cost barrier (attacker must pay transaction fees), but the impact on critical consensus infrastructure could justify Medium severity.

## Likelihood Explanation

**Attack Feasibility:**
- **Technical Complexity:** Very low - simply call `ContributeProfits()` repeatedly with different symbols
- **Permissions Required:** None - method is public and unrestricted
- **Economic Cost:** For 1000 symbols at ~1 ELF per transaction = ~1000 ELF total cost
- **Detection:** Attack is visible on-chain but difficult to prevent without protocol changes

**Attack Conditions:**
- More feasible on chains with many existing tokens
- More impactful when targeting schemes with `IsReleaseAllBalanceEveryTimeByDefault = true`
- Can be executed gradually over time to avoid detection
- Most dangerous when targeting critical protocol infrastructure

**Probability Assessment:**
**Medium-Low** likelihood overall. While technically simple and economically feasible for motivated attackers targeting high-value schemes (consensus pools worth disrupting), the upfront cost and sustained effort required reduce the probability for general profit schemes.

## Recommendation

**Short-term Mitigation:**
1. Add a maximum limit constant for `ReceivedTokenSymbols` size (e.g., 50-100 symbols)
2. Enforce this limit in `ContributeProfits()` and `DistributeProfitsForSubSchemes()`
3. Add access control to `ContributeProfits()` - restrict to scheme manager or whitelisted addresses

**Medium-term Solution:**
1. Implement pagination for symbol iteration in `DistributeProfits()`, `ProfitAllPeriods()`, and view methods
2. Add a cleanup mechanism to remove symbols with zero balance from the list
3. Consider requiring minimum contribution amounts per symbol to increase attack cost

**Example Fix for ContributeProfits:**
```csharp
public const int MaxReceivedTokenSymbols = 50;

public override Empty ContributeProfits(ContributeProfitsInput input)
{
    // ... existing validation ...
    
    if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol))
    {
        Assert(scheme.ReceivedTokenSymbols.Count < MaxReceivedTokenSymbols, 
            "Maximum token symbols limit reached.");
        scheme.ReceivedTokenSymbols.Add(input.Symbol);
    }
    
    // ... rest of method ...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ReceivedTokenSymbols_UnboundedGrowth_CausesDoS()
{
    // Setup: Create a profit scheme with IsReleaseAllBalanceEveryTimeByDefault = true
    var schemeId = await CreateTestSchemeAsync(isReleaseAllBalance: true);
    
    // Attack: Add 1000+ different token symbols
    for (int i = 0; i < 1000; i++)
    {
        var tokenSymbol = $"TOKEN{i}";
        
        // Create token if needed
        await CreateTokenAsync(tokenSymbol);
        
        // Contribute minimal amount to add symbol to ReceivedTokenSymbols
        await ProfitContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId,
            Symbol = tokenSymbol,
            Amount = 1,
            Period = 0
        });
    }
    
    // Verify: ReceivedTokenSymbols has 1000+ entries
    var scheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    Assert.True(scheme.ReceivedTokenSymbols.Count >= 1000);
    
    // DoS: Attempt to distribute profits - this will exceed gas limits
    var distributionResult = await ProfitContractStub.DistributeProfits.SendWithExceptionAsync(
        new DistributeProfitsInput
        {
            SchemeId = schemeId,
            Period = 1,
            AmountsMap = { } // Empty = iterate all symbols
        });
    
    // Expected: Transaction fails due to excessive gas consumption
    Assert.True(distributionResult.TransactionResult.Status == TransactionResultStatus.Failed);
    Assert.Contains("gas", distributionResult.TransactionResult.Error.ToLower());
}
```

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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L860-912)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L154-159)
```csharp
                scheme.ReceivedTokenSymbols.Select(s => State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = scheme.VirtualAddress,
                    Symbol = s
                })).ToDictionary(b => b.Symbol, b => b.Balance)
            }
```
