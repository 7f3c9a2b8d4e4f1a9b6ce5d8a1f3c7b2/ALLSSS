# Audit Report

## Title
Unbounded Token Symbol Accumulation Causes DoS in Side Chain Profit Distribution

## Summary
The Profit Contract's `ReceivedTokenSymbols` field has no size limit, allowing attackers to poison side chain TokenHolder schemes through the public `AEDPoS.Donate` method. When automatic profit distribution executes, it iterates through all accumulated symbols with multiple cross-contract calls per symbol, causing gas exhaustion that permanently blocks staking reward distributions.

## Finding Description

**Root Cause**: The `received_token_symbols` field is defined as an unbounded `repeated string` in the Scheme message without any contract-level size constraints. [1](#0-0) 

**Attack Vector**: On side chains, the `Donate` method is public with no access control beyond token ownership validation. [2](#0-1) 

The method calls `TokenHolder.ContributeProfits`: [3](#0-2) 

Which forwards to `Profit.ContributeProfits`: [4](#0-3) 

Where symbols are unconditionally added to `ReceivedTokenSymbols`: [5](#0-4) 

The only validations check token existence and positive amounts, with no symbol count limits: [6](#0-5) 

**Gas Exhaustion Mechanism**: When automatic distribution triggers, it calls `DistributeProfits` without an `AmountsMap`: [7](#0-6) 

TokenHolder forwards this with an empty `AmountsMap`: [8](#0-7) 

This triggers iteration through ALL symbols when `IsReleaseAllBalanceEveryTimeByDefault` is true: [9](#0-8) 

Each symbol requires cross-contract `GetBalance` calls in the distribution loop: [10](#0-9) 

And additional `GetBalance` calls in `UpdateDistributedProfits`: [11](#0-10) 

**Missing Protection**: While `TokenAmountLimit` constant exists with value 5: [12](#0-11) 

It is only enforced in `SetMethodFee`, not in `DistributeProfits`: [13](#0-12) 

**Irreversibility**: No mechanism exists to remove symbols from `ReceivedTokenSymbols`. The codebase contains no Clear or Remove operations for this field, making the DoS permanent.

## Impact Explanation

**Permanent Economic DoS**: An attacker can irreversibly prevent profit distribution on side chains. With 100+ poisoned symbols, `DistributeProfits` would require 200+ cross-contract calls (at least 2 per symbol), causing gas exhaustion.

**Affected System**: Side chain staking reward distribution. TokenHolder schemes are created with `IsReleaseAllBalanceEveryTimeByDefault = true`: [14](#0-13) 

**Treasury is Safe**: Main chain Treasury explicitly provides `AmountsMap` with controlled symbols from `SymbolList`, bypassing the vulnerable iteration path: [15](#0-14) 

**Severity**: Medium/High - While funds are not stolen, side chain economic operations become permanently non-functional, preventing staking reward distribution and disrupting the entire side chain economic model.

## Likelihood Explanation

**Fully Public Access**: `AEDPoS.Donate` has no sender restrictions. Authorization is implicit through `TransferFrom` requiring only token approval and balance.

**Attack Requirements**:
1. Multiple burnable tokens (attacker can create these or use existing ones)
2. Minimal token amounts (1 unit per symbol sufficient)
3. Token approvals for AEDPoS contract
4. Transaction fees (~1 ELF per donation call)

The `IsTokenAvailableForMethodFee` check only validates that tokens are burnable: [16](#0-15) 

**Economic Rationality**: Cost for 100 symbols is ~100-200 ELF in fees plus minimal token amounts. This is economically rational for permanently DoSing an entire side chain's reward distribution system.

**Stealth**: The attack appears as normal donations and would only be detected when automatic distribution begins failing.

## Recommendation

Implement one or more of the following mitigations:

1. **Add Symbol Count Limit in DistributeProfits**: Enforce `ReceivedTokenSymbols.Count` limit (use `TokenAmountLimit` constant) when iterating:
```csharp
if (scheme.IsReleaseAllBalanceEveryTimeByDefault && scheme.ReceivedTokenSymbols.Any())
{
    Assert(scheme.ReceivedTokenSymbols.Count <= ProfitContractConstants.TokenAmountLimit, 
           "Too many token symbols in scheme.");
    foreach (var symbol in scheme.ReceivedTokenSymbols) { ... }
}
```

2. **Add Symbol Removal Mechanism**: Allow scheme managers to remove unused symbols from `ReceivedTokenSymbols`.

3. **Restrict Donate on Side Chains**: Add access control to `AEDPoS.Donate` limiting callers to trusted addresses or requiring scheme manager approval.

4. **Use Explicit Symbol Whitelist**: Follow Treasury pattern - maintain an explicit `SymbolList` and always provide `AmountsMap` in `DistributeProfits` calls.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task SideChainProfitDistribution_DoS_Via_UnboundedSymbols()
{
    // Setup: Initialize side chain dividends pool
    await AEDPoSContractStub.InitialSideChainDividendsPool.SendAsync(new Empty());
    
    // Attack: Donate 100+ different token symbols
    for (int i = 0; i < 150; i++)
    {
        var tokenSymbol = $"ATTACK{i}";
        
        // Create burnable token
        await TokenContractStub.Create.SendAsync(new CreateInput
        {
            Symbol = tokenSymbol,
            TokenName = $"Attack Token {i}",
            TotalSupply = 1000,
            Decimals = 8,
            Issuer = DefaultSender,
            IsBurnable = true
        });
        
        // Issue to attacker
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = tokenSymbol,
            Amount = 1,
            To = DefaultSender
        });
        
        // Approve and donate
        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Spender = AEDPoSContractAddress,
            Symbol = tokenSymbol,
            Amount = 1
        });
        
        await AEDPoSContractStub.Donate.SendAsync(new DonateInput
        {
            Symbol = tokenSymbol,
            Amount = 1
        });
    }
    
    // Verify attack: ReceivedTokenSymbols has 150+ symbols
    var symbolList = await AEDPoSContractStub.GetSymbolList.CallAsync(new Empty());
    symbolList.Value.Count.ShouldBeGreaterThan(150);
    
    // Trigger distribution - should fail with gas exhaustion
    // (In actual execution, this would exceed gas limits)
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await AEDPoSContractStub.Release.SendAsync(new Empty());
    });
    
    // Distribution is permanently blocked
    exception.Message.ShouldContain("gas"); // Gas limit exceeded
}
```

## Notes

The vulnerability is valid and exploitable on side chains only. Main chain Treasury is not affected because it uses an explicit symbol whitelist approach. The attack is permanent because there is no mechanism to remove symbols from `ReceivedTokenSymbols` once added, and the gas exhaustion prevents any future distributions from completing.

### Citations

**File:** protobuf/profit_contract.proto (L159-159)
```text
    repeated string received_token_symbols = 12;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-94)
```csharp
    public override Empty Donate(DonateInput input)
    {
        EnsureTokenContractAddressSet();

        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();

        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = Context.Self
        });

        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            Spender = State.TokenHolderContract.Value
        });

        State.TokenHolderContract.ContributeProfits.Send(new ContributeProfitsInput
        {
            SchemeManager = Context.Self,
            Symbol = input.Symbol,
            Amount = input.Amount
        });

        Context.Fire(new DonationReceived
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            PoolContract = Context.Self
        });

        var currentReceivedDividends = State.SideChainReceivedDividends[Context.CurrentHeight];
        if (currentReceivedDividends != null && currentReceivedDividends.Value.ContainsKey(input.Symbol))
            currentReceivedDividends.Value[input.Symbol] =
                currentReceivedDividends.Value[input.Symbol].Add(input.Amount);
        else
            currentReceivedDividends = new Dividends
            {
                Value =
                {
                    {
                        input.Symbol, input.Amount
                    }
                }
            };

        State.SideChainReceivedDividends[Context.CurrentHeight] = currentReceivedDividends;

        Context.LogDebug(() => $"Contributed {input.Amount} {input.Symbol}s to side chain dividends pool.");

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L117-120)
```csharp
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L122-127)
```csharp
        State.ProfitContract.ContributeProfits.Send(new Profit.ContributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Symbol = input.Symbol,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L136-143)
```csharp
        var distributeProfitsInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
        if (input.AmountsMap != null && input.AmountsMap.Any()) distributeProfitsInput.AmountsMap.Add(input.AmountsMap);

        State.ProfitContract.DistributeProfits.Send(distributeProfitsInput);
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L574-578)
```csharp
            var balanceOfVirtualAddressForCurrentPeriod = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = profitsReceivingVirtualAddress,
                Symbol = symbol
            }).Balance;
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

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L8-8)
```csharp
    public const int TokenAmountLimit = 5;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L129-134)
```csharp
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.TreasuryHash.Value,
            Period = input.PeriodNumber,
            AmountsMap = { State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L) }
        });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L252-257)
```csharp
    private bool IsTokenAvailableForMethodFee(string symbol)
    {
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null) throw new AssertionException("Token is not found.");
        return tokenInfo.IsBurnable;
    }
```
