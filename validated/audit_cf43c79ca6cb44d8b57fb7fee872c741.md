# Audit Report

## Title
Accounting Error: SymbolList Mismatch Causes Donated Tokens to Be Stuck in Treasury

## Summary
The Treasury contract accepts donations of any burnable token without validating against `SymbolList`, while the `Release` function only distributes tokens present in `SymbolList`. This architectural mismatch causes donated tokens excluded from or removed from `SymbolList` to accumulate permanently in the treasury without distribution, resulting in fund loss for beneficiaries and accounting discrepancies.

## Finding Description

The vulnerability stems from a critical validation mismatch between donation acceptance and distribution logic in the Treasury contract.

**Donation Acceptance - No SymbolList Validation**

The `Donate` function only validates that a token is burnable by checking `IsTokenAvailableForMethodFee`, which simply returns `tokenInfo.IsBurnable`. [1](#0-0)  There is no validation against `SymbolList` during donation acceptance. [2](#0-1) 

For non-convertible tokens (those not sellable via TokenConverter), the donation proceeds directly to contribute to the profit scheme without any SymbolList check. [3](#0-2) 

**Distribution Logic - Only SymbolList Tokens**

The `Release` function creates an `AmountsMap` exclusively from `SymbolList`, meaning only tokens in this list will be distributed. [4](#0-3) 

All sub-scheme distributions also create their `AmountsMap` from `SymbolList` only. [5](#0-4) 

**Profit Contract Distribution**

The Profit contract's `DistributeProfits` processes only symbols present in the input `AmountsMap`, building a `profitsMap` from the provided amounts. [6](#0-5)  Symbols not in the map are never distributed. [7](#0-6) 

**Accounting Query Gap**

The `GetUndistributedDividends` function also queries balances only for symbols in `SymbolList`, making non-listed tokens invisible to accounting. [8](#0-7) 

**Insufficient SetSymbolList Validation**

While `SetSymbolList` validates that the native token is included and that non-native tokens are burnable or whitelisted, [9](#0-8)  there is no validation preventing removal of tokens that have existing donated balances in the treasury.

## Impact Explanation

**HIGH Severity** - This vulnerability causes permanent fund loss and breaks critical treasury accounting invariants:

1. **Permanent Fund Loss**: Donated tokens not in `SymbolList` accumulate in the treasury's virtual address but are never distributed to beneficiaries (miners, citizens, backup nodes). There is no administrative recovery mechanism to extract these stuck tokens.

2. **Accounting Discrepancy**: The actual treasury balance exceeds the reported undistributed balance from `GetUndistributedDividends`, violating the accounting invariant that all donated funds should be distributable.

3. **Affected Parties**:
   - Donors lose their contributed tokens
   - Beneficiaries (miners, voters, backup nodes) lose rightful dividend distributions
   - Treasury accounting becomes unreliable for protocol economics

4. **Protocol Economics Impact**: This affects the core reward distribution mechanism for AElf consensus participants, potentially undermining network incentives.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability can be triggered through normal protocol operations without malicious intent:

**Attack Complexity: LOW**
1. Token X must be burnable (available for method fees)
2. Token X must not be convertible to native via TokenConverter  
3. Either: Token X is never added to `SymbolList`, OR Token X is removed from `SymbolList` after receiving donations

**Feasibility: HIGHLY FEASIBLE**
- Multiple tokens on AElf are likely burnable (method fee eligible) but not all are in `SymbolList`
- Governance regularly updates `SymbolList` for legitimate policy reasons (token deprecation, adding new tokens)
- No validation prevents donation of non-listed tokens
- No validation prevents removal of tokens with existing balances

**Realistic Scenarios**:
1. A new burnable token is created but not added to treasury `SymbolList` - users can still donate it
2. Governance decides to deprecate a token and removes it from `SymbolList` - all accumulated donations become stuck
3. Human error during `SymbolList` updates accidentally removes active tokens

This can easily occur accidentally during normal treasury governance operations.

## Recommendation

Implement comprehensive validation to prevent the SymbolList mismatch:

**1. Add SymbolList validation in Donate function:**
```csharp
public override Empty Donate(DonateInput input)
{
    Assert(input.Amount > 0, "Invalid amount of donating. Amount needs to be greater than 0.");
    
    // Add validation that token must be in SymbolList or native
    Assert(
        input.Symbol == Context.Variables.NativeSymbol || 
        State.SymbolList.Value.Value.Contains(input.Symbol),
        "Token must be in SymbolList to be donated.");
    
    // ... rest of function
}
```

**2. Add balance check in SetSymbolList:**
```csharp
public override Empty SetSymbolList(SymbolList input)
{
    AssertPerformedByTreasuryController();
    Assert(input.Value.Contains(Context.Variables.NativeSymbol), "Need to contain native symbol.");
    
    // Validate no token with existing balance is being removed
    var removedSymbols = State.SymbolList.Value.Value.Except(input.Value).ToList();
    foreach (var symbol in removedSymbols)
    {
        var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
        {
            Owner = State.TreasuryVirtualAddress.Value,
            Symbol = symbol
        }).Balance;
        Assert(balance == 0, 
            $"Cannot remove {symbol} from SymbolList while treasury has {balance} balance.");
    }
    
    // ... rest of validation
}
```

**3. Add emergency withdrawal function for recovery:**
```csharp
public override Empty WithdrawStuckTokens(WithdrawStuckTokensInput input)
{
    AssertPerformedByTreasuryController();
    
    // Only allow withdrawal of tokens NOT in SymbolList
    Assert(!State.SymbolList.Value.Value.Contains(input.Symbol),
        "Cannot withdraw tokens in SymbolList - use Release instead.");
    
    State.TokenContract.TransferFrom.Send(new TransferFromInput
    {
        From = State.TreasuryVirtualAddress.Value,
        To = input.Recipient,
        Symbol = input.Symbol,
        Amount = input.Amount
    });
    
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DonateToken_NotInSymbolList_GetsPermanentlyStuck()
{
    // Setup: Create a burnable token NOT in SymbolList
    await TokenContractStub.Create.SendAsync(new CreateInput
    {
        Symbol = "STUCK",
        TokenName = "Stuck Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true, // Important: token is burnable
        IssueChainId = ChainId
    });
    
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "STUCK",
        Amount = 100000,
        To = DefaultSender
    });
    
    // Verify STUCK is NOT in SymbolList
    var symbolList = await TreasuryContractStub.GetSymbolList.CallAsync(new Empty());
    Assert.DoesNotContain("STUCK", symbolList.Value);
    
    // User donates STUCK tokens - this should fail but doesn't
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Spender = TreasuryContractAddress,
        Symbol = "STUCK",
        Amount = 1000
    });
    
    await TreasuryContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = "STUCK",
        Amount = 1000
    });
    
    // Verify tokens are in treasury virtual address
    var treasuryBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = TreasuryVirtualAddress,
        Symbol = "STUCK"
    });
    Assert.Equal(1000, treasuryBalance.Balance);
    
    // Trigger Release
    await TreasuryContractStub.Release.SendAsync(new ReleaseInput
    {
        PeriodNumber = 2
    });
    
    // VULNERABILITY: Tokens still stuck in treasury after Release
    var balanceAfterRelease = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = TreasuryVirtualAddress,
        Symbol = "STUCK"
    });
    Assert.Equal(1000, balanceAfterRelease.Balance); // Still stuck!
    
    // VULNERABILITY: GetUndistributedDividends doesn't show STUCK tokens
    var undistributed = await TreasuryContractStub.GetUndistributedDividends.CallAsync(new Empty());
    Assert.DoesNotContain("STUCK", undistributed.Value.Keys); // Invisible to accounting!
}
```

## Notes

This vulnerability represents a critical flaw in the Treasury contract's donation/distribution architecture. The lack of synchronization between donation acceptance criteria and distribution logic creates a permanent fund trap. The issue is exacerbated by the absence of recovery mechanisms and incomplete accounting queries, making stuck funds both unrecoverable and invisible to standard treasury reporting.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L252-257)
```csharp
    private bool IsTokenAvailableForMethodFee(string symbol)
    {
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null) throw new AssertionException("Token is not found.");
        return tokenInfo.IsBurnable;
    }
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L181-182)
```csharp
        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L209-223)
```csharp
        else
        {
            State.TokenContract.Approve.Send(new ApproveInput
            {
                Symbol = input.Symbol,
                Amount = input.Amount,
                Spender = State.ProfitContract.Value
            });

            State.ProfitContract.ContributeProfits.Send(new ContributeProfitsInput
            {
                SchemeId = State.TreasuryHash.Value,
                Symbol = input.Symbol,
                Amount = input.Amount
            });
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L285-303)
```csharp
        Assert(input.Value.Contains(Context.Variables.NativeSymbol), "Need to contain native symbol.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        if (State.TokenConverterContract.Value == null)
            State.TokenConverterContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenConverterContractSystemName);

        foreach (var symbol in input.Value.Where(s => s != Context.Variables.NativeSymbol))
        {
            var isTreasuryInWhiteList = State.TokenContract.IsInWhiteList.Call(new IsInWhiteListInput
            {
                Symbol = symbol,
                Address = Context.Self
            }).Value;
            Assert(
                State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value ||
                isTreasuryInWhiteList, "Symbol need to be profitable.");
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L367-380)
```csharp
    public override Dividends GetUndistributedDividends(Empty input)
    {
        return new Dividends
        {
            Value =
            {
                State.SymbolList.Value.Value.Select(s => State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = State.TreasuryVirtualAddress.Value,
                    Symbol = s
                })).ToDictionary(b => b.Symbol, b => b.Balance)
            }
        };
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L707-713)
```csharp
        var amountsMap = State.SymbolList.Value.Value.ToDictionary(s => s, s => 0L);
        State.ProfitContract.DistributeProfits.Send(new DistributeProfitsInput
        {
            SchemeId = State.RewardHash.Value,
            Period = termNumber,
            AmountsMap = { amountsMap }
        });
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L433-446)
```csharp
        if (input.AmountsMap.Any())
        {
            foreach (var amount in input.AmountsMap)
            {
                var actualAmount = amount.Value == 0
                    ? State.TokenContract.GetBalance.Call(new GetBalanceInput
                    {
                        Owner = scheme.VirtualAddress,
                        Symbol = amount.Key
                    }).Balance
                    : amount.Value;
                profitsMap.Add(amount.Key, actualAmount);
            }
        }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L588-603)
```csharp
        foreach (var profits in profitsMap)
        {
            var symbol = profits.Key;
            var amount = profits.Value;
            var remainAmount = DistributeProfitsForSubSchemes(symbol, amount, scheme, totalShares);
            Context.LogDebug(() => $"Distributing {remainAmount} {symbol} tokens.");
            // Transfer remain amount to individuals' receiving profits address.
            if (remainAmount != 0)
                Context.SendVirtualInline(scheme.SchemeId, State.TokenContract.Value,
                    nameof(State.TokenContract.Transfer), new TransferInput
                    {
                        To = profitsReceivingVirtualAddress,
                        Amount = remainAmount,
                        Symbol = symbol
                    }.ToByteString());
        }
```
