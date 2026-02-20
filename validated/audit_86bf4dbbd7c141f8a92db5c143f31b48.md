# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables State Bloat and Iteration DoS on Profit Schemes

## Summary
The `ReceivedTokenSymbols` list in profit schemes has no size limit and can be populated by any user through the permissionless `ContributeProfits()` function. When this list grows large (1000+ symbols), operations that iterate over all symbols exceed gas limits, causing operational denial-of-service for scheme managers attempting to distribute profits and beneficiaries attempting to claim rewards. Critical infrastructure schemes like the consensus dividend pool are particularly vulnerable.

## Finding Description

The `ReceivedTokenSymbols` field is defined as an unbounded repeated field in the Scheme message structure [1](#0-0) , with no size constraint enforced in the protocol. This list is populated by the `ContributeProfits()` function, which adds symbols without any bound check [2](#0-1) .

The attack vector is the permissionless `ContributeProfits()` function which has no access control restrictions [3](#0-2) . The only validation performed is a token existence check [4](#0-3) . Any user can contribute minimal amounts of any existing token to any scheme, causing that token symbol to be added to `ReceivedTokenSymbols`.

The `TokenAmountLimit` constant exists [5](#0-4)  but only applies to method fee configuration [6](#0-5) , not to the `ReceivedTokenSymbols` list.

**DoS Attack Vectors:**

1. **DistributeProfits()**: When `IsReleaseAllBalanceEveryTimeByDefault` is true and no specific amounts are provided, the function iterates over ALL symbols and makes external `GetBalance` calls for each [7](#0-6) .

2. **ProfitAllPeriods()**: Used during profit claiming and calculations, iterates over all symbols unless a specific target symbol is provided [8](#0-7) .

3. **GetUndistributedDividends() in AEDPoS**: Critical consensus functionality that iterates all symbols to calculate undistributed dividends for the consensus dividend pool [9](#0-8) .

Critical system contracts are vulnerable as they create schemes with `IsReleaseAllBalanceEveryTimeByDefault = true`: the Treasury contract [10](#0-9)  and TokenHolder contract [11](#0-10) .

An attacker can systematically contribute dust amounts (e.g., 1 unit) of different token symbols to a target profit scheme. After adding 1000+ symbols, operations that iterate the entire list will consume excessive gas, potentially exceeding block limits and rendering the scheme inoperable.

## Impact Explanation

**Operational Denial-of-Service:**
- Scheme managers become unable to call `DistributeProfits()` when gas costs exceed block limits
- Beneficiaries cannot claim profits via `ClaimProfits()` or query profit amounts via view methods [12](#0-11) 
- Critical schemes like the consensus dividend pool could become completely non-operational, disrupting validator rewards and network economic incentives

**State Bloat:**
- Each token symbol increases the state size of the Scheme object
- State bloat is permanent with no cleanup mechanism
- Increases storage costs for all nodes

**Affected Parties:**
- Scheme managers attempting to distribute profits
- Beneficiaries attempting to claim rewards
- Protocol consensus infrastructure if the dividend pool is targeted
- Any high-value or critical profit scheme

The severity is assessed as **Low** primarily due to the economic cost barrier (attacker must pay transaction fees for each contribution). However, for critical infrastructure schemes like consensus rewards, the impact could be more severe, potentially warranting **Medium** severity.

## Likelihood Explanation

**Attack Feasibility:**
- Low technical complexity: repeatedly call `ContributeProfits()` with different token symbols
- No special permissions required
- Can be executed gradually over time
- Token symbols must exist, but token creation is also permissionless in AElf

**Economic Cost:**
- Attack cost: N × (transaction_fee + minimal_token_amount)
- For N=1000 symbols, economically feasible for a motivated attacker
- Higher incentive when targeting critical infrastructure schemes

**Detection:**
- Attack is detectable through monitoring contribution patterns
- However, contributions are legitimate transactions and difficult to prevent without protocol changes
- No automatic cleanup mechanism exists

**Probability:** Medium-Low. While technically feasible and economically rational for high-value targets (especially consensus dividend pool), it requires sustained effort and upfront transaction costs.

## Recommendation

Add a maximum symbol count limit to the `ReceivedTokenSymbols` list in the `ContributeProfits()` function:

```csharp
public override Empty ContributeProfits(ContributeProfitsInput input)
{
    // Existing validations
    AssertTokenExists(input.Symbol);
    Assert(input.Amount > 0, "Amount need to greater than 0.");
    
    var scheme = State.SchemeInfos[input.SchemeId];
    Assert(scheme != null, "Scheme not found.");
    
    // Add limit check before adding new symbol
    if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol))
    {
        Assert(scheme.ReceivedTokenSymbols.Count < ProfitContractConstants.MaxReceivedTokenSymbols,
            "Maximum token symbol limit reached.");
        scheme.ReceivedTokenSymbols.Add(input.Symbol);
    }
    
    // Rest of the function...
}
```

Also add the constant in `ProfitContractConstants.cs`:
```csharp
public const int MaxReceivedTokenSymbols = 100; // Or appropriate limit
```

Alternatively, implement pagination for symbol iteration in `DistributeProfits()`, `ProfitAllPeriods()`, and `GetUndistributedDividends()` to prevent gas exhaustion.

## Proof of Concept

```csharp
[Fact]
public async Task ContributeProfits_UnboundedSymbols_CausesDoS()
{
    // Create a profit scheme
    var schemeId = await ProfitContractStub.CreateScheme.SendAsync(new CreateSchemeInput
    {
        IsReleaseAllBalanceEveryTimeByDefault = true
    });
    
    // Attacker contributes 1000+ different token symbols
    for (int i = 0; i < 1000; i++)
    {
        var tokenSymbol = $"TOKEN{i}";
        
        // Create token (if not exists)
        await TokenContractStub.Create.SendAsync(new CreateInput
        {
            Symbol = tokenSymbol,
            TokenName = $"Test Token {i}",
            TotalSupply = 1000000,
            Decimals = 8,
            Issuer = DefaultSender
        });
        
        // Contribute minimal amount to add symbol to ReceivedTokenSymbols
        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Spender = ProfitContractAddress,
            Symbol = tokenSymbol,
            Amount = 1
        });
        
        await ProfitContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId.Output,
            Symbol = tokenSymbol,
            Amount = 1
        });
    }
    
    // Attempt to distribute profits - should fail or consume excessive gas
    var result = await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId.Output,
        Period = 1
    });
    
    // Transaction fails or consumes excessive gas due to iteration over 1000 symbols
    Assert.True(result.TransactionResult.Status == TransactionResultStatus.Failed || 
                result.TransactionResult.GasConsumed > AcceptableGasLimit);
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

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L8-8)
```csharp
    public const int TokenAmountLimit = 5;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L14-14)
```csharp
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L60-62)
```csharp
            State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
            {
                IsReleaseAllBalanceEveryTimeByDefault = true,
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-23)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L130-133)
```csharp
            var totalProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, profitDetail.EndPeriod.Sub(profitDetail.LastProfitPeriod),true, symbol);
            AddProfitToDict(allProfitsDict, totalProfitsDictForEachProfitDetail);
            if(i >= profitableDetailCount) continue;
            var claimableProfitsDictForEachProfitDetail = ProfitAllPeriods(scheme, profitDetail, beneficiary, maxProfitReceivingPeriodCount,true, symbol);
```
