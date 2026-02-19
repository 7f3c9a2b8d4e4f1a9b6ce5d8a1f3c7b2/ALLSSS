# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables State Bloat and Iteration DoS on Profit Schemes

## Summary
The `ReceivedTokenSymbols` list in profit schemes has no size limit and can be populated by any user through the permissionless `ContributeProfits()` function. When this list grows large (1000+ symbols), operations that iterate over all symbols exceed gas limits, causing operational denial-of-service for scheme managers attempting to distribute profits and beneficiaries attempting to claim rewards. Critical infrastructure schemes like the consensus dividend pool are particularly vulnerable.

## Finding Description

The `ReceivedTokenSymbols` field tracks all unique token symbols contributed to a profit scheme. [1](#0-0)  This list is populated without any bound check when tokens are contributed. [2](#0-1) 

The attack vector is the permissionless `ContributeProfits()` function which has no access control restrictions. [3](#0-2)  The only validation performed is a token existence check. [4](#0-3)  Any user can contribute minimal amounts of any existing token to any scheme, causing that token symbol to be added to `ReceivedTokenSymbols`.

The `TokenAmountLimit` constant exists but only applies to method fee configuration, not to the `ReceivedTokenSymbols` list. [5](#0-4) [6](#0-5) 

**DoS Attack Vectors:**

1. **DistributeProfits()**: When `IsReleaseAllBalanceEveryTimeByDefault` is true and no specific amounts are provided, the function iterates over ALL symbols and makes external `GetBalance` calls for each. [7](#0-6) 

2. **ProfitAllPeriods()**: Used during profit claiming and calculations, iterates over all symbols unless a specific target symbol is provided. [8](#0-7) 

3. **GetUndistributedDividends() in AEDPoS**: Critical consensus functionality that iterates all symbols to calculate undistributed dividends for the consensus dividend pool. [9](#0-8) 

An attacker can systematically contribute dust amounts (e.g., 1 unit) of different token symbols to a target profit scheme. After adding 1000+ symbols, operations that iterate the entire list will consume excessive gas, potentially exceeding block limits and rendering the scheme inoperable.

## Impact Explanation

**Operational Denial-of-Service:**
- Scheme managers become unable to call `DistributeProfits()` when gas costs exceed block limits
- Beneficiaries cannot claim profits or query profit amounts
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

1. **Implement Maximum Symbol Limit**: Add a maximum size constraint to `ReceivedTokenSymbols` (e.g., 50-100 symbols)
   
2. **Add Access Control**: Restrict `ContributeProfits()` to authorized addresses (scheme manager or whitelisted contributors)

3. **Implement Pagination**: For operations that iterate over symbols, add pagination mechanisms to process symbols in batches

4. **Add Symbol Cleanup**: Implement a mechanism to remove symbols with zero balance from the list

5. **Use Explicit Symbol Specification**: Require callers to specify which token symbols to process rather than defaulting to all symbols

Example mitigation:
```csharp
// In ProfitContract.cs - ContributeProfits method
const int MaxReceivedTokenSymbols = 100;

if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol))
{
    Assert(scheme.ReceivedTokenSymbols.Count < MaxReceivedTokenSymbols, 
        $"Maximum number of token symbols ({MaxReceivedTokenSymbols}) exceeded.");
    scheme.ReceivedTokenSymbols.Add(input.Symbol);
}
```

## Proof of Concept

```csharp
// This test demonstrates the unbounded growth vulnerability
[Fact]
public async Task ContributeProfits_UnboundedSymbolGrowth_Test()
{
    // Create a profit scheme
    var schemeId = await CreateDefaultScheme();
    
    // Attacker repeatedly contributes different token symbols
    const int attackSymbolCount = 100; // In production, 1000+ would cause DoS
    
    for (int i = 0; i < attackSymbolCount; i++)
    {
        // Create a new token for each iteration
        string tokenSymbol = $"TOKEN{i}";
        await CreateToken(tokenSymbol);
        
        // Contribute minimal amount to add symbol to ReceivedTokenSymbols
        await ProfitContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeId = schemeId,
            Symbol = tokenSymbol,
            Amount = 1 // Dust amount
        });
    }
    
    // Verify scheme now has many symbols
    var scheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
    scheme.ReceivedTokenSymbols.Count.ShouldBe(attackSymbolCount);
    
    // Attempting to distribute profits now iterates all symbols
    // With 1000+ symbols, this would exceed gas limits
    var result = await ProfitContractStub.DistributeProfits.SendAsync(new DistributeProfitsInput
    {
        SchemeId = schemeId,
        Period = 1
    });
    // In production with sufficient symbols, this transaction would fail due to gas exhaustion
}
```

## Notes

This vulnerability represents a resource exhaustion attack on the Profit contract's state management. While the economic cost provides some deterrent, the impact on critical infrastructure schemes (particularly the consensus dividend pool) elevates the practical severity. The lack of any size limits or access controls on `ContributeProfits()` combined with unbounded iteration over `ReceivedTokenSymbols` creates a realistic DoS vector that could disrupt core protocol functionality.

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
