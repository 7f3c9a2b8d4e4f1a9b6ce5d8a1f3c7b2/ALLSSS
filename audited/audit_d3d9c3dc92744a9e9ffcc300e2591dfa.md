# Audit Report

## Title
Unbounded ReceivedTokenSymbols Growth Enables DoS of Side Chain Dividend Distribution

## Summary
An attacker can donate dust amounts across thousands of different burnable token symbols to inflate the `ReceivedTokenSymbols` list without limit. When `Release()` is automatically called during consensus operations, it must iterate over all symbols and perform cross-contract balance queries for each, causing execution to exceed AElf's 15,000 method call limit and permanently disabling dividend distribution on side chains.

## Finding Description

The vulnerability exists in the interaction between the donation mechanism and automatic release logic for side chain dividend pools.

**Entry Point - Unrestricted Symbol Addition:**

The `Donate()` function only validates that a token is burnable but places no limit on the number of unique symbols that can be donated. [1](#0-0) 

The validation merely checks `IsTokenAvailableForMethodFee`, which only verifies the token has `IsBurnable` property set to true. [2](#0-1) 

Each donation flows to `TokenHolderContract.ContributeProfits` which calls `ProfitContract.ContributeProfits`, where new symbols are unconditionally added to `ReceivedTokenSymbols` without any limit check. [3](#0-2) 

**Automatic Release Trigger:**

On side chains, `Release()` is called automatically after every consensus update (UpdateValue, NextRound, NextTerm, TinyBlock) when round number exceeds 1. [4](#0-3) 

**Gas Exhaustion Path:**

The `Release()` method triggers `TokenHolderContract.DistributeProfits`. [5](#0-4) 

The TokenHolder scheme is created with `IsReleaseAllBalanceEveryTimeByDefault=true`. [6](#0-5) 

When `ProfitContract.DistributeProfits` executes with this flag and an empty `AmountsMap`, it iterates over ALL `ReceivedTokenSymbols` and performs a cross-contract `GetBalance` call for each symbol. [7](#0-6) 

Similarly, `GetUndistributedDividends()` suffers the same issue by iterating over all symbols and calling `GetBalance` for each. [8](#0-7) 

**No Protection Mechanisms:**

The side chain dividend pool explicitly disables manual symbol list management through `SetSymbolList()`. [9](#0-8) 

AElf enforces a 15,000 method call limit per transaction to prevent infinite loops. [10](#0-9) 

## Impact Explanation

**Severity: High - Permanent DoS of Side Chain Consensus and Economic System**

**Direct Operational Impact:**
- Side chain dividend distribution becomes permanently disabled once symbol count exceeds ~7,500 (considering each `GetBalance` call as a cross-contract invocation that increments the method call counter multiple times)
- Since `Release()` is called automatically after every consensus update, consensus operations will fail when the method call limit is exceeded
- All side chain participants lose access to staking dividends indefinitely

**Economic Damage:**
- Accumulated dividends from transaction fees and mining rewards become permanently locked in the dividend pool
- Token holders cannot claim their rightful profit distributions
- Side chain economic incentive model breaks down entirely

**Systemic Risk:**
- Affects the entire side chain, not individual users
- No recovery mechanism exists - `SetSymbolList()` is explicitly disabled for side chains and symbols cannot be removed from `ReceivedTokenSymbols` once added
- Attack cannot be reversed without a contract upgrade requiring governance approval

**Affected Parties:**
- All side chain token holders expecting dividends
- Side chain miners relying on dividend pool rewards
- Side chain validators who may experience consensus disruption

## Likelihood Explanation

**Likelihood: High - Attack is Practical and Economically Rational**

**Attacker Capabilities:**
- Any user can call the public `Donate()` method without special permissions
- Attacker can create their own burnable tokens with zero cost (by creating tokens with `IsBurnable=true` and minting to themselves)
- Alternatively, attacker can use existing burnable tokens in the ecosystem

**Attack Complexity:**
- Low complexity: Simple repeated donations of minimal amounts (1 wei) across different token symbols
- No special permissions or governance control required
- No timing constraints or race conditions involved
- Attack can be executed with a simple script iterating over token creations and donations

**Economic Feasibility:**
- Cost to create N burnable tokens: N × transaction_fee (minimal)
- Cost to donate: N × (transaction_fee + 1 wei per token) 
- For 10,000 symbols, total cost is roughly 10,000-20,000 transaction fees
- Return: Permanent disruption of entire side chain dividend system (highly asymmetric impact)

**Detection Constraints:**
- Attack can be executed gradually over time to avoid detection
- Each individual donation appears legitimate in isolation
- No immediate visible impact until `Release()` is called with a large symbol count
- Monitoring `ReceivedTokenSymbols` length is possible but may not be standard practice

**Execution Practicality:**
- Attack can be scripted and fully automated
- No coordination with other parties needed
- Works under normal AElf contract execution model
- Does not rely on any edge cases or race conditions

## Recommendation

Implement a maximum limit on the number of unique token symbols that can be added to `ReceivedTokenSymbols`:

1. Add a configurable constant for maximum symbol count (e.g., 100-200 symbols should be sufficient for legitimate use)
2. In `ProfitContract.ContributeProfits`, check the symbol count before adding new symbols
3. Reject donations that would exceed this limit with a clear error message
4. Alternatively, implement pagination in `DistributeProfits` to process symbols in batches within the call limit

Additionally, consider enabling `SetSymbolList` for side chains with appropriate governance controls, allowing removal of unused or malicious token symbols.

## Proof of Concept

```csharp
[Fact]
public async Task SideChainDividendPool_UnboundedSymbols_DoS_Test()
{
    // Setup: Initialize side chain consensus with token holder contract
    await InitializeSideChainConsensus();
    
    // Create and donate many unique burnable tokens
    const int symbolCount = 10000;
    
    for (int i = 0; i < symbolCount; i++)
    {
        var symbol = $"TEST{i}";
        
        // Create burnable token
        await TokenContractStub.Create.SendAsync(new CreateInput
        {
            Symbol = symbol,
            TokenName = $"Test Token {i}",
            TotalSupply = 1000000,
            Decimals = 8,
            Issuer = DefaultSender,
            IsBurnable = true
        });
        
        // Mint tokens to attacker
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = symbol,
            Amount = 1,
            To = DefaultSender
        });
        
        // Approve consensus contract
        await TokenContractStub.Approve.SendAsync(new ApproveInput
        {
            Symbol = symbol,
            Amount = 1,
            Spender = AEDPoSContractAddress
        });
        
        // Donate dust amount
        await AEDPoSContractStub.Donate.SendAsync(new DonateInput
        {
            Symbol = symbol,
            Amount = 1
        });
    }
    
    // Trigger consensus update which calls Release() automatically
    // This should fail due to exceeding the 15,000 method call limit
    var result = await AEDPoSContractStub.UpdateValue.SendAsync(new UpdateValueInput
    {
        // ... consensus update parameters
    });
    
    // Verify the transaction failed due to method call threshold
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("RuntimeCallThresholdExceededException");
}
```

## Notes

This vulnerability represents a critical design flaw where unbounded state growth in `ReceivedTokenSymbols` combined with automatic iteration during consensus operations creates a permanent denial-of-service vector. The attack is particularly severe because:

1. It affects side chains specifically, which rely on automatic dividend distribution
2. The lack of symbol count limits makes the attack trivially executable
3. The disabled `SetSymbolList` method prevents any recovery mechanism
4. The automatic triggering via consensus operations ensures the DoS persists indefinitely

The fix requires both preventing unbounded growth (input validation) and potentially adding recovery mechanisms (governance-controlled symbol list management for side chains).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-42)
```csharp
    public override Empty Donate(DonateInput input)
    {
        EnsureTokenContractAddressSet();

        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L117-120)
```csharp
            State.TokenHolderContract.DistributeProfits.Send(new DistributeProfitsInput
            {
                SchemeManager = Context.Self
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L124-128)
```csharp
    public override Empty SetSymbolList(SymbolList input)
    {
        Assert(false, "Side chain dividend pool not support setting symbol list.");
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L147-160)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L715-717)
```csharp
        // If someone directly use virtual address to do the contribution, won't sense the token symbol he was using.
        if (!scheme.ReceivedTokenSymbols.Contains(input.Symbol)) scheme.ReceivedTokenSymbols.Add(input.Symbol);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L83-83)
```csharp
        if (!State.IsMainChain.Value && currentRound.RoundNumber > 1) Release();
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```
