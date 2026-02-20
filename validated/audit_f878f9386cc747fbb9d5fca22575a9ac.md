# Audit Report

## Title
Auto-Distribution Break Statement Prevents Multiple Token Threshold Checks in TokenHolder Contract

## Summary
The `RegisterForProfits` function in the TokenHolder contract contains an unconditional `break` statement that exits the auto-distribution threshold checking loop after processing only the first qualifying token, preventing subsequent tokens from being evaluated and distributed in multi-token profit schemes.

## Finding Description

The TokenHolder contract's `RegisterForProfits` function implements auto-distribution logic to trigger profit distribution when token balances exceed configured thresholds. The function iterates through the `AutoDistributeThreshold` map to check each token's balance. [1](#0-0) 

The critical flaw occurs when a qualifying token is found. After adding the first token that meets its threshold to `distributedInput.AmountsMap`, an unconditional `break` statement immediately exits the foreach loop, preventing evaluation of remaining tokens. [2](#0-1) 

The `AutoDistributeThreshold` field is explicitly defined as `map<string, int64>` in the protobuf schema, designed to support multiple token symbols with different threshold values. [3](#0-2) [4](#0-3) 

The downstream `DistributeProfits` function in the Profit contract only processes tokens explicitly listed in the `AmountsMap` parameter. When `AmountsMap` contains entries, it iterates through them exclusively. [5](#0-4) 

Tokens not added to `AmountsMap` due to the premature loop exit will not be distributed, even when their balances exceed configured thresholds.

## Impact Explanation

**Reward Misallocation:** When multiple token types accumulate in a profit scheme's virtual address and multiple thresholds are simultaneously met, only the first token encountered in the dictionary iteration will be auto-distributed. Other qualifying tokens remain in the virtual address without automatic distribution to beneficiaries.

**Affected Scenarios:** Multi-token profit schemes are a standard feature demonstrated in the test suite, where schemes are configured with multiple token thresholds. [6](#0-5) 

**Severity - Medium:** This breaks intended profit distribution functionality and requires manual intervention. While funds are not stolen or permanently lost (scheme managers can manually trigger distributions), the auto-distribution mechanism fails its core purpose, causing operational disruption in production deployments using multi-token schemes.

## Likelihood Explanation

**Reachable Entry Point:** The `RegisterForProfits` method is a public function callable by any user who wants to lock tokens and register for profit distribution. [7](#0-6) 

**Feasible Preconditions:**
1. A profit scheme is created with multiple token symbols in `AutoDistributeThreshold`
2. Multiple token types are contributed to the scheme  
3. Multiple tokens simultaneously exceed their configured thresholds
4. Any user calls `RegisterForProfits`

These conditions represent standard production usage. The protobuf design explicitly supports multi-token thresholds as a map structure, and the test suite demonstrates schemes with multiple token thresholds. [8](#0-7) 

**Execution Practicality:** The bug triggers automatically during normal operation without requiring special manipulation. When any user calls `RegisterForProfits` and multiple threshold conditions are met, only the first qualifying token is distributed while others remain stuck.

## Recommendation

Remove the unconditional `break` statement at line 199 to allow all qualifying tokens to be added to `AmountsMap`:

```csharp
foreach (var threshold in scheme.AutoDistributeThreshold)
{
    var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
    {
        Owner = virtualAddress,
        Symbol = threshold.Key
    }).Balance;
    if (balance < threshold.Value) continue;
    if (distributedInput == null)
        distributedInput = new Profit.DistributeProfitsInput
        {
            SchemeId = scheme.SchemeId,
            Period = scheme.Period
        };
    distributedInput.AmountsMap[threshold.Key] = 0;
    // Remove the break statement here to check all tokens
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MultiToken_AutoDistribute_Bug_POC()
{
    var threshold = 1000L;
    var tokenA = "ELF";
    var tokenB = "JUN";
    
    // Create scheme with thresholds for both tokens
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = tokenA,
        AutoDistributeThreshold =
        {
            { tokenA, threshold },
            { tokenB, threshold }
        }
    });
    
    // Contribute both tokens, both exceeding threshold
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = threshold,
        Symbol = tokenA
    });
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Amount = threshold,
        Symbol = tokenB
    });
    
    // Register for profits - triggers auto-distribution
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = threshold,
        SchemeManager = Starter
    });
    
    // Check profit map - only ONE token should have claimable profits due to bug
    var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    var schemeId = schemeIds.SchemeIds.First();
    var profitMap = await ProfitContractStub.GetProfitsMap.CallAsync(
        new Profit.ClaimProfitsInput { Beneficiary = Starter, SchemeId = schemeId });
    
    // BUG: Only first token distributed, second token has 0 claimable despite exceeding threshold
    profitMap.Value[tokenA].ShouldBeGreaterThan(0);  // First token distributed
    profitMap.Value[tokenB].ShouldBe(0);  // Second token NOT distributed due to break statement
}
```

## Notes

The bug is confirmed by examining the code flow: the `break` statement at line 199 unconditionally exits the threshold checking loop after adding only the first qualifying token to `AmountsMap`. The Profit contract's `DistributeProfits` function then only processes tokens present in `AmountsMap`, meaning subsequent qualifying tokens are never distributed during auto-distribution. This breaks the intended functionality where multiple token types with separate thresholds should all be automatically distributed when their respective thresholds are met. The multi-token threshold feature is explicitly supported by the protobuf schema definition and demonstrated in the test suite, confirming this is a logic error rather than a design limitation.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-149)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L184-200)
```csharp
            foreach (var threshold in scheme.AutoDistributeThreshold)
            {
                var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
                {
                    Owner = virtualAddress,
                    Symbol = threshold.Key
                }).Balance;
                if (balance < threshold.Value) continue;
                if (distributedInput == null)
                    distributedInput = new Profit.DistributeProfitsInput
                    {
                        SchemeId = scheme.SchemeId,
                        Period = scheme.Period
                    };
                distributedInput.AmountsMap[threshold.Key] = 0;
                break;
            }
```

**File:** protobuf/token_holder_contract.proto (L69-69)
```text
    map<string, int64> auto_distribute_threshold = 3;
```

**File:** protobuf/token_holder_contract.proto (L126-126)
```text
    map<string, int64> auto_distribute_threshold = 5;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L433-445)
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
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L365-373)
```csharp
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = nativeTokenSymbol,
            AutoDistributeThreshold =
            {
                { nativeTokenSymbol, amount },
                { tokenA, amount }
            }
        });
```
