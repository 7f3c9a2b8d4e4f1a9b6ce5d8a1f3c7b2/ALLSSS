# Audit Report

## Title
Auto-Distribution Break Statement Prevents Multiple Token Threshold Checks in TokenHolder Contract

## Summary
The `RegisterForProfits` function in the TokenHolder contract contains an unconditional `break` statement that exits the auto-distribution threshold checking loop after processing only the first qualifying token. This prevents subsequent tokens from being evaluated and distributed, causing profit distribution failures in multi-token schemes where multiple token balances simultaneously exceed their configured thresholds.

## Finding Description

The TokenHolder contract's `RegisterForProfits` function implements auto-distribution logic that should trigger profit distribution when token balances in a scheme's virtual address exceed configured thresholds. The function iterates through the `AutoDistributeThreshold` map to check each token's balance against its threshold. [1](#0-0) 

The critical flaw occurs when a qualifying token is found. After adding the first token that meets its threshold to `distributedInput.AmountsMap`, an unconditional `break` statement immediately exits the foreach loop. [2](#0-1) 

The `AutoDistributeThreshold` field is explicitly defined as a `map<string, int64>` in the protobuf schema, designed to support multiple token symbols with different threshold values. [3](#0-2) 

The downstream `DistributeProfits` function in the Profit contract only processes tokens explicitly listed in the `AmountsMap` parameter. When `AmountsMap` contains entries, the function iterates through them and either uses the provided amount or fetches the full balance from the virtual address if the amount is zero. [4](#0-3) 

This means tokens not added to `AmountsMap` due to the premature loop exit will not be distributed, even when their balances exceed their configured thresholds.

## Impact Explanation

**Reward Misallocation:**
When multiple token types accumulate in a profit scheme's virtual address and multiple thresholds are simultaneously met, only the first token encountered in the dictionary iteration will be auto-distributed. Other qualifying tokens remain locked in the virtual address, unable to be automatically distributed to beneficiaries.

**Affected Scenarios:**
Multi-token profit schemes are a standard feature demonstrated in the test suite, where schemes are configured with multiple token thresholds. [5](#0-4) 

**Severity - Medium:**
This issue breaks intended profit distribution functionality and requires manual intervention to distribute stuck profits. While funds are not stolen or permanently lost, the auto-distribution mechanism fails to perform its intended purpose, causing operational disruption and requiring scheme managers to manually trigger distributions for the remaining tokens.

## Likelihood Explanation

**Reachable Entry Point:**
The `RegisterForProfits` method is a public function callable by any user who wants to lock tokens and register for profit distribution. [6](#0-5) 

**Feasible Preconditions:**
1. A profit scheme is created with multiple token symbols in `AutoDistributeThreshold`
2. Multiple token types are contributed to the scheme
3. Multiple tokens simultaneously exceed their configured thresholds
4. Any user calls `RegisterForProfits`

These conditions represent standard production usage. The test suite explicitly demonstrates multi-token schemes with multiple thresholds, confirming this is an expected and realistic scenario. [7](#0-6) 

**Execution Practicality:**
The bug triggers automatically during normal operation without requiring special manipulation. When any user calls `RegisterForProfits` and multiple threshold conditions are met, only the first qualifying token is distributed while others remain stuck.

## Recommendation

Remove the unconditional `break` statement to allow the loop to evaluate all tokens in `AutoDistributeThreshold`. The corrected logic should:

1. Iterate through all thresholds in the map
2. For each token meeting its threshold, add it to `distributedInput.AmountsMap`
3. After the loop completes, if any tokens qualified (distributedInput is not null), call DistributeProfits once with all qualifying tokens

The fix involves removing line 199 and allowing the loop to continue processing all thresholds.

## Proof of Concept

The existing test `RegisterForProfits_With_Auto_Distribute_Test` demonstrates the exact scenario but may not properly validate that both tokens are distributed. A proper test should:

1. Create a scheme with multiple token thresholds (ELF: 1000, JUN: 1000)
2. Contribute both tokens to meet their thresholds
3. Call RegisterForProfits
4. Verify the virtual address balance for BOTH tokens has been reduced to zero (or distributed amount)
5. Verify period incremented to 2 (confirming DistributeProfits was called)
6. Verify both tokens appear in beneficiary's claimable profits

The current implementation would fail to auto-distribute the second token due to the break statement at line 199.

---

**Notes:**
This vulnerability affects the economics and rewards distribution domain of the AElf smart contract system. The issue does not result in fund theft but breaks the intended auto-distribution mechanism, requiring manual intervention to distribute profits for all qualifying tokens beyond the first one checked.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-149)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L179-206)
```csharp
        if (scheme.AutoDistributeThreshold != null && scheme.AutoDistributeThreshold.Any())
        {
            var originScheme = State.ProfitContract.GetScheme.Call(scheme.SchemeId);
            var virtualAddress = originScheme.VirtualAddress;
            Profit.DistributeProfitsInput distributedInput = null;
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

            if (distributedInput == null) return new Empty();
            State.ProfitContract.DistributeProfits.Send(distributedInput);
            scheme.Period = scheme.Period.Add(1);
            State.TokenHolderProfitSchemes[input.SchemeManager] = scheme;
        }
```

**File:** protobuf/token_holder_contract.proto (L68-69)
```text
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
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

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L358-372)
```csharp
    [Fact]
    public async Task RegisterForProfits_With_Auto_Distribute_Test()
    {
        var amount = 1000L;
        var nativeTokenSymbol = TokenHolderContractTestConstants.NativeTokenSymbol;
        var tokenA = "JUN";
        await StarterCreateIssueAndApproveTokenAsync(tokenA, 1000000L, 100000L);
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = nativeTokenSymbol,
            AutoDistributeThreshold =
            {
                { nativeTokenSymbol, amount },
                { tokenA, amount }
            }
```
