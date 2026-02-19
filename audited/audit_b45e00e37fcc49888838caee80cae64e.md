### Title
Auto-Distribution Only Triggers for First Qualifying Token, Not All Eligible Tokens

### Summary
The `RegisterForProfits()` function's auto-distribution logic contains a premature loop termination that causes only the first token meeting its threshold to be distributed, even when multiple tokens qualify. This breaks the intended multi-token auto-distribution feature and delays profit distribution for beneficiaries.

### Finding Description

The auto-distribution logic in `RegisterForProfits()` iterates through multiple token thresholds defined in `scheme.AutoDistributeThreshold`, but exits the loop immediately after finding the first token that meets its threshold. [1](#0-0) 

The code checks each threshold sequentially, and when it finds a token with balance >= threshold, it adds that token to `distributedInput.AmountsMap` and then executes a `break` statement at line 199. This prevents checking remaining tokens in the threshold map.

The Profit contract's `DistributeProfits` function only distributes tokens present in the `AmountsMap`: [2](#0-1) 

Therefore, only the first qualifying token gets distributed, while other tokens that also meet their thresholds remain undistributed in the scheme's virtual address.

The design evidence suggests all qualifying tokens should be distributed:
- `AutoDistributeThreshold` is a map structure supporting multiple tokens
- The protobuf definition describes it as "Threshold setting for releasing dividends" (plural) [3](#0-2) 

Test expectations confirm this: when multiple tokens meet thresholds, the test expects multiple tokens to be distributed. [4](#0-3) [5](#0-4) 

### Impact Explanation

**Reward Misallocation**: When a scheme has multiple token types configured with auto-distribution thresholds, and multiple tokens simultaneously meet their thresholds, only one token gets distributed while others remain locked in the virtual address. Beneficiaries are deprived of timely access to profits they're entitled to receive.

**Who is Affected**: All beneficiaries in TokenHolder schemes with multi-token auto-distribution configurations.

**Operational Impact**: The auto-distribution feature is fundamentally broken for multi-token scenarios. While funds are not permanently lost (they remain in the virtual address and can be manually distributed), beneficiaries experience delayed access to their profits, violating the protocol's auto-distribution guarantee.

**Severity Justification**: Medium severity because:
- No permanent fund loss occurs
- Manual distribution workaround exists via `DistributeProfits()`
- Affects protocol functionality and user experience
- Breaks documented feature behavior

### Likelihood Explanation

**Attacker Capabilities**: No attacker needed - this is a deterministic logic bug that triggers during normal operation.

**Preconditions**: 
1. Scheme manager creates a TokenHolder scheme with multiple auto-distribution thresholds (common configuration)
2. Multiple tokens are contributed to the scheme
3. Multiple tokens simultaneously exceed their thresholds
4. Any user calls `RegisterForProfits()`

**Execution Practicality**: Highly practical - occurs automatically during normal protocol usage. The scenario of multiple tokens meeting thresholds is common in production environments where schemes accept multiple token types as contributions.

**Probability**: HIGH - This bug triggers whenever the preconditions are met, which is a standard use case for the multi-token threshold feature.

### Recommendation

**Code-Level Fix**: Remove the `break` statement at line 199 to allow the loop to check all thresholds and add all qualifying tokens to the `AmountsMap`:

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
    // Remove the break statement here
}
```

**Test Cases**: Add explicit test validation that when multiple tokens meet thresholds, ALL of them are present in the distribution `AmountsMap` and subsequently distributed to beneficiaries.

### Proof of Concept

**Initial State**:
1. Create TokenHolder scheme with two thresholds: `{"ELF": 1000, "TOKEN_A": 1000}`
2. Contribute 1000 ELF to the scheme (meets threshold)
3. Contribute 1000 TOKEN_A to the scheme (meets threshold)

**Execution**:
4. User calls `RegisterForProfits()` with 100 tokens

**Expected Result**: Both ELF and TOKEN_A should be auto-distributed to beneficiaries

**Actual Result**: Only the first token in the iteration order (likely ELF) is distributed. TOKEN_A remains in the virtual address despite meeting its threshold.

**Verification**: Query `GetProfitsMap` - only one token appears in beneficiary's claimable profits instead of two.

### Notes

The break statement appears to be a copy-paste error or incomplete implementation. The data structure design (using a map for thresholds) and test expectations clearly indicate the intended behavior is to distribute ALL qualifying tokens, not just the first one found. While this doesn't cause permanent fund loss, it violates the auto-distribution invariant and requires manual intervention to distribute the remaining qualifying tokens.

### Citations

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

**File:** protobuf/token_holder_contract.proto (L68-70)
```text
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
}
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L368-372)
```csharp
            AutoDistributeThreshold =
            {
                { nativeTokenSymbol, amount },
                { tokenA, amount }
            }
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L412-414)
```csharp
        profitMap.Value.Count.ShouldBe(2);
        profitMap.Value.ContainsKey(nativeTokenSymbol).ShouldBeTrue();
        profitMap.Value[nativeTokenSymbol].ShouldBe(amount);
```
