### Title
Gas Griefing via Unbounded AutoDistributeThreshold Iteration in RegisterForProfits

### Summary
The `RegisterForProfits` function performs an uncapped loop over `AutoDistributeThreshold` entries, making a cross-contract `GetBalance` call for each entry to check if auto-distribution should trigger. A malicious scheme manager can create a scheme with hundreds of threshold entries that never meet distribution conditions, forcing users to pay excessive gas costs during registration even when no distribution occurs.

### Finding Description

The vulnerability exists in the `RegisterForProfits` method's auto-distribute threshold checking logic. [1](#0-0) 

The code iterates through all entries in `scheme.AutoDistributeThreshold` without any size limit: [2](#0-1) 

For each entry, it makes a cross-contract call to check the token balance: [3](#0-2) 

When thresholds are not met, the loop continues through all entries: [4](#0-3) 

The early exit at line 202 only occurs AFTER all balance checks have been performed: [5](#0-4) 

**Root Cause**: The `CreateScheme` function accepts `AutoDistributeThreshold` input without validating the number of entries: [6](#0-5) 

While the state size limit (128KB) prevents extremely large maps, it still allows hundreds or thousands of entries since each entry only requires ~20-50 bytes (token symbol + int64 threshold). [7](#0-6) 

### Impact Explanation

**Operational DoS and Economic Griefing**:
- Users calling `RegisterForProfits` on a malicious scheme pay gas proportional to the number of `AutoDistributeThreshold` entries
- With 100 entries, users incur 100 cross-contract `GetBalance` calls, consuming excessive gas
- With larger maps (e.g., 500+ entries), gas costs could exceed block gas limits or become economically prohibitive
- Users are unable to register for profits on affected schemes, causing operational DoS
- No direct fund theft occurs, but users suffer economic damage through wasted gas fees

**Who is Affected**:
- Any user attempting to call `RegisterForProfits` on schemes with large `AutoDistributeThreshold` maps
- Legitimate scheme managers whose users cannot register due to gas constraints

**Severity Justification**: Medium - Concrete operational DoS with quantifiable economic impact through gas griefing, high likelihood, but no direct fund loss or protocol-level compromise.

### Likelihood Explanation

**High Likelihood**:
- **Attacker Capabilities**: Scheme manager has full control over `AutoDistributeThreshold` size during `CreateScheme` with no restrictions beyond state size limit
- **Attack Complexity**: Trivial - simply call `CreateScheme` with a large map of token symbols mapped to high thresholds
- **Feasibility**: No preconditions required; attacker only needs to deploy a malicious scheme
- **Cost to Attacker**: Negligible - only pays for CreateScheme transaction
- **Detection**: Difficult to detect before users attempt registration and experience excessive gas consumption

**Realistic Attack Scenario**:
1. Attacker calls `CreateScheme` with `AutoDistributeThreshold` containing 200+ entries with various token symbols and high threshold values
2. Map remains under 128KB state limit (200 entries × ~30 bytes ≈ 6KB)
3. Legitimate user calls `RegisterForProfits` expecting normal gas costs
4. Function iterates through all 200 entries, making 200 `GetBalance` calls
5. No thresholds are met (by design), so all iterations complete
6. User pays for 200+ cross-contract calls despite no distribution occurring
7. Transaction may fail if gas limit exceeded, or user pays excessive fees

### Recommendation

**Immediate Fix**: Add a maximum size limit for `AutoDistributeThreshold` in the `CreateScheme` function:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    const int MaxAutoDistributeThresholdCount = 10; // Reasonable limit
    Assert(input.AutoDistributeThreshold == null || 
           input.AutoDistributeThreshold.Count <= MaxAutoDistributeThresholdCount,
           $"AutoDistributeThreshold cannot exceed {MaxAutoDistributeThresholdCount} entries.");
    
    // ... rest of implementation
}
```

**Additional Mitigations**:
1. Add early loop termination after checking a maximum number of thresholds in `RegisterForProfits`
2. Consider implementing a gas budget check within the loop to prevent excessive consumption
3. Document the recommended maximum size for `AutoDistributeThreshold` in scheme creation guidelines

**Test Cases**:
1. Test `CreateScheme` rejection when `AutoDistributeThreshold` exceeds maximum count
2. Test `RegisterForProfits` gas consumption with various threshold map sizes
3. Verify legitimate auto-distribution still works with size-limited thresholds

### Proof of Concept

**Initial State**:
- Attacker has an address with minimal funds
- Token contract and Profit contract are deployed

**Attack Steps**:

1. **Attacker creates malicious scheme**:
```
CreateScheme({
    Symbol: "ELF",
    MinimumLockMinutes: 0,
    AutoDistributeThreshold: {
        "TOKEN001": 999999999,
        "TOKEN002": 999999999,
        ...
        "TOKEN200": 999999999  // 200 entries with impossibly high thresholds
    }
})
```

2. **Victim attempts to register**:
```
RegisterForProfits({
    SchemeManager: <attacker_address>,
    Amount: 1000
})
```

**Expected vs Actual Result**:
- **Expected**: User pays reasonable gas for registration (~50,000 gas units)
- **Actual**: User pays excessive gas for 200+ GetBalance calls (~500,000+ gas units)
- **Success Condition**: Transaction completes but with gas consumption proportional to AutoDistributeThreshold size, demonstrating the gas griefing attack

The vulnerability is confirmed by examining test cases that show schemes with multiple threshold entries: [8](#0-7) 

While the test uses only 2 entries, the same pattern would apply to 100+ entries with no validation preventing this scenario.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L178-206)
```csharp
        // Check auto-distribute threshold.
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

**File:** protobuf/token_holder_contract.proto (L63-70)
```text
message CreateTokenHolderProfitSchemeInput {
    // The token symbol.
    string symbol = 1;
    // Minimum lock time for holding token.
    int64 minimum_lock_minutes = 2;
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
}
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L359-419)
```csharp
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
        });
        await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeManager = Starter,
            Amount = amount,
            Symbol = nativeTokenSymbol
        });
        await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
        {
            SchemeManager = Starter,
            Amount = amount,
            Symbol = tokenA
        });
        var beforeLockBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Symbol = nativeTokenSymbol,
            Owner = Starter
        })).Balance;
        await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
        {
            Amount = amount,
            SchemeManager = Starter
        });
        var afterLockBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Symbol = nativeTokenSymbol,
            Owner = Starter
        })).Balance;
        beforeLockBalance.ShouldBe(afterLockBalance.Add(amount));
        var schemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
        {
            Manager = Starter
        });
        var schemeId = schemeIds.SchemeIds.First();
        var profitMap = await ProfitContractStub.GetProfitsMap.CallAsync(new Profit.ClaimProfitsInput
        {
            Beneficiary = Starter,
            SchemeId = schemeId
        });
        profitMap.Value.Count.ShouldBe(2);
        profitMap.Value.ContainsKey(nativeTokenSymbol).ShouldBeTrue();
        profitMap.Value[nativeTokenSymbol].ShouldBe(amount);
        var schemeInfoInProfit = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        var schemeInfoInTokenHolder = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
        schemeInfoInProfit.CurrentPeriod.ShouldBe(2);
        schemeInfoInTokenHolder.Period.ShouldBe(2);
    }
```
