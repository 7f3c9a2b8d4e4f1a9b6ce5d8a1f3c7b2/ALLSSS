# Audit Report

## Title
Missing Validation Allows Negative AutoDistributeThreshold Values, Breaking Auto-Distribution Logic

## Summary
The TokenHolder contract's `CreateScheme` function fails to validate `AutoDistributeThreshold` values, allowing negative amounts to be set. This causes the auto-distribution logic in `RegisterForProfits` to malfunction, triggering profit distribution on every registration regardless of balance, wasting gas and corrupting the period tracking state.

## Finding Description

The vulnerability exists in two locations:

**Root Cause - Missing Validation:**
The `CreateScheme` function directly assigns input threshold values without validation [1](#0-0) . The protobuf definition uses `map<string, int64>` which permits negative values [2](#0-1) .

**Exploitable Logic Flaw:**
The `RegisterForProfits` function implements auto-distribution by checking if token balances meet configured thresholds [3](#0-2) . The critical comparison at line 191 uses `if (balance < threshold.Value) continue;`. 

When `threshold.Value` is negative (e.g., -1):
- Token balances are always ≥ 0 (non-negative)
- The condition `0 < -1` evaluates to `false`
- The `continue` statement never executes
- Distribution logic always triggers [4](#0-3) 

This causes `DistributeProfits` to be called unconditionally [5](#0-4)  and the period counter to increment on every registration [6](#0-5) .

## Impact Explanation

**Operational Disruption:**
- Every `RegisterForProfits` call triggers an unnecessary `DistributeProfits` operation, consuming significant gas for all participants registering in the affected scheme
- The period counter increments on every registration instead of only when thresholds are met, completely desynchronizing the distribution schedule
- The auto-distribution feature's intended behavior is inverted—it distributes when it shouldn't

**Affected Parties:**
- Users registering for profits pay unnecessary transaction fees
- Scheme creators who accidentally set negative thresholds create broken schemes
- Malicious actors can deliberately create schemes that waste gas for victims

**Severity Assessment:**
Medium severity because while there is no direct fund loss or theft, the vulnerability causes measurable financial harm through gas waste and breaks critical functionality, making the auto-distribution feature unreliable.

## Likelihood Explanation

**Attack Complexity:**
Trivial—the `CreateScheme` method is public with no authorization checks [7](#0-6) . Any address can create a scheme by simply providing negative values in the `AutoDistributeThreshold` map.

**Execution Requirements:**
- No special permissions needed
- No preconditions or state setup required
- Fully executable under normal AElf runtime operation

**Detection:**
The malfunction is immediately observable when any user calls `RegisterForProfits`—distribution occurs regardless of actual balance and periods increment unexpectedly.

**Probability:**
High likelihood due to either:
- Accidental misconfiguration (developers may not realize negative values are invalid)
- Malicious griefing attacks to waste users' gas

## Recommendation

Add validation in `CreateScheme` to reject negative threshold values:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // ... existing code ...
    
    // Validate threshold values are positive
    if (input.AutoDistributeThreshold != null)
    {
        foreach (var threshold in input.AutoDistributeThreshold)
        {
            Assert(threshold.Value > 0, 
                $"Invalid threshold for {threshold.Key}: value must be positive.");
        }
    }
    
    State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
    {
        Symbol = input.Symbol,
        MinimumLockMinutes = input.MinimumLockMinutes,
        AutoDistributeThreshold = { input.AutoDistributeThreshold }
    };
    
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_WithNegativeThreshold_TriggersAutoDistributeOnEveryRegistration()
{
    // Setup: Create scheme with negative threshold
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        AutoDistributeThreshold = { { "ELF", -1 } } // Negative threshold
    });
    
    // Get initial scheme state
    var schemeBefore = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var initialPeriod = schemeBefore.Period;
    
    // Register for profits - should NOT trigger distribution since balance is 0
    // but WILL trigger due to negative threshold bug
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = 1000,
        SchemeManager = Starter
    });
    
    // Verify bug: period incremented even though no threshold was met
    var schemeAfter = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    schemeAfter.Period.ShouldBe(initialPeriod + 1); // Period incorrectly incremented
    
    // Register again - period increments AGAIN without meeting threshold
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = 500,
        SchemeManager = Starter
    });
    
    var schemeFinal = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    schemeFinal.Period.ShouldBe(initialPeriod + 2); // Confirms bug: increments on every call
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-14)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
```

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

**File:** protobuf/token_holder_contract.proto (L69-69)
```text
    map<string, int64> auto_distribute_threshold = 3;
```
