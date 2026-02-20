# Audit Report

## Title
Missing Validation Allows Negative AutoDistributeThreshold Values, Breaking Auto-Distribution Logic

## Summary
The TokenHolder contract's `CreateScheme` function fails to validate `AutoDistributeThreshold` values, allowing negative amounts to be set. This causes the auto-distribution logic in `RegisterForProfits` to malfunction, triggering profit distribution on every registration regardless of balance, wasting gas and corrupting the period tracking state.

## Finding Description

The vulnerability exists in two locations:

**Root Cause - Missing Validation:**
The `CreateScheme` function directly assigns input threshold values without any validation of whether the values are positive. [1](#0-0) 

The protobuf definition uses `map<string, int64>` which is a signed integer type that permits negative values. [2](#0-1) 

**Exploitable Logic Flaw:**
The `RegisterForProfits` function implements auto-distribution by checking if token balances meet configured thresholds. [3](#0-2) 

The critical comparison at line 191 uses `if (balance < threshold.Value) continue;`. When `threshold.Value` is negative (e.g., -1):
- Token balances are always ≥ 0 (non-negative)
- The condition `0 < -1` evaluates to `false`
- The `continue` statement never executes
- Distribution logic always triggers

This causes `DistributeProfits` to be called unconditionally and the period counter to increment on every registration. [4](#0-3) 

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
Trivial—the `CreateScheme` method is public with no authorization checks. [5](#0-4)  Any address can create a scheme by simply providing negative values in the `AutoDistributeThreshold` map.

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

Add validation in the `CreateScheme` function to ensure all `AutoDistributeThreshold` values are non-negative:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Validate AutoDistributeThreshold values
    if (input.AutoDistributeThreshold != null)
    {
        foreach (var threshold in input.AutoDistributeThreshold)
        {
            Assert(threshold.Value > 0, $"AutoDistributeThreshold for {threshold.Key} must be positive.");
        }
    }
    
    // ... rest of the method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task RegisterForProfits_NegativeThreshold_AlwaysTriggersDistribution()
{
    // Create scheme with negative threshold
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        AutoDistributeThreshold = { { "ELF", -1 } } // Negative threshold
    });

    // Get initial scheme state
    var schemeBefore = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    var initialPeriod = schemeBefore.Period;

    // Register for profits - should trigger distribution despite zero balance
    await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = 10,
        SchemeManager = Starter
    });

    // Verify period incremented (indicating distribution occurred)
    var schemeAfter = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    schemeAfter.Period.ShouldBe(initialPeriod.Add(1)); // Period should have incremented
    
    // This proves distribution always happens with negative threshold,
    // even when balance doesn't meet any legitimate threshold
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
