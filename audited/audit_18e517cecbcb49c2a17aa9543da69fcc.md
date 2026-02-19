### Title
Missing Validation Allows Negative AutoDistributeThreshold Values, Breaking Auto-Distribution Logic

### Summary
The `CreateScheme` function fails to validate `AutoDistributeThreshold` values, allowing negative threshold amounts to be set. This causes the auto-distribution logic in `RegisterForProfits` to malfunction, triggering profit distribution on every registration regardless of actual balance, resulting in excessive gas consumption and incorrect period tracking.

### Finding Description
**Root Cause:**
In `CreateScheme`, line 31 directly assigns the input `AutoDistributeThreshold` without any validation to ensure values are positive. [1](#0-0) 

The `AutoDistributeThreshold` is defined as `map<string, int64>` in the protobuf specification, which permits negative values. [2](#0-1) 

**Why Protections Fail:**
The comparison logic in `RegisterForProfits` at line 191 checks `if (balance < threshold.Value) continue;`. When `threshold.Value` is negative (e.g., -100):
- Token balance is always ≥ 0
- The condition `balance < -100` evaluates to `false` for any non-negative balance
- The `continue` statement never executes
- Auto-distribution triggers unconditionally on every `RegisterForProfits` call [3](#0-2) 

**Execution Path:**
1. Scheme creator calls `CreateScheme` with negative threshold (e.g., `{"ELF": -1}`)
2. Any user calling `RegisterForProfits` triggers lines 184-199
3. Line 191's condition `(0 < -1)` is always false
4. Lines 193-199 execute, creating distribution input
5. Line 203 calls `DistributeProfits` even when balance is 0
6. Line 204 increments the period counter inappropriately

### Impact Explanation
**Operational Impact:**
- **Excessive Gas Consumption**: Every `RegisterForProfits` call unnecessarily invokes `DistributeProfits`, wasting gas for all participants
- **Period Desynchronization**: The scheme period counter increments on every registration instead of only when the threshold is genuinely reached, breaking the distribution schedule tracking
- **Broken Auto-Distribution Logic**: The intended behavior (distribute only when balance exceeds threshold) is completely inverted—distribution triggers regardless of balance

**Affected Parties:**
- Scheme creators who mistakenly or maliciously set negative thresholds
- All users registering for profits in such schemes, who pay unnecessary gas costs
- The scheme's profit distribution becomes unreliable and unpredictable

**Severity Justification:**
Medium severity due to operational disruption rather than direct fund theft. The vulnerability breaks a critical feature's intended functionality and imposes unnecessary costs on users, though funds remain safe.

### Likelihood Explanation
**Attacker Capabilities:**
Any address can create a TokenHolder profit scheme by calling the public `CreateScheme` method. No special permissions required.

**Attack Complexity:**
Trivial—simply provide a negative value in the `AutoDistributeThreshold` map when creating a scheme:
```
AutoDistributeThreshold = { {"ELF", -1} }
```

**Feasibility:**
Fully executable under normal contract operation. No edge cases or race conditions required.

**Detection:**
The malfunction becomes immediately apparent when any user calls `RegisterForProfits`—distribution occurs regardless of balance, and periods increment unexpectedly.

**Probability:**
High probability of occurrence either through:
- Accidental misconfiguration by scheme creators
- Malicious creation of broken schemes to waste users' gas

### Recommendation
**Code-Level Mitigation:**
Add validation in `CreateScheme` to enforce positive threshold values:

```csharp
// After line 30, before line 31
if (input.AutoDistributeThreshold != null && input.AutoDistributeThreshold.Any())
{
    foreach (var threshold in input.AutoDistributeThreshold)
    {
        Assert(threshold.Value > 0, 
            $"Invalid auto-distribute threshold for {threshold.Key}: must be positive.");
    }
}
```

**Invariant to Enforce:**
- All `AutoDistributeThreshold` values must be strictly positive (> 0)
- Zero values should also be rejected as they would trigger distribution on every call

**Test Cases:**
1. Attempt to create scheme with negative threshold—should revert
2. Attempt to create scheme with zero threshold—should revert  
3. Create scheme with positive threshold—should succeed
4. Verify `RegisterForProfits` only triggers distribution when balance exceeds positive threshold

### Proof of Concept
**Initial State:**
- User A creates a TokenHolder profit scheme
- User A has sufficient tokens to participate

**Attack Steps:**
1. User A calls `CreateScheme` with input:
   ```
   Symbol = "ELF"
   MinimumLockMinutes = 100
   AutoDistributeThreshold = { {"ELF", -1} }
   ```
   
2. User B calls `RegisterForProfits` with:
   ```
   SchemeManager = User A's address
   Amount = 100
   ```

**Expected Behavior:**
Auto-distribution should NOT trigger because the virtual address balance (0 tokens initially) is below any reasonable positive threshold.

**Actual Result:**
- Line 191 evaluates `(0 < -1)` → `false`
- Auto-distribution logic at lines 193-203 executes
- `DistributeProfits` is called unnecessarily
- Period counter increments from 1 to 2
- Unnecessary gas consumed

**Success Condition:**
Observe that `GetScheme` shows `Period = 2` immediately after the first `RegisterForProfits` call, and transaction logs show `DistributeProfits` was invoked with zero or minimal balance, confirming the malfunction.

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
