### Title
Division by Zero DoS in Miner Count Calculation Due to Missing Validation in SetMinerIncreaseInterval()

### Summary
The `SetMinerIncreaseInterval()` function lacks validation to prevent setting the miner increase interval to zero. When combined with a subsequent call to `SetMaximumMinersCount()` or any consensus operation that calculates miner counts, this causes a division by zero exception that can permanently break consensus operations and term transitions.

### Finding Description

The vulnerability exists in the `SetMinerIncreaseInterval()` function which only validates that the new interval value is less than or equal to the current value, but fails to validate that it must be positive: [1](#0-0) 

The assertion `Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval")` allows setting the interval to 0 or any value less than the current interval, with no lower bound check.

When `MinerIncreaseInterval` is set to 0, subsequent miner count calculations fail. The `GetAutoIncreasedMinersCount()` function performs division by this interval value: [2](#0-1) 

The `.Div()` operation throws `DivideByZeroException` when the divisor is zero, as confirmed by the SafeMath implementation: [3](#0-2) 

The same vulnerable calculation pattern exists in `GetMinersCount(Round input)`: [4](#0-3) 

**Exploitation Path:**

1. Governance calls `SetMinerIncreaseInterval(0)` - passes validation and sets interval to 0
2. Any subsequent operation triggers division by zero:
   - Direct call to `SetMaximumMinersCount()` which calls `GetMinersCount(round)`
   - Term transition via `UpdateMinersCountToElectionContract()` during `ProcessNextRound`
   - View calls to `GetMaximumMinersCount()`

### Impact Explanation

**Operational Impact - Critical DoS:**
- All consensus operations that calculate miner counts become permanently broken
- Term transitions fail when `UpdateMinersCountToElectionContract()` is called, halting consensus progression
- Miner list updates cannot be sent to the Election contract
- The blockchain cannot proceed to new terms or update validator sets

**Affected Operations:**
- `SetMaximumMinersCount()` - immediate failure when called after setting interval to 0
- `ProcessNextRound()` - fails during first round initialization
- `ProcessNextTerm()` - fails during term transitions
- All view methods calling `GetMaximumMinersCount()` or `GetMinersCount()`

**Severity Justification:**
This is a High/Critical severity issue because it can completely halt consensus operations. Once the interval is set to 0, the system cannot recover without manual intervention or contract upgrade. The blockchain cannot transition to new terms, update miner counts, or adjust validator sets.

### Likelihood Explanation

**Attacker Capabilities:**
Requires `MaximumMinersCountController` permission, which defaults to the Parliament contract's default organization. This is a trusted governance role. [5](#0-4) 

**Attack Complexity:**
Low - single transaction with straightforward parameters.

**Feasibility Conditions:**
While this requires governance permission, it represents a critical input validation bug rather than a governance attack. Even trusted roles should not be able to set invalid parameters that break core system functionality.

**Execution Practicality:**
Highly practical - the vulnerability is triggered by:
1. Calling `SetMinerIncreaseInterval(0)` 
2. Any subsequent consensus operation or miner count query

**Detection/Operational Constraints:**
The division by zero exception would be immediately visible in transaction failures, but by that point the damage is done and consensus operations are broken.

### Recommendation

**Immediate Fix:**
Add validation in `SetMinerIncreaseInterval()` to enforce a positive interval value:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value > 0, "Miner increase interval must be positive.");
    Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

**Additional Safeguards:**
1. Consider adding a minimum interval threshold (e.g., 1 day = 86400 seconds) to prevent impractically small intervals that could cause integer overflow in calculations
2. Add a defensive check in `GetAutoIncreasedMinersCount()` to handle zero interval gracefully, though primary fix should prevent invalid state
3. Emit an event when the interval is changed for monitoring purposes

**Test Cases:**
1. Test attempting to set interval to 0 - should revert
2. Test attempting to set interval to negative value - should revert  
3. Test setting interval to valid positive values - should succeed
4. Test that consensus operations continue working after interval changes
5. Test edge cases with very small intervals (potential overflow scenarios)

### Proof of Concept

**Initial State:**
- `State.MinerIncreaseInterval.Value = 31536000` (1 year in seconds, default initialization)
- `State.MaximumMinersCount.Value = 100`
- Blockchain has been running for some time
- Attacker has `MaximumMinersCountController` permission

**Attack Sequence:**

**Transaction 1:**
```
Call: SetMinerIncreaseInterval(Int64Value{Value: 0})
Validation: 0 <= 31536000 ✓ (passes)
Result: State.MinerIncreaseInterval.Value = 0
Status: Success
```

**Transaction 2:**
```
Call: SetMaximumMinersCount(Int32Value{Value: 100})
Execution Path:
  → SetMaximumMinersCount() line 10
  → GetMinersCount(round) line 25
  → GetAutoIncreasedMinersCount() calculation line 92-94
  → .Div(State.MinerIncreaseInterval.Value) where value = 0
  → DivideByZeroException thrown
Result: Transaction fails with DivideByZeroException
Status: Failed - consensus operations broken
```

**Alternative Trigger (Automatic):**
```
Consensus Operation: ProcessNextRound() during first round
Execution Path:
  → UpdateMinersCountToElectionContract() line 131
  → GetMinersCount(nextRound) line 55
  → Division by zero in calculation
Result: Term transition fails
Status: Consensus halted
```

**Expected vs Actual:**
- Expected: System rejects invalid interval value of 0
- Actual: System accepts 0 and subsequently crashes on all miner count calculations

**Success Condition:**
After implementing the fix, `SetMinerIncreaseInterval(0)` should revert with error "Miner increase interval must be positive." and consensus operations should continue functioning normally.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L31-43)
```csharp
    private void RequiredMaximumMinersCountControllerSet()
    {
        if (State.MaximumMinersCountController.Value != null) return;
        EnsureParliamentContractAddressSet();

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MaximumMinersCountController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```
