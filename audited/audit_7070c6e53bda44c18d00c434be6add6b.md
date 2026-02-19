### Title
Unvalidated MinerIncreaseInterval Initialization Enables Unrecoverable Division by Zero DoS in Consensus Operations

### Summary
The `InitialAElfConsensusContract` method lacks validation to ensure `MinerIncreaseInterval` is non-zero, allowing deployment with a zero value. This causes `DivideByZeroException` in critical consensus calculation functions `GetAutoIncreasedMinersCount()` and `GetMinersCount()`. The vulnerability cannot be remediated post-deployment due to a flawed assertion in `SetMinerIncreaseInterval` that only permits decreasing the interval value, making it impossible to recover from a zero initialization without a chain restart.

### Finding Description

**Root Cause - No Input Validation:**

The consensus contract initialization accepts `MinerIncreaseInterval` without validating it must be positive: [1](#0-0) 

**Division by Zero Locations:**

The unvalidated value is used directly in division operations:

1. In `GetAutoIncreasedMinersCount()` (called by public method `GetMaximumMinersCount()`): [2](#0-1) 

2. In `GetMinersCount()` (internal method used by `SetMaximumMinersCount()`): [3](#0-2) 

**SafeMath.Div() Does Not Prevent Division by Zero:**

The `.Div()` extension method simply performs standard division which throws `DivideByZeroException`: [4](#0-3) 

**Broken Recovery Mechanism:**

The `SetMinerIncreaseInterval` method contains a flawed assertion that only allows setting values less than or equal to the current value, preventing recovery from zero: [5](#0-4) 

If `State.MinerIncreaseInterval.Value` is 0, the assertion `input.Value <= 0` prevents setting any positive value, making the contract permanently broken.

### Impact Explanation

**Operational Impact - Complete Consensus DoS:**

1. **Public View Method Failure**: `GetMaximumMinersCount()` becomes permanently uncallable, throwing `DivideByZeroException` on every invocation [6](#0-5) 

2. **Governance Operation Failure**: `SetMaximumMinersCount()` fails because it calls `GetMinersCount()` which performs the same division: [7](#0-6) 

3. **Unrecoverable State**: Cannot fix via `SetMinerIncreaseInterval` governance action due to the broken assertion logic

**Severity Justification:**
- **Critical** severity due to complete DoS of core consensus configuration functionality
- Affects miner count management which is fundamental to AEDPoS consensus
- Requires hard fork or chain restart to recover
- Breaks coordination between Election and Consensus contracts

### Likelihood Explanation

**Preconditions:**
- Requires misconfiguration during genesis block initialization
- `InitialAElfConsensusContractInput.MinerIncreaseInterval` must be set to 0 in deployment configuration

**Feasibility Assessment:**
- **Entry Point**: Reachable - `InitialAElfConsensusContract` is called during genesis
- **Attack Complexity**: LOW - simply requires wrong configuration value
- **Attacker Capabilities**: Not an attack per se, but deployment error
- **Economic Cost**: None - happens during initialization

**Likelihood Rating: LOW but POSSIBLE**
- Default value in `ConsensusOptions` is 31536000 (non-zero): [8](#0-7) 

- No evidence in codebase of zero values being used in tests or production
- However, NO validation exists to prevent configuration error
- Genesis initialization is one-time operation that should be carefully reviewed
- If it happens, impact is catastrophic and unrecoverable

### Recommendation

**1. Add Input Validation in Initialization:**

Modify `InitialAElfConsensusContract` to validate the input:

```csharp
public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
{
    Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
    Assert(input.MinerIncreaseInterval > 0, "MinerIncreaseInterval must be positive."); // ADD THIS
    State.Initialized.Value = true;
    // ... rest of method
}
```

**2. Fix SetMinerIncreaseInterval Assertion Logic:**

The assertion at line 61 should allow both increasing and decreasing, or require the value to be positive:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value > 0, "MinerIncreaseInterval must be positive."); // FIX THIS
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

**3. Add Guard in Division Operations:**

Add defensive checks before division:

```csharp
private int GetAutoIncreasedMinersCount()
{
    if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;
    if (State.MinerIncreaseInterval.Value <= 0) return AEDPoSContractConstants.SupposedMinersCount; // ADD THIS
    
    return AEDPoSContractConstants.SupposedMinersCount.Add(
        (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
        .Div(State.MinerIncreaseInterval.Value).Mul(2));
}
```

**4. Add Regression Test:**

Create test case verifying initialization fails with zero/negative `MinerIncreaseInterval`.

### Proof of Concept

**Initial State:**
- Deploy AElf chain with genesis configuration containing:
```
InitialAElfConsensusContractInput {
    PeriodSeconds = 604800,
    MinerIncreaseInterval = 0  // Misconfiguration
}
```

**Exploitation Steps:**

1. Genesis block successfully creates consensus contract with `State.MinerIncreaseInterval.Value = 0`

2. Any call to `GetMaximumMinersCount()`:
   - Invokes `GetAutoIncreasedMinersCount()` 
   - Executes line 94: `.Div(State.MinerIncreaseInterval.Value)` where value is 0
   - Throws `DivideByZeroException`
   - Transaction fails

3. Attempt governance recovery via Parliament proposal to call `SetMinerIncreaseInterval(100)`:
   - Line 61 assertion evaluates: `Assert(100 <= 0, "Invalid interval")`
   - Assertion fails with "Invalid interval"
   - Cannot fix the zero value

**Expected vs Actual Result:**
- **Expected**: Initialization should reject zero value, or at minimum allow fixing via governance
- **Actual**: Zero value accepted, division by zero crashes contract, cannot recover

**Success Condition for Exploit:**
- `GetMaximumMinersCount()` throws exception instead of returning valid count
- Consensus contract enters permanently broken state requiring hard fork to recover

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L31-31)
```csharp
        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L20-26)
```csharp
        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L72-78)
```csharp
    public override Int32Value GetMaximumMinersCount(Empty input)
    {
        return new Int32Value
        {
            Value = Math.Min(GetAutoIncreasedMinersCount(), State.MaximumMinersCount.Value)
        };
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L13-13)
```csharp
    public long MinerIncreaseInterval { get; set; } = 31536000;
```
