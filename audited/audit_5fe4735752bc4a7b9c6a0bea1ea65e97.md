### Title
Division by Zero in MinerIncreaseInterval Causes Unrecoverable Consensus DoS

### Summary
The `SetMinerIncreaseInterval` function fails to validate that the miner increase interval is greater than zero, allowing governance to set it to 0. This causes division by zero exceptions in critical consensus functions (`GetMinersCount` and `GetAutoIncreasedMinersCount`), permanently halting all term transitions and consensus operations. Once set to 0, the value cannot be increased due to the validation logic requiring new values to be less than or equal to the current value.

### Finding Description

The root cause exists in the `SetMinerIncreaseInterval` function which only validates that the new value is less than or equal to the current value, but does not enforce a minimum positive value: [1](#0-0) 

This missing validation allows `State.MinerIncreaseInterval.Value` to be set to 0. The value is then used as a divisor in two critical functions without any zero-check:

**First division point** in `GetMinersCount`: [2](#0-1) 

**Second division point** in `GetAutoIncreasedMinersCount`: [3](#0-2) 

The `Div` extension method performs raw division and will throw `DivideByZeroException` when the divisor is 0: [4](#0-3) 

**Critical execution paths affected:**

1. **Term transitions** call `UpdateMinersCountToElectionContract` which invokes `GetMinersCount`: [5](#0-4) 

2. **First round processing** calls `GetMinersCount` to initialize miner counts: [6](#0-5) 

3. **Setting maximum miners count** calls `GetMinersCount`: [7](#0-6) 

The initial value is set during contract initialization without validation: [8](#0-7) 

### Impact Explanation

**Complete Consensus Halt**: Once `MinerIncreaseInterval` is set to 0, the blockchain cannot execute any of the following critical consensus operations:

1. **Term transitions** (`NextTerm`) will fail with `DivideByZeroException`, preventing the blockchain from moving to new terms
2. **Round initialization** in the first round will fail, blocking blockchain startup/recovery
3. **Miner count updates** via `SetMaximumMinersCount` become impossible

**Irreversible Damage**: The vulnerability creates a one-way door. Once set to 0, the value cannot be increased because the validation logic requires new values to be ≤ current value. This means:
- No recovery through normal governance actions
- Requires emergency contract upgrade to fix
- All consensus operations permanently blocked

**Affected Parties**:
- All miners cannot produce blocks or receive rewards
- All users cannot submit transactions
- The entire blockchain is effectively dead until contract upgrade

**Severity Justification**: This is CRITICAL because it causes permanent, unrecoverable consensus failure affecting the entire network with no mitigation available through existing contract functions.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must control the `MaximumMinersCountController`, which defaults to the Parliament's default organization: [9](#0-8) 

**Attack Complexity**: LOW - Only requires two governance proposals:
1. Propose to decrease `MinerIncreaseInterval` to 1 (or small value)
2. Propose to decrease it to 0

**Feasibility Conditions**: 
- Requires Parliament governance control OR
- Malicious proposal that passes governance review OR
- Governance mistake/misconfiguration

**Probability Assessment**: MEDIUM likelihood because:
- Governance proposals go through multi-sig approval process
- However, proposals to "optimize" or "adjust" intervals might appear benign
- Configuration mistakes in governance proposals are realistic
- Once exploited, damage is permanent and unrecoverable
- The one-way nature (cannot increase interval) makes this a critical design flaw

### Recommendation

**Immediate Fix**: Add validation in `SetMinerIncreaseInterval` to enforce a minimum positive value:

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

**Additional Safeguards**:
1. Add defensive checks in `GetMinersCount` and `GetAutoIncreasedMinersCount`:
```csharp
Assert(State.MinerIncreaseInterval.Value > 0, "Invalid miner increase interval configuration.");
```

2. Add validation during initialization in `InitialAElfConsensusContract`:
```csharp
Assert(input.MinerIncreaseInterval > 0, "Miner increase interval must be positive.");
State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
```

**Test Cases**:
1. Test that `SetMinerIncreaseInterval` rejects 0 and negative values
2. Test that `SetMinerIncreaseInterval` rejects attempts to set value > current value
3. Test that initialization rejects 0 or negative intervals
4. Test that `GetMinersCount` handles edge cases gracefully with minimum valid interval

### Proof of Concept

**Initial State**:
- Blockchain operational with default `MinerIncreaseInterval` = 31536000 (1 year)
- Attacker controls Parliament governance

**Attack Steps**:
1. Attacker submits Parliament proposal to call `SetMinerIncreaseInterval(1)`
   - This passes validation: 1 ≤ 31536000 ✓
   - Proposal approved and executed
   - State: `MinerIncreaseInterval` = 1

2. Attacker submits Parliament proposal to call `SetMinerIncreaseInterval(0)`
   - This passes validation: 0 ≤ 1 ✓
   - Proposal approved and executed
   - State: `MinerIncreaseInterval` = 0

3. Next term transition occurs:
   - `NextTerm` → `UpdateMinersCountToElectionContract` → `GetMinersCount`
   - Line 390 executes: `.Div(State.MinerIncreaseInterval.Value)` = `.Div(0)`
   - **Result**: `DivideByZeroException` thrown
   - **Expected**: Successful term transition
   - **Actual**: Transaction fails, consensus halts

4. Recovery attempt via `SetMinerIncreaseInterval(1)`:
   - Validation fails: 1 ≤ 0 ✗ ("Invalid interval")
   - **Result**: Cannot recover through normal means
   - **Success Condition**: Blockchain permanently halted until contract upgrade

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L126-136)
```csharp
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-32)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;

        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;

        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;

```
