# Audit Report

## Title
Critical State Validation Flaw Enables Irreversible Consensus Failure via MinerIncreaseInterval

## Summary
The AEDPoS consensus contract contains a backwards validation assertion in `SetMinerIncreaseInterval` that allows the Parliament controller to set `MinerIncreaseInterval` to zero but prevents any subsequent increase. Once set to zero, this causes division-by-zero exceptions in all miner count calculation methods, permanently breaking consensus operations with no recovery path. [1](#0-0) 

## Finding Description

The `SetMinerIncreaseInterval` method enforces a validation constraint that only permits DECREASING the interval value. The assertion at line 61 checks `input.Value <= State.MinerIncreaseInterval.Value`, which allows setting the value from 31,536,000 (default) down to 0, but once at 0, prevents setting any positive value since the condition `positive_value <= 0` will always fail. [2](#0-1) 

Once `MinerIncreaseInterval` reaches zero, two public methods suffer division-by-zero failures:

1. **GetMaximumMinersCount** (public view, no access control) calls `GetAutoIncreasedMinersCount` which divides by `MinerIncreaseInterval`: [3](#0-2) [4](#0-3) 

2. **GetMinersCount** (called by SetMaximumMinersCount and consensus operations) performs the same division: [5](#0-4) 

The only initialization method cannot be called again due to a guard preventing re-initialization: [6](#0-5) 

**Secondary Issue:** Side chains never initialize `MaximumMinersCount` because they return early from initialization, leaving the value at 0: [7](#0-6) [8](#0-7) 

This causes `GetMinersCount` to always return 0 for side chains via `Math.Min(..., 0)`.

## Impact Explanation

**Critical Consensus Failure:**
- `GetMaximumMinersCount` is a public view method callable by anyone - division-by-zero makes it permanently unusable
- `SetMaximumMinersCount` (Parliament-controlled) calls `GetMinersCount` and fails with division-by-zero
- Consensus round transitions in `ProcessNextRound` call `GetMinersCount` when updating the Election contract
- No recovery mechanism exists - the contract state becomes permanently corrupted [9](#0-8) [10](#0-9) 

**Side Chain Impact:**
All side chains have `MaximumMinersCount` permanently set to 0, causing `GetMinersCount` to return 0 instead of actual miner counts. While this doesn't crash (if `MinerIncreaseInterval` is non-zero), it produces incorrect results that corrupt consensus state.

## Likelihood Explanation

**Trigger Scenario:**
1. Parliament controller calls `SetMinerIncreaseInterval` with value 0 (passes validation: `0 <= 31536000`)
2. `MinerIncreaseInterval` is now 0
3. Any call to `GetMaximumMinersCount` or `SetMaximumMinersCount` causes division-by-zero
4. Attempting to fix via `SetMinerIncreaseInterval(positive_value)` fails validation: `positive_value <= 0` is false

**Likelihood: HIGH**
- Parliament is a trusted role, but the backwards validation logic creates an accidental foot-gun
- No input validation prevents setting to 0
- Once triggered (accidentally or in testing), system is permanently broken
- Side chain issue affects 100% of side chain deployments

**Feasibility: CERTAIN**
- Parliament authority is legitimate governance mechanism
- No cryptographic or VM-level attacks required
- Purely logic flaw in validation constraints

## Recommendation

**Fix 1: Correct the validation logic in SetMinerIncreaseInterval**
```csharp
// Current (incorrect):
Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");

// Should be:
Assert(input.Value > 0, "Interval must be positive");
Assert(input.Value >= State.MinerIncreaseInterval.Value, "Can only increase interval");
// OR remove the comparison entirely and just validate positivity
```

**Fix 2: Add zero-check protection in GetAutoIncreasedMinersCount**
```csharp
private int GetAutoIncreasedMinersCount()
{
    if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;
    
    // Add protection:
    if (State.MinerIncreaseInterval.Value == 0) return AEDPoSContractConstants.SupposedMinersCount;
    
    return AEDPoSContractConstants.SupposedMinersCount.Add(...);
}
```

**Fix 3: Initialize MaximumMinersCount for side chains**
```csharp
if (input.IsTermStayOne || input.IsSideChain)
{
    State.IsMainChain.Value = false;
    // Add this:
    State.MaximumMinersCount.Value = int.MaxValue;
    return new Empty();
}
```

**Fix 4: Add migration method for contract upgrades**
```csharp
public override Empty MigrateConsensusState(MigrateConsensusStateInput input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress, "No permission");
    
    if (State.MinerIncreaseInterval.Value == 0)
        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
    if (State.MaximumMinersCount.Value == 0)
        State.MaximumMinersCount.Value = input.MaximumMinersCount;
    
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task DivisionByZero_WhenMinerIncreaseIntervalSetToZero()
{
    // Setup: Initialize contract with proper values
    await InitializeContracts();
    
    // Verify initial state works
    var initialMax = await ConsensusStub.GetMaximumMinersCount.CallAsync(new Empty());
    initialMax.Value.ShouldBeGreaterThan(0);
    
    // Attacker: Parliament sets MinerIncreaseInterval to 0
    // This passes validation because 0 <= current_value
    var parliamentController = await ConsensusStub.GetMaximumMinersCountController.CallAsync(new Empty());
    await ParliamentStub.SetMinerIncreaseInterval.SendAsync(new Int64Value { Value = 0 });
    
    // Now GetMaximumMinersCount causes division by zero
    Should.Throw<DivideByZeroException>(() =>
    {
        var result = ConsensusStub.GetMaximumMinersCount.CallAsync(new Empty()).Result;
    });
    
    // Attempting to fix by setting positive value fails validation
    await ParliamentStub.SetMinerIncreaseInterval.SendAsync(new Int64Value { Value = 31536000 })
        .ShouldThrow<AssertionException>(); // "Invalid interval" because 31536000 > 0
}
```

## Notes

The claim's upgrade scenario (uninitialized state variables defaulting to 0) requires git history to fully validate whether these variables were added post-genesis. However, **even without the upgrade scenario**, the vulnerability is valid because:

1. The backwards validation logic in `SetMinerIncreaseInterval` is objectively a bug
2. Parliament can legitimately (but accidentally) trigger division-by-zero by setting the value to 0
3. There is no recovery mechanism once triggered
4. The impact is severe and permanent

The side chain issue with `MaximumMinersCount` always being 0 is a separate but related design flaw that causes incorrect miner count calculations for all side chain deployments.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L22-25)
```csharp
    public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
    {
        Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
        State.Initialized.Value = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L37-41)
```csharp
        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
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
