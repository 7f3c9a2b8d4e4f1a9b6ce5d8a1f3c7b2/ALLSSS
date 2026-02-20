# Audit Report

## Title
Unvalidated MinerIncreaseInterval Initialization Enables Unrecoverable Division by Zero DoS in Consensus Operations

## Summary
The AEDPoS consensus contract's `InitialAElfConsensusContract` method lacks validation to prevent `MinerIncreaseInterval` from being initialized to zero. This causes immediate consensus failure during the first round transition when `GetMinersCount()` performs division by zero, halting the mainchain without possibility of recovery through governance mechanisms.

## Finding Description

The vulnerability exists across multiple layers of the consensus initialization and operation flow:

**Missing Input Validation:**
The initialization method directly assigns the input value without any validation. [1](#0-0) 

**Division by Zero in Critical Path:**
During the first round to second round transition on mainchain, when `ProcessNextRound` executes the special initialization block for round 1, it calls `GetMinersCount()` after setting the blockchain start timestamp. [2](#0-1) 

The `GetMinersCount()` internal method performs unchecked division by `MinerIncreaseInterval` after `BlockchainStartTimestamp` is set. [3](#0-2) 

Similarly, the public view method `GetMaximumMinersCount()` calls `GetAutoIncreasedMinersCount()` which also divides by `MinerIncreaseInterval`. [4](#0-3) 

**SafeMath Does Not Prevent Division by Zero:**
The `.Div()` extension method performs standard division without zero checking. [5](#0-4) 

**Broken Recovery Mechanism:**
The governance method to update `MinerIncreaseInterval` only allows decreasing the value, preventing recovery from zero. [6](#0-5) 

If the current value is 0, the assertion at line 61 (`input.Value <= State.MinerIncreaseInterval.Value`) prevents setting any positive value.

## Impact Explanation

**Critical Consensus Failure:**

1. **Immediate Chain Halt**: During the transition from round 1 to round 2, the `ProcessNextRound` method calls `GetMinersCount()` which throws `DivideByZeroException`, causing the transaction to fail and preventing further rounds from being created.

2. **Mainchain-Specific**: The vulnerability only affects mainnets due to the conditional check at the failure point. [7](#0-6) 

3. **Multiple Failure Points**: Beyond the automatic consensus failure, any call to `GetMaximumMinersCount()` (public view method) or `SetMaximumMinersCount()` (governance method) will also fail, preventing manual intervention.

4. **Permanent Damage**: The recovery method's flawed assertion logic makes it impossible to fix via governance. A hard fork or complete chain restart would be required.

5. **Election Contract Integration Broken**: The failure prevents updating the Election Contract with miner count information, breaking the coordination between consensus and election subsystems. [8](#0-7) 

## Likelihood Explanation

**Likelihood: LOW but POSSIBLE**

While unlikely in practice, this vulnerability represents a critical configuration error with no safety net:

**Mitigating Factors:**
- Default configuration value is 31536000 (one year). [9](#0-8) 
- Genesis initialization is typically carefully reviewed
- No evidence in codebase of zero values being used in tests

**Risk Factors:**
- **No Validation**: Zero technical barrier prevents the misconfiguration
- **One-Time Operation**: Genesis initialization happens once, potentially without comprehensive testing of edge cases
- **Catastrophic Consequence**: If it occurs, recovery requires chain restart
- **Silent Acceptance**: The contract accepts zero without warning or error

The combination of no validation with catastrophic unrecoverable impact makes this a valid security concern despite low likelihood.

## Recommendation

Add input validation to the `InitialAElfConsensusContract` method to ensure `MinerIncreaseInterval` is greater than zero:

```csharp
public override Empty InitialAElfConsensusContract(InitialAElfConsensusContractInput input)
{
    Assert(State.CurrentRoundNumber.Value == 0 && !State.Initialized.Value, "Already initialized.");
    State.Initialized.Value = true;

    State.PeriodSeconds.Value = input.IsTermStayOne
        ? int.MaxValue
        : input.PeriodSeconds;

    // Add validation
    Assert(input.MinerIncreaseInterval > 0, "MinerIncreaseInterval must be greater than zero.");
    State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
    
    // ... rest of the method
}
```

Additionally, fix the `SetMinerIncreaseInterval` method to allow increasing the value:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value > 0, "MinerIncreaseInterval must be greater than zero.");
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

## Proof of Concept

```csharp
[Fact]
public async Task InitialAElfConsensusContract_WithZeroMinerIncreaseInterval_ShouldCauseConsensusFailure()
{
    // Initialize consensus with MinerIncreaseInterval = 0
    var input = new InitialAElfConsensusContractInput
    {
        PeriodSeconds = 604800,
        MinerIncreaseInterval = 0, // Zero value - no validation exists
        IsSideChain = false,
        IsTermStayOne = false
    };
    
    // This succeeds because there's no validation
    await ConsensusStub.InitialAElfConsensusContract.SendAsync(input);
    
    // Initialize first round
    var firstRound = GenerateFirstRound(InitialMinersCount);
    await ConsensusStub.FirstRound.SendAsync(firstRound);
    
    // Generate next round input (transition from round 1 to round 2)
    var nextRound = GenerateNextRound(firstRound);
    var nextRoundInput = new NextRoundInput { /* ... */ };
    
    // This will fail with DivideByZeroException in GetMinersCount
    // when ProcessNextRound executes the mainchain initialization code
    var result = await ConsensusStub.NextRound.SendWithExceptionAsync(nextRoundInput);
    
    // Verify consensus failure
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("DivideByZero");
}
```

## Notes

The vulnerability is particularly severe because:
1. It affects mainchain consensus operations only, which are critical for the entire network
2. The failure occurs automatically during normal round progression, not requiring attacker action
3. There is no recovery path through governance due to the broken `SetMinerIncreaseInterval` logic
4. The issue is only detectable at runtime after genesis initialization completes, not at deployment time

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L31-31)
```csharp
        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L117-136)
```csharp
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L13-13)
```csharp
    public long MinerIncreaseInterval { get; set; } = 31536000;
```
