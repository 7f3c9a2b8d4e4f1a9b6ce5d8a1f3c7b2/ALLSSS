# Audit Report

## Title
Division by Zero DoS in SetMinerIncreaseInterval Allows Complete Consensus Failure

## Summary
The `SetMinerIncreaseInterval()` function lacks validation to prevent setting `MinerIncreaseInterval` to zero or negative values. Since this interval is used as a divisor in critical consensus calculations, setting it to zero causes a `DivideByZeroException` that breaks all round transitions, term changes, and miners count updates, resulting in complete consensus denial-of-service.

## Finding Description

The vulnerability exists in the `SetMinerIncreaseInterval()` method which only validates that the new interval value is less than or equal to the current value, but fails to enforce a minimum positive value. [1](#0-0) 

The problematic validation only prevents increases but allows zero or negative values. The `MinerIncreaseInterval` is then used as a divisor in two critical locations:

1. In `GetAutoIncreasedMinersCount()` where the elapsed time since blockchain start is divided by the interval: [2](#0-1) 

2. In `GetMinersCount()` where the same division calculation occurs: [3](#0-2) 

The `Div()` method performs standard division without zero-checking and will throw `DivideByZeroException`: [4](#0-3) 

Test suite confirms division by zero throws `DivideByZeroException`: [5](#0-4) 

These calculation functions are called during critical consensus operations:

- **First round transition**: When transitioning from round 1 to round 2, `ProcessNextRound` calls `GetMinersCount()` to initialize the Election Contract's miner count [6](#0-5) 

- **Every term transition**: `ProcessNextTerm` calls `UpdateMinersCountToElectionContract()` which invokes `GetMinersCount()` [7](#0-6)  and [8](#0-7) 

- **Maximum miners count updates**: `SetMaximumMinersCount()` directly calls `GetMinersCount()` [9](#0-8) 

- **View method queries**: `GetMaximumMinersCount()` calls `GetAutoIncreasedMinersCount()` which will fail [10](#0-9) 

## Impact Explanation

**Complete Consensus Denial of Service**: Once `MinerIncreaseInterval` is set to zero, all consensus operations that calculate miners count will fail with `DivideByZeroException`. This includes:

1. **Round transitions fail**: The blockchain cannot move from round 1 to round 2, as `ProcessNextRound` calls `GetMinersCount()` to update the Election Contract
2. **Term transitions fail**: Every term change requires `GetMinersCount()` calculation, preventing the blockchain from advancing terms
3. **Miners count updates fail**: Any attempt to update maximum miners count via `SetMaximumMinersCount()` will fail
4. **View method failures**: `GetMaximumMinersCount()` queries will throw exceptions

The blockchain becomes completely stuck, unable to produce blocks beyond the initial round. No recovery is possible without contract upgrade or hard fork, as the interval can only be decreased (never increased) per the existing validation logic at line 61.

**Affected parties**: All network participants - miners cannot produce blocks, users cannot submit transactions, and the entire blockchain halts.

## Likelihood Explanation

**Attack Requirements**:
- Attacker must control the `MaximumMinersCountController`, which defaults to Parliament's default organization [11](#0-10) 
- Requires creating and passing a governance proposal
- One simple transaction: `SetMinerIncreaseInterval(0)`

**Feasibility**: HIGH
- Parliament governance is the intended control mechanism, but is vulnerable to:
  - Malicious governance takeover (if voting power is concentrated)
  - Accidental misconfiguration (human error in proposal parameters)
  - No validation prevents honest mistakes
- The attack is irreversible due to the decrease-only constraint
- No gas cost barrier (standard governance transaction)

**Detection**: The attack would be immediately obvious as all consensus operations fail, but by then the damage is done and the blockchain is halted.

**Probability**: Medium-to-High depending on governance security, but the impact severity (complete DoS) makes this a critical vulnerability regardless.

## Recommendation

Add validation in `SetMinerIncreaseInterval()` to ensure the interval value is strictly positive:

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

This simple check ensures the interval can never be set to zero or negative values, preventing the division-by-zero exception while maintaining the intended decrease-only constraint.

## Proof of Concept

```csharp
[Fact]
public async Task SetMinerIncreaseIntervalToZero_CausesConsensusFailure()
{
    // Setup: Initialize contracts and reach term 2
    InitialContracts();
    await BlockMiningService.MineBlockToNextTermAsync();
    
    // Initialize Parliament for governance
    InitialAcs3Stubs();
    await ParliamentStubs.First().Initialize.SendAsync(new InitializeInput());
    var defaultOrganizationAddress = 
        await ParliamentStubs.First().GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Attack: Set MinerIncreaseInterval to zero through governance
    await ParliamentReachAnAgreementAsync(new CreateProposalInput
    {
        ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
        ContractMethodName = nameof(ConsensusStub.SetMinerIncreaseInterval),
        Params = new Int64Value { Value = 0 }.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        OrganizationAddress = defaultOrganizationAddress
    });
    
    // Verify: GetMaximumMinersCount() now throws DivideByZeroException
    await Assert.ThrowsAsync<DivideByZeroException>(async () =>
    {
        await ConsensusStub.GetMaximumMinersCount.CallAsync(new Empty());
    });
    
    // Verify: NextTerm (term transitions) now fail with DivideByZeroException
    await Assert.ThrowsAsync<DivideByZeroException>(async () =>
    {
        await BlockMiningService.MineBlockToNextTermAsync();
    });
}
```

## Notes

The vulnerability stems from incomplete input validation. While the function correctly restricts the interval to only decrease (preserving the intended economic model), it fails to enforce a lower bound. The `MinerIncreaseInterval` is initialized to 31536000 seconds (1 year) by default [12](#0-11) , but the validation logic allows governance to set it to any value ≤ current value, including zero or negative numbers.

The irreversibility is a critical factor - since the validation uses `<=`, once set to zero, the interval cannot be increased back to any positive value through normal contract execution. This makes the DoS permanent and unrecoverable without a contract upgrade or hard fork.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L20-26)
```csharp
        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });
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

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L50-51)
```csharp
        Should.Throw<DivideByZeroException>(() => { number1.Div(0); });
        Should.Throw<DivideByZeroException>(() => { number2.Div(0); });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L117-137)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-177)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L27-31)
```csharp
        State.PeriodSeconds.Value = input.IsTermStayOne
            ? int.MaxValue
            : input.PeriodSeconds;

        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
```
