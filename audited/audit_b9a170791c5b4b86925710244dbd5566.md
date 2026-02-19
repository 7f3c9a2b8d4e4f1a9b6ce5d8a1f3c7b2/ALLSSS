# Audit Report

## Title
Inconsistent Miner Count Calculation Between GetMinersCount() and GetMaximumMinersCount() Causes Election Contract State Divergence

## Summary
The `GetMinersCount(Round input)` function conditionally applies time-based auto-increase only when the current round has at least 17 miners, while `GetMaximumMinersCount()` unconditionally applies the same formula. This causes `SetMaximumMinersCount()` to send a lower miner count to the Election contract than what external systems observe, resulting in fewer miners being elected than the blockchain age warrants.

## Finding Description

The root cause is divergent logic between two miner count calculation functions in the AEDPoS consensus contract:

**GetMinersCount(Round input)** contains conditional auto-increase logic [1](#0-0) . This function checks if `input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount` (17). If true, it returns exactly 17 without applying the time-based auto-increase formula. Only when the round has ≥17 miners does it apply the auto-increase calculation.

**GetMaximumMinersCount()** unconditionally applies auto-increase via `GetAutoIncreasedMinersCount()` [2](#0-1) . The `GetAutoIncreasedMinersCount()` function always calculates the time-based increase [3](#0-2)  regardless of the current round's miner count.

**SetMaximumMinersCount()** sends the inconsistent value to the Election contract [4](#0-3) . At line 25, it calls `GetMinersCount(round)` and sends the result via `UpdateMinersCount`.

The Election contract stores this value [5](#0-4)  and uses it to determine election outcomes [6](#0-5) . At line 81, `GetVictories()` uses `.Take(State.MinersCount.Value)` to select the top N candidates.

**Concrete Execution Flow:**
- Blockchain has aged enough that auto-increase adds 4 miners (theoretical max: 21)
- Current round has only 12 miners (side chain or after ejections)
- Parliament calls `SetMaximumMinersCount(50)` to set a high cap
- `GetMinersCount(round)` evaluates: 12 < 17, returns 17 (no auto-increase)
- Election contract stores: `MinersCount = 17`
- But `GetMaximumMinersCount()` returns: 21 (with auto-increase)
- `GetVictories()` elects only 17 miners instead of 21

The SupposedMinersCount constant is defined as 17 [7](#0-6) .

## Impact Explanation

This creates measurable consensus integrity issues:

1. **State Divergence**: The public view method `GetMaximumMinersCount()` returns a different value than what's actually used for elections, violating the principle that observable state should match operational state.

2. **Reduced Decentralization**: The Election contract elects fewer miners than the blockchain's maturity level warrants. In the example scenario, 4 miners who should be elected based on the auto-increase schedule are excluded.

3. **Consensus System Integrity**: The time-based auto-increase mechanism is designed to gradually expand the miner set as the blockchain matures. This bug undermines that design by capping elections at 17 when conditions require fewer than 17 current miners.

4. **Legitimate Candidate Exclusion**: Candidate nodes that should qualify based on the advertised maximum miner count are denied election, affecting their expected participation and rewards.

The severity is **Medium** because while it doesn't cause direct fund theft, it compromises consensus system correctness and creates observable state inconsistency.

## Likelihood Explanation

The preconditions are realistic and occur naturally:

1. **Side Chain Initialization**: Side chains commonly start with fewer than 17 miners for operational efficiency
2. **After Miner Ejections**: When multiple evil miners are detected and removed during term transitions
3. **Early Blockchain Lifecycle**: During initial bootstrapping before the full miner set is established
4. **Test Networks**: Development and test environments typically run with reduced miner counts

The trigger is a legitimate governance action (Parliament calling `SetMaximumMinersCount()`), not an exploit. The issue manifests automatically when:
- Current round has < 17 miners
- Blockchain has aged enough for auto-increase to be non-zero
- Parliament updates the maximum miners count setting

This combination is **Medium likelihood** as it occurs naturally in the scenarios above, particularly on side chains and during network growth phases.

## Recommendation

Unify the miner count calculation logic. The `GetMinersCount(Round input)` function should apply the same unconditional auto-increase formula as `GetAutoIncreasedMinersCount()`:

```csharp
private int GetMinersCount(Round input)
{
    if (State.BlockchainStartTimestamp.Value == null) 
        return AEDPoSContractConstants.SupposedMinersCount;

    if (!TryToGetRoundInformation(1, out _)) 
        return 0;
    
    // Remove the conditional check - always apply auto-increase
    var autoIncreasedCount = GetAutoIncreasedMinersCount();
    return Math.Min(autoIncreasedCount, State.MaximumMinersCount.Value);
}
```

This ensures that `SetMaximumMinersCount()` sends the same value to the Election contract that external systems observe via `GetMaximumMinersCount()`, eliminating the state divergence.

## Proof of Concept

```csharp
[Fact]
public async Task MinersCount_Inconsistency_Between_GetMinersCount_And_GetMaximumMinersCount()
{
    // Setup: Initialize blockchain with 12 miners (less than SupposedMinersCount=17)
    const int initialMinersCount = 12;
    await InitializeConsensusWithMiners(initialMinersCount);
    
    // Advance blockchain time to enable auto-increase of 4 miners
    // (e.g., 2 intervals passed, each adding 2 miners)
    await AdvanceBlockchainTime(days: 180); // Sufficient for +4 auto-increase
    
    // Parliament sets a high maximum (50) to allow auto-increase
    var parliamentResult = await SetMaximumMinersCountViaParliament(50);
    parliamentResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Query the Election contract's stored miners count
    var electionMinersCount = await ElectionContractStub.GetMinersCount.CallAsync(new Empty());
    
    // Query the public view method on AEDPoS contract
    var publicMaxCount = await AEDPoSContractStub.GetMaximumMinersCount.CallAsync(new Empty());
    
    // BUG: These should match but don't
    electionMinersCount.Value.ShouldBe(17); // Returns 17 (no auto-increase applied)
    publicMaxCount.Value.ShouldBe(21); // Returns 21 (17 + 4 auto-increase)
    
    // Verify elections are capped at the lower value
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    victories.Value.Count.ShouldBe(17); // Only 17 miners elected, not 21
}
```

### Citations

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L149-160)
```csharp
    public override Empty UpdateMinersCount(UpdateMinersCountInput input)
    {
        Context.LogDebug(() =>
            $"Consensus Contract Address: {Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName)}");
        Context.LogDebug(() => $"Sender Address: {Context.Sender}");
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only consensus contract can update miners count.");
        State.MinersCount.Value = input.MinersCount;
        SyncSubsidyInfoAfterReduceMiner();
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```
