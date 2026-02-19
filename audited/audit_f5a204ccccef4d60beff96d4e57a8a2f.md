# Audit Report

## Title
Retroactive Miner Count Calculation Causes Sudden Jumps When MinerIncreaseInterval is Modified

## Summary
The `SetMinerIncreaseInterval()` function allows governance to decrease the miner increase interval, but the miner count calculation retroactively applies the new interval to the entire blockchain history. This causes an immediate jump in the calculated miner count, violating the intended gradual increase mechanism and disrupting consensus by suddenly selecting more miners than should be eligible.

## Finding Description

The vulnerability exists in the miner count calculation logic. When `SetMinerIncreaseInterval()` updates the interval value [1](#0-0) , this new value is immediately used by `GetAutoIncreasedMinersCount()` to calculate the miner count [2](#0-1) .

The calculation formula divides the **entire elapsed time since blockchain start** by the **current interval value**, then multiplies by 2. When the interval decreases (e.g., from 1 year to 6 months), the division produces a larger quotient, as if the shorter interval had always been in effect throughout the blockchain's history.

This retroactive calculation is also used in `GetMinersCount()` [3](#0-2) , which is called during term transitions [4](#0-3)  and when setting the maximum miners count [5](#0-4) .

The jumped value is propagated to the Election Contract via `UpdateMinersCountToElectionContract()` [6](#0-5) , where it's stored [7](#0-6)  and used by `GetVictories()` to determine how many candidates should become miners [8](#0-7) .

## Impact Explanation

**Concrete Example:**
- Initial: 2 years elapsed (63,072,000 seconds), interval = 31,536,000 seconds → count = 17 + (2 intervals × 2) = 21 miners
- After decreasing to 6 months (15,768,000 seconds) → count = 17 + (4 intervals × 2) = 25 miners  
- Result: Sudden jump of 4 miners

**Protocol Damage:**

1. **Consensus Disruption**: The sudden addition of 4+ miners changes the consensus participant set abruptly, violating the intended gradual decentralization where only 2 miners should be added per interval [9](#0-8) 

2. **Reward Dilution**: Mining rewards are distributed among all active miners, so existing miners suddenly receive proportionally less reward per block

3. **Security Model Violation**: AEDPoS consensus uses Byzantine fault tolerance where the number of miners affects security thresholds. An unexpected jump in miner count alters these assumptions

4. **Candidate Selection Error**: Less-qualified candidates who weren't supposed to be eligible yet become miners immediately, potentially affecting network quality

**Severity: MEDIUM** - While this doesn't directly steal funds or break authorization, it violates critical consensus invariants and causes operational disruption with reward misallocation.

## Likelihood Explanation

This requires governance authorization through `MaximumMinersCountController` (Parliament by default), which is a trusted role. However, the vulnerability is a **logic bug**, not governance abuse.

**Key Point**: Even when governance acts legitimately and honestly to accelerate decentralization, the bug triggers automatically. The governance's intent is to change the **future rate** of miner additions, but the implementation retroactively recalculates **all historical additions** as if the new interval had always been in effect.

**Triggering Conditions:**
- Governance approves an interval decrease through the validation check [10](#0-9) 
- Next term transition or `SetMaximumMinersCount` call propagates the jumped value
- The retroactive calculation is deterministic and automatic

**Probability: HIGH** - If governance ever adjusts the interval for legitimate policy reasons (e.g., accelerating decentralization), the bug triggers with certainty. Governance may not realize the retroactive effect until after approval.

## Recommendation

Implement a proper tracking mechanism that records the actual interval history instead of retroactively applying the current interval to all elapsed time. The fix should:

1. Store interval change history with timestamps
2. Calculate miner increases by summing actual intervals that have passed
3. Only apply the new interval to future time periods

Example fix approach:
```csharp
// Track when intervals changed and calculate based on actual historical intervals
private int GetAutoIncreasedMinersCount()
{
    if (State.BlockchainStartTimestamp.Value == null) 
        return AEDPoSContractConstants.SupposedMinersCount;
    
    // Calculate increases based on recorded interval history
    var totalIncrements = CalculateHistoricalIntervalIncrements();
    return AEDPoSContractConstants.SupposedMinersCount.Add(totalIncrements.Mul(2));
}
```

Alternatively, prevent interval changes entirely and use a fixed interval to maintain consistency with the original gradual increase design.

## Proof of Concept

The existing test demonstrates interval changes but doesn't validate the retroactive calculation impact [11](#0-10) . 

A proof-of-concept test would:
1. Initialize blockchain with a 1-year interval
2. Advance time by 2 years
3. Verify miner count is 21 (17 + 2*2)
4. Decrease interval to 6 months via Parliament
5. Verify miner count suddenly jumps to 25 (17 + 4*2) without any actual time passing
6. Confirm this value propagates to Election contract and affects `GetVictories()`

This demonstrates the retroactive calculation bug where changing future policy parameters incorrectly recalculates historical miner growth.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L23-26)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L176-176)
```csharp
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L79-83)
```csharp
        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L108-147)
```csharp
    [Fact]
    public async Task SetMinerIncreaseIntervalTest()
    {
        InitialContracts();
        await BlockMiningService.MineBlockToNextTermAsync();

        InitialAcs3Stubs();
        await ParliamentStubs.First().Initialize.SendAsync(new InitializeInput());
        var minerIncreaseInterval = await ConsensusStub.GetMinerIncreaseInterval.CallAsync(new Empty());
        
        var defaultOrganizationAddress =
            await ParliamentStubs.First().GetDefaultOrganizationAddress.CallAsync(new Empty());

        var transactionResult = await ParliamentReachAnAgreementWithExceptionAsync(new CreateProposalInput
        {
            ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            ContractMethodName = nameof(ConsensusStub.SetMinerIncreaseInterval),
            Params = new Int64Value
            {
                Value = minerIncreaseInterval.Value + 1
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = defaultOrganizationAddress
        });
        transactionResult.Error.ShouldContain("Invalid interval");
        var newMinerIncreaseInterval = minerIncreaseInterval.Value - 1;
        await ParliamentReachAnAgreementAsync(new CreateProposalInput
        {
            ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            ContractMethodName = nameof(ConsensusStub.SetMinerIncreaseInterval),
            Params = new Int64Value
            {
                Value = newMinerIncreaseInterval
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = defaultOrganizationAddress
        });
        minerIncreaseInterval = await ConsensusStub.GetMinerIncreaseInterval.CallAsync(new Empty());
        minerIncreaseInterval.Value.ShouldBe(newMinerIncreaseInterval);
    }
```
