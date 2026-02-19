### Title
Incorrect Miner Count Calculation When Current Round Has Fewer Than Initial Miners

### Summary
The `GetMinersCount()` function incorrectly returns the initial `SupposedMinersCount` (17) instead of the time-based auto-increased count when the current round has fewer than 17 miners. This causes the Election contract to select fewer block producers than intended based on blockchain age, reducing network decentralization and security.

### Finding Description

The vulnerability exists in the `GetMinersCount()` function: [1](#0-0) 

The function uses a conditional check `input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount` to decide whether to apply the time-based auto-increase calculation. If the current round has fewer than 17 miners, it returns `Math.Min(17, MaximumMinersCount)` and completely ignores the blockchain age calculation.

This logic error means that when `input.RealTimeMinersInformation.Count < 17` (current round has fewer miners), the function returns 17 instead of calculating the correct auto-increased value. For example, if the blockchain has been running for a year and the auto-increased count should be 25, but the current round only has 15 miners, the function incorrectly returns 17 instead of 25.

The incorrect value is then propagated to the Election contract via `UpdateMinersCount`: [2](#0-1) [3](#0-2) 

The Election contract stores this value and uses it to determine how many miners to select: [4](#0-3) [5](#0-4) 

### Impact Explanation

When the miners count is incorrectly set to a lower value:

1. **Reduced Block Producers**: The `GetVictories()` function selects only 17 miners instead of the intended 25 (in the example scenario), resulting in 8 fewer block producers.

2. **Reduced Data Center Slots**: The validation data center count is calculated as `MinersCount * 5`, so incorrect miners count also caps data center participation at 85 instead of 125 (40 fewer slots): [6](#0-5) 

3. **Network Security Impact**: Fewer block producers means reduced decentralization, making the network more vulnerable to censorship and attacks.

4. **Persistent Issue**: Once set incorrectly, the miners count remains at the lower value until explicitly updated, affecting multiple terms.

### Likelihood Explanation

This vulnerability can be triggered during normal blockchain operations:

**Preconditions:**
- Blockchain has been running long enough that the auto-increased count exceeds `SupposedMinersCount` (17)
- Current round has fewer than 17 active miners

**Scenarios:**
1. During initial blockchain bootstrap when the miner set is still building up
2. After temporary network issues that reduce active miners below 17
3. During the first term transition after genesis

**Attack Vector:**
No attacker action required - this is a logic error that triggers automatically during normal consensus operations. The function is called in:
- `SetMaximumMinersCount()` (governance-controlled but legitimate use)
- `UpdateMinersCountToElectionContract()` during term transitions
- `ProcessNextRound()` when round 1 completes

**Probability:** Medium - occurs whenever the current round has < 17 miners and sufficient blockchain age has passed.

### Recommendation

Remove the conditional check on `input.RealTimeMinersInformation.Count` and always calculate the auto-increased count based on blockchain age:

```csharp
private int GetMinersCount(Round input)
{
    if (State.BlockchainStartTimestamp.Value == null) 
        return AEDPoSContractConstants.SupposedMinersCount;
    
    if (!TryToGetRoundInformation(1, out _)) 
        return 0;
    
    var autoIncreasedCount = AEDPoSContractConstants.SupposedMinersCount.Add(
        (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
        .Div(State.MinerIncreaseInterval.Value).Mul(2));
    
    // Ensure minimum of SupposedMinersCount and cap at MaximumMinersCount
    return Math.Min(
        Math.Max(autoIncreasedCount, AEDPoSContractConstants.SupposedMinersCount), 
        State.MaximumMinersCount.Value);
}
```

Alternatively, use the existing `GetAutoIncreasedMinersCount()` helper: [7](#0-6) 

**Test Cases:**
1. Verify miners count calculation when current round has < 17 miners but blockchain age warrants more
2. Ensure auto-increase applies correctly regardless of current round size
3. Validate Election contract receives correct miners count during term transitions

### Proof of Concept

**Initial State:**
- Blockchain running for sufficient time that auto-increased count = 25
- `State.MaximumMinersCount.Value = 30`
- `MinerIncreaseInterval` configured appropriately
- Current round has 15 miners (< 17)

**Execution Steps:**
1. NextTerm or NextRound consensus operation executes
2. `UpdateMinersCountToElectionContract(nextRound)` is called
3. `GetMinersCount(nextRound)` evaluates with `nextRound.RealTimeMinersInformation.Count = 15`
4. Condition `15 < 17` is true
5. Function returns `Math.Min(17, 30) = 17`

**Expected Result:** 
Function should return `Math.Min(25, 30) = 25` based on blockchain age

**Actual Result:** 
Function returns 17, causing Election contract to select only 17 miners instead of 25

**Success Condition:** 
Election contract's `State.MinersCount.Value` is set to 17 instead of the correct 25, and subsequent `GetVictories()` calls select 8 fewer block producers than intended.

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L406-409)
```csharp
    private int GetValidationDataCenterCount()
    {
        return GetMinersCount(new Empty()).Value.Mul(5);
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
