# Audit Report

## Title
Non-Deterministic Data Center Removal Due to Unstable Sorting with Equal Vote Amounts

## Summary
The `SyncSubsidyInfoAfterReduceMiner()` function in the Election contract uses non-deterministic sorting when removing data centers with equal vote amounts, causing different blockchain nodes to remove different candidates. This breaks the fundamental blockchain invariant of deterministic execution, leading to state divergence and consensus failure.

## Finding Description

The vulnerability exists in the `SyncSubsidyInfoAfterReduceMiner()` function which removes the lowest-ranked data centers when the miner count is reduced. [1](#0-0) 

The root cause is that `DataCentersRankingList.DataCenters` is a protobuf `map<string, int64>` field [2](#0-1) , which compiles to a MapField (dictionary-based collection) with non-deterministic iteration order.

When `OrderBy(x => x.Value)` is applied to the MapField:
1. The MapField enumerator provides KeyValuePair entries in non-deterministic order
2. OrderBy performs a stable sort, but the input order is already non-deterministic
3. For entries with equal values (vote amounts), the relative order after sorting remains non-deterministic
4. Different nodes enumerate the MapField in different orders
5. `Take(diffCount)` selects different sets of candidates on different nodes

The codebase demonstrates awareness of this issue - when deterministic ordering is required, explicit secondary sort keys are used. In the consensus contract: [3](#0-2) 

This shows the correct pattern: sorting by `m.Order` to ensure deterministic iteration over the `RealTimeMinersInformation` MapField.

The vulnerable function is called from `UpdateMinersCount()`: [4](#0-3) 

Which is invoked by the consensus contract during term transitions: [5](#0-4) 

And when governance sets the maximum miner count: [6](#0-5) 

The same vulnerability exists in two additional locations where MapField is sorted without a secondary key: [7](#0-6)  and [8](#0-7) 

## Impact Explanation

**Consensus Failure (Critical)**: When multiple data centers have equal vote amounts at the removal boundary, different blockchain nodes will remove different sets of candidates. This causes their blockchain states to diverge. In blockchain systems, state divergence prevents nodes from reaching consensus on subsequent blocks, effectively halting the chain or causing a fork.

**Incorrect Subsidy Distribution**: The removed candidates are also removed from the subsidy profit scheme: [9](#0-8) 

This affects the Profit contract's distribution calculations, causing wrong candidates to lose subsidy eligibility.

**Affected Parties**:
- **Blockchain network**: Consensus integrity compromised, potential chain halt
- **Data center operators**: Wrong candidates incorrectly lose subsidy eligibility  
- **Token holders**: Incorrect profit distribution calculations

The severity is **High** because:
- Causes immediate consensus failure when triggered
- Violates the fundamental blockchain invariant of deterministic execution
- No fund theft, but operational integrity is critically impacted

## Likelihood Explanation

**High Likelihood - Natural Occurrence**

This is a determinism bug that triggers naturally without any attacker involvement. Equal vote amounts occur in several common scenarios:

1. **Newly announced candidates** all start with 0 votes
2. **Equal vote amounts from different voters** (e.g., two candidates each receiving exactly 1000 tokens)
3. **Post-withdrawal states** where candidates end up with the same remaining vote count

**Triggering Conditions**:
- Miner count reduction via governance proposal, OR
- Automatic miner count adjustment during term transitions, AND
- Multiple candidates have equal vote amounts at the removal boundary

**Realistic Scenario**:
The data center ranking list typically contains n×5 candidates (e.g., 15-25 candidates for 3-5 miners). With this many candidates, having 2-3 candidates with equal vote amounts at the boundary position is highly probable, especially when:
- New candidates are frequently announced (all starting at 0 votes)
- Vote amounts are round numbers (1000, 5000, 10000 tokens)
- After vote withdrawals leave candidates with identical remaining amounts

The function executes on **every node** during consensus operations, so any non-determinism immediately causes network-wide state divergence.

## Recommendation

Add a secondary sort key (the candidate public key string) to ensure deterministic ordering when vote amounts are equal:

```csharp
var toRemoveList = rankingList.DataCenters
    .OrderBy(x => x.Value)
    .ThenBy(x => x.Key)  // Add secondary sort by public key
    .Take(diffCount)
    .ToList();
```

Apply the same fix to the two other vulnerable locations:

1. In `TryToBecomeAValidationDataCenter()` (line 475)
2. In `CandidateReplaceMemberInDataCenter()` (line 741)

This ensures that when multiple candidates have equal vote amounts, they are always sorted in the same order (alphabetically by public key) across all nodes.

## Proof of Concept

While demonstrating non-determinism in a single test is challenging (as it requires showing different execution results across different nodes), the vulnerability can be proven by:

1. The protobuf `map<string, int64>` compiles to `MapField<TKey, TValue>` backed by `Dictionary`
2. C# `Dictionary` enumeration order is not guaranteed to be deterministic across processes
3. The code uses `OrderBy(x => x.Value)` without a secondary key
4. When multiple entries have equal values, `OrderBy` preserves input order (stable sort)
5. Since input order is non-deterministic, output order for equal values is non-deterministic

A determinism test would require:
- Setting up multiple candidates with equal vote amounts
- Reducing miner count to trigger removal
- Verifying that the same candidates are removed in different execution contexts

The fix (adding `.ThenBy(x => x.Key)`) ensures consistent ordering regardless of dictionary enumeration order.

### Citations

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L368-369)
```csharp
        var toRemoveList = rankingList.DataCenters.OrderBy(x => x.Value)
            .Take(diffCount).ToList();
```

**File:** protobuf/election_contract.proto (L460-463)
```text
message DataCenterRankingList {
    // The top n * 5 candidates with vote amount, candidate public key -> vote amount.
    map<string, int64> data_centers = 1;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L35-35)
```csharp
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-60)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L23-26)
```csharp
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L475-475)
```csharp
        foreach (var pubkeyToVotesAmount in rankingList.DataCenters.OrderBy(x => x.Value))
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L741-741)
```csharp
        var minimumVoteCandidateInDataCenter = list.OrderBy(x => x.Value).First();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L801-806)
```csharp
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.SubsidyHash.Value,
            Beneficiary = beneficiaryAddress,
            ProfitDetailId = previousSubsidyId
        });
```
