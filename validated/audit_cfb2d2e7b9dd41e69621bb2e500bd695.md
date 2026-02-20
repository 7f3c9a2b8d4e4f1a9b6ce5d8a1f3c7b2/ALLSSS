# Audit Report

## Title
Non-Deterministic Data Center Removal Due to Unstable Sorting with Equal Vote Amounts

## Summary
The `SyncSubsidyInfoAfterReduceMiner()` function in the Election contract uses non-deterministic sorting when removing data centers with equal vote amounts, causing different blockchain nodes to remove different candidates. This breaks the fundamental blockchain invariant of deterministic execution, leading to state divergence and consensus failure.

## Finding Description

The vulnerability exists in the `SyncSubsidyInfoAfterReduceMiner()` function which removes the lowest-ranked data centers when the miner count is reduced. [1](#0-0) 

The root cause is that `DataCentersRankingList.DataCenters` is a protobuf `map<string, int64>` field, which compiles to a MapField (dictionary-based collection) with non-deterministic iteration order. [2](#0-1) 

When `OrderBy(x => x.Value)` is applied to the MapField:
1. The MapField enumerator provides KeyValuePair entries in non-deterministic order
2. OrderBy performs a stable sort, but the input order is already non-deterministic  
3. For entries with equal values (vote amounts), the relative order after sorting remains non-deterministic
4. Different nodes enumerate the MapField in different orders
5. `Take(diffCount)` selects different sets of candidates on different nodes

The codebase demonstrates the correct pattern in the consensus contract where deterministic ordering is required by using explicit secondary sort keys. [3](#0-2) 

The vulnerable function is called from `UpdateMinersCount()` [4](#0-3)  which is invoked by the consensus contract during term transitions [5](#0-4)  and when governance sets the maximum miner count. [6](#0-5) 

An additional vulnerable location exists at: [7](#0-6) 

## Impact Explanation

**Consensus Failure (Critical)**: When multiple data centers have equal vote amounts at the removal boundary, different blockchain nodes will remove different sets of candidates. This causes their blockchain states to diverge. In blockchain systems, state divergence prevents nodes from reaching consensus on subsequent blocks, effectively halting the chain or causing a fork.

**Incorrect Subsidy Distribution**: The removed candidates are also removed from the subsidy profit scheme. [8](#0-7)  This affects the Profit contract's distribution calculations, causing wrong candidates to lose subsidy eligibility.

**Affected Parties**:
- **Blockchain network**: Consensus integrity compromised, potential chain halt
- **Data center operators**: Wrong candidates incorrectly lose subsidy eligibility  
- **Token holders**: Incorrect profit distribution calculations

The severity is **High/Critical** because it causes immediate consensus failure when triggered and violates the fundamental blockchain invariant of deterministic execution.

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

The data center ranking list typically contains n×5 candidates (e.g., 15-25 candidates for 3-5 miners). With this many candidates, having 2-3 candidates with equal vote amounts at the boundary position is highly probable.

The function executes on **every node** during consensus operations, so any non-determinism immediately causes network-wide state divergence.

## Recommendation

Add a deterministic secondary sort key (such as the candidate's public key string) to ensure consistent ordering when vote amounts are equal:

```csharp
var toRemoveList = rankingList.DataCenters
    .OrderBy(x => x.Value)
    .ThenBy(x => x.Key)  // Add deterministic secondary key
    .Take(diffCount)
    .ToList();
```

Apply the same fix to all MapField sorting operations, including the location at ElectionContract_Elector.cs:475.

## Proof of Concept

While a complete PoC would require multi-node execution environment to demonstrate state divergence, the vulnerability can be validated by:

1. Creating a test scenario with multiple candidates having equal vote amounts (e.g., all starting at 0)
2. Calling `UpdateMinersCount` with a reduced miner count  
3. Observing that without a secondary sort key, the dictionary enumeration order is non-deterministic across different process instances
4. This would result in different `toRemoveList` selections on different nodes

The existing test [9](#0-8)  does not cover the equal-votes scenario as it uses incrementing vote amounts.

## Notes

- The AElf runtime ensures deterministic state **storage** through sorted keys [10](#0-9)  but does NOT guarantee deterministic **execution** of contract logic
- This is a subtle but critical distinction: state changes are stored deterministically, but if contract code produces different state changes due to non-deterministic execution, consensus fails
- The vulnerability affects core consensus operations and cannot be mitigated without code changes
- Standard C#/.NET dictionaries do NOT guarantee deterministic iteration order across different process instances

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L370-374)
```csharp
        foreach (var kv in toRemoveList)
        {
            rankingList.DataCenters.Remove(kv.Key);
            RemoveBeneficiary(kv.Key);
        }
```

**File:** protobuf/election_contract.proto (L460-463)
```text
message DataCenterRankingList {
    // The top n * 5 candidates with vote amount, candidate public key -> vote amount.
    map<string, int64> data_centers = 1;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_GetLogs.cs (L27-27)
```csharp
        foreach (var minerInRound in RealTimeMinersInformation.Values.OrderBy(m => m.Order))
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

**File:** test/AElf.Contracts.Election.Tests/BVT/ElectionTests.cs (L1838-1887)
```csharp
    public async Task ElectionContract_UpdateMinerCount_ReduceBp_Test()
    {
        var voter = VoterKeyPairs.First();
        var voteAmount = 100;
        var span = 100;
        var lockTime = 120 * 60 * 60 * 24;
        var fullCount = 5.Mul(5);
        foreach (var keyPair in ValidationDataCenterKeyPairs.Take(fullCount))
        {
            await AnnounceElectionAsync(keyPair);
            await VoteToCandidateAsync(voter, keyPair.PublicKey.ToHex(), lockTime, voteAmount);
            voteAmount = voteAmount.Add(span);
        }

        var minerCount = 3;
        await NextRound(InitialCoreDataCenterKeyPairs[0]);
        var dataCenterList = await ElectionContractStub.GetDataCenterRankingList.CallAsync(new Empty());
        dataCenterList.DataCenters.Count.ShouldBe(fullCount);
        var diffCount = fullCount.Sub(minerCount.Mul(5));
        var subsidy = ProfitItemsIds[ProfitType.BackupSubsidy];
        foreach (var keyPair in ValidationDataCenterKeyPairs.Take(diffCount))
        {
            var profitDetail = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = subsidy,
                Beneficiary = Address.FromPublicKey(keyPair.PublicKey)
            });
            profitDetail.Details[0].EndPeriod.ShouldNotBe(0);
            profitDetail.Details.Count.ShouldBe(1);
        }

        await ResetMinerCount(minerCount);
        await NextTerm(InitialCoreDataCenterKeyPairs[0]);
        var newMinerCount = await ElectionContractStub.GetMinersCount.CallAsync(new Empty());
        newMinerCount.Value.ShouldBe(minerCount);
        var dataCenterListAfterReduceBp =
            await ElectionContractStub.GetDataCenterRankingList.CallAsync(new Empty());

        dataCenterList.DataCenters.Count.Sub(dataCenterListAfterReduceBp.DataCenters.Count).ShouldBe(diffCount);
        foreach (var keyPair in ValidationDataCenterKeyPairs.Take(diffCount))
        {
            dataCenterListAfterReduceBp.DataCenters.ContainsKey(keyPair.PublicKey.ToHex()).ShouldBeFalse();
            var profitDetail = await ProfitContractStub.GetProfitDetails.CallAsync(new GetProfitDetailsInput
            {
                SchemeId = subsidy,
                Beneficiary = Address.FromPublicKey(keyPair.PublicKey)
            });
            profitDetail.Details[0].EndPeriod.ShouldBe(0);
        }
    }
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockExecutingService.cs (L165-180)
```csharp
    private IEnumerable<byte[]> GetDeterministicByteArrays(BlockStateSet blockStateSet)
    {
        var keys = blockStateSet.Changes.Keys;
        foreach (var k in new SortedSet<string>(keys))
        {
            yield return Encoding.UTF8.GetBytes(k);
            yield return blockStateSet.Changes[k].ToByteArray();
        }

        keys = blockStateSet.Deletes;
        foreach (var k in new SortedSet<string>(keys))
        {
            yield return Encoding.UTF8.GetBytes(k);
            yield return ByteString.Empty.ToByteArray();
        }
    }
```
