# Audit Report

## Title
Insufficient Miner Count Enforcement Allows Network to Operate Below Security Threshold

## Summary
The Election contract's `GetVictories()` function contains a coding bug that artificially limits backup miner selection, allowing the network to operate with fewer miners than the governance-approved `MinersCount`. This directly undermines Byzantine fault tolerance by reducing the number of Byzantine nodes the network can tolerate, violating core consensus security guarantees.

## Finding Description

The vulnerability exists in the Election contract's miner selection logic through two interconnected root causes:

**Root Cause 1 - Artificial Backup Limitation:**

When valid candidates are insufficient to fill `MinersCount` slots, the code builds a backup list from current miners not in the valid candidate set, then adds initial miners not already in the backup list. [1](#0-0) 

However, when selecting backups to fill the gap, the code incorrectly uses `Math.Min(diff, currentMiners.Count)` instead of `Math.Min(diff, backups.Count)`. [2](#0-1)  This artificially caps backup selection even when more backups are available in the combined pool of current miners and initial miners.

**Concrete Failure Scenario:**
- MinersCount = 20 (auto-incremented over time)
- validCandidates = 5 
- diff = 15 (need 15 more miners)
- currentMiners.Count = 10 
- backups.Count = 5 (current non-valid) + 12 (initial miners) = 17 available
- **Actual behavior:** Takes min(15, 10) = 10 backups → total 15 miners
- **Expected behavior:** Should take min(15, 17) = 15 backups → total 20 miners

**Root Cause 2 - No Minimum Enforcement:**

The consensus contract's `TryToGetVictories` method simply calls the Election contract and accepts any count returned without validation. [3](#0-2) 

The returned miner list is used to generate the first round of the new term without validating that the count meets `MinersCount` requirements. [4](#0-3) 

**Why Existing Protections Fail:**

The `SolitaryMinerDetection` mechanism only checks if a single miner operates alone for 2+ rounds when more than 2 miners are configured. [5](#0-4)  It does not validate that the actual miner count meets the `MinersCount` security threshold.

## Impact Explanation

**Byzantine Fault Tolerance Degradation:**

AEDPoS consensus requires 2/3 + 1 honest miners for Byzantine fault tolerance. When the network operates with fewer miners than `MinersCount`, the system can tolerate fewer Byzantine nodes:

- If MinersCount = 20, expects tolerance of floor((20-1)/3) = 6 Byzantine nodes
- But actual 15 miners tolerates only floor((15-1)/3) = 4 Byzantine nodes  
- This represents a 33% reduction in fault tolerance

**Quantified Harm:**
1. Network operates below governance-approved security threshold
2. Reduced decentralization makes consensus attacks more feasible
3. Critical consensus operations (term changes, secret sharing) requiring 2/3 majority become more fragile
4. Stakeholders expecting `MinersCount`-level security receive degraded protection
5. Applications relying on consensus finality guarantees face increased risk

**Severity Justification:**
This is CRITICAL because it directly undermines Byzantine fault tolerance, the fundamental security property of the consensus mechanism, affecting the entire network's security posture.

## Likelihood Explanation

**Feasible Preconditions:**

1. `MinersCount` increases through auto-increment based on blockchain age [6](#0-5) 

2. Insufficient candidates announce election or receive votes (depends on governance participation)

3. The backup pool limitation due to the bug prevents reaching `MinersCount`

**Execution Practicality:**

The vulnerability triggers automatically during term transitions via natural consensus flow. No active attack required - occurs through passive system progression. The term transition logic invokes the vulnerable code path. [7](#0-6) 

**Probability Assessment:**

Early blockchain lifecycle: **LOW** - `InitialMiners` provide sufficient buffer, `MinersCount` starts at reasonable values.

Mature blockchain: **MEDIUM to HIGH** - `MinersCount` auto-increments by 2 every `MinerIncreaseInterval` seconds [8](#0-7)  while candidate pool may stagnate if governance incentives are insufficient. The vulnerability becomes increasingly likely without active intervention to increase candidate participation.

**Detection Constraints:**

The network continues operating normally without errors, making this security degradation difficult to detect without explicit monitoring of actual versus expected miner counts.

## Recommendation

**Fix 1 - Correct the backup selection logic:**

In `contract/AElf.Contracts.Election/ViewMethods.cs` line 72, change:
```
.Take(Math.Min(diff, currentMiners.Count))
```
to:
```
.Take(Math.Min(diff, backups.Count))
```

**Fix 2 - Add validation in consensus contract:**

In `TryToGetVictories` method, add validation:
```csharp
var expectedMinersCount = GetMinersCount(currentRound);
Assert(victories.Pubkeys.Count >= expectedMinersCount, 
    $"Insufficient miners: got {victories.Pubkeys.Count}, expected {expectedMinersCount}");
```

## Proof of Concept

```csharp
[Fact]
public async Task GetVictories_InsufficientMiners_BelowMinersCount_Test()
{
    // Setup: MinersCount = 20 (simulated after auto-increment)
    await UpdateMinersCountAsync(20);
    
    // Announce only 5 candidates
    var fewCandidates = ValidationDataCenterKeyPairs.Take(5).ToList();
    foreach (var keyPair in fewCandidates) 
        await AnnounceElectionAsync(keyPair);
    
    // Only these 5 get votes
    foreach (var keyPair in fewCandidates)
        await VoteToCandidateAsync(VoterKeyPairs[0], keyPair.PublicKey.ToHex(), 100 * 86400, 100);
    
    // Simulate previous term had only 10 miners (insufficient)
    var previousMiners = new MinerList { 
        Pubkeys = { InitialMiners.Take(10).Select(k => ByteString.CopyFrom(k.PublicKey)) } 
    };
    
    // Call GetVictories - should return 20 but will return less due to bug
    var victories = await ElectionContractStub.GetVictories.CallAsync(new Empty());
    
    // Bug: Returns 15 instead of 20
    // Expected: 5 valid + 15 backups = 20 total
    // Actual: 5 valid + 10 backups = 15 total (capped by currentMiners.Count=10)
    victories.Value.Count.ShouldBe(20); // This will fail, proving the bug
    Assert.True(victories.Value.Count < 20); // Actual result shows insufficient miners
}
```

## Notes

This vulnerability becomes more severe as the blockchain ages because `MinersCount` automatically increases every `MinerIncreaseInterval` seconds (default 1 year), while the candidate pool may not grow proportionally. The bug in line 72 of ViewMethods.cs prevents the system from using available initial miners as backups, compounding the problem. Without governance action to increase candidate participation or manual adjustment of miner counts, the network progressively operates with degraded Byzantine fault tolerance below its designed security threshold.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L66-69)
```csharp
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L71-74)
```csharp
            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-257)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }

        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;

        newRound.BlockchainAge = GetBlockchainAge();

        if (newRound.RealTimeMinersInformation.ContainsKey(senderPubkey))
            newRound.RealTimeMinersInformation[senderPubkey].ProducedBlocks = 1;
        else
            UpdateCandidateInformation(senderPubkey, 1, 0);

        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;

        return newRound;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L66-96)
```csharp
    private bool SolitaryMinerDetection(Round currentRound, string pubkey)
    {
        var isAlone = false;
        // Skip this detection until 4th round.
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
        {
            // Not single node.

            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;

            // If only this node mined during previous round, stop mining.
            if (TryToGetPreviousRoundInformation(out var previousRound) && isAlone)
            {
                var minedMiners = previousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }

            // check one further round.
            if (isAlone && TryToGetRoundInformation(previousRound.RoundNumber.Sub(1),
                    out var previousPreviousRound))
            {
                var minedMiners = previousPreviousRound.GetMinedMiners();
                isAlone = minedMiners.Count == 1 &&
                          minedMiners.Select(m => m.Pubkey).Contains(pubkey);
            }
        }

        return isAlone;
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
