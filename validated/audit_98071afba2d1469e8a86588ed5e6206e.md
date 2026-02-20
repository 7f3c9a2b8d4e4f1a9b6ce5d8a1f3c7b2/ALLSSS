# Audit Report

## Title
Solitary Miner Detection Logic Error Causes False Positive and Potential Chain Halt

## Summary
The `SolitaryMinerDetection()` function contains a critical logic error that incorrectly treats the absence of miners at the start of a new round as evidence of solitary mining. This false positive can block the only operational miner after a network partition, potentially causing a complete consensus halt.

## Finding Description

The vulnerability exists in the solitary miner detection mechanism designed to prevent a single miner from continuously mining alone. When a miner requests a consensus command via the public `GetConsensusCommand()` method [1](#0-0) , the private `GetConsensusCommand` helper invokes `SolitaryMinerDetection()` [2](#0-1) .

The root cause is a logic error where the function checks if the current round has zero miners and treats this as evidence of solitary mining [3](#0-2) . 

The `GetMinedMiners()` method returns only miners where `SupposedOrderOfNextRound != 0` [4](#0-3) .

However, when a new round is created via `GenerateNextRoundInformation()`, new `MinerInRound` objects are instantiated with fields like `Pubkey`, `Order`, `ExpectedMiningTime`, `ProducedBlocks`, and `MissedTimeSlots` [5](#0-4) , but `SupposedOrderOfNextRound` is NOT explicitly set. 

Since `SupposedOrderOfNextRound` is defined as `int32` in the protobuf definition [6](#0-5) , it defaults to 0. The field is only set when a miner produces a block through `ProcessUpdateValue()` [7](#0-6) .

**Why the bug occurs:** The logic error treats "no one has mined yet in current round" (count == 0) identically to "only this miner is mining" (solitary mining). At the start of any new round, before any miner produces a block, `GetMinedMiners()` will always return an empty list because all `SupposedOrderOfNextRound` values are still at their default of 0. The subsequent checks in `SolitaryMinerDetection()` correctly validate that only this specific miner mined in the previous 2 rounds [8](#0-7) , but this doesn't confirm the miner is currently mining alone—it only confirms past behavior during a network partition period.

## Impact Explanation

**Harm:** Complete consensus halt (DoS) preventing any block production.

**Scenario:**
1. During rounds N-2 and N-1, a network partition or infrastructure issues cause only MinerA to successfully produce blocks
2. At the end of round N-1, MinerA calls `NextRound` which invokes `ProcessNextRound` [9](#0-8) 
3. Round N is created with all `SupposedOrderOfNextRound` values at 0 (not explicitly set during round generation)
4. MinerA (the only operational miner) attempts to produce the first block in round N by calling `GetConsensusCommand()`
5. `SolitaryMinerDetection()` returns true because:
   - Current round has 0 mined miners (all `SupposedOrderOfNextRound == 0`)
   - Previous 2 rounds show only MinerA mined (validating the network partition condition is met [10](#0-9) )
6. The method returns `InvalidConsensusCommand`, blocking MinerA from mining
7. If network issues persist and other miners remain offline/partitioned, no miner can produce blocks
8. Chain halts completely until manual intervention or network recovery

**Who is affected:** The entire blockchain network—all users, dApps, and validators lose access to a functioning chain.

**Severity justification:** HIGH - This is an operational DoS vulnerability affecting consensus integrity and liveness. While it requires specific preconditions (network partition lasting 2+ rounds), such conditions are realistic in distributed systems and the impact is catastrophic (complete chain halt).

## Likelihood Explanation

**Attacker capabilities:** No malicious attacker required—this triggers through natural network conditions.

**Preconditions:**
- Multi-miner network with more than 2 miners (checked by the detection logic)
- After round 3 (checked by the same condition)
- Network partition or miner downtime affecting all but one miner for 2 consecutive rounds
- The working miner continues to be the only operational miner into the next round

**Execution practicality:** The vulnerability triggers automatically through the normal consensus flow. When a miner requests a consensus command, the solitary detection runs before any block is produced in the new round.

**Feasibility conditions:** Network partitions, infrastructure failures, and miner downtime are common occurrences in distributed blockchain systems. The probability is MEDIUM—not frequent but realistic enough to warrant serious concern, especially during infrastructure incidents, cloud provider outages, or network-level attacks.

## Recommendation

Modify `SolitaryMinerDetection()` to distinguish between "no blocks mined yet in current round" and "solitary mining in progress". One approach:

```csharp
private bool SolitaryMinerDetection(Round currentRound, string pubkey)
{
    var isAlone = false;
    if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
    {
        var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
        
        // NEW: Only consider solitary if someone has mined AND it's only this miner
        // Don't block at the very start of a round when no one has mined yet
        if (minedMinersOfCurrentRound.Count == 1 && 
            minedMinersOfCurrentRound[0].Pubkey == pubkey)
        {
            isAlone = true;
        }
        // REMOVED: isAlone = minedMinersOfCurrentRound.Count == 0;
        
        if (isAlone && TryToGetPreviousRoundInformation(out var previousRound))
        {
            var minedMiners = previousRound.GetMinedMiners();
            isAlone = minedMiners.Count == 1 && 
                      minedMiners.Select(m => m.Pubkey).Contains(pubkey);
        }
        
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

Alternatively, ensure `SupposedOrderOfNextRound` is properly initialized in `GenerateNextRoundInformation()` based on `FinalOrderOfNextRound` values from the current round.

## Proof of Concept

A PoC would require setting up a multi-node AElf testnet, simulating a network partition where only one miner remains operational for 2+ rounds, then observing that when a new round begins, the operational miner cannot produce blocks because `GetConsensusCommand()` returns `InvalidConsensusCommand` due to the false positive in `SolitaryMinerDetection()`. The key is to call `GetConsensusCommand()` immediately at the start of round N before any `UpdateValue` transactions have been processed, when all `SupposedOrderOfNextRound` values are still 0.

---

## Notes

This vulnerability breaks the **consensus liveness guarantee**. The solitary miner detection is intended to prevent a single miner from monopolizing block production indefinitely, but the faulty implementation creates a catch-22: the only operational miner is prevented from starting a new round precisely when they should be allowed to continue until other miners recover. The fix must allow the first block of a new round to be produced before applying solitary detection, or correctly initialize the round state to avoid the false positive.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L17-17)
```csharp
    public override ConsensusCommand GetConsensusCommand(BytesValue input)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L23-24)
```csharp
        if (SolitaryMinerDetection(currentRound, pubkey))
            return ConsensusCommandProvider.InvalidConsensusCommand;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L70-70)
```csharp
        if (currentRound.RoundNumber > 3 && currentRound.RealTimeMinersInformation.Count > 2)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L74-75)
```csharp
            var minedMinersOfCurrentRound = currentRound.GetMinedMiners();
            isAlone = minedMinersOfCurrentRound.Count == 0;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusCommand.cs (L78-92)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** protobuf/aedpos_contract.proto (L288-288)
```text
    int32 supposed_order_of_next_round = 11;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
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

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L246-246)
```csharp
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```
