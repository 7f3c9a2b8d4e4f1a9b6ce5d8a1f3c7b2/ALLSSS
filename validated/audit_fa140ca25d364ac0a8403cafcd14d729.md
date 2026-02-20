# Audit Report

## Title
Banned Miners Can Remain in Consensus When All Initial Miner Backups Are Unavailable

## Summary
The miner replacement mechanism fails to remove all banned miners when insufficient alternative candidates are available, allowing known malicious nodes to continue participating in consensus and earning rewards until the next term transition.

## Finding Description

The vulnerability exists in the interaction between the Election contract's `GetMinerReplacementInformation()` method and the Consensus contract's replacement execution logic.

When the Election contract identifies banned miners requiring replacement, it attempts to find alternative candidates in two stages. First, it searches the previous term's election snapshot for valid candidates, explicitly excluding initial miners and current miners. [1](#0-0) 

Second, if insufficient candidates are found, it attempts to use initial miners as backups, but explicitly filters out banned initial miners using `!State.BannedPubkeyMap[k]`. [2](#0-1) 

The critical issue occurs when all available initial miners are either (1) already banned via `State.BannedPubkeyMap[k]` or (2) already serving as current miners. In this scenario, the `selectedInitialMiners` collection becomes empty or insufficient, resulting in `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`.

The Consensus contract's replacement loop only iterates up to `AlternativeCandidatePubkeys.Count`, meaning it can only replace as many evil miners as there are alternatives available. [3](#0-2) 

Banned miners are only removed from `currentRound.RealTimeMinersInformation` when a replacement occurs inside this loop. [4](#0-3)  Therefore, unreplaced banned miners persist in the active miner set.

The mining permission validation during block production only verifies that a miner's public key exists in `RealTimeMinersInformation.Keys` and does not check the `BannedPubkeyMap`. [5](#0-4) 

Similarly, the `PreCheck()` method in consensus information processing only validates miner list membership using `IsInMinerList()` without checking banned status. [6](#0-5)  The `IsInMinerList()` helper only checks dictionary key membership. [7](#0-6) 

Miners are marked as banned through the `UpdateCandidateInformation` method when `IsEvilNode` is true, which sets `State.BannedPubkeyMap[input.Pubkey] = true`. [8](#0-7) 

The evil miner detection logic identifies banned miners as those where `State.BannedPubkeyMap[p]` returns true. [9](#0-8) 

## Impact Explanation

This vulnerability has HIGH severity impact because it allows known malicious nodes to maintain active consensus participation after being explicitly banned by the protocol:

**Consensus Integrity Violation**: The core security invariant that banned miners are removed from active participation is violated. Nodes that have been detected as malicious (through consensus monitoring or governance action) can continue producing blocks and participating in consensus decisions.

**Permanent State Degradation**: Once this condition is reached, the system cannot self-heal within the current term. Banned miners remain active for the entire term duration until a new election cycle provides sufficient candidates. In production networks with term lengths of days or weeks, this represents extended exposure to known malicious actors.

**Economic Impact**: Banned miners continue earning block production rewards and consensus participation incentives despite being identified as bad actors. This undermines the economic security model that relies on removing misbehaving nodes from reward distributions.

**Attack Surface Expansion**: Malicious nodes that have already been detected maintain their ability to potentially coordinate further attacks, knowing they cannot be removed until the next term. This creates a window where the security assumption that "banned = removed" is false.

## Likelihood Explanation

The likelihood is MEDIUM to HIGH because this condition can emerge naturally from normal network operations without requiring any malicious action:

**Feasible Preconditions**:
1. Networks typically start with small initial miner sets (5-21 miners is common for production blockchains)
2. Active governance operations that ban multiple malicious miners over time are expected and desirable
3. Low election candidate participation is common during early network stages or market downturns
4. The condition becomes more likely as the network actively enforces security policies

**No Attack Required**: This is not an exploit that requires attacker action. It naturally emerges when legitimate security mechanisms (banning malicious miners) interact with network participation dynamics (low candidate availability).

**Real-World Scenario**: Consider a network with 7 initial miners A-G. If miners A, B, C are progressively banned for malicious behavior, and the current active set is D, E, F, G (the remaining initial miners), then when miner D exhibits malicious behavior, no unbanned alternatives exist. The system must choose between keeping a known bad actor or losing consensus capacity.

**Probability Factors**:
- Small initial miner sets (< 10): HIGH probability
- Active security enforcement: INCREASES probability  
- Low election participation periods: INCREASES probability
- Long-running networks that have banned multiple initial miners: HIGH probability

## Recommendation

Add a banned status check to the mining permission validation logic:

1. Modify `MiningPermissionValidationProvider.ValidateHeaderInformation()` to check `State.BannedPubkeyMap` before allowing block production
2. Add a similar check in the `PreCheck()` method to prevent banned miners from participating even if they remain in `RealTimeMinersInformation`
3. Consider adding a fallback mechanism that allows the system to continue with fewer miners rather than keeping banned miners active
4. Implement an emergency governance action to force-remove banned miners mid-term if no alternatives exist

## Proof of Concept

A test scenario demonstrating this vulnerability would:
1. Initialize a network with 7 initial miners
2. Ban 5 initial miners over time via `UpdateCandidateInformation` with `IsEvilNode=true`
3. Ensure no election candidates are available (low participation simulation)
4. Trigger a round where one of the remaining initial miners gets banned
5. Observe that the replacement mechanism finds no alternatives (all other initial miners are banned)
6. Verify the banned miner remains in `RealTimeMinersInformation` 
7. Confirm the banned miner can still produce blocks and pass validation
8. Demonstrate continued reward accrual by the banned miner

The key assertion is that `GetMinerReplacementInformation` returns fewer alternatives than evil miners, and the replacement loop leaves some banned miners in the active set who then pass mining permission validation.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-380)
```csharp
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
        // Check out election snapshot.
        if (latestSnapshot != null && latestSnapshot.ElectionResult.Any())
        {
            Context.LogDebug(() => $"Previous term snapshot:\n{latestSnapshot}");
            var maybeNextCandidates = latestSnapshot.ElectionResult
                // Except initial miners.
                .Where(cs =>
                    !State.InitialMiners.Value.Value.Contains(
                        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
                // Except current miners.
                .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
                .OrderByDescending(s => s.Value).ToList();
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
            Context.LogDebug(() =>
                $"Found alternative miner from candidate list: {alternativeCandidates.Aggregate("\n", (key1, key2) => key1 + "\n" + key2)}");
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L382-392)
```csharp
        // If the count of evil miners is greater than alternative candidates, add some initial miners to alternative candidates.
        var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
        if (diff > 0)
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L401-404)
```csharp
    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-339)
```csharp
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L326-328)
```csharp
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L137-140)
```csharp
    public bool IsInMinerList(string pubkey)
    {
        return RealTimeMinersInformation.Keys.Contains(pubkey);
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```
