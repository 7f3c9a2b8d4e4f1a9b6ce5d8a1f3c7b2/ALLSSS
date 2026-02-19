# Audit Report

## Title
Welcome Reward Capture Through Coordinated Evil Miner Replacement

## Summary
The Treasury contract's welcome reward distribution mechanism fails to distinguish between legitimately elected new miners and evil miner replacements. A coordinated cartel can deliberately trigger evil miner replacement to capture welcome rewards through fresh alternative candidates, diluting rewards intended for genuine new participants.

## Finding Description

The vulnerability exists in how the Treasury contract identifies and rewards "new miners" at term boundaries. The protocol uses a single criterion - `LatestMinedTerm[pubkey] == 0` - to determine whether a miner is "new," without validating the reason they are new. [1](#0-0) 

When miners accumulate 4,320 missed time slots (approximately 3 days), they are automatically detected as evil miners and replaced mid-term with alternative candidates from the election snapshot. [2](#0-1) [3](#0-2) 

The evil miner detection triggers automatic replacement where alternative candidates are selected from the election snapshot based purely on vote count, without checking whether candidates have previously mined. [4](#0-3) [5](#0-4) 

At term end, the Treasury contract identifies new miners by checking all current miners, previous term miners, and replacement candidates, then filtering for those with `LatestMinedTerm[pubkey] == 0`. If a replacement candidate has never mined before, they qualify as a "new miner" and receive welcome rewards. [6](#0-5) 

All new miners receive exactly 1 share of welcome rewards, regardless of how they became "new." [7](#0-6) 

**Attack Flow:**
1. A cartel with voting control deliberately causes K of their current miners to miss blocks for 3 days
2. These miners are automatically detected as evil and banned
3. The election contract selects K alternatives from the snapshot based on vote count (which the cartel influences)
4. The cartel ensures their fresh candidate pubkeys (never mined before) are selected as replacements
5. These replacements join the current miner list mid-term
6. At term end, replacements with `LatestMinedTerm == 0` qualify as "new miners"
7. They receive welcome rewards alongside legitimately elected new miners
8. Legitimate new miners' welcome rewards are diluted from 100% to 1/(K+1)

## Impact Explanation

Using the default reward weights (BasicMinerReward=2, WelcomeReward=1, FlexibleReward=1), the attack provides substantial economic benefit: [8](#0-7) 

**Quantified Impact:**
- Without attack (1 legitimate new miner among 17 total miners):
  - Legitimate new miner receives ~100% of welcome reward
  
- With attack (1 legitimate + 10 cartel replacements = 11 new miners):
  - Legitimate new miner receives only ~9% of welcome reward (1/11 share)
  - Cartel captures ~91% of welcome reward through 10 replacements
  - Cartel's total reward increases by approximately 51%

**Affected Parties:**
- Legitimate new miners have their welcome rewards diluted from 100% to 1/(K+1)
- The protocol's mechanism for attracting new participants through welcome rewards is undermined
- The integrity of the reward distribution system is compromised

**Severity:** Medium - The economic gain is substantial (~50% increase for cartel), but the attack requires significant resources (voting control, coordinated miner sacrifice) and only provides benefit when legitimate new miners are joining the network.

## Likelihood Explanation

**Attacker Requirements:**
1. Control over sufficient voting power to ensure cartel-controlled candidates are selected as alternative miners
2. Ability to coordinate K miners to deliberately miss blocks for 3 consecutive days
3. Access to K fresh candidate pubkeys that have never mined (`LatestMinedTerm[p] == 0`)
4. Willingness to have K pubkeys permanently banned from future mining

**Feasibility:** The attack is technically straightforward - miners simply stop producing blocks. Evil miner detection is automatic and requires no special permissions. Alternative candidate selection is deterministic based on election snapshot votes.

**Economic Constraints:** The attack is most effective when:
- Legitimate new miners are joining (otherwise welcome rewards redirect to Basic Reward)
- Welcome reward value exceeds the cost of acquiring and sacrificing K candidate pubkeys
- The cartel has sufficient voting power to control alternative candidate selection

**Detection:** Missing blocks for 3 days is highly visible and creates on-chain evidence. Patterns of coordinated evil behavior followed by fresh replacements would be suspicious, though no automatic circuit breakers exist to prevent this.

**Probability:** Medium - Requires substantial resources (voting power, multiple candidate pubkeys) but is technically achievable for a well-funded cartel, especially during periods when new miners are naturally joining the network.

## Recommendation

Implement one or more of the following mitigations:

1. **Distinguish Replacement from Election**: Track whether a new miner joined through normal election or evil miner replacement. Only grant welcome rewards to miners elected through the normal term transition process.

```csharp
// In Release method, modify new miner identification:
maybeNewElectedMiners = maybeNewElectedMiners
    .Where(p => State.LatestMinedTerm[p] == 0 
        && !GetInitialMinerList().Contains(p)
        && !State.IsReplacementMiner[p])  // Exclude replacements
    .ToList();
```

2. **Rate Limit Evil Replacements**: Limit the number of evil miner replacements per term that can qualify for welcome rewards, or exclude all replacements from welcome rewards.

3. **Validate Alternative Candidates**: In `GetMinerReplacementInformation`, exclude candidates who have `LatestMinedTerm == 0` from being selected as replacements, ensuring replacements have mining history.

4. **Separate Welcome Reward Pool**: Create a separate welcome reward pool that only distributes to miners elected through the normal term election process, not mid-term replacements.

## Proof of Concept

A full proof of concept would require:

1. Setting up a test environment with 17 initial miners
2. Having a cartel control 6 miners and sufficient voting power
3. Creating 10 fresh candidate pubkeys with votes but no mining history
4. Forcing the 6 cartel miners to miss 4,320+ time slots
5. Verifying they are replaced by the 10 fresh candidates
6. Having 1 legitimate new miner join through normal election
7. Advancing to term end and triggering Release
8. Verifying that all 11 miners (1 legitimate + 10 replacements) receive equal welcome reward shares (1 share each)
9. Calculating that the legitimate new miner receives only 1/11 of the welcome reward instead of 100%
10. Verifying the cartel's total reward increase of approximately 51%

The test would validate that the `UpdateWelcomeRewardWeights` method treats replacements identically to legitimately elected new miners, enabling the reward capture described in this report.

### Citations

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L141-156)
```csharp
        var currentMinerList = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(p => p.ToHex()).ToList();
        var maybeNewElectedMiners = new List<string>();
        maybeNewElectedMiners.AddRange(currentMinerList);
        maybeNewElectedMiners.AddRange(previousTermInformation.RealTimeMinersInformation.Keys);
        var replaceCandidates = State.ReplaceCandidateMap[input.PeriodNumber];
        if (replaceCandidates != null)
        {
            Context.LogDebug(() =>
                $"New miners from replace candidate map: {replaceCandidates.Value.Aggregate((l, r) => $"{l}\n{r}")}");
            maybeNewElectedMiners.AddRange(replaceCandidates.Value);
            State.ReplaceCandidateMap.Remove(input.PeriodNumber);
        }

        maybeNewElectedMiners = maybeNewElectedMiners
            .Where(p => State.LatestMinedTerm[p] == 0 && !GetInitialMinerList().Contains(p)).ToList();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L480-488)
```csharp
    private MinerRewardWeightSetting GetDefaultMinerRewardWeightSetting()
    {
        return new MinerRewardWeightSetting
        {
            BasicMinerRewardWeight = 2,
            WelcomeRewardWeight = 1,
            FlexibleRewardWeight = 1
        };
    }
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L872-877)
```csharp
            foreach (var minerAddress in newElectedMiners.Select(GetProfitsReceiver))
                newBeneficiaries.BeneficiaryShares.Add(new BeneficiaryShare
                {
                    Beneficiary = minerAddress,
                    Shares = 1
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L368-377)
```csharp
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
