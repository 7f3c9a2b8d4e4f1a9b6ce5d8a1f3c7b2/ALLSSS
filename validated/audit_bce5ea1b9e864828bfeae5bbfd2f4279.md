# Audit Report

## Title
Partial Miner Replacement Causes isMinerListChanged Flag to Be Set Incorrectly, Allowing Banned Miners to Continue Mining

## Summary
When the Election contract returns fewer alternative candidates than evil miners during miner replacement, the consensus contract processes only partial replacements but incorrectly sets `isMinerListChanged=true`. This leaves banned miners active in the consensus round while triggering side effects designed for complete miner list changes, including disabling secret sharing and bypassing certain mining permission checks.

## Finding Description

The vulnerability exists in the miner replacement logic during round transitions. When miners are detected as evil and marked in the `BannedPubkeyMap`, the system attempts to replace them with alternative candidates from the election results. However, a critical mismatch occurs when there are insufficient replacement candidates. [1](#0-0) 

The replacement loop iterates based on `AlternativeCandidatePubkeys.Count` rather than `EvilMinerPubkeys.Count`. When the Election contract cannot provide enough alternatives, only the first N evil miners are replaced (where N = number of available alternatives), but the `isMinerListChanged` flag is unconditionally set to `true` if any alternatives exist. [2](#0-1) 

The Election contract's `GetMinerReplacementInformation()` explicitly takes the minimum count between available candidates and evil miners, and even with initial miner fallback, may not provide enough alternatives due to restrictions (banned initial miners, miners already in current list).

**Why Existing Protections Fail:**

The `MiningPermissionValidationProvider` only verifies pubkey existence in `RealTimeMinersInformation`, not ban status: [3](#0-2) 

The `IsCurrentMiner` method skips miner list membership verification when `IsMinerListJustChanged=true`: [4](#0-3) 

The flag is directly propagated to the next round: [5](#0-4) 

## Impact Explanation

**Consensus Integrity Violation:**
Banned miners who should be excluded remain active and can produce blocks. Unreplaced evil miners retain their time slots, order, and block production privileges, directly violating the core security invariant that evil miners must be excluded from consensus participation.

**Secret Sharing Disruption:**
When `IsMinerListJustChanged=true`, the secret sharing mechanism is disabled: [6](#0-5) 

This disrupts the random number generation mechanism critical for consensus security, even though banned miners remain in the active set.

**Altered Consensus Behavior:**
The `IsMinerListJustChanged` flag affects multiple consensus logic paths. Unreplaced evil miners may gain or lose block production opportunities incorrectly due to the flag being set when the miner list change is incomplete.

**Severity:** HIGH - Banned miners continue participating in consensus despite being marked as evil, directly undermining the protocol's security model and miner accountability mechanism.

## Likelihood Explanation

**Reachable Entry Point:**
The vulnerability is triggered through normal consensus flow when `ProcessNextRound` is called during round transitions: [7](#0-6) [8](#0-7) 

**Feasible Preconditions:**
1. Main chain operation (line 299 check in GenerateNextRoundInformation)
2. Same term operation (line 299 check)
3. Multiple miners flagged as evil in `BannedPubkeyMap`
4. Limited candidate pool - election snapshot has fewer qualified candidates than evil miners
5. Initial miners either banned or already in current miner list

**Execution Practicality:**
This scenario naturally occurs when:
- Network has a small candidate pool (common in side chains or early mainnet phases)
- Multiple miners violate consensus rules simultaneously (e.g., mass downtime event)
- Initial miners have also been compromised or banned

**Economic Rationality:**
No attack cost required - this is a natural failure mode when legitimate banning mechanisms encounter insufficient replacement candidates. It represents a protocol design flaw rather than an exploitable attack vector.

**Probability:** MEDIUM - More likely in smaller networks with limited candidates or during security incidents involving multiple miners, but not an everyday occurrence on established networks with healthy candidate pools.

## Recommendation

Modify the miner replacement logic to handle mismatched counts correctly:

1. **Option 1 (Conservative):** Only set `isMinerListChanged=true` if ALL evil miners were successfully replaced:
```csharp
if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
{
    // Only set flag if we can replace ALL evil miners
    if (minerReplacementInformation.AlternativeCandidatePubkeys.Count == 
        minerReplacementInformation.EvilMinerPubkeys.Count)
    {
        // Perform replacements
        for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
        {
            // ... existing replacement logic ...
        }
        isMinerListChanged = true;
    }
}
```

2. **Option 2 (Fail-safe):** Force term transition if insufficient replacements are available, ensuring all evil miners are removed from the active set.

3. **Option 3 (Complete replacement):** Keep attempting partial replacements across multiple rounds until all evil miners are replaced, only setting the flag when complete.

## Proof of Concept

```csharp
// Test setup: 5 miners, 3 are evil, only 2 alternative candidates available
[Fact]
public async Task PartialMinerReplacement_LeavesEvilMinersActive()
{
    // Setup: Initialize consensus with 5 miners
    var initialMiners = new[] { "miner1", "miner2", "miner3", "miner4", "miner5" };
    await InitializeConsensus(initialMiners);
    
    // Mark 3 miners as evil
    await BanMiners(new[] { "miner3", "miner4", "miner5" });
    
    // Setup election to return only 2 alternatives (insufficient)
    var alternatives = new[] { "candidate1", "candidate2" };
    await SetupElectionAlternatives(alternatives);
    
    // Trigger next round with miner replacement
    await TriggerNextRound();
    
    // Verify vulnerability:
    var currentRound = await GetCurrentRound();
    
    // Assert: miner5 (3rd evil miner) should be removed but isn't
    Assert.True(currentRound.RealTimeMinersInformation.ContainsKey("miner5"));
    
    // Assert: IsMinerListJustChanged flag is incorrectly set to true
    Assert.True(currentRound.IsMinerListJustChanged);
    
    // Assert: miner5 can still produce blocks
    var canMine = await IsCurrentMiner("miner5");
    Assert.True(canMine); // Vulnerability: banned miner can still mine
    
    // Assert: Secret sharing is disabled despite incomplete replacement
    var secretSharingEvents = GetFiredEvents<SecretSharingInformation>();
    Assert.Empty(secretSharingEvents); // Should fire, but doesn't due to flag
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L142-144)
```csharp
        if (!currentRound.IsMinerListJustChanged)
            if (!currentRound.RealTimeMinersInformation.ContainsKey(pubkey))
                return false;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-342)
```csharp
            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
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

                isMinerListChanged = true;
            }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-399)
```csharp
    public override MinerReplacementInformation GetMinerReplacementInformation(
        GetMinerReplacementInformationInput input)
    {
        var evilMinersPubKeys = GetEvilMinersPubkeys(input.CurrentMinerList);
        Context.LogDebug(() => $"Got {evilMinersPubKeys.Count} evil miners pubkeys from {input.CurrentMinerList}");
        var alternativeCandidates = new List<string>();
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

        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-14)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
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
