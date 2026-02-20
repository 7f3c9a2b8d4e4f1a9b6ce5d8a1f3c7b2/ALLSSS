# Audit Report

## Title
Banned Miners Can Continue Producing Blocks for One Round Due to Timing Gap Between Round Generation and Evil Miner Detection

## Summary
The AEDPoS consensus mechanism contains a timing vulnerability where miners who have accumulated ≥4,320 missed time slots (indicating unreliability over 3 days) can continue producing blocks for exactly one additional round after reaching the ban threshold. This occurs because round generation (which queries ban status) happens during block creation before evil miner detection (which sets ban status) executes during block execution.

## Finding Description

The vulnerability stems from the ordering of operations in the consensus state machine's round transition flow.

**Root Cause:**

Mining permission validation only checks if a miner exists in the current round's miner list without consulting ban status: [1](#0-0) 

The validation context contains no reference to the Election contract's ban status: [2](#0-1) 

**Timing Vulnerability:**

When generating the next round during block creation, `GetConsensusExtraDataForNextRound` calls `GenerateNextRoundInformation`: [3](#0-2) 

This queries the Election contract for miners to replace via `GetMinerReplacementInformation`: [4](#0-3) 

The replacement check queries `BannedPubkeyMap` to find evil miners: [5](#0-4) 

**However, at block creation time, the miner has NOT been marked as banned yet.**

Evil miner detection happens AFTER the block is created, during execution in `ProcessNextRound`: [6](#0-5) 

Detection checks if missed time slots exceed the threshold of 4,320: [7](#0-6) 

The detection logic identifies miners with excessive missed slots: [8](#0-7) 

Only then does `UpdateCandidateInformation` set the ban flag: [9](#0-8) 

**Result:** The evil miner remains in Round N+1's `RealTimeMinersInformation` and can produce blocks during that entire round. Only when Round N+2 is generated does the system detect them in `BannedPubkeyMap` and remove them from the active miner list.

## Impact Explanation

**Consensus Reliability Breach:**
The evil miner detection mechanism exists to maintain network reliability by removing miners who consistently fail to produce blocks. A miner missing 4,320 time slots over 3 days has demonstrated severe unreliability. Allowing such miners to continue for an additional round undermines the security guarantee that unreliable participants are promptly excluded from consensus.

**Reward Misallocation:**
During the grace period of Round N+1, the banned miner receives full mining rewards for any blocks they produce. These rewards should have been distributed to the alternative candidate who was intended to replace them, violating the economic incentive structure.

**Architectural Integrity:**
The system fires `EvilMinerDetected` events yet the detected miner continues producing blocks, creating observable inconsistency between the detection mechanism and actual enforcement. This reduces confidence in the consensus protocol's ability to self-regulate.

## Likelihood Explanation

**Certainty: Guaranteed**

This is not an exploitable vulnerability requiring attacker action but an inherent architectural design issue. The vulnerability triggers deterministically whenever any miner accumulates ≥4,320 missed time slots within a term. The timing gap exists by design due to the separation between:
- Block creation phase (when round generation queries ban status)  
- Block execution phase (when detection marks ban status)

No special permissions, network manipulation, or timing attacks are required. The gap persists regardless of network conditions or miner behavior patterns.

## Recommendation

Modify the validation system to check ban status in real-time during block validation. Options include:

1. **Add Election Contract State Access to Validation Context:**
   Extend `ConsensusValidationContext` to include a reference to the Election contract, allowing `MiningPermissionValidationProvider` to query `BannedPubkeyMap` during validation.

2. **Immediate Ban Enforcement:**
   When `ProcessNextRound` detects evil miners, immediately update the current round's `RealTimeMinersInformation` to remove them, preventing them from producing any blocks in the current round.

3. **Proactive Detection:**
   Move evil miner detection to occur BEFORE round generation rather than after, ensuring ban status is set prior to creating the next round.

The recommended approach is option 1, as it maintains separation of concerns while providing validation access to ban status without requiring architectural changes to the round transition flow.

## Proof of Concept

A PoC would demonstrate:
1. A miner accumulating 4,320+ missed time slots over multiple rounds
2. The NextRound transaction being created and executed
3. The `EvilMinerDetected` event firing during execution
4. The same miner successfully producing blocks during the subsequent round
5. The miner only being removed when the next round is generated

Due to the complexity of the consensus state machine and the need for multi-round simulation, a full PoC requires extensive test infrastructure. However, the code path is deterministic and can be traced through the cited code sections above, confirming the vulnerability exists in the current implementation.

---

**Notes:**

The vulnerability is limited in scope (one round delay) but represents a genuine violation of consensus security guarantees. The evil miner has already demonstrated unreliability but receives a grace period to continue earning rewards. While not catastrophic, this undermines the prompt enforcement mechanism that the detection system is designed to provide.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L8-41)
```csharp
public class ConsensusValidationContext
{
    public long CurrentTermNumber { get; set; }
    public long CurrentRoundNumber { get; set; }

    /// <summary>
    ///     We can trust this because we already validated the pubkey
    ///     during `AEDPoSExtraDataExtractor.ExtractConsensusExtraData`
    /// </summary>
    public string SenderPubkey => ExtraData.SenderPubkey.ToHex();

    /// <summary>
    ///     Round information fetch from StateDb.
    /// </summary>
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;

    /// <summary>
    ///     Previous round information fetch from StateDb.
    /// </summary>
    public Round PreviousRound { get; set; }

    /// <summary>
    ///     This filed is to prevent one miner produces too many continues blocks
    ///     (which may cause problems to other parts).
    /// </summary>
    public LatestPubkeyToTinyBlocksCount LatestPubkeyToTinyBlocksCount { get; set; }

    public AElfConsensusHeaderInformation ExtraData { get; set; }
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-343)
```csharp
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

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
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L357-404)
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

    private List<string> GetEvilMinersPubkeys(IEnumerable<string> currentMinerList)
    {
        return currentMinerList.Where(p => State.BannedPubkeyMap[p]).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```
