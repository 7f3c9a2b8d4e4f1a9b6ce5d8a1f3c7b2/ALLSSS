# Audit Report

## Title
Missing Duplicate Pubkey Validation in GenerateFirstRoundOfNewTerm Causes Consensus Halt

## Summary
The on-chain `GenerateFirstRoundOfNewTerm()` method in the consensus contract lacks duplicate pubkey validation before calling `ToDictionary()`, while corresponding off-chain implementations include `.Distinct()` for this protection. If duplicate pubkeys exist in the miner list due to state inconsistency, the dictionary conversion throws `ArgumentException`, aborting term transitions and halting consensus.

## Finding Description

The vulnerability exists in the on-chain consensus contract implementation where `MinerList.GenerateFirstRoundOfNewTerm()` directly converts pubkeys to a dictionary without deduplication: [1](#0-0) 

This creates a sorted miner list using `ToHex()` as the dictionary key. Since `ToHex()` is a bijective encoding, identical byte sequences produce identical keys, causing `ToDictionary()` to throw `ArgumentException` on duplicates.

**Critical Evidence of Known Risk**: Off-chain implementations explicitly include `.Distinct()` protection: [2](#0-1) [3](#0-2) 

This discrepancy proves the duplicate risk was identified for off-chain code but the defensive check was not applied to the on-chain contract.

**Duplicate Source Path**:

The `MinerList.Pubkeys` originates from the Election contract's `GetVictories()` method: [4](#0-3) 

Which builds the victory list without deduplication: [5](#0-4) 

The candidate list is sourced from `State.Candidates` defined as: [6](#0-5) 

This `SingletonState<PubkeyList>` wraps a protobuf `RepeatedField<ByteString>` which does NOT enforce uniqueness: [7](#0-6) 

Candidates are added to this list via: [8](#0-7) 

With only an `IsCurrentCandidate` flag check as protection: [9](#0-8) 

If this flag becomes inconsistent with the actual list state (through bugs, race conditions, or state corruption), duplicate pubkeys can be added. These duplicates then flow: `State.Candidates` → `GetValidCandidates()` → `GetVictories()` → `GenerateFirstRoundOfNewTerm()` → `ToDictionary()` throws.

## Impact Explanation

**Severity: HIGH - Complete Consensus Halt**

When `ToDictionary()` throws `ArgumentException`, term transition fails. This method is invoked during term transitions: [10](#0-9) [11](#0-10) 

Term processing occurs through: [12](#0-11) 

A failed term transition prevents:
- New consensus rounds from being established  
- Miner list updates from taking effect
- Consensus from progressing beyond the current term
- Block production schedule updates

This constitutes complete operational failure requiring emergency intervention (governance proposal or chain restart with patched contract). All block producers and the entire network are affected.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Preconditions:**
1. Duplicate pubkeys must exist in `State.Candidates.Value.Value`
2. Duplicates must survive through an election cycle to be selected as winners
3. Term transition must be attempted with the duplicate-containing miner list

**Feasibility Analysis:**
- **Not directly exploitable** by untrusted users - no public method forces duplicate insertion
- **Requires state inconsistency** in candidate management (e.g., `IsCurrentCandidate` flag desynchronization with actual list state)
- **Deterministic failure** once duplicates exist - every term transition attempt fails
- **No defensive validation** - contract assumes input uniqueness without verification

**Risk Assessment:** Medium probability due to:
- Existing `IsCurrentCandidate` protection lowers direct exploitation likelihood
- Off-chain code having `.Distinct()` proves developers identified this risk
- No defensive checks in on-chain code increases exposure
- State inconsistency risk grows with system complexity over time

## Recommendation

Add `.Distinct()` deduplication before `ToDictionary()` in the on-chain contract implementation to match the off-chain protection:

```csharp
var sortedMiners =
    (from obj in Pubkeys.Distinct()  // Add .Distinct() here
            .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
        orderby obj.Value descending
        select obj.Key).ToList();
```

Additionally, consider adding defensive validation in `GetVictories()` to detect and handle duplicates before they reach consensus:

```csharp
private List<ByteString> GetVictories(List<string> currentMiners)
{
    var validCandidates = GetValidCandidates();
    // ... existing logic ...
    
    // Deduplicate before returning
    return victories.Distinct().ToList();
}
```

## Proof of Concept

Due to the nature of this vulnerability requiring state inconsistency, a complete PoC would need to simulate the state corruption scenario. However, the vulnerability can be demonstrated by:

1. Creating a unit test that manually constructs a `MinerList` with duplicate pubkeys
2. Calling `GenerateFirstRoundOfNewTerm()` on this list
3. Observing the `ArgumentException` from `ToDictionary()`

The fix can be validated by adding `.Distinct()` and confirming the method succeeds even with duplicate inputs, matching the off-chain implementation behavior.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Extensions/MinerListExtensions.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in miners.Pubkeys.Distinct()
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** src/AElf.Blockchains.SideChain/Protobuf/MinerListExtension.cs (L14-18)
```csharp
        var sortedMiners =
            (from obj in miners.Pubkeys.Distinct()
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L41-50)
```csharp
    public override PubkeyList GetVictories(Empty input)
    {
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);

        var currentMiners = State.AEDPoSContract.GetCurrentMinerList.Call(new Empty()).Pubkeys
            .Select(k => k.ToHex()).ToList();
        return new PubkeyList { Value = { GetVictories(currentMiners) } };
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L27-27)
```csharp
    public SingletonState<PubkeyList> Candidates { get; set; }
```

**File:** protobuf/election_contract.proto (L423-426)
```text
message PubkeyList {
    // Candidates’ public keys
    repeated bytes value = 1;
}
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-162)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L174-174)
```csharp
        State.Candidates.Value.Value.Add(pubkeyByteString);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-210)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L228-232)
```csharp
        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```
