# Audit Report

## Title
Missing Duplicate Pubkey Validation in GenerateFirstRoundOfNewTerm Causes Consensus Halt

## Summary
The on-chain `GenerateFirstRoundOfNewTerm()` method in the AEDPoS consensus contract lacks duplicate pubkey validation before calling `ToDictionary()`, while corresponding off-chain implementations include `.Distinct()` for this protection. If duplicate pubkeys exist in the miner list due to state inconsistency, the dictionary conversion throws `ArgumentException`, causing term transitions to fail and halting consensus entirely.

## Finding Description

The vulnerability exists in the on-chain consensus contract where `MinerList.GenerateFirstRoundOfNewTerm()` directly converts pubkeys to a dictionary without deduplication: [1](#0-0) 

This code converts `Pubkeys` to a dictionary using `ToHex()` as the key. Since `ToHex()` is a bijective encoding, identical `ByteString` values produce identical keys, causing `ToDictionary()` to throw `ArgumentException` when duplicates are encountered.

**Critical Evidence of Developer Awareness:** Off-chain implementations explicitly include `.Distinct()` protection before the same `ToDictionary()` call: [2](#0-1) 

This discrepancy proves developers identified the duplicate risk for off-chain code but failed to apply the defensive check to the on-chain contract.

**Duplicate Source Path:**

The `MinerList.Pubkeys` originates from the Election contract's `GetVictories()` method: [3](#0-2) 

Which retrieves victory candidates without deduplication: [4](#0-3) 

The candidate list comes from `State.Candidates`, defined as a protobuf `repeated bytes` field that does NOT enforce uniqueness: [5](#0-4) [6](#0-5) 

Candidates are added to this list with only an `IsCurrentCandidate` flag check as protection: [7](#0-6) 

If the `IsCurrentCandidate` flag becomes desynchronized from the actual list contents (through bugs, state corruption, or edge cases), duplicate pubkeys can be added to `State.Candidates.Value.Value`. These duplicates flow through: `State.Candidates` → `GetValidCandidates()` → `GetVictories()` → `GenerateFirstRoundOfNewTerm()` → `ToDictionary()` throws `ArgumentException`.

## Impact Explanation

**Severity: HIGH - Complete Consensus Halt**

When `ToDictionary()` throws `ArgumentException`, the term transition transaction fails. Term transitions are invoked through: [8](#0-7) 

And processed via: [9](#0-8) 

A failed term transition prevents:
- New consensus rounds from being established
- Miner list updates from taking effect  
- Consensus from progressing beyond the current term
- Block production schedule updates

This constitutes complete operational failure requiring emergency intervention through governance proposals or chain restart with a patched contract. All block producers and the entire network are affected, making this a critical availability violation.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Required Preconditions:**
1. Duplicate pubkeys must exist in `State.Candidates.Value.Value`
2. Duplicates must survive through an election cycle to be selected as winners
3. Term transition must be attempted with the duplicate-containing miner list

**Feasibility Analysis:**
- **Not directly exploitable** by untrusted users - no public method allows forcing duplicate insertion while bypassing the `IsCurrentCandidate` check
- **Requires state inconsistency** in candidate management where the flag becomes desynchronized from the actual list
- **Deterministic failure** once duplicates exist - every term transition attempt fails until state is manually corrected
- **No defensive validation** - contract assumes input uniqueness without verification

**Risk Assessment:** Medium probability is assigned because:
- The existing `IsCurrentCandidate` flag check provides baseline protection under normal operation
- Off-chain code having `.Distinct()` proves developers explicitly identified this risk
- Lack of defensive checks in on-chain code increases exposure to state inconsistency edge cases
- State inconsistency can arise from contract upgrade bugs, state migration issues, or complex concurrent scenarios
- The catastrophic impact and trivial fix make this a significant vulnerability despite indirect exploitation

## Recommendation

Add `.Distinct()` call before `ToDictionary()` in the on-chain implementation to match the defensive approach used in off-chain code:

```csharp
var sortedMiners =
    (from obj in Pubkeys.Distinct()
            .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
        orderby obj.Value descending
        select obj.Key).ToList();
```

This ensures the contract gracefully handles duplicate pubkeys rather than throwing exceptions that halt consensus.

## Proof of Concept

A proof of concept would require:

1. Simulating state inconsistency by directly manipulating `State.Candidates.Value.Value` to contain duplicate `ByteString` entries
2. Ensuring the duplicate pubkey has sufficient votes to be selected in `GetVictories()`
3. Triggering a term transition via `NextTerm()`
4. Observing the `ArgumentException` thrown by `ToDictionary()` causing transaction failure

The vulnerability is proven by code inspection showing the on-chain implementation lacks the `.Distinct()` protection that off-chain implementations explicitly include, combined with the protobuf data structure allowing duplicates and the flag-based protection mechanism being vulnerable to desynchronization.

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L41-84)
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-174)
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
        else
        {
            Assert(!IsPubkeyBanned(pubkey), "This candidate already banned before.");
            State.CandidateInformationMap[pubkey] = new CandidateInformation
            {
                Pubkey = pubkey,
                AnnouncementTransactionId = Context.OriginTransactionId,
                IsCurrentCandidate = true
            };
        }

        State.Candidates.Value.Value.Add(pubkeyByteString);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
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
