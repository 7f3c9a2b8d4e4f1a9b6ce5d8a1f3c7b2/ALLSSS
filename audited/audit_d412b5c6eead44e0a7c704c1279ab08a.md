### Title
Missing Duplicate Pubkey Validation in GenerateFirstRoundOfNewTerm Causes Consensus Halt

### Summary
The `GenerateFirstRoundOfNewTerm()` method in the consensus contract calls `ToDictionary()` without deduplicating the pubkey list, while off-chain extension implementations include `.Distinct()` for this exact protection. If duplicate pubkeys exist in `MinerList.Pubkeys` due to state inconsistency or bugs in candidate management, the `ToDictionary()` call throws `ArgumentException`, halting term generation and consensus progression.

### Finding Description

The vulnerability exists in the contract implementation at: [1](#0-0) 

This code directly converts `Pubkeys` to a dictionary using `ToHex()` as the key without deduplication. The `ToHex()` method is a bijective hex encoding [2](#0-1) , so identical byte sequences produce identical hex strings.

**Critical Evidence**: Off-chain implementations explicitly include `.Distinct()` before `ToDictionary()`: [3](#0-2) 

This discrepancy proves the duplicate risk was identified but the fix was not applied to the on-chain contract code.

**Duplicate Sources**:

The `MinerList.Pubkeys` is populated from `GetVictories()` in the Election contract: [4](#0-3) 

Which calls the internal `GetVictories()` method that builds the list from `validCandidates` and backups: [5](#0-4) 

The `validCandidates` derives from `State.Candidates.Value`: [6](#0-5) 

Where `State.Candidates` is defined as: [7](#0-6) 

This is a `RepeatedField<ByteString>` that does NOT enforce uniqueness. Candidates are added via: [8](#0-7) 

Protection relies solely on the `IsCurrentCandidate` check: [9](#0-8) 

If this flag becomes inconsistent with the list state (through bugs, race conditions in multi-step operations, or state corruption), duplicates can be added. Once duplicates exist in `State.Candidates`, they flow through `GetValidCandidates()` → `GetVictories()` → `GenerateFirstRoundOfNewTerm()`, where `ToDictionary()` throws.

### Impact Explanation

**Operational Impact - Consensus Halt**: When `ToDictionary()` throws `ArgumentException`, the `GenerateFirstRoundOfNewTerm()` call fails. This method is invoked during term transitions via: [10](#0-9) 

And term processing occurs in: [11](#0-10) 

A failed term transition prevents:
- New consensus rounds from being established
- Miner list updates from taking effect
- Consensus from progressing beyond the current term
- Block production schedule updates

This constitutes a **complete consensus halt**, requiring emergency intervention (likely governance proposal or chain restart with patched contract) to resolve. All block producers and the entire network are affected.

**Severity**: HIGH - Complete operational failure of the consensus system.

### Likelihood Explanation

**Preconditions**:
1. Duplicate pubkeys must exist in `State.Candidates.Value.Value` or be generated through the `GetVictories()` logic
2. These duplicates must survive through an election cycle to be selected as winners
3. Term transition must be attempted with the duplicate-containing miner list

**Feasibility**:
- **Not directly exploitable** by untrusted users - there's no public method to force duplicate insertion
- **Requires bug or state inconsistency** in candidate management (e.g., `IsCurrentCandidate` flag desync)
- **Deterministic failure** once duplicates exist - every term transition attempt will fail
- **No defensive validation** - the contract assumes input uniqueness without verification

**Probability Assessment**: MEDIUM
- Lower probability due to existing `IsCurrentCandidate` protection
- Higher consequence due to no defensive checks and evidence of known issue (off-chain code has `.Distinct()`)
- Risk increases over time as state complexity grows and potential for flag desynchronization increases

### Recommendation

**Immediate Fix**: Add `.Distinct()` before `ToDictionary()` in the contract code to match the off-chain implementations:

```csharp
var sortedMiners =
    (from obj in Pubkeys.Distinct()
            .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
        orderby obj.Value descending
        select obj.Key).ToList();
```

**Additional Validations**:
1. Add uniqueness assertion in `AnnounceElection()` before adding to `State.Candidates`
2. Add duplicate detection in `GetVictories()` with proper logging
3. Add validation in `ProcessNextTerm()` before calling `SetMinerList()`

**Test Coverage**:
1. Unit test: `MinerList` with duplicate pubkeys passed to `GenerateFirstRoundOfNewTerm()`
2. Integration test: Simulate candidate state corruption and verify graceful handling
3. Regression test: Verify `.Distinct()` exists in all `GenerateFirstRoundOfNewTerm()` implementations

### Proof of Concept

**Required Initial State**:
1. Blockchain with functional consensus and election contracts
2. Multiple registered candidates in `State.Candidates.Value`

**Exploitation Steps**:
1. Through a bug in candidate management or state manipulation, cause `State.Candidates.Value.Value` to contain duplicate `ByteString` entries (e.g., same pubkey added twice)
2. Wait for election cycle where these candidates have sufficient votes
3. `GetVictories()` returns the duplicate pubkeys in its result
4. Miner attempts to trigger `NextTerm` transition
5. `ProcessNextTerm()` calls `GenerateFirstRoundOfNewTerm()`
6. Line 17 executes: `Pubkeys.ToDictionary(miner => miner.ToHex(), miner => miner[0])`

**Expected Result**: New term generated successfully with deduplicated miner list

**Actual Result**: `ArgumentException: An item with the same key has already been added` thrown by `ToDictionary()`, transaction fails, term transition aborted, consensus halted

**Success Condition**: No new terms can be generated until duplicate pubkeys are removed from state through emergency governance action or contract upgrade.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L8-31)
```csharp
        public static string ToHex(this ByteString bytes, bool withPrefix = false)
        {
            var offset = withPrefix ? 2 : 0;
            var length = bytes.Length * 2 + offset;
            var c = new char[length];

            byte b;

            if (withPrefix)
            {
                c[0] = '0';
                c[1] = 'x';
            }

            for (int bx = 0, cx = offset; bx < bytes.Length; ++bx, ++cx)
            {
                b = (byte)(bytes[bx] >> 4);
                c[cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);

                b = (byte)(bytes[bx] & 0x0F);
                c[++cx] = (char)(b > 9 ? b + 0x37 + 0x20 : b + 0x30);
            }

            return new string(c);
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Extensions/MinerListExtensions.cs (L15-19)
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L86-95)
```csharp
    private List<string> GetValidCandidates()
    {
        if (State.Candidates.Value == null) return new List<string>();

        return State.Candidates.Value.Value
            .Where(c => State.CandidateVotes[c.ToHex()] != null &&
                        State.CandidateVotes[c.ToHex()].ObtainedActiveVotedVotesAmount > 0)
            .Select(p => p.ToHex())
            .ToList();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L27-27)
```csharp
    public SingletonState<PubkeyList> Candidates { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L154-161)
```csharp
        if (candidateInformation != null)
        {
            Assert(!candidateInformation.IsCurrentCandidate,
                $"This public key already announced election. {pubkey}");
            candidateInformation.AnnouncementTransactionId = Context.OriginTransactionId;
            candidateInformation.IsCurrentCandidate = true;
            // In this way we can keep history of current candidate, like terms, missed time slots, etc.
            State.CandidateInformationMap[pubkey] = candidateInformation;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L174-174)
```csharp
        State.Candidates.Value.Value.Add(pubkeyByteString);
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
