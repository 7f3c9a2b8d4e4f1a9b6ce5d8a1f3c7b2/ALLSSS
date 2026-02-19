### Title
NextTerm Miner List Bypass - Arbitrary Miner Installation Without Election Validation

### Summary
The `NextTermInput.Create()` method and the `ProcessNextTerm()` execution path do not validate that the `RealTimeMinersInformation` miners match the elected top N candidates from the Election contract's `GetVictories()` method. A malicious extra block producer can supply arbitrary miners in `NextTermInput`, completely bypassing the election/governance system and installing unauthorized nodes as consensus miners for the next term.

### Finding Description

**Root Cause:**

The `NextTermInput.Create()` method blindly copies `RealTimeMinersInformation` from the provided Round parameter without any validation: [1](#0-0) 

During term transition execution, `ProcessNextTerm()` extracts the miner list directly from the input and stores it in state without calling `GetVictories()` or validating against the Election contract: [2](#0-1) 

Specifically, line 188-190 creates a `MinerList` from `nextRound.RealTimeMinersInformation.Keys` (which came from the unvalidated input) and stores it via `SetMinerList()` without any election validation.

**Why Protections Fail:**

1. **Pre-execution validation** only checks structural properties (round/term number increments, null InValues), not miner list correctness: [3](#0-2) 

2. **Post-execution validation** compares header round info against the current state, but the state was already updated with the malicious miners, so they match: [4](#0-3) 

3. **Election contract integration** exists only in the honest generation path (`GenerateFirstRoundOfNextTerm` calls `TryToGetVictories`), but is never called during validation or execution: [5](#0-4) 

The `GetVictories()` method in the Election contract properly returns the top N candidates by vote weight, but this validation is never enforced during `NextTerm` processing: [6](#0-5) 

### Impact Explanation

**Critical Consensus Takeover:**

- An attacker controlling the extra block producer at term end can install completely arbitrary miners for the next term
- This allows installing attacker-controlled nodes as 100% of the miner set, achieving complete blockchain control
- Once controlling all miners, the attacker can: censor transactions, rewrite history, halt the chain, or manipulate all governance/economic mechanisms
- The election/voting system becomes meaningless as vote results are ignored
- All staked tokens and voting weights become worthless as they don't influence miner selection

**Affected Parties:**

- All token holders who voted in elections (their votes are ignored)
- All legitimate miner candidates (bypassed regardless of vote weight)
- The entire blockchain security model (DPoS consensus broken)
- All protocol participants (subject to attacker-controlled consensus)

**Severity Justification:** CRITICAL - Complete bypass of the core governance mechanism, enabling total blockchain takeover by a single malicious miner.

### Likelihood Explanation

**Attacker Capabilities Required:**

- Control of ANY extra block producer position at the end of ANY term
- Ability to modify their node software to generate malicious `NextTermInput`

**Attack Complexity:** Low

1. Wait until scheduled as extra block producer at term end
2. Modify node to skip `GenerateFirstRoundOfNextTerm()` and construct a `Round` with attacker-controlled public keys as miners
3. Generate `NextTermInput` with this malicious Round
4. Block passes all validations (only structural checks exist)
5. Execution installs attacker's miners for next term

**Feasibility Conditions:**

- Extra block producers rotate among current miners, so any current miner can execute this attack when their turn comes
- No cryptographic or economic barriers exist (cost = normal block production)
- Attack is undetectable until after execution (post-validation compares manipulated state against itself)
- No recovery mechanism exists once malicious miners are installed

**Probability:** HIGH - Any miner can execute this attack during their regular extra block production duty. The preconditions are routinely satisfied during normal blockchain operation.

### Recommendation

**Immediate Fix:**

Add validation in `ProcessNextTerm()` to verify that the miners in `NextTermInput` match the Election contract's `GetVictories()` result:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // CRITICAL: Validate miners match election results
    if (State.IsMainChain.Value)
    {
        var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
        var actualMiners = nextRound.RealTimeMinersInformation.Keys
            .Select(k => ByteStringHelper.FromHexString(k))
            .OrderBy(p => p.ToHex())
            .ToList();
        var expectedMiners = expectedVictories.Value
            .OrderBy(p => p.ToHex())
            .ToList();
            
        Assert(
            actualMiners.Count == expectedMiners.Count &&
            actualMiners.SequenceEqual(expectedMiners),
            "Miner list in NextTermInput does not match Election contract GetVictories result."
        );
    }
    
    // ... rest of existing ProcessNextTerm logic
}
```

**Additional Hardening:**

1. Add the same validation in `ValidateBeforeExecution()` for defense-in-depth
2. Add integration tests that attempt to supply non-elected miners in `NextTermInput` and verify rejection
3. Consider adding a hash commitment to the previous term's election results that must match

### Proof of Concept

**Initial State:**
- Blockchain at block height N, term T ending
- Election contract has valid candidates: [A, B, C, D, E] with votes [1000, 900, 800, 700, 600]
- `GetVictories()` would return top 3: [A, B, C]
- Attacker controls miner X who is scheduled as extra block producer for term-ending block

**Attack Steps:**

1. Attacker's node generates `NextTerm` consensus command
2. Instead of calling `GenerateFirstRoundOfNextTerm()` which would call `TryToGetVictories()`, attacker constructs:
   ```
   Round {
     RealTimeMinersInformation: {
       "AttackerPubkey1": {...},
       "AttackerPubkey2": {...},
       "AttackerPubkey3": {...}
     },
     TermNumber: T+1,
     RoundNumber: R+1,
     ...
   }
   ```
3. Creates `NextTermInput` via `NextTermInput.Create(maliciousRound, randomNumber)`
4. Produces block with this `NextTermInput` transaction

**Expected Result:**
- Validation should reject the block because miners [AttackerPubkey1, AttackerPubkey2, AttackerPubkey3] ≠ elected miners [A, B, C]

**Actual Result:**
- `ValidateConsensusBeforeExecution`: PASS (only checks round/term numbers)
- `NextTerm` execution: PASS (no validation, stores attacker's miners)
- `ValidateConsensusAfterExecution`: PASS (compares manipulated state against itself)
- **State corruption complete**: Next term miners are now [AttackerPubkey1, AttackerPubkey2, AttackerPubkey3] instead of the elected [A, B, C]

**Success Condition:** 
After block execution, `State.MinerListMap[T+1]` contains attacker's miners instead of election winners, and all subsequent blocks in term T+1 are produced only by attacker-controlled nodes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
        {
            RoundNumber = round.RoundNumber,
            RealTimeMinersInformation = { round.RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = round.ExtraBlockProducerOfPreviousRound,
            BlockchainAge = round.BlockchainAge,
            TermNumber = round.TermNumber,
            ConfirmedIrreversibleBlockHeight = round.ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = round.ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = round.IsMinerListJustChanged,
            RoundIdForValidation = round.RoundIdForValidation,
            MainChainMinersRoundNumber = round.MainChainMinersRoundNumber,
            RandomNumber = randomNumber
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L83-128)
```csharp
    public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
    {
        var headerInformation = new AElfConsensusHeaderInformation();
        headerInformation.MergeFrom(input.Value);
        if (TryToGetCurrentRoundInformation(out var currentRound))
        {
            if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
                headerInformation.Round =
                    currentRound.RecoverFromUpdateValue(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            if (headerInformation.Behaviour == AElfConsensusBehaviour.TinyBlock)
                headerInformation.Round =
                    currentRound.RecoverFromTinyBlock(headerInformation.Round,
                        headerInformation.SenderPubkey.ToHex());

            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
                var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys;
                var stateMiners = currentRound.RealTimeMinersInformation.Keys;
                var replacedMiners = headerMiners.Except(stateMiners).ToList();
                if (!replacedMiners.Any())
                    return new ValidationResult
                    {
                        Success = false, Message =
                            "Current round information is different with consensus extra data.\n" +
                            $"New block header consensus information:\n{headerInformation.Round}" +
                            $"Stated block header consensus information:\n{currentRound}"
                    };

                var newMiners = stateMiners.Except(headerMiners).ToList();
                var officialNewestMiners = replacedMiners.Select(miner =>
                        State.ElectionContract.GetNewestPubkey.Call(new StringValue { Value = miner }).Value)
                    .ToList();

                Assert(
                    newMiners.Count == officialNewestMiners.Count &&
                    newMiners.Union(officialNewestMiners).Count() == newMiners.Count,
                    "Incorrect replacement information.");
            }
        }

        return new ValidationResult { Success = true };
    }
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
