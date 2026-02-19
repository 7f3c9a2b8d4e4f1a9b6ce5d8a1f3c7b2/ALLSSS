# Audit Report

## Title
NextTerm Validation Bypass Allows Outdated Miner Keys After Replacement

## Summary
The `ValidateConsensusAfterExecution` function contains a critical logic flaw for NextTerm blocks. It only validates miner replacements when round hashes differ, but NextTerm execution sets the state directly from the header input, causing hashes to always match. This creates a circular validation that bypasses the `GetNewestPubkey` replacement check, allowing blocks with replaced (potentially compromised) miner public keys to be accepted.

## Finding Description

The vulnerability exists in the post-execution validation logic where the replacement check is conditional on hash mismatches. [1](#0-0) 

The validation assumes that matching hashes guarantee miner list validity. However, for NextTerm blocks, the `ProcessNextTerm` function unconditionally sets the current round state from the input without validating the miner list against current election results. [2](#0-1) 

The state update occurs via `AddRoundInformation` which directly writes the input round to state storage. [3](#0-2) 

The NextTerm input is generated at block creation time by calling `GenerateFirstRoundOfNextTerm`, which queries `GetVictories` from the Election contract to obtain the current elected miner list. [4](#0-3) 

This creates a time-of-check to time-of-use vulnerability where:
1. Block generation (time T1): Calls `GetVictories()` returning `[A, B, C]`
2. Between generation and validation: `ReplaceCandidatePubkey(A → A')` executes
3. Block validation (time T2): State already matches header, no replacement validation occurs

**Why existing protections fail:**

Pre-execution validation for NextTerm only validates round termination logic, not the miner list composition. [5](#0-4) 

The `RoundTerminateValidationProvider` confirms this - it only checks round number and term number correctness, with no miner list validation. [6](#0-5) 

When a candidate is replaced via `ReplaceCandidatePubkey`, the consensus contract's `RecordCandidateReplacement` is notified, but it only updates the **current round** information, not future rounds in pending blocks. [7](#0-6) 

The Election contract's replacement tracking updates the mapping to track the newest pubkey. [8](#0-7) 

## Impact Explanation

**Consensus Security Breach:** This vulnerability directly violates the critical invariant that replaced miners must be immediately removed from block production eligibility. When a candidate's key is replaced (typically due to key compromise or security concerns), the old key should be banned and unable to participate in consensus.

**Specific Attack Consequences:**
- A compromised or malicious miner whose key was replaced can continue producing blocks in the new term
- The legitimate replacement miner (new key holder) is denied their rightful block production slot
- Network security is degraded as compromised keys maintain consensus power
- Block production rewards are misdirected to the old (potentially compromised) key holder

**Affected Parties:**
- Network consensus integrity
- Legitimate miners with replacement keys who lose rewards and participation rights  
- Token holders who face increased security risk from compromised validators

This is a **High severity** issue because it allows continued participation of potentially compromised validator keys in consensus, directly undermining the blockchain's security model.

## Likelihood Explanation

**Realistic Attack Scenario:**
1. Miner produces NextTerm block at height N (calls `GetVictories()` → `[A, B, C]`)
2. Block N propagates through network with delays
3. Before Block N executes on all nodes, `ReplaceCandidatePubkey(A → A')` transaction executes in Block M < N
4. Block N arrives for validation after replacement
5. Validation: `ProcessNextTerm` sets state to `[A, B, C]` from header
6. `ValidateConsensusAfterExecution` compares header `[A, B, C]` with state `[A, B, C]` (just set) → hashes match
7. Replacement check skipped, block accepted
8. New term begins with compromised miner A instead of legitimate A'

**Feasibility Factors:**
- **Network delays**: Normal blockchain network latency can cause blocks to arrive out of generation order
- **Chain reorganizations**: Fork resolution can cause blocks to be re-validated in different state contexts  
- **No special privileges required**: Uses legitimate protocol operations (key replacement + block propagation)
- **Window of opportunity**: Any time between NextTerm block generation and execution

The replacement function is part of normal protocol operations for legitimate security maintenance. [9](#0-8) 

**Attack Complexity:** Medium - requires timing coordination between block propagation and replacement transaction, but exploits inherent network conditions.

## Recommendation

Add explicit miner list validation for NextTerm blocks in `ValidateConsensusAfterExecution`:

```csharp
public override ValidationResult ValidateConsensusAfterExecution(BytesValue input)
{
    var headerInformation = new AElfConsensusHeaderInformation();
    headerInformation.MergeFrom(input.Value);
    
    if (TryToGetCurrentRoundInformation(out var currentRound))
    {
        // Special handling for NextTerm: always validate miner list
        if (headerInformation.Behaviour == AElfConsensusBehaviour.NextTerm)
        {
            var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys.ToList();
            foreach (var miner in headerMiners)
            {
                var newestPubkey = State.ElectionContract.GetNewestPubkey.Call(
                    new StringValue { Value = miner }).Value;
                    
                if (newestPubkey != miner)
                {
                    return new ValidationResult
                    {
                        Success = false,
                        Message = $"NextTerm contains replaced miner {miner}, should be {newestPubkey}"
                    };
                }
            }
        }
        
        // Existing validation logic for other behaviors...
        if (headerInformation.Behaviour == AElfConsensusBehaviour.UpdateValue)
            headerInformation.Round = currentRound.RecoverFromUpdateValue(
                headerInformation.Round, headerInformation.SenderPubkey.ToHex());
                
        // ... rest of existing code
    }
    
    return new ValidationResult { Success = true };
}
```

Alternatively, add miner list validation in `ValidateBeforeExecution` for NextTerm blocks to catch the issue earlier.

## Proof of Concept

A complete test demonstrating this vulnerability would require:

```csharp
[Fact]
public async Task NextTerm_AcceptsOutdatedMinersAfterReplacement()
{
    // Setup: Initialize consensus with miners [A, B, C]
    var minerA = "original_pubkey_A";
    var minerA_new = "replacement_pubkey_A";
    
    // Step 1: Generate NextTerm block at term N
    var nextTermBlock = await GenerateNextTermBlock(minerList: new[] { minerA, "B", "C" });
    
    // Step 2: Execute replacement transaction before NextTerm block validation
    await ElectionContract.ReplaceCandidatePubkey(new ReplaceCandidatePubkeyInput
    {
        OldPubkey = minerA,
        NewPubkey = minerA_new
    });
    
    // Step 3: Validate NextTerm block (should reject but doesn't)
    var validationResult = await ConsensusContract.ValidateConsensusAfterExecution(
        nextTermBlock.ConsensusExtraData);
    
    // BUG: Validation passes even though minerA was replaced
    Assert.True(validationResult.Success); // This passes but shouldn't
    
    // Step 4: Execute NextTerm 
    await ConsensusContract.NextTerm(nextTermBlock.NextTermInput);
    
    // Verify: New term has old miner instead of replacement
    var currentMiners = await ConsensusContract.GetCurrentMinerList(new Empty());
    Assert.Contains(minerA, currentMiners.Pubkeys.Select(p => p.ToHex())); // Old key present
    Assert.DoesNotContain(minerA_new, currentMiners.Pubkeys.Select(p => p.ToHex())); // New key missing
}
```

The test would demonstrate that a NextTerm block containing a replaced miner is accepted during validation, allowing the old (potentially compromised) key to remain in the active miner set.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-124)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-256)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-157)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L173-257)
```csharp
    public override Empty ReplaceCandidatePubkey(ReplaceCandidatePubkeyInput input)
    {
        Assert(IsCurrentCandidateOrInitialMiner(input.OldPubkey),
            "Pubkey is neither a current candidate nor an initial miner.");
        Assert(!IsPubkeyBanned(input.OldPubkey) && !IsPubkeyBanned(input.NewPubkey),
            "Pubkey is in already banned.");

        // Permission check.
        Assert(Context.Sender == GetCandidateAdmin(new StringValue { Value = input.OldPubkey }), "No permission.");

        // Record the replacement.
        PerformReplacement(input.OldPubkey, input.NewPubkey);

        var oldPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.OldPubkey));
        var newPubkeyBytes = ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(input.NewPubkey));

        //     Remove origin pubkey from Candidates, DataCentersRankingList and InitialMiners; then add new pubkey.
        var candidates = State.Candidates.Value;
        Assert(!candidates.Value.Contains(newPubkeyBytes), "New pubkey is already a candidate.");
        if (candidates.Value.Contains(oldPubkeyBytes))
        {
            candidates.Value.Remove(oldPubkeyBytes);
            candidates.Value.Add(newPubkeyBytes);
            State.Candidates.Value = candidates;
        }

        var rankingList = State.DataCentersRankingList.Value;
        //the profit receiver is not exist but candidate in the data center ranking list
        if (rankingList.DataCenters.ContainsKey(input.OldPubkey))
        {
            rankingList.DataCenters.Add(input.NewPubkey, rankingList.DataCenters[input.OldPubkey]);
            rankingList.DataCenters.Remove(input.OldPubkey);
            State.DataCentersRankingList.Value = rankingList;

            // Notify Profit Contract to update backup subsidy profiting item.
            if (State.ProfitContract.Value == null)
                State.ProfitContract.Value =
                    Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
            
            var oldProfitReceiver = GetProfitsReceiverOrDefault(input.OldPubkey);
            var profitReceiver = oldProfitReceiver.Value.Any()
                ? oldProfitReceiver
                : null;
            RemoveBeneficiary(input.OldPubkey);
            AddBeneficiary(input.NewPubkey, profitReceiver);
        }

        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }

        //     For CandidateVotes and CandidateInformation, just replace value of origin pubkey.
        var candidateVotes = State.CandidateVotes[input.OldPubkey];
        if (candidateVotes != null)
        {
            candidateVotes.Pubkey = newPubkeyBytes;
            State.CandidateVotes[input.NewPubkey] = candidateVotes;
            State.CandidateVotes.Remove(input.OldPubkey);
        }

        var candidateInformation = State.CandidateInformationMap[input.OldPubkey];
        if (candidateInformation != null)
        {
            candidateInformation.Pubkey = input.NewPubkey;
            State.CandidateInformationMap[input.NewPubkey] = candidateInformation;
            State.CandidateInformationMap.Remove(input.OldPubkey);
        }

        //     Ban old pubkey.
        State.BannedPubkeyMap[input.OldPubkey] = true;

        ReplaceCandidateProfitsReceiver(input.OldPubkey, input.NewPubkey);
        
        Context.Fire(new CandidatePubkeyReplaced
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L280-302)
```csharp
    private void PerformReplacement(string oldPubkey, string newPubkey)
    {
        State.CandidateReplacementMap[newPubkey] = oldPubkey;

        // Initial pubkey is:
        // - miner pubkey of the first round (aka. Initial Miner), or
        // - the pubkey announced election

        var initialPubkey = State.InitialPubkeyMap[oldPubkey] ?? oldPubkey;
        State.InitialPubkeyMap[newPubkey] = initialPubkey;

        State.InitialToNewestPubkeyMap[initialPubkey] = newPubkey;

        // Notify Consensus Contract to update replacement information. (Update from old record.)
        if (State.AEDPoSContract.Value == null)
            State.AEDPoSContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);

        State.AEDPoSContract.RecordCandidateReplacement.Send(new RecordCandidateReplacementInput
        {
            OldPubkey = oldPubkey,
            NewPubkey = newPubkey
        });
```
