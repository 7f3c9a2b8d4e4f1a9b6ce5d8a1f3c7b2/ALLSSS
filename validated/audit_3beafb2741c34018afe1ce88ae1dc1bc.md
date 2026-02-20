# Audit Report

## Title
Miner List Manipulation via Unvalidated NextTerm Input Allows Consensus Takeover

## Summary
The `NextTerm` method in the AEDPoS consensus contract accepts arbitrary miner list data without validating it against election results from `ElectionContract.GetVictories()`. Any current miner can submit a `NextTerm` transaction with a fraudulent miner list, completely bypassing the election system to maintain indefinite control over consensus.

## Finding Description

The vulnerability exists in the term transition flow where the new miner list is accepted without on-chain validation against election results.

The `NextTerm` method accepts `NextTermInput` and calls `ProcessConsensusInformation`, which only performs basic authorization checks via `PreCheck()` that validate the sender is in the current or previous miner list, but does not validate the NEW miner list being submitted. [1](#0-0) 

The authorization check only verifies the sender's identity, not the legitimacy of the new miner list being proposed. [2](#0-1) 

The `ProcessNextTerm` method extracts the miner list directly from the `NextTermInput` parameter and updates the state without any validation against election results. It converts the input to a `Round`, extracts miners from `RealTimeMinersInformation`, and stores them via `SetMinerList`. [3](#0-2) 

The `SetMinerList` method simply stores the provided miner list in state without any validation. [4](#0-3) 

The intended design uses `GenerateFirstRoundOfNextTerm` to obtain legitimate election results. This method calls `TryToGetVictories` which retrieves the legitimate miner list from the Election contract's `GetVictories()` method. [5](#0-4) 

The `TryToGetVictories` method calls the Election contract to get the actual election winners based on votes. [6](#0-5) 

The Election contract's `GetVictories` method returns the legitimate election winners based on candidate votes. [7](#0-6) 

However, this legitimate miner list derivation occurs **only off-chain** during block generation when `GetConsensusExtraDataForNextTerm` is called. There is no on-chain validation that the submitted `NextTermInput` contains the same miner list. [8](#0-7) 

The validation system fails to prevent this attack. The `RoundTerminateValidationProvider` used for NextTerm behavior only validates that term and round numbers increment by 1, with no miner list validation. [9](#0-8) 

For NextTerm behavior, the validation framework only adds `RoundTerminateValidationProvider`, which does not validate miner lists. [10](#0-9) 

The `ValidateConsensusAfterExecution` method only validates within-term miner replacements via `GetNewestPubkey`. This method handles intra-term evil miner replacements but does not validate term transition miner lists against election results. [11](#0-10) 

The `GetNewestPubkey` method is specifically for tracking pubkey replacements when evil miners are replaced by backups during a term, not for validating term transition miner lists. [12](#0-11) 

## Impact Explanation

**Critical Consensus Integrity Compromise**: This vulnerability completely bypasses the election system, which is the fundamental security mechanism of the AEDPoS consensus. Token holders vote for validators through the election system, but this vulnerability renders those votes meaningless as any current miner can arbitrarily set the next term's miner list.

**Indefinite Control**: Once an attacker gains control (requiring only one legitimate election initially), they can perpetuate it indefinitely by including themselves in every subsequent term's miner list while excluding legitimate elected validators. The attacker can include accomplice nodes to maintain majority control over the 2/3 consensus threshold required for block production and finality.

**Protocol-Wide Damage**:
- **Mining Rewards Theft**: Block production rewards are misdirected to fraudulent miners instead of legitimately elected validators who earned votes from token holders
- **Treasury Corruption**: Fraudulent miners control treasury donation and release mechanisms, corrupting economic distributions
- **Cross-Chain Security Degradation**: Side chains rely on main chain miner integrity for security guarantees; fraudulent main chain miners compromise the entire cross-chain ecosystem
- **Governance Capture**: Attacker-controlled miners can manipulate proposal outcomes, parameter changes, and protocol upgrades

**Affected Parties**: All network participants lose consensus security guarantees, legitimate validators lose mining rewards they should have earned through election, and token holders lose the voting power that is fundamental to the governance model. The attack undermines the entire delegated proof-of-stake security model.

## Likelihood Explanation

**Directly Reachable Entry Point**: The `NextTerm` method is public and can be called by any current miner when term transition conditions are met based on `PeriodSeconds` configuration and blockchain age.

**Feasible Preconditions**: 
1. Attacker must be a current miner (achievable through one legitimate election initially or by being an initial miner)
2. Network must be at a term transition point (occurs automatically at predictable intervals based on configured period)

**Execution Sequence**:
1. Attacker monitors consensus state to detect when term transition time arrives
2. Attacker constructs a modified `NextTermInput` with arbitrary `RealTimeMinersInformation` containing their own pubkey and accomplice pubkeys instead of election winners
3. Attacker produces a block containing the malicious `NextTerm` transaction during their assigned time slot
4. The transaction passes `PreCheck()` since attacker is a current miner
5. The transaction passes `RoundTerminateValidationProvider` since term/round numbers are correctly incremented
6. `ProcessNextTerm` executes and stores the fraudulent miner list via `SetMinerList`
7. `ValidateConsensusAfterExecution` does not reject it since it only validates intra-term replacements
8. State is updated with fraudulent miner list in `State.MinerListMap[termNumber]`
9. In the next term, the fraudulent miners are now the official consensus participants
10. Attacker repeats this process at every term transition to maintain perpetual control

**Detection Difficulty**: The attack appears as a normal term transition on-chain with valid transaction structure and proper term/round number increments. Detection requires external off-chain monitoring to compare the on-chain miner list in `State.MinerListMap` against the expected winners from `ElectionContract.GetVictories()`, which most monitoring systems may not implement.

**Economic Rationality**: The attack is highly profitable. The one-time cost of getting elected initially (or being an initial miner) is vastly exceeded by ongoing block production rewards, consensus control, and governance power over protocol parameters and treasury funds. The attacker gains complete control over the network's economic incentives and governance mechanisms.

## Recommendation

Add on-chain validation in `ProcessNextTerm` to verify the submitted miner list matches the election results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ADD VALIDATION: Verify miner list matches election results
    if (State.IsMainChain.Value)
    {
        if (TryToGetVictories(out var legitimateVictories))
        {
            var submittedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
            var electionWinners = legitimateVictories.Pubkeys.Select(p => p.ToHex()).OrderBy(k => k).ToList();
            
            Assert(submittedMiners.Count == electionWinners.Count &&
                   submittedMiners.SequenceEqual(electionWinners),
                   "Miner list does not match election results from GetVictories()");
        }
    }
    
    // Continue with existing logic
    RecordMinedMinerListOfCurrentRound();
    CountMissedTimeSlots();
    // ... rest of the method
}
```

This ensures that term transitions must use the legitimate election winners, preventing arbitrary miner list manipulation while maintaining the existing off-chain consensus command generation workflow.

## Proof of Concept

A proof-of-concept would require:
1. Deploy a test network with the AEDPoS consensus contract
2. Have an attacker node become a current miner through legitimate election
3. Reach a term transition point
4. Submit a `NextTerm` transaction with a modified `NextTermInput` containing arbitrary miners (attacker + accomplices) instead of election winners
5. Observe that the transaction executes successfully without validation failure
6. Verify that `State.MinerListMap[nextTermNumber]` contains the fraudulent miner list
7. Confirm that subsequent blocks are produced by the fraudulent miners rather than the election winners
8. Demonstrate that this can be repeated indefinitely at each term transition

The vulnerability is confirmed through code analysis showing no validation path compares the submitted miner list against `ElectionContract.GetVictories()` during on-chain execution.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-190)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L353-357)
```csharp
    private string GetNewestPubkey(string pubkey)
    {
        var initialPubkey = State.InitialPubkeyMap[pubkey] ?? pubkey;
        return State.InitialToNewestPubkeyMap[initialPubkey] ?? initialPubkey;
    }
```
