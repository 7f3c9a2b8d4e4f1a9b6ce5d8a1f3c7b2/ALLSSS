# Audit Report

## Title
Election Bypass via Unchecked Miner List in NextTerm Consensus Transition

## Summary
The AEDPoS consensus contract's `NextTerm` method accepts arbitrary miner lists without validating them against the Election contract's democratic vote results. A malicious current-term miner producing the NextTerm block can manipulate the miner list to maintain control indefinitely, completely bypassing the election system.

## Finding Description

The AEDPoS consensus contract fails to validate that the miner list in a `NextTerm` transaction matches the Election contract's `GetVictories` results, enabling complete election bypass and consensus capture.

**Root Cause:**

`NextTermInput.Create()` directly copies `RealTimeMinersInformation` from any provided `Round` object without validation. [1](#0-0) 

When `ProcessNextTerm` executes, it blindly trusts this input and extracts miners directly from the unvalidated data to create the miner list for the new term. [2](#0-1) 

The `SetMinerList` method only checks if a miner list was previously set for the term, NOT whether the miners are legitimate election winners. [3](#0-2) 

**Why Validations Fail:**

Pre-execution validation for NextTerm only adds `RoundTerminateValidationProvider`, which checks structural correctness (term/round number increments) but NOT miner list correctness. [4](#0-3) 

The `RoundTerminateValidationProvider` only validates that term and round numbers increment by 1, with no validation of miner list legitimacy. [5](#0-4) 

Post-execution validation compares the header round hash with the state round hash, but since `ProcessNextTerm` just updated the state FROM the header via `AddRoundInformation(nextRound)`, they trivially match—this is a tautology. [6](#0-5) 

**The Honest Path (Not Enforced):**

The intended behavior is that `GenerateFirstRoundOfNextTerm` queries the Election contract via `TryToGetVictories` to get legitimate election winners. [7](#0-6) 

`TryToGetVictories` calls the Election contract's `GetVictories` method. [8](#0-7) 

The Election contract's `GetVictories` returns top candidates by vote weight, representing the democratic election results. [9](#0-8) 

However, this election validation is only called **off-chain** when generating the consensus command. The on-chain execution path in `ProcessNextTerm` has **NO validation** that enforces the submitted `NextTermInput` matches these election results.

**Attack Flow:**

1. Attacker is a current-term miner who lost the election
2. Attacker is scheduled to produce the NextTerm block (normal miner rotation)
3. Attacker calls `GetConsensusBlockExtraData` off-chain to see the correct Round (with legitimate election winners) [10](#0-9) 
4. Attacker modifies the Round's `RealTimeMinersInformation` to include themselves and exclude legitimate winners
5. Attacker submits both modified consensus extra data in the block header AND the modified `NextTermInput` in the transaction
6. Pre-validation passes (only checks term/round number increments, not miner list)
7. `ProcessNextTerm` executes and updates state with malicious miner list (lines 188-190)
8. Post-validation passes (compares header with state that was just set from header)
9. Attacker has captured consensus for the entire next term

The `PreCheck` method allows this because it only validates that the sender is in the current OR previous round miner list, which the attacker satisfies. [11](#0-10) 

## Impact Explanation

**Critical Consensus Integrity Violation:**

This vulnerability breaks the most fundamental security guarantee of the AEDPoS consensus system: that miner selection must be determined by democratic token-holder elections.

- **Complete election bypass**: The election system becomes meaningless as any current miner can ignore vote results
- **Consensus capture**: Attacker maintains mining privileges indefinitely regardless of election outcomes
- **Reward theft**: All mining rewards for the entire term (potentially millions of native tokens based on mining reward calculations) flow to attacker-controlled addresses
- **Systemic governance failure**: Token holder votes become worthless, destroying the core promise of decentralized governance
- **Network centralization**: Single malicious actor controls block production, enabling transaction censorship and potential double-spend attacks
- **Perpetual control**: Since attacker remains a miner in subsequent terms, they can repeat the attack indefinitely across all future terms

**Affected Parties:**
- **Token holders**: Their election votes are completely ignored
- **Legitimate election winners**: Denied their rightful mining privileges and all associated rewards
- **Entire network**: Suffers centralization, loss of trust, and potential for further attacks

This violates the invariant: **"Miner schedule integrity must be maintained through democratic election."**

## Likelihood Explanation

**High Likelihood:**

**Attacker Capabilities:**
- Must be a current-term miner (obtainable through legitimate means in one term)
- Must be scheduled to produce the NextTerm transition block (happens via normal miner rotation)
- No special privileges required beyond normal mining rights

**Attack Complexity:**
- **Very Low**: Simply modify the `Round` object's `RealTimeMinersInformation` before creating `NextTermInput`
- Single transaction achieves complete consensus capture
- No need to break cryptographic primitives, exploit race conditions, or perform complex attacks
- Attacker can observe the honest miner list off-chain and craft their malicious version

**Feasibility:**
- In a typical 7-miner setup, each miner has approximately 14% probability per term to produce the NextTerm block
- Over multiple terms, probability of getting the opportunity approaches certainty
- **Massive economic incentive**: Continued mining rewards (potentially millions of tokens) versus losing election and mining privileges

**Detection Difficulty:**
- All validation checks pass (only structural properties are validated)
- Transaction appears valid to all honest nodes
- By the time the wrong miner list is detected by observing block production patterns, state is already committed and irreversible without hard fork
- No on-chain mechanism exists to verify the miner list against election results after the fact

**Probability Assessment:**
Any miner who loses an election has enormous incentive to execute this attack when they have the opportunity to produce the NextTerm block. The technical barriers are essentially non-existent and the reward is massive and perpetual.

## Recommendation

Add validation in `ProcessNextTerm` to verify that the submitted miner list matches the Election contract's results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ... existing code ...
    
    // ADDED VALIDATION: Verify miner list matches election results
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var victories = State.ElectionContract.GetVictories.Call(new Empty());
        var expectedMiners = new HashSet<string>(
            victories.Value.Select(v => v.ToHex()).OrderBy(k => k)
        );
        var actualMiners = new HashSet<string>(
            nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k)
        );
        
        Assert(expectedMiners.SetEquals(actualMiners), 
            "Miner list does not match election results.");
    }
    
    // ... rest of existing code ...
}
```

Alternatively, add this validation in `ValidateConsensusAfterExecution` for NextTerm behavior to ensure the miner list in the new term matches democratic election outcomes.

## Proof of Concept

The POC would demonstrate:

1. Deploy a test network with Election and Consensus contracts
2. Run an election with legitimate candidates
3. Have a current-term miner (who lost the election) produce the NextTerm block
4. In the NextTerm transaction, submit a modified `NextTermInput` with:
   - Correct term/round number increments (to pass structural validation)
   - Modified `RealTimeMinersInformation` containing the attacker but excluding legitimate winners
5. Observe that:
   - The transaction executes successfully
   - The malicious miner list is set for the new term
   - The attacker maintains mining privileges despite losing the election
   - Legitimate election winners are excluded from the miner list

The test would verify that `State.MinerListMap[newTermNumber]` contains the attacker's address but not the legitimate election winners, proving the election bypass.

---

## Notes

This is a **critical consensus integrity vulnerability** that undermines the fundamental security model of AEDPoS. The vulnerability exists because:

1. **Off-chain generation** (honest path) uses `TryToGetVictories` to query election results
2. **On-chain execution** (attack path) has no validation that enforces this
3. All existing validations only check structural properties (term/round increments, time slots, mining permissions for current term)
4. No validation checks that the new term's miner list matches the Election contract's democratic results

The attack is realistic because current-term miners regularly produce NextTerm blocks as part of normal consensus operation, and a miner who loses an election has overwhelming incentive to exploit this vulnerability to maintain their lucrative mining privileges indefinitely.

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
