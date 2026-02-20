# Audit Report

## Title
Election Bypass via Unchecked Miner List in NextTerm Consensus Transition

## Summary
The AEDPoS consensus contract fails to validate that the miner list submitted in a `NextTerm` transaction matches the Election contract's democratic voting results. A malicious current-term miner producing the NextTerm transition block can substitute an arbitrary miner list to maintain control indefinitely, completely bypassing the election system.

## Finding Description

The vulnerability exists because the on-chain execution path for `NextTerm` has no validation connecting the submitted miner list to the Election contract's `GetVictories` results.

**Root Cause - No Input Validation:**

The `NextTermInput.Create()` method directly copies `RealTimeMinersInformation` from any provided `Round` object without validation. [1](#0-0) 

When `ProcessNextTerm` executes, it blindly extracts miners from this unvalidated input and updates the miner list for the new term. [2](#0-1) 

The `SetMinerList` method only checks whether a miner list was previously set for the term, NOT whether the miners are legitimate election winners. [3](#0-2) 

**Why Existing Validations Fail:**

Pre-execution validation for `NextTerm` only adds the `RoundTerminateValidationProvider`, which validates structural correctness (term/round number increments) but NOT miner list correctness. [4](#0-3) [5](#0-4) 

Post-execution validation compares the header round hash with the state round hash, but this is tautological—since `ProcessNextTerm` just updated the state FROM the header data, they will trivially match. [6](#0-5) 

**The Honest Path (Not Enforced On-Chain):**

The intended behavior is that `GenerateFirstRoundOfNextTerm` calls `TryToGetVictories` to query the Election contract for legitimate miners. [7](#0-6) [8](#0-7) 

The Election contract's `GetVictories` returns the top candidates by vote weight. [9](#0-8) 

However, this is only executed **off-chain** when generating the consensus command. The on-chain execution path has **NO validation** enforcing that the submitted `NextTermInput` matches these election results.

**Attack Execution:**

1. Attacker is a current-term miner scheduled to produce the NextTerm block
2. Attacker calls `GetConsensusExtraData` off-chain to obtain the correct `Round` object (containing election winners)
3. Attacker modifies `Round.RealTimeMinersInformation` to include themselves and exclude legitimate election winners
4. Attacker submits both the modified consensus extra data (in block header) AND modified `NextTermInput` (in transaction)
5. Pre-validation passes (only checks term/round number increments)
6. `ProcessNextTerm` executes and updates state with the malicious miner list
7. Post-validation passes (header matches state that was just set from header)
8. Attacker has successfully captured the next term's consensus

The `PreCheck` method only verifies the sender is in the current or previous round's miner list, which the attacker satisfies as a current-term miner. [10](#0-9) 

## Impact Explanation

**Critical Consensus Integrity Violation:**

This vulnerability breaks the most fundamental security guarantee of the AEDPoS consensus system: that miner selection is determined democratically through token holder voting.

- **Complete election bypass**: The Election contract's voting mechanism becomes meaningless
- **Consensus capture**: Attacker maintains mining privileges indefinitely regardless of election results
- **Reward theft**: All mining rewards for entire terms (potentially millions of native tokens) flow to attacker-controlled addresses
- **Perpetual control**: Since the attacker remains a miner in subsequent terms, they can repeat the attack indefinitely
- **Network centralization**: Single malicious actor controls block production, enabling censorship and potential double-spend attacks
- **Systemic governance failure**: Token holder votes are worthless, breaking the core promise of democratic governance

**Affected Parties:**
- Token holders: Election votes are ignored
- Legitimate election winners: Denied mining rights and rewards
- Entire network: Loss of decentralization and trust

## Likelihood Explanation

**High Likelihood:**

**Attacker Capabilities:**
- Must be a current-term miner (achievable through one legitimate election)
- Must be scheduled to produce the NextTerm transition block
- Requires only normal mining privileges, no special access

**Attack Complexity:**
- **Very Low**: Simply modify the `Round` object's `RealTimeMinersInformation` before creating `NextTermInput`
- Single transaction achieves complete consensus capture
- No cryptographic breaks or race conditions required

**Feasibility:**
- In a typical 7-miner configuration, each miner has ~14% probability per term to produce the NextTerm block
- Over multiple terms, the probability of opportunity approaches certainty
- **Massive economic incentive**: Continued mining rewards (potentially millions) vs. losing election and rewards

**Detection Difficulty:**
- All validation checks pass (only structural properties validated)
- Transaction appears valid to honest nodes
- By the time incorrect miner list is detected, state is committed and irreversible
- No on-chain mechanism exists to verify miner list against election results

Any miner who loses an election has enormous incentive to execute this attack when scheduled to produce the NextTerm block.

## Recommendation

Add on-chain validation in `ProcessNextTerm` to verify that the submitted miner list matches the Election contract's results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // CRITICAL FIX: Validate miner list against Election contract
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var expectedVictories = State.ElectionContract.GetVictories.Call(new Empty());
        var expectedMiners = expectedVictories.Value.Select(pk => pk.ToHex()).OrderBy(k => k).ToList();
        var actualMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        
        Assert(
            expectedMiners.Count == actualMiners.Count && 
            expectedMiners.SequenceEqual(actualMiners),
            "NextTerm miner list does not match Election contract results.");
    }
    
    // ... rest of ProcessNextTerm
}
```

Alternatively, compute the expected miner list on-chain and reject any `NextTermInput` that doesn't match.

## Proof of Concept

The vulnerability can be demonstrated with a test that:
1. Sets up initial miners and holds an election with different winners
2. Has a current miner create a modified `NextTermInput` with arbitrary miners
3. Calls `NextTerm` with the modified input
4. Verifies that the malicious miner list was accepted and set for the new term
5. Confirms that legitimate election winners were excluded

The test would show that `ProcessNextTerm` accepts and commits the arbitrary miner list without validating against `GetVictories` results, proving that election results are not enforced on-chain during term transitions.

---

## Notes

This is a **critical consensus vulnerability** that undermines the entire democratic governance model of AElf. The honest path correctly queries the Election contract off-chain, but there is zero on-chain enforcement that the submitted miner list matches those results. Any current-term miner with the opportunity to produce the NextTerm block can capture consensus indefinitely.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L188-190)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-280)
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
