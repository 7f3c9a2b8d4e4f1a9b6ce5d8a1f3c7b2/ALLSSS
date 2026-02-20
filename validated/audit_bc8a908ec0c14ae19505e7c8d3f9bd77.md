# Audit Report

## Title
Missing Miner List Validation in NextTerm Allows Consensus Takeover

## Summary
The `ProcessNextTerm` function accepts a `NextTermInput` and stores the miner list without validating it against the Election contract's legitimate election results. A malicious miner producing the NextTerm block can manipulate the miner list to exclude elected miners and maintain indefinite control over consensus, completely bypassing the democratic election mechanism.

## Finding Description

The AEDPoS consensus mechanism has a critical validation gap during term transitions that allows arbitrary miner list manipulation.

**Root Cause - Unvalidated Conversion:**

The `ToRound()` method performs a direct field-by-field copy from `NextTermInput` to `Round` without any validation of the miner list: [1](#0-0) 

**Root Cause - Storage Without Verification:**

When `ProcessNextTerm` processes the term transition, it extracts the miner list directly from the provided `nextRound` and stores it to state without verifying against the Election contract: [2](#0-1) 

The `SetMinerList` function stores the provided miner list without any validation against the Election contract: [3](#0-2) 

**Insufficient Pre-Execution Validation:**

The `RoundTerminateValidationProvider` only validates that term and round numbers increment by 1, but never checks the miner list: [4](#0-3) 

For NextTerm behavior, only the `RoundTerminateValidationProvider` is added to the validation pipeline: [5](#0-4) 

**Flawed Post-Execution Validation:**

The post-execution validation compares the header Round hash with the current state Round hash. However, since `ProcessNextTerm` already stored the malicious Round to state during execution, the validation compares the malicious data against itself and passes: [6](#0-5) 

The validation at lines 100-101 compares hashes, but at line 87, `TryToGetCurrentRoundInformation` retrieves the already-updated malicious round from state. The miner replacement check (lines 116-123) that queries the Election contract is only executed if the hashes DON'T match - but they match because both contain the same malicious data.

The block execution order confirms this flaw: [7](#0-6) 

The ChainContext is set to the current block (line 94-95), meaning state has already been updated by the block's execution before validation runs.

**Contrast with Legitimate Flow:**

The legitimate flow properly calls `GenerateFirstRoundOfNextTerm` which retrieves the correct miner list from the Election contract: [8](#0-7) [9](#0-8) [10](#0-9) 

However, nothing in the consensus protocol enforces that the `NextTermInput` used in the actual transaction matches this legitimate data. A malicious miner can generate the legitimate Round, modify `RealTimeMinersInformation`, and include the malicious version in their block.

## Impact Explanation

**Consensus Compromise (CRITICAL):**
- The attacker gains complete control over the miner list for an entire term (potentially days to weeks)
- Legitimate elected miners are excluded from consensus participation
- The attacker can perpetuate control indefinitely by repeating the attack at each term boundary

**Democratic Process Violation:**
- The Election contract's voting mechanism becomes meaningless
- Token holders' votes for validator candidates are completely ignored
- The fundamental governance model of elected consensus is broken

**System-Wide Effects:**
- All consensus-dependent operations (block production, transaction ordering, finality determination) are controlled by unauthorized miners
- Mining reward distribution goes to the wrong parties
- Cross-chain operations and LIB (Last Irreversible Block) calculations may be manipulated
- Treasury distributions and economic mechanisms tied to legitimate miner identity are compromised

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an authorized miner in the current term (realistic - mainnet typically has 17-23 miners)
- Must produce the NextTerm block (occurs naturally when the attacker is the extra block producer at term boundary)
- Requires running modified node software (Byzantine behavior - standard security assumption in blockchain systems)

**Attack Execution:**
1. Monitor for upcoming term transition
2. When scheduled to produce the NextTerm block, internally call `GetConsensusExtraDataForNextTerm` to generate legitimate data
3. Parse the returned `AElfConsensusHeaderInformation` containing the legitimate Round
4. Modify `Round.RealTimeMinersInformation` to the desired attacker-controlled miner set
5. Create `NextTermInput` with the modified Round and proper random number
6. Include in block and sign
7. All validations pass because only term/round number increments are checked

**Feasibility:**
- Occurs at predictable intervals (every term boundary)
- No cryptographic barriers - miner controls their own block production
- No multi-signature or threshold requirements
- Detection would require honest nodes to independently query the Election contract and compare results (not currently implemented in the protocol)

**Economic Rationality:**
- Low cost: Attacker is already a miner (sunk cost)
- High benefit: Control entire consensus for a full term, capture all mining rewards, exclude competitors
- Low risk: If other miners are unaware or also compromised, attack succeeds

## Recommendation

Add miner list validation in `ProcessNextTerm` to verify the provided miner list matches the Election contract's legitimate election results:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    
    // ADD VALIDATION: Verify miner list matches Election contract
    if (State.IsMainChain.Value && State.ElectionContract.Value != null)
    {
        var legitimateVictories = State.ElectionContract.GetVictories.Call(new Empty());
        var providedMiners = nextRound.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
        var legitimateMiners = legitimateVictories.Value.Select(v => v.ToHex()).OrderBy(k => k).ToList();
        
        Assert(providedMiners.Count == legitimateMiners.Count && 
               providedMiners.SequenceEqual(legitimateMiners),
               "Miner list does not match Election contract results.");
    }
    
    // Continue with existing logic...
}
```

Additionally, modify `ValidateConsensusAfterExecution` to compare against the Election contract when miner list changes:

```csharp
if (headerInformation.Behaviour == AElfConsensusBehaviour.NextTerm)
{
    var headerMiners = headerInformation.Round.RealTimeMinersInformation.Keys.OrderBy(k => k).ToList();
    var legitimateVictories = State.ElectionContract.GetVictories.Call(new Empty());
    var legitimateMiners = legitimateVictories.Value.Select(v => v.ToHex()).OrderBy(k => k).ToList();
    
    if (!headerMiners.SequenceEqual(legitimateMiners))
    {
        return new ValidationResult
        {
            Success = false,
            Message = "NextTerm miner list does not match Election contract results."
        };
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated by creating a test that:
1. Sets up a blockchain with legitimate elected miners from the Election contract
2. Simulates a malicious miner producing a NextTerm block with a modified miner list
3. Verifies that the malicious miner list is accepted and stored to state
4. Confirms that the legitimate miners are excluded from the next term

The test would show that `ProcessNextTerm` accepts and stores arbitrary miner lists without validation against the Election contract, and that post-execution validation compares the malicious data against itself (passing validation).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L25-40)
```csharp
    public Round ToRound()
    {
        return new Round
        {
            RoundNumber = RoundNumber,
            RealTimeMinersInformation = { RealTimeMinersInformation },
            ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
            BlockchainAge = BlockchainAge,
            TermNumber = TermNumber,
            ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
            ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
            IsMinerListJustChanged = IsMinerListJustChanged,
            RoundIdForValidation = RoundIdForValidation,
            MainChainMinersRoundNumber = MainChainMinersRoundNumber
        };
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

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusValidationProvider.cs (L80-99)
```csharp
    public async Task<bool> ValidateBlockAfterExecuteAsync(IBlock block)
    {
        if (block.Header.Height == AElfConstants.GenesisBlockHeight)
            return true;

        var consensusExtraData = _consensusExtraDataExtractor.ExtractConsensusExtraData(block.Header);
        if (consensusExtraData == null || consensusExtraData.IsEmpty)
        {
            Logger.LogDebug($"Invalid consensus extra data {block}");
            return false;
        }

        var isValid = await _consensusService.ValidateConsensusAfterExecutionAsync(new ChainContext
        {
            BlockHash = block.GetHash(),
            BlockHeight = block.Header.Height
        }, consensusExtraData.ToByteArray());

        return isValid;
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
