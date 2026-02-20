# Audit Report

## Title
Missing Validation of ExtraBlockProducerOfPreviousRound in NextTermInput Allows Reward Manipulation

## Summary
The AEDPoS consensus system fails to validate that the `ExtraBlockProducerOfPreviousRound` field in NextTerm transactions matches the actual block producer. A malicious miner can manipulate this field to grant extra mining privileges to arbitrary miners, resulting in unfair reward distribution from the Treasury contract.

## Finding Description

The vulnerability exists because the `ExtraBlockProducerOfPreviousRound` field is never validated against the actual sender during NextTerm processing:

**1. No validation in NextTermInput.Create()** [1](#0-0) 

The Create() method simply copies `ExtraBlockProducerOfPreviousRound` from the input Round without any validation.

**2. Missing validation in RoundTerminateValidationProvider** [2](#0-1) 

The NextTerm validation only checks round number, term number, and InValues - it does NOT validate `ExtraBlockProducerOfPreviousRound`.

**3. ExtraBlockProducerOfPreviousRound excluded from hash calculation** [3](#0-2) 

The GetCheckableRound() method creates the hash without including `ExtraBlockProducerOfPreviousRound`, making hash-based validation ineffective.

**4. Field grants special mining privileges** [4](#0-3) 

Miners matching `ExtraBlockProducerOfPreviousRound` can produce tiny blocks before the round starts. [5](#0-4) 

The IsCurrentMiner method explicitly grants mining rights to `ExtraBlockProducerOfPreviousRound` before round start time.

**5. ProducedBlocks directly affects rewards** [6](#0-5) 

Each tiny block increments the miner's `ProducedBlocks` counter. [7](#0-6) 

Mining rewards are calculated as `minedBlocks * miningRewardPerBlock` and donated to Treasury.

**Root Cause**

In the honest case, the system correctly sets this field: [8](#0-7) 

However, a malicious miner can modify the Round object after generation but before signing the block. The system has validation to ensure `SenderPubkey` matches the block signer: [9](#0-8) 

But this only validates `SenderPubkey`, not `ExtraBlockProducerOfPreviousRound`. The attacker can set these to different values:
- `SenderPubkey` = their own pubkey (required for validation)
- `ExtraBlockProducerOfPreviousRound` = colluding miner's pubkey (to grant privileges) [10](#0-9) 

ProcessNextTerm directly converts the input to Round and stores it in state without validating `ExtraBlockProducerOfPreviousRound`.

## Impact Explanation

**Direct Fund Impact - Reward Misallocation:**

1. The miner whose pubkey matches `ExtraBlockProducerOfPreviousRound` receives extra mining time slots before the round officially starts
2. Each tiny block produced increments their `ProducedBlocks` counter
3. Mining rewards are proportional to `ProducedBlocks`, so manipulated miners receive disproportionately higher rewards from the Treasury contract

**Attack Scenarios:**
- **Collusion**: Malicious NextTerm producer sets `ExtraBlockProducerOfPreviousRound` to a colluding miner's pubkey
- **Self-enrichment**: The producer can set it to their own pubkey if they're also in the next term
- **Denial of Service**: Setting it to a non-existent pubkey prevents the legitimate producer from utilizing these privileges

**Affected Parties:**
- The legitimate extra block producer loses rightful mining privileges and proportional rewards
- Other honest miners receive reduced reward shares when a malicious miner inflates their block count
- Protocol integrity is compromised as rewards no longer accurately reflect actual work performed

## Likelihood Explanation

**Reachable Entry Point:**
The attack uses the standard NextTerm transaction flow during term transitions.

**Attacker Capabilities:**
The attacker must be selected to produce the NextTerm block, which happens regularly in the normal course of consensus operations. Every miner will eventually have this opportunity.

**Execution Practicality:**
1. Attacker produces a NextTerm block during their designated time slot
2. System generates honest consensus data with correct `ExtraBlockProducerOfPreviousRound`
3. Before signing, attacker modifies only the `ExtraBlockProducerOfPreviousRound` field in both block header extra data and transaction input
4. `SenderPubkey` remains unchanged (required for validation)
5. Block passes all validation because no validator checks this specific field
6. ProcessNextTerm stores the manipulated Round in state
7. Beneficiary miner gains extra mining privileges in the new term

**Detection Constraints:**
- The field is excluded from hash-based validation
- No regeneration or recomputation occurs during validation
- The manipulation is cryptographically valid and indistinguishable from honest behavior at the protocol level

**Economic Rationality:**
Minimal cost (simple field modification) with direct economic benefit through increased reward allocation makes this attack highly attractive for rational miners.

## Recommendation

Add validation in the NextTerm validation flow to ensure `ExtraBlockProducerOfPreviousRound` matches the actual sender:

1. In `RoundTerminateValidationProvider.ValidationForNextTerm()`, add:
```csharp
if (extraData.Round.ExtraBlockProducerOfPreviousRound != extraData.SenderPubkey.ToHex())
    return new ValidationResult { Message = "ExtraBlockProducerOfPreviousRound must match sender." };
```

2. Alternatively, regenerate the expected value in `ValidateBeforeExecution()` and compare:
```csharp
if (extraData.Behaviour == AElfConsensusBehaviour.NextTerm)
{
    var expectedProducer = extraData.SenderPubkey.ToHex();
    if (extraData.Round.ExtraBlockProducerOfPreviousRound != expectedProducer)
        return new ValidationResult { Message = "Invalid ExtraBlockProducerOfPreviousRound." };
}
```

3. Include `ExtraBlockProducerOfPreviousRound` in `GetCheckableRound()` for hash-based integrity verification.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Deploying an AEDPoS test environment
2. Having a miner produce a NextTerm block
3. Modifying the `ExtraBlockProducerOfPreviousRound` field to a different miner's pubkey before signing
4. Observing that the block passes all validation
5. Verifying that the wrong miner receives extra mining privileges in the new term
6. Confirming that reward distribution is skewed based on the manipulated `ProducedBlocks` counts

The core issue is that no validation layer checks this field, making the attack trivially executable by any miner producing a NextTerm block.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L185-207)
```csharp
    private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
    {
        var minersInformation = new Dictionary<string, MinerInRound>();
        foreach (var minerInRound in RealTimeMinersInformation.Clone())
        {
            var checkableMinerInRound = minerInRound.Value.Clone();
            checkableMinerInRound.EncryptedPieces.Clear();
            checkableMinerInRound.DecryptedPieces.Clear();
            checkableMinerInRound.ActualMiningTimes.Clear();
            if (!isContainPreviousInValue) checkableMinerInRound.PreviousInValue = Hash.Empty;

            minersInformation.Add(minerInRound.Key, checkableMinerInRound);
        }

        var checkableRound = new Round
        {
            RoundNumber = RoundNumber,
            TermNumber = TermNumber,
            RealTimeMinersInformation = { minersInformation },
            BlockchainAge = BlockchainAge
        };
        return checkableRound.ToByteArray();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L104-112)
```csharp
            if (
                // If this miner is extra block producer of previous round,
                CurrentRound.ExtraBlockProducerOfPreviousRound == _pubkey &&
                // and currently the time is ahead of current round,
                _currentBlockTime < CurrentRound.GetRoundStartTime() &&
                // make this miner produce some tiny blocks.
                _minerInRound.ActualMiningTimes.Count < _maximumBlocksCount
            )
                return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L149-155)
```csharp
        // Check confirmed extra block producer of previous round.
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L107-141)
```csharp
    private bool DonateMiningReward(Round previousRound)
    {
        if (State.TreasuryContract.Value == null)
        {
            var treasuryContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
            // Return false if Treasury Contract didn't deployed.
            if (treasuryContractAddress == null) return false;
            State.TreasuryContract.Value = treasuryContractAddress;
        }

        var miningRewardPerBlock = GetMiningRewardPerBlock();
        var minedBlocks = previousRound.GetMinedBlocks();
        var amount = minedBlocks.Mul(miningRewardPerBlock);
        State.TreasuryContract.UpdateMiningReward.Send(new Int64Value { Value = miningRewardPerBlock });

        if (amount > 0)
        {
            State.TreasuryContract.Donate.Send(new DonateInput
            {
                Symbol = Context.Variables.NativeSymbol,
                Amount = amount
            });

            Context.Fire(new MiningRewardGenerated
            {
                TermNumber = previousRound.TermNumber,
                Amount = amount
            });
        }

        Context.LogDebug(() => $"Released {amount} mining rewards.");

        return true;
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSExtraDataExtractor.cs (L21-33)
```csharp
    public ByteString ExtractConsensusExtraData(BlockHeader header)
    {
        var consensusExtraData =
            _blockExtraDataService.GetExtraDataFromBlockHeader(_consensusExtraDataProvider.BlockHeaderExtraDataKey,
                header);
        if (consensusExtraData == null)
            return null;

        var headerInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(consensusExtraData);

        // Validate header information
        return headerInformation.SenderPubkey != header.SignerPubkey ? null : consensusExtraData;
    }
```
