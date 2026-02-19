# Audit Report

## Title
Malicious Miner Can Manipulate ExtraBlockProducerOfPreviousRound to Grant Unauthorized Mining Privileges

## Summary
A malicious block producer can manipulate the `ExtraBlockProducerOfPreviousRound` field in the `NextTermInput` transaction parameter to differ from the block header's consensus extra data. The validation bypass occurs because the Round hash comparison explicitly excludes this field, allowing attackers to grant unauthorized early mining privileges and extra block rewards to controlled miners at the start of new terms.

## Finding Description

The vulnerability exists due to a critical validation gap in the AEDPoS consensus mechanism during term transitions.

**Root Cause Analysis:**

The `GetCheckableRound` method creates a Round object for hash computation that excludes `ExtraBlockProducerOfPreviousRound`: [1](#0-0) 

This method only includes `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge` in the checkable round, while the protobuf definition shows that `Round` contains the `ExtraBlockProducerOfPreviousRound` field: [2](#0-1) 

The `ValidateConsensusAfterExecution` method compares Round hashes from the block header with the state but cannot detect manipulations to `ExtraBlockProducerOfPreviousRound` because it's excluded from the hash: [3](#0-2) 

**Attack Execution Path:**

1. When a NextTerm block is produced, `GetConsensusExtraDataForNextTerm` generates the block header with the correct `ExtraBlockProducerOfPreviousRound` set to the sender's pubkey: [4](#0-3) 

2. `GenerateTransactionListByExtraData` creates the NextTerm transaction using `NextTermInput.Create`: [5](#0-4) 

The `NextTermInput.Create` method copies all fields from the Round including `ExtraBlockProducerOfPreviousRound`: [6](#0-5) 

3. A malicious miner modifies the `NextTermInput.ExtraBlockProducerOfPreviousRound` field to point to a different miner (attacker-controlled) before including the transaction in the block.

4. `ProcessNextTerm` executes and converts the manipulated input to a Round, updating state with the malicious data: [7](#0-6) 

5. The `RoundTerminateValidationProvider` only validates round number, term number, and InValues - it does NOT check `ExtraBlockProducerOfPreviousRound`: [8](#0-7) 

## Impact Explanation

The `ExtraBlockProducerOfPreviousRound` field grants critical mining privileges at the start of new terms:

**Early Mining Access:** The designated miner can produce tiny blocks before the new round officially starts: [9](#0-8) 

**Extended Block Production:** The miner receives additional block production capacity beyond normal limits: [10](#0-9) 

**Mining Permission Checks:** The field is used to determine current mining eligibility: [11](#0-10) 

**Increased Rewards:** More block production leads to higher `ProducedBlocks` count, which is updated during transaction execution and directly impacts mining reward calculations: [12](#0-11) 

These rewards are donated to the Treasury and distributed based on produced blocks: [13](#0-12) 

**Affected Parties:**
- The legitimate miner who actually produced the extra block loses mining privileges and rewards
- The attacker-controlled miner gains unauthorized privileges and unearned rewards
- Overall consensus fairness and economic security are compromised

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be a miner capable of producing the NextTerm block (part of current miner set)
- Must control or collude with a second miner in the next term's miner list
- Requires ability to modify node software to craft malicious transactions

**Attack Complexity:**
The attack is straightforward:
1. Generate standard consensus transactions via `GenerateConsensusTransactions`
2. Modify the `NextTermInput.ExtraBlockProducerOfPreviousRound` field in the transaction bytes
3. Include the modified transaction in the block while keeping the header unchanged
4. The validation passes due to the hash exclusion

**Feasibility Factors:**
- NextTerm blocks occur at regular term transitions (predictable opportunities)
- Any miner selected to produce a NextTerm block can execute this attack
- Detection requires comparing transaction parameters with block header data, which is not performed
- The block appears valid to standard validation checks
- No additional cryptographic material or special permissions are needed beyond normal miner privileges

**Economic Incentive:**
- Cost: Standard block production cost (no additional expense)
- Benefit: Additional mining rewards from extra block production privileges
- The attack can be repeated at every term transition controlled by the attacker
- Clear positive return on investment given the minimal cost

## Recommendation

Add explicit validation of the `ExtraBlockProducerOfPreviousRound` field by comparing the value in the block header's consensus extra data with the value in the transaction parameter. This can be implemented in either:

1. **Include field in hash computation:** Modify `GetCheckableRound` to include `ExtraBlockProducerOfPreviousRound` in the checkable round:

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
        BlockchainAge = BlockchainAge,
        ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound // ADD THIS
    };
    return checkableRound.ToByteArray();
}
```

2. **Add explicit validation:** Add a specific check in `ValidateConsensusAfterExecution` or `RoundTerminateValidationProvider` to compare this field directly between header and state.

## Proof of Concept

```csharp
// This test demonstrates the vulnerability by showing that:
// 1. A miner can create a NextTerm block with mismatched ExtraBlockProducerOfPreviousRound
// 2. The validation passes despite the manipulation
// 3. The wrong miner gains unauthorized privileges

[Fact]
public async Task ExtraBlockProducerManipulation_ShouldFail_ButPasses()
{
    // Setup: Get to a term transition point
    var currentMiners = await GetCurrentMinersAsync();
    var legitimateMiner = currentMiners[0]; // Miner who should get privileges
    var attackerMiner = currentMiners[1];   // Attacker's controlled miner
    
    // Step 1: Generate consensus extra data (header) - has correct value
    var triggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(legitimateMiner),
        Behaviour = AElfConsensusBehaviour.NextTerm
    };
    var headerExtraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        new BytesValue { Value = triggerInfo.ToByteString() });
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(headerExtraData.Value);
    
    // Verify header has correct ExtraBlockProducerOfPreviousRound
    headerInfo.Round.ExtraBlockProducerOfPreviousRound.ShouldBe(legitimateMiner.ToHex());
    
    // Step 2: Generate transaction with MANIPULATED value
    var maliciousInput = NextTermInput.Create(headerInfo.Round, triggerInfo.RandomNumber);
    maliciousInput.ExtraBlockProducerOfPreviousRound = attackerMiner.ToHex(); // ATTACK
    
    // Step 3: Execute the transaction
    await ConsensusStub.NextTerm.SendAsync(maliciousInput);
    
    // Step 4: Validation passes despite mismatch
    var validationResult = await ConsensusStub.ValidateConsensusAfterExecution.CallAsync(
        new BytesValue { Value = headerInfo.ToByteString() });
    validationResult.Success.ShouldBeTrue(); // VULNERABILITY: This should fail but passes!
    
    // Step 5: Verify attacker gained unauthorized privileges
    var newRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    newRound.ExtraBlockProducerOfPreviousRound.ShouldBe(attackerMiner.ToHex()); // Manipulated value in state
    
    // Step 6: Verify attacker can mine early (has the privilege)
    var command = await ConsensusStub.GetConsensusCommand.CallAsync(
        new BytesValue { Value = attackerMiner });
    command.NextBlockMiningLeftMilliseconds.ShouldBeLessThan(0); // Can mine before round start
}
```

## Notes

This vulnerability represents a fundamental flaw in the consensus validation mechanism where critical privilege-granting fields are excluded from integrity checks. The attack is particularly severe because it allows direct theft of mining rewards through manipulation of a single field, with no additional cryptographic or permission requirements beyond standard miner status. The fix requires including `ExtraBlockProducerOfPreviousRound` in the hash computation to ensure end-to-end integrity between block headers and transaction parameters.

### Citations

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

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L172-179)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                return new TransactionList
                {
                    Transactions =
                    {
                        GenerateTransaction(nameof(NextTerm), NextTermInput.Create(round,randomNumber))
                    }
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L150-155)
```csharp
        if (Context.CurrentBlockTime <= currentRound.GetRoundStartTime() &&
            currentRound.ExtraBlockProducerOfPreviousRound == pubkey)
        {
            Context.LogDebug(() => "[CURRENT MINER]PREVIOUS");
            return true;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L254-254)
```csharp
        newRound.ExtraBlockProducerOfPreviousRound = senderPubkey;
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
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
