### Title
Malicious Miner Can Manipulate ExtraBlockProducerOfPreviousRound to Grant Unauthorized Mining Privileges

### Summary
A malicious block producer can manipulate the `ExtraBlockProducerOfPreviousRound` field in the `NextTermInput` transaction parameter to differ from the value in the block header's consensus extra data. This bypasses validation because the Round hash comparison excludes this field, allowing an attacker to grant unauthorized early mining privileges and extra block rewards to a controlled miner at the start of a new term.

### Finding Description

**Root Cause:**

The vulnerability exists due to two critical validation gaps:

1. **Round hash excludes ExtraBlockProducerOfPreviousRound**: The `GetCheckableRound` method only includes `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge` in the hash computation, explicitly excluding `ExtraBlockProducerOfPreviousRound`. [1](#0-0) 

2. **No validation between header and transaction parameter**: While `ValidateConsensusAfterExecution` compares the Round hash from the block header with the Round hash from state (updated by the transaction), it doesn't validate the `ExtraBlockProducerOfPreviousRound` field specifically because it's excluded from the hash. [2](#0-1) 

**Execution Path:**

When a NextTerm block is produced:
1. `GetConsensusExtraDataForNextTerm` generates the header extra data with the correct `ExtraBlockProducerOfPreviousRound` set to the sender's pubkey [3](#0-2) 

2. `GenerateTransactionListByExtraData` creates the NextTerm transaction using `NextTermInput.Create(round, randomNumber)` [4](#0-3) 

3. A malicious miner modifies the `NextTermInput` to point `ExtraBlockProducerOfPreviousRound` to a different miner (attacker-controlled) before including it in the block

4. `ProcessNextTerm` executes and updates state with the malicious Round data [5](#0-4) 

5. Validation passes because:
   - `RoundTerminateValidationProvider` only checks round/term numbers and InValues [6](#0-5) 
   
   - The hash comparison in `ValidateConsensusAfterExecution` excludes `ExtraBlockProducerOfPreviousRound`

### Impact Explanation

**Direct Mining Privilege Theft:**

The `ExtraBlockProducerOfPreviousRound` field grants special mining privileges at the start of a new term:

1. **Early mining access**: The designated miner can produce tiny blocks before the new round officially starts [7](#0-6) 

2. **Extended block production**: The miner can produce additional tiny blocks beyond normal limits [8](#0-7) 

3. **Increased rewards**: More block production leads to higher `ProducedBlocks` count, which directly impacts mining reward distribution through the Treasury contract [9](#0-8) 

**Affected Parties:**
- Legitimate miner who actually produced the extra block loses mining privileges and rewards
- Attacker-controlled miner gains unauthorized privileges and unearned rewards
- Overall consensus fairness is compromised

**Severity:** High - Direct theft of mining rewards through privilege manipulation with clear financial impact.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a miner in the current round capable of producing the NextTerm block
- Requires ability to modify their node software to craft malicious transactions
- No additional cryptographic material or special permissions needed

**Attack Complexity:**
- Low to Medium - The attacker only needs to:
  1. Run the standard `GenerateConsensusTransactions` method
  2. Modify the returned `NextTermInput.ExtraBlockProducerOfPreviousRound` field before block inclusion
  3. Keep the original header extra data unchanged

**Feasibility:**
- Any miner producing a NextTerm block can execute this attack
- NextTerm blocks occur at every term transition (regular occurrence)
- Detection is difficult as the block header appears valid
- The manipulation only becomes apparent by comparing transaction parameters with header data

**Economic Rationality:**
- Cost: Standard block production cost
- Benefit: Additional mining rewards from extra block production privileges
- The attack can be repeated at every term transition by the attacker

### Recommendation

**Immediate Fix:**

Add validation in `ProcessNextTerm` to ensure the `ExtraBlockProducerOfPreviousRound` in the transaction input matches the transaction sender:

```csharp
private void ProcessNextTerm(NextTermInput input)
{
    var nextRound = input.ToRound();
    var senderPubkey = Context.RecoverPublicKey().ToHex();
    
    // Validate ExtraBlockProducerOfPreviousRound matches the sender
    Assert(nextRound.ExtraBlockProducerOfPreviousRound == senderPubkey,
        "ExtraBlockProducerOfPreviousRound must match the NextTerm transaction sender.");
    
    // Continue with existing logic...
}
```

**Alternative Fix:**

Include `ExtraBlockProducerOfPreviousRound` in the `GetCheckableRound` method to make it part of the Round hash:

```csharp
var checkableRound = new Round
{
    RoundNumber = RoundNumber,
    TermNumber = TermNumber,
    RealTimeMinersInformation = { minersInformation },
    BlockchainAge = BlockchainAge,
    ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound  // Add this field
};
```

**Test Cases:**
1. Verify NextTerm transaction with mismatched `ExtraBlockProducerOfPreviousRound` is rejected
2. Verify legitimate NextTerm with correct sender succeeds
3. Verify mining privileges are correctly granted only to the actual NextTerm block producer

### Proof of Concept

**Initial State:**
- Current term T, round R is active
- Miner Alice is about to produce the NextTerm block to transition to term T+1
- Miner Bob is an attacker-controlled miner in the next term's miner list

**Attack Steps:**

1. Alice calls the consensus contract's `GenerateConsensusTransactions` method, which generates:
   - Header extra data with `ExtraBlockProducerOfPreviousRound = "Alice"`
   - NextTermInput transaction with `ExtraBlockProducerOfPreviousRound = "Alice"`

2. Alice modifies her node to change the NextTermInput before block creation:
   - Header extra data remains: `ExtraBlockProducerOfPreviousRound = "Alice"` (for validation)
   - Transaction modified to: `NextTermInput.ExtraBlockProducerOfPreviousRound = "Bob"`

3. Alice proposes the block with the mismatched data

4. **Expected Result:** Validation should reject the block for inconsistent Round data
   **Actual Result:** 
   - `ValidateConsensusBeforeExecution` passes (validates header only)
   - `NextTerm` transaction executes successfully, setting `ExtraBlockProducerOfPreviousRound = "Bob"` in state
   - `ValidateConsensusAfterExecution` passes (hash excludes `ExtraBlockProducerOfPreviousRound`)

5. **Success Condition:** At the start of term T+1, Bob (not Alice) is able to produce tiny blocks before the round officially starts, gaining unauthorized mining privileges and rewards, while Alice (who legitimately produced the NextTerm block) loses these privileges.

**Notes**

The vulnerability stems from an architectural mismatch: the block header extra data and transaction parameters both contain Round information, but there's no validation ensuring they match. The Round hash mechanism was designed to detect Round tampering, but `ExtraBlockProducerOfPreviousRound` was excluded from the hash, likely because it changes frequently. However, this exclusion creates an exploitable gap for malicious miners during NextTerm transitions.

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
