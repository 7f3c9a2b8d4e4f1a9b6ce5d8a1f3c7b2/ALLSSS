# Audit Report

## Title
Consensus Corruption via Unvalidated Round Fields in NextRound Transition

## Summary
Critical consensus fields in the `Round` structure can be manipulated during NextRound transitions due to incomplete validation. A malicious block producer can inject arbitrary values for `ConfirmedIrreversibleBlockHeight`, `ExtraBlockProducerOfPreviousRound`, `MainChainMinersRoundNumber`, `IsMinerListJustChanged`, and `RoundIdForValidation` that bypass both before-execution and after-execution validation checks, enabling consensus state corruption with severe impact on block production, finality tracking, and secret sharing.

## Finding Description

The vulnerability stems from a fundamental architectural gap where consensus validation operates on block header extra data independently from transaction input validation, and the hash-based integrity check excludes 6 of 10 critical Round fields.

**Root Cause - Unvalidated Field Copying:**

The `NextRoundInput.ToRound()` method performs direct field copying without any validation of the excluded fields. [1](#0-0)  This conversion creates a Round object with all 10 fields, including those that will not be validated.

**Validation Gap - Before Execution:**

For NextRound behavior, the validation only applies `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`. [2](#0-1)  Critically, `LibInformationValidationProvider` is NOT applied to NextRound (only to UpdateValue), leaving `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` completely unvalidated. [3](#0-2) 

The `RoundTerminateValidationProvider` only validates that the round number increments by 1 and that InValues are null. [4](#0-3)  It performs no validation of the excluded fields.

**Validation Gap - After Execution:**

The after-execution validation compares Round hashes to verify state consistency. [5](#0-4)  However, the `GetCheckableRound()` method used for hash calculation only includes 4 fields: `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge`. [6](#0-5) 

The Round protobuf defines 10 fields total. [7](#0-6)  This means 6 fields are completely excluded from validation: `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, `ExtraBlockProducerOfPreviousRound`, `IsMinerListJustChanged`, `RoundIdForValidation`, and `MainChainMinersRoundNumber`.

**Execution Path:**

When `NextRound` is called, `ProcessConsensusInformation` invokes `ProcessNextRound()` which immediately calls `input.ToRound()` to convert the input. [8](#0-7)  The resulting Round object is then written to state via `AddRoundInformation()` without any validation of the excluded fields. [9](#0-8) 

**Attack Scenario:**

A malicious miner controlling block production can:
1. Generate or obtain legitimate consensus extra data with correct `RoundNumber` (N+1), `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge`
2. Craft a `NextRoundInput` transaction with the same validated fields but manipulated values for the excluded fields
3. Include this transaction in their block alongside the legitimate extra data in the block header
4. Before-execution validation checks only the extra data against current state - passes because extra data is legitimate
5. Transaction executes, writing the manipulated Round (including malicious excluded field values) to state
6. After-execution validation compares extra data hash against state hash using `GetHash()` - passes because both hashes only include the 4 validated fields, ignoring the manipulated excluded fields

## Impact Explanation

**CRITICAL Severity - Multi-Vector Consensus Corruption:**

**1. LIB Manipulation and Denial of Service:**
The `ConfirmedIrreversibleBlockHeight` field drives blockchain health evaluation in `GetMaximumBlocksCount()`. [10](#0-9)  When this field is manipulated to an artificially low value (or the round number is manipulated relative to it), the blockchain enters Abnormal or Severe status. [11](#0-10)  In Severe status, the system reduces maximum block production to 1 block per miner and fires `IrreversibleBlockHeightUnacceptable` events, [12](#0-11)  effectively causing a denial-of-service condition where normal block production is severely throttled.

**2. Unauthorized Mining Privileges:**
The `ExtraBlockProducerOfPreviousRound` field determines which miner can produce extra tiny blocks. [13](#0-12)  A malicious miner can set this to their own public key, granting themselves additional block production rights during the extra block time slot that should belong to the legitimate extra block producer. [14](#0-13)  This violates mining fairness and allows the attacker to produce more blocks than entitled.

**3. Secret Sharing Disruption:**
The `IsMinerListJustChanged` flag controls whether the `SecretSharingInformation` event fires during round transitions. [15](#0-14)  By setting this flag to `true`, an attacker skips secret sharing, disrupting the cryptographic random number generation mechanism essential for consensus security. This undermines the randomness and unpredictability guarantees of the AEDPoS consensus protocol.

**4. Cross-Chain State Corruption:**
For side chains, `MainChainMinersRoundNumber` tracks synchronization with the main chain. Manipulation of this field can corrupt cross-chain consensus validation and miner list update logic, potentially enabling attacks on side chain security and integrity.

The cumulative impact is severe and multi-faceted consensus corruption affecting finality guarantees, mining fairness, cryptographic security, and cross-chain integrity.

## Likelihood Explanation

**HIGH Likelihood:**

**Attacker Profile:** Any current block producer (miner) in the active consensus participant set can execute this attack. The only requirement is being an active miner, which is the normal operational state for consensus participants. No special privileges, key compromise, or social engineering is required.

**Attack Complexity:** LOW - The attack only requires:
1. Being selected to produce a block (normal miner operation)
2. Calling standard consensus API methods to obtain the current round information
3. Manually constructing a `NextRoundInput` transaction with manipulated excluded fields
4. Including this transaction in the block being produced

**Preconditions:** The attacker must be an active miner in the current or previous round, which is verified by the `PreCheck()` method. [16](#0-15)  This is not a privilege escalation scenario but rather exploitation by an authorized participant.

**Detection:** NONE - The current validation architecture has no mechanism to detect this manipulation. The malicious values are written to consensus state and will affect all subsequent consensus operations. There are no alerts, events, or checks that would flag the discrepancy between extra data and transaction input for excluded fields. The corruption only becomes apparent when it manifests as observable consensus failures (DoS, unfair mining, broken secret sharing).

**Reproducibility:** This vulnerability is deterministically reproducible on any AElf chain using AEDPoS consensus. Whenever a NextRound transition occurs and the block producer is malicious, the attack can be executed with 100% success rate given the validation gaps.

## Recommendation

Implement comprehensive validation of all Round fields during NextRound transitions:

1. **Add LibInformationValidationProvider to NextRound validation** - Apply the same LIB validation used for UpdateValue to NextRound behavior to validate `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber`.

2. **Expand GetCheckableRound() to include all critical fields** - Include all 10 Round fields in the hash calculation, not just 4. Alternatively, exclude only truly non-critical fields (like `ActualMiningTimes` which are temporal and miner-specific).

3. **Add explicit field validation in ProcessNextRound** - Before calling `AddRoundInformation()`, validate that:
   - `ConfirmedIrreversibleBlockHeight` >= current LIB height (no regression)
   - `ExtraBlockProducerOfPreviousRound` matches the actual extra block producer from previous round
   - `IsMinerListJustChanged` correctly reflects whether the miner set changed
   - `MainChainMinersRoundNumber` (for side chains) is properly synchronized

4. **Cross-validate transaction input against extra data** - Add validation that ensures the NextRoundInput transaction parameters match the Round object in the consensus extra data for all critical fields.

Example fix for GetCheckableRound():
```csharp
private byte[] GetCheckableRound(bool isContainPreviousInValue = true)
{
    // ... existing miner information cleaning ...
    
    var checkableRound = new Round
    {
        RoundNumber = RoundNumber,
        TermNumber = TermNumber,
        RealTimeMinersInformation = { minersInformation },
        BlockchainAge = BlockchainAge,
        // ADD THESE CRITICAL FIELDS:
        ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight,
        ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber,
        ExtraBlockProducerOfPreviousRound = ExtraBlockProducerOfPreviousRound,
        IsMinerListJustChanged = IsMinerListJustChanged,
        RoundIdForValidation = RoundIdForValidation,
        MainChainMinersRoundNumber = MainChainMinersRoundNumber
    };
    return checkableRound.ToByteArray();
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Deploy an AEDPoS consensus contract in a test environment with a malicious miner
2. When the malicious miner's turn arrives to produce a block that triggers NextRound:
   - Generate legitimate consensus extra data via `GetConsensusExtraData`
   - Manually construct a `NextRoundInput` with:
     - Same `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, `BlockchainAge` as extra data
     - Manipulated `ConfirmedIrreversibleBlockHeight` set to extremely low value (e.g., 1)
     - Manipulated `ExtraBlockProducerOfPreviousRound` set to attacker's pubkey
     - Manipulated `IsMinerListJustChanged` set to `true`
   - Include both the legitimate extra data in block header and malicious transaction in block body
3. Observe that:
   - Before-execution validation passes (validates extra data only)
   - Transaction executes successfully (no input validation)
   - After-execution validation passes (hash excludes manipulated fields)
   - Consensus state is now corrupted with malicious values
4. Observe impact:
   - `GetMaximumBlocksCount()` returns 1 (DoS condition)
   - Attacker can produce extra tiny blocks (unauthorized privileges)
   - `SecretSharingInformation` event is not fired (security compromise)

The test would verify that a NextRoundInput transaction with manipulated excluded fields successfully updates consensus state without triggering any validation failures.

## Notes

This vulnerability represents a fundamental architectural flaw in the separation between consensus extra data validation and transaction input processing. The validation system was designed to validate the extra data independently, assuming the transaction would match it. However, there is no enforcement mechanism to ensure this correspondence, and the hash-based after-execution check excludes the majority of Round fields. This creates an exploitable gap where a malicious miner can inject arbitrary values into consensus-critical fields that directly control block production rates, mining privileges, cryptographic security mechanisms, and cross-chain synchronization. The impact is severe because these fields are not merely informational but actively control consensus behavior in subsequent rounds.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L25-40)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L99-102)
```csharp
            var isContainPreviousInValue = !currentRound.IsMinerListJustChanged;
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
            {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-111)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-156)
```csharp
        AddRoundInformation(nextRound);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-39)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L119-129)
```csharp
        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```
