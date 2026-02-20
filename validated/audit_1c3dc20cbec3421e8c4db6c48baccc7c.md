# Audit Report

## Title
Consensus Corruption via Unvalidated Round Fields in NextRound Transition

## Summary
The AEDPoS consensus contract contains a critical validation gap allowing malicious block producers to corrupt consensus state by injecting arbitrary values into six unvalidated Round fields during NextRound transitions. This enables consensus-level DoS, unauthorized mining privileges, and disruption of the random number generation mechanism.

## Finding Description

The vulnerability exists due to a fundamental mismatch between what fields are validated and what fields are written to consensus state during NextRound transitions.

**Root Cause - No Input Validation:**

The `NextRoundInput.Create()` method copies all Round fields without validation [1](#0-0) , and `ToRound()` performs the inverse conversion with no validation [2](#0-1) .

**Validation Gap - Before Execution:**

For NextRound behavior, the validation system only applies `NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider` [3](#0-2) . The `RoundTerminateValidationProvider` validates only round number increment and null InValues [4](#0-3) .

Critically, `LibInformationValidationProvider` does NOT run for NextRound behavior [5](#0-4) , leaving `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` completely unvalidated.

**Validation Gap - After Execution:**

The after-execution validation compares Round hashes between the block header and the state [6](#0-5) . However, the `GetCheckableRound()` method only includes `RoundNumber`, `TermNumber`, `RealTimeMinersInformation`, and `BlockchainAge` in the hash [7](#0-6) .

The protobuf definition confirms six critical fields exist in Round but are excluded from validation [8](#0-7) .

**Execution Path:**

When NextRound is called [9](#0-8) , it processes the input via `ProcessNextRound()` which calls `input.ToRound()` [10](#0-9)  and writes the Round to state via `AddRoundInformation()` [11](#0-10) .

**Attack Execution:**

A malicious miner can:
1. Generate legitimate consensus extra data for the block header with correct checkable fields
2. Create a NextRoundInput transaction with the same checkable fields but manipulated excluded fields (e.g., setting `ExtraBlockProducerOfPreviousRound` to their own pubkey, or `ConfirmedIrreversibleBlockHeight` to an artificially high value)
3. Include this transaction in their block
4. Before-execution validation checks only the header Round's checkable fields - **passes**
5. Transaction executes, writing the manipulated Round with corrupted excluded fields to state
6. After-execution validation compares hashes of checkable fields only - **passes** because excluded fields aren't included in the hash

## Impact Explanation

**1. Consensus-Level DoS via LIB Manipulation:**

`ConfirmedIrreversibleBlockHeight` is used in `GetMaximumBlocksCount()` to evaluate blockchain mining status [12](#0-11) . When this field is set artificially high, the evaluator detects Severe status, reducing `MaximumBlocksCount` to 1 and firing `IrreversibleBlockHeightUnacceptable` events [13](#0-12) , effectively halting normal block production.

**2. Unauthorized Mining Privileges:**

`ExtraBlockProducerOfPreviousRound` determines which miner can produce additional tiny blocks before the new round starts and during their time slot [14](#0-13)  and [15](#0-14) . A malicious miner can set this to their own pubkey, granting themselves unauthorized extra block production rights beyond their allocated time slot.

**3. Secret Sharing Disruption:**

`IsMinerListJustChanged` controls whether the `SecretSharingInformation` event fires when adding round information [16](#0-15) . Incorrect values prevent this event from firing, breaking the random number generation mechanism that depends on secret sharing between miners.

**Severity:** HIGH - Direct consensus state corruption enabling DoS, unauthorized mining privileges, and broken randomness generation.

## Likelihood Explanation

**Attacker Capabilities:** Any current block producer can execute this attack. Block producers control both block header construction and transaction inclusion within the consensus protocol.

**Feasibility:** HIGH
- No special permissions beyond being a current miner are required
- Attack operates within normal consensus protocol mechanics
- No cryptographic binding exists between header Round and transaction Round for the excluded fields
- The validation system only checks checkable fields in both before-execution and after-execution phases
- Undetectable by current validation logic until effects manifest in consensus behavior

The attack is reproducible and executable under normal AElf runtime conditions.

## Recommendation

**Immediate Fix:**

1. **Add validation for excluded fields in NextRound before-execution validation:**
   - Extend `RoundTerminateValidationProvider` or add a dedicated validator to check that excluded fields in the header Round match expected values from current state
   - Specifically validate `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` do not decrease

2. **Include all consensus-critical fields in `GetCheckableRound()`:**
   - Add `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, `ExtraBlockProducerOfPreviousRound`, `IsMinerListJustChanged`, `MainChainMinersRoundNumber`, and `RoundIdForValidation` to the checkable round for hash comparison

3. **Add input validation in `ToRound()` method:**
   - Validate that excluded field values are within acceptable ranges and consistent with current consensus state before conversion

**Long-term Solution:**
Consider redesigning the validation architecture to ensure all fields written to consensus state are explicitly validated, with no fields excluded from integrity checks.

## Proof of Concept

The vulnerability can be demonstrated by:
1. A test miner creating a block during NextRound transition
2. Setting `ConfirmedIrreversibleBlockHeight` to an artificially high value (e.g., current height + 1000)
3. Observing that the manipulated value persists in state after both validation phases pass
4. Verifying that subsequent calls to `GetMaximumBlocksCount()` return 1 (Severe status) and fire `IrreversibleBlockHeightUnacceptable` events

The POC would require integration testing with the full AElf consensus mechanism to demonstrate the complete attack flow, as it involves block production and consensus state transitions.

## Notes

This vulnerability represents a fundamental flaw in the consensus validation architecture where critical state fields are excluded from validation checks. The separation between "checkable" and "non-checkable" fields creates an exploitable gap that allows miners to corrupt consensus state while passing all validation checks. The impact is severe as it directly affects consensus integrity, block production, and the random number generation mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextRoundInput.cs (L7-23)
```csharp
    public static NextRoundInput Create(Round round, ByteString randomNumber)
    {
        return new NextRoundInput
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-101)
```csharp
            if (headerInformation.Round.GetHash(isContainPreviousInValue) !=
                currentRound.GetHash(isContainPreviousInValue))
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L24-28)
```csharp
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L104-115)
```csharp
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```
