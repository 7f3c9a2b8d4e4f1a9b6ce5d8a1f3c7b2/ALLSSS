# Audit Report

## Title
NextTerm Consensus Transaction Bypasses Critical Field Validation Allowing Consensus State Corruption

## Summary
The `NextTerm` consensus behavior lacks validation for 6 critical Round fields. A malicious miner can craft a `NextTermInput` transaction with manipulated values for `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, `IsMinerListJustChanged`, and other unvalidated fields while maintaining valid consensus header data, allowing corrupted consensus state to persist and propagate to all future rounds.

## Finding Description

The vulnerability exists due to asymmetric validation in the consensus transaction pipeline:

**Asymmetric Pre-Execution Validation:**

For `NextTerm` behavior, `ValidateBeforeExecution` only adds `RoundTerminateValidationProvider`: [1](#0-0) 

In contrast, `UpdateValue` behavior includes `LibInformationValidationProvider`: [2](#0-1) 

The `LibInformationValidationProvider` validates that LIB-related fields cannot decrease: [3](#0-2) 

**Incomplete Post-Execution Hash Validation:**

The `GetCheckableRound` method only includes 4 of 10 fields for hash comparison: [4](#0-3) 

The full Round protobuf message contains 10 fields: [5](#0-4) 

**Vulnerable Execution Path:**

When executing `NextTerm`, the `NextTermInput` is converted to a full Round object including all unvalidated fields: [6](#0-5) 

This Round is stored directly to state via `AddRoundInformation`: [7](#0-6) 

The post-execution validation compares only the 4 checkable fields: [8](#0-7) 

**Attack Execution:**

A malicious miner can generate valid consensus header data: [9](#0-8) 

Then manually construct a `NextTermInput` transaction with the same 4 checkable fields (RoundNumber, TermNumber, RealTimeMinersInformation, BlockchainAge) but manipulated values for the 6 excluded fields (MainChainMinersRoundNumber, ExtraBlockProducerOfPreviousRound, ConfirmedIrreversibleBlockHeight, ConfirmedIrreversibleBlockRoundNumber, IsMinerListJustChanged, RoundIdForValidation). The transaction passes all validation despite containing corrupted state.

## Impact Explanation

**Critical Consensus Invariant Violations:**

1. **LIB State Corruption Propagation**: The corrupted `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` values are copied to all subsequent term transitions: [10](#0-9) 

This corrupted baseline allows miners to provide artificially low LIB values in future `UpdateValue` operations without triggering the `LibInformationValidationProvider` checks, gradually eroding finality guarantees across the entire chain.

2. **Secret Sharing Mechanism Disruption**: The `IsMinerListJustChanged` field controls whether critical `SecretSharingInformation` events are fired: [11](#0-10) 

Manipulating this boolean to false can skip mandatory secret sharing events or setting it to true can cause them to fire incorrectly, breaking the random number generation mechanism used for miner selection and consensus operations.

3. **Permanent Protocol-Wide Impact**: Once corrupted, these values persist indefinitely through the round generation chain, affecting all future consensus decisions, block validation, and finality calculations.

**Severity: HIGH** - Violates core consensus invariants including correct round transitions, miner schedule integrity, and LIB height monotonicity rules with permanent protocol-wide damage.

## Likelihood Explanation

**Attacker Profile**: Any active miner with block production rights during term transition periods.

**Attack Complexity**: Low
- Generate valid header using standard `GetConsensusExtraData` mechanism
- Construct `NextTermInput` with 4 matching checkable fields plus manipulated excluded fields
- No cryptographic breaking or unusual privileges required beyond normal miner status
- Deterministic success once executed

**Detection Difficulty**: High - The block appears valid to all standard validation checks since the header data is legitimate. The corrupted state only manifests through protocol behavior degradation over time.

**Feasibility**: MEDIUM-HIGH
- Requires miner status (achievable through election process)
- Must coincide with term transition (periodic and predictable events)
- No economic cost beyond normal block production
- Attack succeeds with 100% probability once preconditions are met

## Recommendation

Add `LibInformationValidationProvider` to the `NextTerm` validation chain to ensure LIB fields cannot decrease:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add LIB validation
    break;
```

Additionally, expand `GetCheckableRound` to include all critical consensus fields in the hash comparison, particularly `ConfirmedIrreversibleBlockHeight`, `ConfirmedIrreversibleBlockRoundNumber`, and `IsMinerListJustChanged`.

## Proof of Concept

A malicious miner during term transition can:
1. Call `GetConsensusExtraDataForNextTerm` to obtain legitimate header data with correct LIB values
2. Craft a `NextTermInput` with the same RoundNumber, TermNumber, RealTimeMinersInformation, and BlockchainAge
3. Set `ConfirmedIrreversibleBlockHeight` to 0 and `IsMinerListJustChanged` to false
4. Submit this transaction in their block
5. Pre-execution validation passes (only checks round/term number increment)
6. Transaction executes, storing corrupted Round to state
7. Post-execution validation passes (hash only compares 4 fields)
8. Subsequent rounds inherit the corrupted LIB baseline, and secret sharing events are skipped

**Notes**

The vulnerability stems from the design assumption that consensus transactions are always generated via `GenerateConsensusTransactions`. However, since `NextTerm` is a public method accepting `NextTermInput` parameters, and validation only compares a subset of fields between header and state, a miner can exploit this gap to inject corrupted consensus state that persists indefinitely.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-21)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L100-113)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
```
