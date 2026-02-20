# Audit Report

## Title
Missing Validation Allows Negative LIB Height Injection via NextTerm Transaction

## Summary
A malicious miner can permanently corrupt the consensus state by injecting a negative `ConfirmedIrreversibleBlockHeight` value during term transitions. The `NextTerm` transaction validation omits the LIB height validation that protects other consensus behaviors, allowing corrupted values to persist indefinitely.

## Finding Description

The vulnerability exists in the consensus validation logic where different validation providers are applied based on the consensus behavior type. The critical security gap is that `LibInformationValidationProvider` is only applied to `UpdateValue` behavior but not to `NextTerm` behavior.

**Validation Inconsistency:**

For `UpdateValue` behavior, the validation includes `LibInformationValidationProvider` which enforces LIB height monotonicity [1](#0-0) . This provider validates that `ConfirmedIrreversibleBlockHeight` cannot decrease [2](#0-1) .

However, for `NextTerm` behavior, only `RoundTerminateValidationProvider` is added [3](#0-2) . This provider only validates term and round number increments, completely ignoring LIB height fields [4](#0-3) .

**Attack Execution:**

1. A malicious miner crafts a `NextTermInput` with `ConfirmedIrreversibleBlockHeight = -1`. The protobuf definition allows negative int64 values [5](#0-4) .

2. The `NextTerm()` method is publicly callable [6](#0-5)  and invokes validation via `ValidateConsensusBeforeExecution` [7](#0-6) .

3. Authorization only checks if the sender is in the miner list [8](#0-7) , which a legitimate miner satisfies.

4. After passing validation, `ProcessNextTerm()` converts the input via `ToRound()` which preserves all fields including the corrupted `ConfirmedIrreversibleBlockHeight` [9](#0-8) .

5. The corrupted round is stored directly in state [10](#0-9) .

**Propagation Mechanism:**

The corrupted value propagates to all subsequent rounds because `GenerateNextRoundInformation()` unconditionally copies the `ConfirmedIrreversibleBlockHeight` from the current round [11](#0-10) . Similarly, `GenerateFirstRoundOfNewTerm()` copies the value when creating new terms [12](#0-11) .

## Impact Explanation

**Critical Consensus State Corruption:**

A negative `ConfirmedIrreversibleBlockHeight` value breaks the fundamental blockchain invariant that LIB height represents the highest irreversible block. This corruption has severe cascading effects:

1. **Broken Finality Tracking**: The LIB height is used throughout the system to determine which blocks are considered final. A negative value invalidates all finality guarantees.

2. **Persistent State Corruption**: The corrupted value is stored in consensus state and propagates to every subsequent round and term through the copy operations in round generation logic. Once injected, it persists indefinitely without manual intervention.

3. **Cross-Chain Security Failures**: Cross-chain indexing depends on `ConfirmedIrreversibleBlockHeight` to determine which blocks are safe to index. Negative values could cause validation bypasses or complete cross-chain bridge failures.

4. **Protocol Integrity Violation**: This breaks a core consensus invariant that underpins the entire blockchain's security model.

**Severity: CRITICAL** - A single malicious miner can permanently corrupt core consensus state, breaking fundamental blockchain invariants and requiring emergency intervention to recover.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner (one of the network validators)
- Attacker must wait for their turn during a term transition
- Attacker must run modified node software to craft malicious `NextTermInput`

**Execution Complexity: LOW**
- Single transaction during legitimate mining slot
- No race conditions or timing dependencies required
- No need to compromise other miners or governance mechanisms
- Validation deterministically passes due to missing checks
- Direct state manipulation via public contract method

**Feasibility: HIGH**
The `NextTerm` method is public and callable by any authorized miner. The only permission check verifies the sender is in the miner list, which a legitimate miner satisfies. Any miner can execute this attack during their term transition slot with guaranteed success.

**Overall Likelihood: HIGH** - The attack is straightforward to execute for any active miner during term transitions.

## Recommendation

Add `LibInformationValidationProvider` to the validation providers for `NextTerm` behavior, ensuring LIB height monotonicity is enforced consistently across all consensus behaviors.

Modify the validation logic in `AEDPoSContract_Validation.cs`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // Add this line
    break;
```

This ensures that any attempt to inject invalid or decreasing LIB heights during term transitions will be rejected during the validation phase, preventing consensus state corruption.

## Proof of Concept

A proof of concept would require:
1. Set up an AElf test network with multiple miners
2. Modify a miner node to craft a `NextTermInput` with `ConfirmedIrreversibleBlockHeight = -1`
3. Wait for the malicious miner's turn during a term transition
4. Submit the malicious `NextTerm` transaction
5. Verify that the transaction passes validation
6. Confirm that the corrupted LIB height (-1) is stored in consensus state
7. Verify that subsequent rounds propagate the corrupted value

The vulnerability is deterministic and will succeed whenever executed by an authorized miner during their term transition slot.

## Notes

This vulnerability demonstrates a critical inconsistency in the consensus validation framework where security-critical checks (LIB height validation) are applied selectively based on behavior type. While `UpdateValue` transactions correctly enforce LIB height monotonicity, `NextTerm` transactions bypass this check entirely. This creates an exploitable gap where a fundamental consensus invariant can be violated through a specific transaction path. The issue is particularly severe because the corrupted value persists permanently and propagates through all future consensus rounds, requiring emergency intervention to recover.

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

**File:** protobuf/aedpos_contract.proto (L497-498)
```text
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L13-18)
```csharp
    public override Empty NextTerm(NextTermInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L47-54)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval, Timestamp currentBlockTime, Round currentRound)
    {
        var round = GenerateFirstRoundOfNewTerm(miningInterval, currentBlockTime, currentRound.RoundNumber,
            currentRound.TermNumber);
        round.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        round.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        return round;
    }
```
