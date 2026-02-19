### Title
Missing LIB Height Validation in NextTerm Allows Malicious Miner to Corrupt Blockchain Finality

### Summary
The `NextTerm` consensus operation does not validate the `ConfirmedIrreversibleBlockHeight` (LIB) field in its input, allowing a malicious miner to provide arbitrary LIB values when transitioning to a new term. This corrupted LIB height is then persisted to state and propagates to future rounds, enabling manipulation of blockchain finality guarantees.

### Finding Description

The vulnerability exists in the term transition flow of the AEDPoS consensus mechanism:

**Location of LIB Copying**: [1](#0-0) 

The `GenerateFirstRoundOfNextTerm` function copies the LIB height from `currentRound` to the new round without validation. However, this is only the off-chain preparation step.

**Root Cause - Missing Validation**: [2](#0-1) 

When validating `NextTerm` behavior, only `RoundTerminateValidationProvider` is registered, which validates round and term numbers but NOT the LIB height fields.

**Comparison - UpdateValue Has Protection**: [3](#0-2) 

In contrast, `UpdateValue` operations include `LibInformationValidationProvider` which prevents LIB from going backwards.

**LibInformationValidationProvider Logic**: [4](#0-3) 

This validator checks that `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` do not decrease, but it is never applied to `NextTerm` operations.

**NextTermInput Structure**: [5](#0-4) 

The `NextTermInput.ToRound()` method converts the input to a Round object, including the attacker-controlled `ConfirmedIrreversibleBlockHeight` value at line 34.

**Persistence Without Validation**: [6](#0-5) 

The `ProcessNextTerm` function takes the round from `input.ToRound()` and persists it to state via `AddRoundInformation` without any validation of the LIB height.

**Execution Flow**: [7](#0-6) 

All consensus inputs go through `ProcessConsensusInformation` which only performs permission checks via `PreCheck()` but relies on validation providers to check field values.

### Impact Explanation

**Consensus/Cross-Chain Integrity Violation**: The Last Irreversible Block (LIB) height is a critical consensus invariant that determines blockchain finality. Manipulation of this value has severe consequences:

1. **Premature Finality (LIB set too high)**: If a malicious miner sets the LIB height higher than the legitimate value, blocks that are not truly irreversible (have not achieved 2/3+ miner consensus) would be marked as final. This violates Byzantine fault tolerance guarantees and could enable:
   - Acceptance of fraudulent cross-chain transfers
   - Invalid state finalization
   - Chain split scenarios if different nodes have different finality views

2. **Finality Reversion (LIB set too low)**: If the LIB is set lower than the legitimate value, blocks that should be irreversible become subject to reorganization, enabling:
   - Double-spend attacks on transactions that appeared finalized
   - Reversion of cross-chain message commitments
   - Breaking of "once confirmed, always confirmed" guarantee

3. **Propagation Effect**: The corrupted LIB value persists in state and is inherited by subsequent rounds and terms, causing long-term corruption of the finality mechanism until manually corrected.

**Affected Parties**: All network participants relying on blockchain finality, including exchanges, cross-chain bridges, and applications requiring transaction finality guarantees.

### Likelihood Explanation

**Attacker Capabilities Required**:
- Must be a legitimate miner in the current or previous round (verified by `PreCheck`)
- Must be eligible to produce the block that triggers the term transition
- No collusion with other miners required

**Attack Complexity**: LOW
1. Miner calls off-chain view method `GetConsensusExtraDataForNextTerm` to obtain legitimate round data
2. Miner modifies the `ConfirmedIrreversibleBlockHeight` field in the resulting `NextTermInput` to any desired value (higher or lower)
3. Miner submits `NextTerm` transaction with the modified input
4. Validation passes (only checks round/term numbers, not LIB)
5. Corrupted LIB is persisted to state

**Feasibility**: HIGH - The attack requires only parameter manipulation at transaction submission time. No complex timing, no race conditions, no reliance on external state.

**Detection**: Difficult to detect in real-time as the malicious transaction appears valid and will be accepted by all nodes. The corruption would only be noticed when comparing expected vs. actual LIB progression.

**Economic Rationality**: The cost is minimal (one transaction fee), while the potential gain from double-spend or cross-chain manipulation could be substantial.

### Recommendation

**Immediate Fix**: Add `LibInformationValidationProvider` to the validation providers for `NextTerm` behavior in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new RoundTerminateValidationProvider());
    validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS LINE
    break;
```

**Location to modify**: [2](#0-1) 

**Additional Hardening**: Consider also adding the same validation for `NextRound` behavior: [8](#0-7) 

**Invariant Checks**: Enforce that:
1. `ConfirmedIrreversibleBlockHeight` never decreases
2. `ConfirmedIrreversibleBlockHeight` cannot increase by more than the number of blocks in the current term (to prevent unrealistic jumps)
3. `ConfirmedIrreversibleBlockRoundNumber` never decreases

**Test Cases**:
1. Test that `NextTerm` with LIB lower than current round is rejected
2. Test that `NextTerm` with LIB higher than current block height is rejected
3. Test that `NextTerm` with decreasing `ConfirmedIrreversibleBlockRoundNumber` is rejected
4. Verify legitimate `NextTerm` with correctly copied LIB still succeeds

### Proof of Concept

**Initial State**:
- Current round has `ConfirmedIrreversibleBlockHeight = 1000` and `ConfirmedIrreversibleBlockRoundNumber = 50`
- Current block height is 1100
- Attacker is a legitimate miner eligible to produce the term transition block

**Attack Steps**:
1. Attacker calls `GetConsensusExtraDataForNextTerm` (view method) to obtain legitimate `NextTermInput` data
2. Attacker modifies the obtained data:
   - Sets `ConfirmedIrreversibleBlockHeight = 500` (lower than legitimate value), OR
   - Sets `ConfirmedIrreversibleBlockHeight = 2000` (higher than current block height)
3. Attacker submits `NextTerm` transaction with modified input
4. Transaction passes validation (only `RoundTerminateValidationProvider` runs, which doesn't check LIB)
5. `ProcessNextTerm` converts input to Round via `ToRound()` and saves to state via `AddRoundInformation`

**Expected Result**: Transaction should be rejected with "Incorrect lib information" error

**Actual Result**: Transaction succeeds, and the corrupted LIB value (500 or 2000) is now persisted in state as the `ConfirmedIrreversibleBlockHeight` for the new term. This value will be inherited by all subsequent rounds until manually corrected, breaking blockchain finality guarantees.

**Success Condition**: Query `GetCurrentRoundInformation` after the attack - the returned `ConfirmedIrreversibleBlockHeight` will show the attacker's manipulated value instead of the legitimate value of 1000.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L244-245)
```csharp
        newRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        newRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-53)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");

        State.RoundBeforeLatestExecution.Value = GetCurrentRoundInformation(new Empty());

        ByteString randomNumber = null;

        // The only difference.
        switch (input)
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
            case NextTermInput nextTermInput:
                randomNumber = nextTermInput.RandomNumber;
                ProcessNextTerm(nextTermInput);
                break;
            case UpdateValueInput updateValueInput:
                randomNumber = updateValueInput.RandomNumber;
                ProcessUpdateValue(updateValueInput);
                break;
            case TinyBlockInput tinyBlockInput:
                randomNumber = tinyBlockInput.RandomNumber;
                ProcessTinyBlock(tinyBlockInput);
                break;
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
