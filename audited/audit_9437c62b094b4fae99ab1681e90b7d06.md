### Title
Miner Set Mismatch in RecoverFromUpdateValue Causes Consensus Validation Failure During Term Transitions

### Summary
The `RecoverFromUpdateValue` method in `Round_Recover.cs` iterates through all miners in `ProvidedRound` and unconditionally accesses them in `BaseRound` without checking for key existence. During term transitions when the miner list changes, this causes a `KeyNotFoundException`, leading to consensus validation failures and potential network disruption.

### Finding Description

**Root Cause Location:** [1](#0-0) 

The `RecoverFromUpdateValue` method contains a critical unsafe dictionary access pattern. While lines 10-12 check if the sender pubkey exists in both rounds, the subsequent loop (lines 22-30) iterates through ALL miners in `providedRound.RealTimeMinersInformation` and attempts to update their information in `BaseRound.RealTimeMinersInformation` without verifying that each miner key exists in the BaseRound.

**Validation Call Site:** [2](#0-1) 

This method is called during block validation BEFORE any validation providers execute, meaning an exception here bypasses all normal validation error handling.

**Miner Set Construction:** [3](#0-2) 

The `GetUpdateValueRound` method creates a `ProvidedRound` containing ALL miners from the current round state at block production time. This snapshot includes miners who may no longer exist in the BaseRound when the block is validated.

**Term Transition Path:** [4](#0-3) 

During `ProcessNextTerm`, the miner list is updated at lines 179-190, which changes the `RealTimeMinersInformation` keys in the stored round state, creating the mismatch condition.

**Why Existing Protections Fail:**
The early return check at lines 10-12 in `RecoverFromUpdateValue` only validates that the sender exists in both rounds, but does not prevent the subsequent loop from accessing miners who were removed during term transitions. No validation provider checks miner set consistency between BaseRound and ProvidedRound for UpdateValue behavior. [5](#0-4) 

### Impact Explanation

**Consensus Disruption:**
During term transitions, blocks produced by honest miners using the pre-transition miner list will fail validation with a `KeyNotFoundException` exception rather than a clean validation failure. This breaks the consensus validation flow and can cause network splits.

**Affected Parties:**
- Miners producing blocks during term transition windows experience block rejection
- Network nodes attempting to validate these blocks crash or reject them
- The blockchain may stall if multiple blocks encounter this issue during critical transition periods

**Severity Justification:**
This is a HIGH severity issue because:
1. It directly impacts consensus integrity during term transitions
2. Causes operational DoS of the validation pipeline
3. Can be triggered naturally through network latency during legitimate term transitions
4. Could be exploited by malicious miners to intentionally disrupt consensus by timing block production

### Likelihood Explanation

**Attack Vector:**
Natural occurrence: During every term transition when the miner list changes, there is a race window where blocks created with the old miner list are being validated against the new miner list.

**Feasibility:**
- **Entry Point**: Reachable through standard block validation via `ValidateBeforeExecution`
- **Preconditions**: Only requires a term transition to occur (happens regularly in AEDPoS)
- **Attacker Capabilities**: No special privileges needed; network latency alone can trigger this
- **Complexity**: Low - occurs naturally when blocks are delayed during term transitions

**Exploitation Scenarios:**
1. **Natural Race Condition**: Miner A produces block at end of Term N. Before block propagates, NextTerm is called. Block arrives for validation with Term N miners against Term N+1 state.
2. **Intentional Timing Attack**: Malicious miner deliberately delays block submission to arrive during term transition window, causing validation failures for other nodes.

**Detection Constraints:**
The exception would be visible in node logs but could be mistaken for network issues rather than a code vulnerability.

### Recommendation

**Immediate Fix:**
Add `ContainsKey` validation in the recovery loop:

```csharp
foreach (var information in providedRound.RealTimeMinersInformation)
{
    if (!RealTimeMinersInformation.ContainsKey(information.Key))
        continue; // Skip miners not in current round
    
    RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
        information.Value.SupposedOrderOfNextRound;
    RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
        information.Value.FinalOrderOfNextRound;
    RealTimeMinersInformation[information.Key].PreviousInValue =
        information.Value.PreviousInValue;
}
```

**Additional Hardening:**
Add miner set consistency validation for UpdateValue behavior: [6](#0-5) 

Create a new validation provider that checks if ProvidedRound contains miners not in BaseRound and fails gracefully with an appropriate error message rather than throwing an exception.

**Regression Testing:**
Add test cases covering:
1. Block validation during term transition with partial miner overlap
2. Block validation after complete miner list replacement
3. Concurrent NextTerm and UpdateValue processing

### Proof of Concept

**Initial State:**
- Current term: Term 1, Round 10
- Miner list: [Alice, Bob, Charlie, David, Eve]
- All miners are actively producing blocks

**Exploitation Steps:**

1. **Block Creation (Height N)**: 
   - Alice produces a block with UpdateValue behavior
   - Calls `GetUpdateValueRound` which creates ProvidedRound with miners [Alice, Bob, Charlie, David, Eve]
   - Block is broadcast but experiences network delay

2. **Term Transition (Height N)**: 
   - Before Alice's block is validated, Bob triggers NextTerm
   - New miner list becomes [Alice, Bob, Charlie, Frank, Grace] (David and Eve replaced)
   - State.Rounds is updated with Term 2, Round 1

3. **Block Validation (Height N+1)**:
   - Alice's block arrives for validation
   - `TryToGetCurrentRoundInformation` fetches BaseRound with miners [Alice, Bob, Charlie, Frank, Grace]
   - ProvidedRound from block header contains miners [Alice, Bob, Charlie, David, Eve]
   - `RecoverFromUpdateValue` is called:
     - Lines 10-12: Check passes (Alice exists in both rounds)
     - Lines 22-30: Loop processes all miners in ProvidedRound
     - When processing "David": `RealTimeMinersInformation["David"]` throws `KeyNotFoundException`

**Expected Result:**
Block should either be validated successfully or rejected with a clean validation error message.

**Actual Result:**
Consensus validation crashes with `KeyNotFoundException`, causing validation pipeline failure and potential node crash or block rejection without proper error handling.

**Success Condition:**
The vulnerability is triggered when the validation exception occurs, demonstrating that BaseRound and ProvidedRound can have mismatched miner sets leading to consensus validation failure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L22-30)
```csharp
        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-47)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-92)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Simplify.cs (L35-53)
```csharp
        foreach (var information in RealTimeMinersInformation)
            if (information.Key == pubkey)
            {
                round.RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound =
                    minerInRound.SupposedOrderOfNextRound;
                round.RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = minerInRound.FinalOrderOfNextRound;
            }
            else
            {
                round.RealTimeMinersInformation.Add(information.Key, new MinerInRound
                {
                    Pubkey = information.Value.Pubkey,
                    SupposedOrderOfNextRound = information.Value.SupposedOrderOfNextRound,
                    FinalOrderOfNextRound = information.Value.FinalOrderOfNextRound,
                    Order = information.Value.Order,
                    IsExtraBlockProducer = information.Value.IsExtraBlockProducer,
                    PreviousInValue = information.Value.PreviousInValue
                });
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
