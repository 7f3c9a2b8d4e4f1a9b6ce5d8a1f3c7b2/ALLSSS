### Title
Late UpdateValue Transaction Can Corrupt Next Round Mining Schedule

### Summary
The `ProcessUpdateValue` method fails to validate that an `UpdateValueInput` transaction belongs to the current round, allowing late submissions from previous rounds to corrupt the mining order calculation for subsequent rounds. This enables miners to manipulate their position in future rounds or falsely appear as having mined in rounds where they did not participate.

### Finding Description

The vulnerability exists in the round update flow where consensus data is applied without proper round validation.

**Root Cause:**

The `UpdateValueInput` message includes a `round_id` field specifically documented to "ensure the values to update will be apply to correct round by comparing round id." [1](#0-0) 

However, `ProcessUpdateValue` never validates this field. The method directly retrieves the current round from storage and applies the update values without checking if they belong to that round: [2](#0-1) 

**Attack Flow:**

1. During normal block production with `UpdateValue` behavior, `ApplyNormalConsensusData` calculates `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` based on the miner's signature: [3](#0-2) 

2. These values are extracted into an `UpdateValueInput` transaction: [4](#0-3) 

3. If the extra block producer executes `NextRound` before the `UpdateValue` transaction is processed, the round advances to Round N+1.

4. When the late `UpdateValue` transaction finally executes, it updates Round N+1 (the current round in storage) instead of Round N, setting the miner's `SupposedOrderOfNextRound` and `FinalOrderOfNextRound` values in the wrong round: [5](#0-4) 

5. When `GenerateNextRoundInformation` is called to create Round N+2, it identifies miners who mined in Round N+1 by checking `SupposedOrderOfNextRound != 0`: [6](#0-5) 

6. The attacker's miner is incorrectly included as having mined in Round N+1, and their `FinalOrderOfNextRound` value determines their mining position in Round N+2: [7](#0-6) 

**Why Existing Protections Fail:**

- The `UpdateValueValidationProvider` only validates that consensus information is properly filled and that previous in values are correct, but does not check round_id: [8](#0-7) 

- The `PreCheck` method only verifies the miner is in the current or previous round's miner list, but does not prevent applying outdated consensus data: [9](#0-8) 

- `EnsureTransactionOnlyExecutedOnceInOneBlock` prevents multiple consensus transactions per block but does not prevent stale transactions from previous rounds: [10](#0-9) 

### Impact Explanation

**Consensus Schedule Manipulation:**
An attacker can manipulate the mining schedule by injecting false mining participation records into rounds where they did not actually mine. This directly violates the consensus invariant requiring "correct round transitions and miner schedule integrity."

**Specific Harms:**
1. **False Mining Records**: Miners can appear to have mined in rounds where they didn't participate, affecting reward calculations and reputation
2. **Order Manipulation**: Attackers can influence their mining position in future rounds, potentially securing more favorable time slots
3. **Schedule Disruption**: Legitimate miners' expected positions can be displaced by the corrupted order calculations
4. **Compounding Effect**: Repeated exploitation across multiple rounds can lead to sustained manipulation of the mining schedule

**Affected Parties:**
- All honest miners whose mining schedules are disrupted
- The consensus protocol's fairness and integrity
- Block production predictability and network stability

### Likelihood Explanation

**Attack Feasibility:**
The vulnerability is highly exploitable due to natural timing conditions in blockchain systems:

1. **Entry Point**: Any authorized miner can trigger this via the public `UpdateValue` method: [11](#0-10) 

2. **Timing Window**: The race condition occurs naturally when:
   - A miner produces a block near the end of a round
   - Network latency delays the `UpdateValue` transaction inclusion
   - The extra block producer's `NextRound` block is included first
   - The delayed `UpdateValue` transaction executes in the next round

3. **Attacker Capabilities**: Only requires being an authorized miner with ability to produce blocks - no special privileges needed beyond normal mining participation

4. **Detection Difficulty**: The transaction appears valid (passes all existing checks) and executes successfully, making detection challenging

5. **Intentional Exploitation**: While the race can occur naturally, a malicious miner could deliberately:
   - Delay broadcasting their `UpdateValue` transaction
   - Wait for round transition
   - Submit the transaction in the next round to manipulate order

**Probability**: MEDIUM-HIGH - The conditions occur naturally in distributed systems and can be deliberately engineered by malicious miners.

### Recommendation

**Immediate Fix:**
Add round validation in `ProcessUpdateValue` before applying any updates:

```csharp
private void ProcessUpdateValue(UpdateValueInput updateValueInput)
{
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // ADD THIS VALIDATION:
    Assert(updateValueInput.RoundId == currentRound.RoundId, 
        "UpdateValue transaction round_id mismatch with current round.");
    
    var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
    // ... rest of implementation
}
```

**Location to modify:** [12](#0-11) 

**Additional Safeguards:**
1. Add similar validation in `ProcessTinyBlock` for consistency
2. Consider adding a tolerance window (e.g., allow updates from previous round only if current round just started)
3. Implement transaction pool-level validation to reject stale consensus transactions before inclusion

**Test Cases:**
1. Verify `UpdateValue` with mismatched round_id is rejected
2. Test that legitimate concurrent round transitions handle updates correctly
3. Verify that attempting late submission from Round N into Round N+1 fails
4. Ensure the fix doesn't break legitimate consensus flows

### Proof of Concept

**Initial State:**
- Round N in progress with miners [M1, M2, M3, M4, M5]
- Miner M1 has time slot at end of Round N
- M5 is designated extra block producer for Round N

**Attack Sequence:**

1. **Block Height 100** (Round N, near end):
   - M1 produces block with `UpdateValue` behavior
   - `ApplyNormalConsensusData` calculates M1's order for Round N+1 (e.g., order = 3)
   - `UpdateValueInput` transaction TX1 is generated with `round_id = N`
   - TX1 is broadcast but delayed in network/pool

2. **Block Height 101** (Round N finalization):
   - M5 produces block with `NextRound` behavior
   - `GenerateNextRoundInformation` creates Round N+1 using miners who actually mined in Round N
   - Round N+1 becomes current round in storage
   - M1 is not in Round N+1's mined miners list (because TX1 hasn't executed yet)

3. **Block Height 102** (Round N+1):
   - TX1 (M1's late UpdateValue for Round N) executes
   - `ProcessUpdateValue` retrieves currentRound = Round N+1 (wrong!)
   - Sets `Round N+1.RealTimeMinersInformation[M1].SupposedOrderOfNextRound = 3`
   - Sets `Round N+1.RealTimeMinersInformation[M1].FinalOrderOfNextRound = 3`
   - Updates Round N+1 in storage with corrupted data

4. **Block Height 110** (Round N+1 finalization):
   - Extra block producer produces `NextRound` block
   - `GenerateNextRoundInformation` calls `GetMinedMiners()` on Round N+1
   - M1 is included in result because `SupposedOrderOfNextRound = 3 != 0`
   - M1's `FinalOrderOfNextRound = 3` assigns them order 3 in Round N+2
   - Round N+2 created with M1 in position 3

**Expected Result:**
TX1 should be rejected at step 3 because round_id (N) doesn't match current round (N+1).

**Actual Result:**
TX1 executes successfully, corrupting Round N+1 and causing M1 to appear in Round N+2's mining schedule despite not mining in Round N+1.

**Success Criteria:**
The attack succeeds if M1 appears in the mined miners list for Round N+1 and is assigned a position in Round N+2's mining schedule.

### Citations

**File:** protobuf/aedpos_contract.proto (L199-200)
```text
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-248)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-44)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

        // Check the existence of conflicts about OrderOfNextRound.
        // If so, modify others'.
        var conflicts = RealTimeMinersInformation.Values
            .Where(i => i.FinalOrderOfNextRound == supposedOrderOfNextRound).ToList();

        foreach (var orderConflictedMiner in conflicts)
            // Multiple conflicts is unlikely.

            for (var i = supposedOrderOfNextRound + 1; i < minersCount * 2; i++)
            {
                var maybeNewOrder = i > minersCount ? i % minersCount : i;
                if (RealTimeMinersInformation.Values.All(m => m.FinalOrderOfNextRound != maybeNewOrder))
                {
                    RealTimeMinersInformation[orderConflictedMiner.Pubkey].FinalOrderOfNextRound =
                        maybeNewOrder;
                    break;
                }
            }

        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ExtractInformationToUpdateConsensus.cs (L35-43)
```csharp
        return new UpdateValueInput
        {
            OutValue = minerInRound.OutValue,
            Signature = minerInRound.Signature,
            PreviousInValue = minerInRound.PreviousInValue ?? Hash.Empty,
            RoundId = RoundIdForValidation,
            ProducedBlocks = minerInRound.ProducedBlocks,
            ActualMiningTime = minerInRound.ActualMiningTimes.Last(),
            SupposedOrderOfNextRound = minerInRound.SupposedOrderOfNextRound,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L25-36)
```csharp
        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-19)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L134-138)
```csharp
    private void EnsureTransactionOnlyExecutedOnceInOneBlock()
    {
        Assert(State.LatestExecutedHeight.Value != Context.CurrentHeight, "Cannot execute this tx.");
        State.LatestExecutedHeight.Value = Context.CurrentHeight;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```
