### Title
Consensus Integrity Bypass via Duplicate Mining Order Validation Failure

### Summary
The `NextRoundMiningOrderValidationProvider` uses `Distinct()` on entire `MinerInRound` objects instead of validating distinct `FinalOrderOfNextRound` values. This allows a malicious block producer to craft a NextRound with duplicate mining orders that passes validation, corrupting the consensus schedule and causing multiple miners to compete for the same time slot while leaving other slots empty.

### Finding Description

The vulnerability exists in the validation logic that checks mining order uniqueness when a miner proposes a NextRound transition. [1](#0-0) 

**Root Cause**: The code applies `Distinct()` to a collection of `MinerInRound` objects. Since `MinerInRound` is a protobuf-generated class [2](#0-1) , its equality comparison checks ALL fields (pubkey, OutValue, Signature, InValue, etc.). Because each miner has different values for these fields, `Distinct()` never filters out any objects, even when multiple miners share the same `FinalOrderOfNextRound`.

**Why Validation Fails**: The validation compares the count of "distinct" miners (which is always the total count) against miners who produced blocks. When a malicious round has duplicate `FinalOrderOfNextRound` values, all miners are still counted as "distinct" because they differ in other fields, so the counts match and validation passes.

**Execution Path**: 
1. A miner requests NextRound consensus data via the public ACS4 method, which generates legitimate round information [3](#0-2) 
2. The miner modifies the Round object to introduce duplicate `FinalOrderOfNextRound` values before including it in their block header
3. When other nodes validate the block, they check the `ProvidedRound` from the block's extra data [4](#0-3) 
4. The NextRoundMiningOrderValidationProvider runs but fails to detect duplicates
5. The validation passes and the malicious round is saved to state [5](#0-4) [6](#0-5) 

### Impact Explanation

**Consensus Breakdown**: When the malicious round with duplicate orders is used to generate the next round [7](#0-6) , multiple miners are assigned the same `Order` value in the mining schedule, while other order positions are left unassigned.

**Specific Harms**:
- **Schedule Corruption**: Two or more miners believe they should mine at the same time slot, leading to block production conflicts
- **Slot Gaps**: Order positions that should be occupied are skipped (e.g., if miners have orders [1,2,2,4,5], position 3 is missing)
- **Mining Logic Failures**: The `BreakContinuousMining` function uses `First(i => i.Order == X)` [8](#0-7) , which only finds one miner even when multiple share the same order, causing incorrect mining rotation
- **Consensus Halt**: The corrupted mining schedule can prevent proper block production and round progression

**Affected Parties**: All network participants, as consensus integrity is compromised for all subsequent rounds until manual intervention or recovery.

**Severity**: CRITICAL - This directly violates the "miner schedule integrity" invariant and breaks the core consensus mechanism.

### Likelihood Explanation

**Attacker Capabilities**: Any miner in the active miner set can execute this attack when they are selected to produce the NextRound block. No special privileges beyond normal mining rights are required.

**Attack Complexity**: LOW
- The miner simply needs to modify the `FinalOrderOfNextRound` values in the Round object before including it in their block
- No complex cryptographic operations or timing requirements
- The attack requires only a single malicious block

**Feasibility Conditions**:
- Attacker must be an active miner (standard consensus requirement)
- Attacker must win the right to produce a NextRound block (happens regularly in normal operation)
- No detection mechanism exists - the malicious round appears valid to all validators

**Detection Constraints**: The vulnerability is silent - there's no way for honest nodes to detect the tampering since the flawed validation logic accepts the malicious data.

**Probability**: HIGH - Every time a potentially malicious miner produces a NextRound block, they have the opportunity to exploit this vulnerability.

### Recommendation

Replace the validation logic to check for distinct `FinalOrderOfNextRound` values specifically:

**Current Code** (lines 15-16):
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
    .Distinct().Count();
```

**Fixed Code**:
```csharp
var distinctCount = providedRound.RealTimeMinersInformation.Values
    .Where(m => m.FinalOrderOfNextRound > 0)
    .Select(m => m.FinalOrderOfNextRound)
    .Distinct()
    .Count();
```

**Additional Invariant Check**: Add validation to ensure all `FinalOrderOfNextRound` values are within the valid range [1, minerCount] with no duplicates or gaps.

**Test Cases**:
1. Test that validation rejects a NextRound where two miners have `FinalOrderOfNextRound = 2`
2. Test that validation rejects a NextRound with orders [1,2,2,4,5] for 5 miners
3. Test that validation accepts a NextRound with orders [1,2,3,4,5] for 5 miners
4. Test that the fix handles edge cases like all miners having `FinalOrderOfNextRound = 0`

### Proof of Concept

**Initial State**:
- 5 active miners in current round: Alice, Bob, Carol, Dave, Eve
- All 5 miners successfully mined blocks (all have `OutValue != null`)
- Current round number: 100

**Attack Sequence**:

1. **Malicious Miner (Alice) Produces NextRound Block**:
   - Alice's node requests consensus data for NextRound behavior
   - Contract generates legitimate round 101 with unique orders: Alice=1, Bob=2, Carol=3, Dave=4, Eve=5

2. **Alice Modifies the Round Data**:
   - Before including in block header, Alice modifies the Round object:
     - Alice: `FinalOrderOfNextRound = 1`
     - Bob: `FinalOrderOfNextRound = 2`  
     - Carol: `FinalOrderOfNextRound = 2` (DUPLICATE!)
     - Dave: `FinalOrderOfNextRound = 4`
     - Eve: `FinalOrderOfNextRound = 5`

3. **Validation Executes** [9](#0-8) :
   ```
   distinctCount = [Alice, Bob, Carol, Dave, Eve].Distinct().Count() = 5
   minersWithOutValue = 5
   5 == 5 → PASSES (INCORRECT!)
   ```
   
   **Expected**: Should detect that only 4 distinct order values exist (1,2,4,5)

4. **Malicious Round Saved to State** [10](#0-9) :
   - Round 101 with duplicate orders is written to `State.Rounds[101]`

5. **Next Round Generation Corrupted**:
   - When round 102 is generated from round 101, both Bob and Carol have `Order = 2`
   - Position 3 is marked as "available" but was never occupied
   - Both Bob and Carol attempt to mine at the same time slot
   - The mining schedule is permanently corrupted

**Success Condition**: The attack succeeds when a NextRound with duplicate `FinalOrderOfNextRound` values passes validation and gets saved to state, as evidenced by multiple miners having identical `Order` values in the subsequent round.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-16)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
```

**File:** protobuf/aedpos_contract.proto (L266-301)
```text
message MinerInRound {
    // The order of the miner producing block.
    int32 order = 1;
    // Is extra block producer in the current round.
    bool is_extra_block_producer = 2;
    // Generated by secret sharing and used for validation between miner.
    aelf.Hash in_value = 3;
    // Calculated from current in value.
    aelf.Hash out_value = 4;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 5;
    // The expected mining time.
    google.protobuf.Timestamp expected_mining_time = 6;
    // The amount of produced blocks.
    int64 produced_blocks = 7;
    // The amount of missed time slots.
    int64 missed_time_slots = 8;
    // The public key of this miner.
    string pubkey = 9;
    // The InValue of the previous round.
    aelf.Hash previous_in_value = 10;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 11;
    // The final order of mining for the next round.
    int32 final_order_of_next_round = 12;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    repeated google.protobuf.Timestamp actual_mining_times = 13;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 14;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 15;
    // The amount of produced tiny blocks.
    int64 produced_tiny_blocks = 16;
    // The irreversible block height that current miner recorded.
    int64 implied_irreversible_block_height = 17;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L40-43)
```csharp
            case AElfConsensusBehaviour.NextRound:
                information = GetConsensusExtraDataForNextRound(currentRound, pubkey,
                    triggerInformation);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L105-105)
```csharp
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L79-90)
```csharp
        var firstMinerOfNextRound = nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 1);
        var extraBlockProducerOfCurrentRound = GetExtraBlockProducerInformation();
        if (firstMinerOfNextRound.Pubkey == extraBlockProducerOfCurrentRound.Pubkey)
        {
            var secondMinerOfNextRound =
                nextRound.RealTimeMinersInformation.Values.First(i => i.Order == 2);
            secondMinerOfNextRound.Order = 1;
            firstMinerOfNextRound.Order = 2;
            var tempTimestamp = secondMinerOfNextRound.ExpectedMiningTime;
            secondMinerOfNextRound.ExpectedMiningTime = firstMinerOfNextRound.ExpectedMiningTime;
            firstMinerOfNextRound.ExpectedMiningTime = tempTimestamp;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L86-86)
```csharp
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
```
