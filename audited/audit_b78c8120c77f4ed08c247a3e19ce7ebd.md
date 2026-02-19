### Title
Missing Miner List Validation in NextRound Transitions Allows Consensus Disruption via Inflated Miner Count

### Summary
The `NextRound` validation logic does not verify that the provided round's miner list matches the authorized miners. A malicious miner can inject fake entries into `RealTimeMinersInformation` during round transitions, causing `ApplyNormalConsensusData` to use an inflated `minersCount` value that mismatches the actual authorized miner count, disrupting consensus order assignments and time slot calculations.

### Finding Description

**Root Cause:**
The vulnerability exists in the validation flow for `NextRound` consensus behavior. When a miner produces a block to transition to the next round, the validation only checks internal consistency of the provided round but does not validate that the miner list is legitimate. [1](#0-0) 

The validator only checks that miners with `FinalOrderOfNextRound > 0` equals miners with `OutValue != null`. For a freshly generated next round, both counts are zero (all miners have default null/0 values), so the validation passes with `0 == 0` even if fake miners are added.

**Exploitation Path:**

1. During block production, the miner calls `GetConsensusExtraDataForNextRound` which generates the next round: [2](#0-1) 

2. The malicious miner modifies the generated `nextRound.RealTimeMinersInformation` to add fake miner entries with default field values (`OutValue = null`, `FinalOrderOfNextRound = 0`).

3. The modified round is included in the block header and validated: [3](#0-2) 

4. Validation passes because no validator checks miner list integrity against authorized miners.

5. The corrupted round is written to state: [4](#0-3) 

6. Subsequent operations use the inflated miner count: [5](#0-4) 

**Why Protections Fail:**
The validation context uses `ProvidedRound` from the block header: [6](#0-5) 

But no validator compares this miner list against `BaseRound` (the trusted current round from state) or an authorized miner list.

### Impact Explanation

**Consensus Integrity Breach:**
- The inflated `minersCount` causes incorrect order assignments in `ApplyNormalConsensusData`, disrupting the deterministic miner ordering mechanism
- Order calculation uses `GetAbsModulus(sigNum, minersCount) + 1`, which produces wrong results with corrupted count
- Conflict resolution loop (lines 31-40) may fail to find valid orders or assign duplicates

**Operational Disruption:**
- Fake miners never actually produce blocks, creating persistent missed time slots
- Time slot calculations use `minersCount` to determine mining intervals, causing schedule desynchronization
- Network may experience prolonged periods without valid blocks

**Economic Impact:**
- If rewards are calculated based on miner count, fake entries dilute legitimate miner rewards: [7](#0-6) 

**Affected Parties:**
- All network validators (disrupted consensus)
- Legitimate miners (reduced rewards, disrupted mining schedule)
- Network users (degraded block production)

**Severity Justification:**
High severity due to consensus integrity violation and protocol-wide disruption from a single malicious miner.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an authorized miner in the current round (to pass `MiningPermissionValidationProvider`)
- Must have the ability to produce blocks during their time slot
- Can construct and modify block header data (standard blockchain capability)

**Attack Complexity:**
- Low: Simple modification of the generated `nextRound` object before block submission
- No complex timing requirements or state manipulation needed
- Single transaction achieves persistent corruption

**Feasibility Conditions:**
- Attacker waits for their turn to produce a `NextRound` block
- Generates legitimate next round via contract logic
- Adds fake `MinerInRound` entries with default field values
- Submits modified block

**Detection Constraints:**
- Attack succeeds silently as validation passes
- Corrupted state persists until a subsequent legitimate `NextRound` transition
- Fake miners cause observable missed time slots, but this may be attributed to network issues

**Probability Assessment:**
High likelihood if any current miner is malicious, as the attack is straightforward and validation does not prevent it.

### Recommendation

**Code-Level Mitigation:**

Add miner list validation in `NextRoundMiningOrderValidationProvider`:

1. Compare `providedRound.RealTimeMinersInformation.Keys` against `validationContext.BaseRound.RealTimeMinersInformation.Keys`
2. Verify counts match: `providedRound.RealTimeMinersInformation.Count == baseRound.RealTimeMinersInformation.Count`
3. Ensure all pubkeys in provided round exist in base round (unless `IsMinerListJustChanged` flag is set)

**Invariant Checks:**
- Round miner count must match authorized miner list size (except during term transitions with replacement)
- All miner pubkeys in a round must be in the authorized Election Contract miner list
- No duplicate pubkeys in `RealTimeMinersInformation`

**Additional Validation:**
For term transitions (`NextTerm`), validate the new miner list against the Election Contract's authorized list: [8](#0-7) 

**Test Cases:**
1. Attempt NextRound with extra fake miner → should fail validation
2. Attempt NextRound with removed real miner → should fail validation  
3. Attempt NextRound with correct miner list → should succeed
4. Legitimate NextTerm with Election Contract authorized list → should succeed

### Proof of Concept

**Initial State:**
- Current round has 5 authorized miners (A, B, C, D, E)
- Attacker is Miner A

**Attack Steps:**

1. Miner A's turn to produce NextRound block arrives
2. Contract generates legitimate nextRound with 5 miners via `GenerateNextRoundInformation`
3. Attacker modifies `nextRound.RealTimeMinersInformation` to add 3 fake miners (F, G, H):
   ```
   nextRound.RealTimeMinersInformation["F"] = new MinerInRound { Pubkey = "F", Order = 0 }
   nextRound.RealTimeMinersInformation["G"] = new MinerInRound { Pubkey = "G", Order = 0 }
   nextRound.RealTimeMinersInformation["H"] = new MinerInRound { Pubkey = "H", Order = 0 }
   ```
4. Attacker submits NextRound block with corrupted round (8 miners)
5. Validation runs:
   - `NextRoundMiningOrderValidationProvider`: Checks `0 == 0` (all OutValue and FinalOrderOfNextRound are defaults) → PASSES
   - `RoundTerminateValidationProvider`: Checks round number increment → PASSES
6. `ProcessNextRound` executes, adds corrupted round to state
7. State now has round with `RealTimeMinersInformation.Count = 8`

**Expected vs Actual Result:**
- Expected: Validation rejects block due to unauthorized miners
- Actual: Validation passes, corrupted round persists in state

**Success Condition:**
Query `GetCurrentRoundInformation` shows 8 miners instead of 5, with fake miners F, G, H included. Subsequent `ApplyNormalConsensusData` calls use `minersCount = 8` instead of 5.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-187)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-92)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-190)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L24-27)
```csharp
    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```
