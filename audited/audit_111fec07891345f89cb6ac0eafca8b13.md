### Title
Missing LIB Height Monotonicity Validation in NextRound and NextTerm Behaviors Allows Irreversibility Violation

### Summary
The `ValidateBeforeExecution` function only adds `LibInformationValidationProvider` for the `UpdateValue` behavior, but not for `NextRound` or `NextTerm` behaviors. This allows a malicious miner to submit NextRound or NextTerm transactions with decreased Last Irreversible Block (LIB) heights, violating the blockchain's irreversibility guarantee and potentially enabling chain reorganizations beyond the supposedly irreversible point.

### Finding Description

The validation logic in `ValidateBeforeExecution` conditionally adds validation providers based on consensus behavior: [1](#0-0) 

The `LibInformationValidationProvider` is only added for `UpdateValue` behavior (line 82), ensuring that LIB heights cannot decrease. This provider validates two critical invariants: [2](#0-1) 

However, `NextRound` and `NextTerm` behaviors receive different validation providers (`NextRoundMiningOrderValidationProvider` and `RoundTerminateValidationProvider`) that do NOT check LIB monotonicity.

Both `NextRoundInput` and `NextTermInput` include LIB fields in their structure: [3](#0-2) [4](#0-3) 

When `ProcessNextRound` or `ProcessNextTerm` executes, the Round object with these LIB fields is stored directly in state: [5](#0-4) [6](#0-5) 

The Round information is persisted via `AddRoundInformation`: [7](#0-6) 

While legitimate consensus extra data generation copies LIB values from the current round: [8](#0-7) 

A malicious miner can craft modified consensus header information with decreased LIB values, bypassing validation since `LibInformationValidationProvider` is absent from the validation pipeline for these behaviors.

### Impact Explanation

**Consensus/Cross-Chain Integrity Violation:**
- The Last Irreversible Block (LIB) height is a critical consensus parameter that guarantees finality. Once a block is marked as irreversible, it should never be subject to reorganization.
- By allowing LIB height to decrease, an attacker can retroactively mark previously irreversible blocks as reversible, fundamentally breaking the finality guarantee.
- This enables chain reorganizations beyond what should be the irreversible checkpoint, potentially allowing double-spend attacks if transactions in the supposedly irreversible range are reorganized.
- Cross-chain operations rely on LIB information for security. Decreased LIB heights could cause cross-chain transfers to be reversed after being considered finalized on the parent chain.

**Affected Parties:**
- All users relying on transaction finality for high-value transfers
- Cross-chain bridge users whose transactions may be reversed
- Applications and exchanges using LIB as a settlement confirmation metric
- The entire network's consensus integrity

**Severity Justification:**
This is a **Critical** severity issue because it directly violates a fundamental blockchain invariant (irreversibility) and compromises the security guarantees that the entire system depends on.

### Likelihood Explanation

**Attacker Capabilities:**
- The attacker must be an active miner in the consensus set (typically the extra block producer for NextRound, or any miner eligible to trigger NextTerm)
- The attacker needs to produce a block with modified consensus header information containing decreased LIB values

**Attack Complexity:**
- Low to Medium complexity. The attacker simply needs to:
  1. Prepare a NextRound or NextTerm consensus transaction
  2. Modify the `ConfirmedIrreversibleBlockHeight` and `ConfirmedIrreversibleBlockRoundNumber` fields to values lower than the current state
  3. Submit the block with this modified consensus information
  4. The validation passes because `LibInformationValidationProvider` is not in the validation pipeline

**Feasibility Conditions:**
- The attacker must be part of the active miner set (realistic for a compromised or malicious miner)
- NextRound transitions happen regularly at the end of each round
- NextTerm transitions happen periodically (default every 7 days)
- No additional authentication or authorization beyond being a valid miner is required

**Detection/Operational Constraints:**
- The attack may be detectable by monitoring nodes that track LIB progression, but by the time it's detected, the state has already been corrupted
- The transaction would appear valid to all validation checks currently in place

**Probability:**
Medium-High. While it requires a malicious miner, the attack is straightforward to execute and the validation gap is clear.

### Recommendation

**Immediate Fix:**
Add `LibInformationValidationProvider` to the validation pipeline for both `NextRound` and `NextTerm` behaviors in the `ValidateBeforeExecution` method:

```csharp
switch (extraData.Behaviour)
{
    case AElfConsensusBehaviour.UpdateValue:
        validationProviders.Add(new UpdateValueValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider());
        break;
    case AElfConsensusBehaviour.NextRound:
        validationProviders.Add(new NextRoundMiningOrderValidationProvider());
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
    case AElfConsensusBehaviour.NextTerm:
        validationProviders.Add(new RoundTerminateValidationProvider());
        validationProviders.Add(new LibInformationValidationProvider()); // ADD THIS
        break;
}
```

**Invariant Checks:**
- LIB height must be monotonically non-decreasing across all consensus behaviors
- `ConfirmedIrreversibleBlockHeight` in any new round must be >= current round's value
- `ConfirmedIrreversibleBlockRoundNumber` in any new round must be >= current round's value

**Test Cases:**
1. Test that NextRound transactions with decreased LIB height are rejected
2. Test that NextRound transactions with equal LIB height are accepted
3. Test that NextRound transactions with increased LIB height are accepted
4. Repeat all tests for NextTerm behavior
5. Test that UpdateValue behavior continues to enforce LIB monotonicity
6. Add integration tests that verify LIB height never decreases across round and term transitions

### Proof of Concept

**Required Initial State:**
- Active AEDPoS consensus network with multiple miners
- Current round with `ConfirmedIrreversibleBlockHeight = 1000` and `ConfirmedIrreversibleBlockRoundNumber = 10`

**Attack Steps:**

1. **Attacker (Extra Block Producer) prepares NextRound block:**
   - Query current round information: LIB height = 1000, LIB round = 10
   - Create a malicious `NextRoundInput` with:
     - `RoundNumber = currentRound.RoundNumber + 1` (valid increment)
     - `ConfirmedIrreversibleBlockHeight = 800` (DECREASED from 1000)
     - `ConfirmedIrreversibleBlockRoundNumber = 8` (DECREASED from 10)
     - Other fields populated correctly to pass other validations

2. **Submit the NextRound transaction:**
   - The transaction enters `ValidateBeforeExecution`
   - `MiningPermissionValidationProvider` passes (attacker is valid miner)
   - `TimeSlotValidationProvider` passes (proper timing)
   - `ContinuousBlocksValidationProvider` passes (not producing too many blocks)
   - `NextRoundMiningOrderValidationProvider` passes (mining orders correct)
   - `RoundTerminateValidationProvider` passes (round number incremented correctly)
   - **`LibInformationValidationProvider` is NOT checked** (vulnerability)
   - Validation passes ✓

3. **Transaction executes via `ProcessNextRound`:**
   - `nextRound = input.ToRound()` creates Round with LIB height = 800
   - `AddRoundInformation(nextRound)` stores the round in state
   - State now has: `ConfirmedIrreversibleBlockHeight = 800` (decreased from 1000)

**Expected vs Actual Result:**
- **Expected:** Transaction should be rejected with "Incorrect lib information" error
- **Actual:** Transaction is accepted and LIB height decreases from 1000 to 800, violating irreversibility

**Success Condition:**
Query `GetCurrentRoundInformation` after the attack:
- `ConfirmedIrreversibleBlockHeight` has decreased from 1000 to 800
- Blocks 801-1000 are no longer considered irreversible despite previously being finalized
- Chain reorganizations can now occur in this range, breaking the finality guarantee

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/LibInformationValidationProvider.cs (L14-30)
```csharp
        if (providedRound.ConfirmedIrreversibleBlockHeight != 0 &&
            providedRound.ConfirmedIrreversibleBlockRoundNumber != 0 &&
            (baseRound.ConfirmedIrreversibleBlockHeight > providedRound.ConfirmedIrreversibleBlockHeight ||
             baseRound.ConfirmedIrreversibleBlockRoundNumber > providedRound.ConfirmedIrreversibleBlockRoundNumber))
        {
            validationResult.Message = "Incorrect lib information.";
            return validationResult;
        }

        if (providedRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight != 0 &&
            baseRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight >
            providedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight)
        {
            validationResult.Message = "Incorrect implied lib height.";
            return validationResult;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L69-70)
```csharp
        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
```
