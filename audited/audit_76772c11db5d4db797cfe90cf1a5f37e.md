### Title
Missing Miner Count Validation in NextRound Allows Consensus Manipulation

### Summary
The `ValidationForNextRound()` function fails to validate that the number of miners in the next round matches expected consensus parameters (minimum 17, maximum determined by governance). A malicious miner can craft a NextRound block with an arbitrary number of miners, bypassing election-based miner selection and breaking fundamental consensus invariants.

### Finding Description

The `ValidationForNextRound()` method only performs two checks: [1](#0-0) 

These checks validate round number increment and that InValues are null, but **critically omit validation of the miner count** in `extraData.Round.RealTimeMinersInformation`.

The consensus system defines clear miner count constraints:
- Minimum: `SupposedMinersCount` (17 miners) [2](#0-1) 

- Maximum: Governance-controlled parameter with auto-increase logic [3](#0-2) 

When `NextRound` behavior is validated, `RoundTerminateValidationProvider` is added to the validation pipeline: [4](#0-3) 

However, none of the validation providers check whether `RealTimeMinersInformation.Count` in the provided next round matches these constraints.

When processing the NextRound input, `ProcessNextRound` accepts the provided round without validating miner count for rounds after the first: [5](#0-4) 

The miner count check at line 128 only executes when `currentRound.RoundNumber == 1`, leaving all subsequent rounds unvalidated.

Normal round generation maintains miner count from current round: [6](#0-5) 

But since validation doesn't enforce this, a malicious block producer can bypass the legitimate generation logic and submit arbitrary miner lists.

### Impact Explanation

**Consensus Manipulation**: An attacker can add colluding miners beyond `MaximumMinersCount`, potentially gaining majority control of consensus. With majority control, they can:
- Approve malicious blocks
- Manipulate irreversible block heights
- Control reward distribution

**Election Bypass**: The Election contract carefully selects miners based on vote weights: [7](#0-6) 

This vulnerability allows a single malicious miner to bypass election results entirely, adding arbitrary miners without governance approval.

**DoS Attack**: Reducing miners below the minimum threshold (17) can cause consensus failure, preventing block production and halting the chain.

**Governance Violation**: The `MaximumMinersCount` parameter is governance-controlled and can only be changed through Parliament proposals. This vulnerability allows direct circumvention without authorization.

### Likelihood Explanation

**Reachable Entry Point**: Any current miner can trigger this when producing their assigned NextRound block. Becoming a miner requires election but is a normal operational role, not a privileged position.

**Attack Complexity**: LOW
- Attacker modifies their consensus node software to generate malicious `NextRoundInput` with manipulated `RealTimeMinersInformation`
- No cryptographic bypasses needed
- No complex timing requirements
- Single transaction execution

**Feasibility**: The attack is highly feasible:
1. Attacker becomes elected miner through normal voting process
2. Waits for their turn to produce the NextRound block (deterministic, happens every round)
3. Modified node generates NextRound with arbitrary miner list
4. Validation passes due to missing checks
5. Malicious round is committed to state

**Detection**: No on-chain detection mechanisms exist. The validation system incorrectly accepts the malicious round as valid.

**Economic Rationality**: For a motivated attacker seeking consensus control or chain disruption, the cost of getting elected as one miner is significantly lower than the impact of controlling the entire consensus.

### Recommendation

Add miner count validation to `ValidationForNextRound()` in `RoundTerminateValidationProvider.cs`:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    
    // Existing checks
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };
    
    if (extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null))
        return new ValidationResult { Message = "Incorrect next round information." };
    
    // NEW: Validate miner count
    var nextRoundMinerCount = extraData.Round.RealTimeMinersInformation.Count;
    var currentRoundMinerCount = validationContext.BaseRound.RealTimeMinersInformation.Count;
    
    // For same-term round transitions, miner count should match (except during evil miner replacement)
    if (!extraData.Round.IsMinerListJustChanged && nextRoundMinerCount != currentRoundMinerCount)
        return new ValidationResult { Message = "Miner count mismatch in next round." };
    
    // Enforce minimum miners
    if (nextRoundMinerCount < AEDPoSContractConstants.SupposedMinersCount)
        return new ValidationResult { Message = "Next round has fewer than minimum required miners." };
    
    // Enforce maximum miners (requires access to contract state - may need different approach)
    // Consider adding this check in ProcessNextRound before accepting the round
    
    return new ValidationResult { Success = true };
}
```

Additionally, add validation in `ProcessNextRound`:
```csharp
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // NEW: Validate miner count against consensus parameters
    var expectedMaxMiners = GetMaximumMinersCount().Value;
    if (nextRound.RealTimeMinersInformation.Count > expectedMaxMiners)
        Assert(false, $"Next round exceeds maximum miners count: {expectedMaxMiners}");
    
    // Continue with existing processing...
}
```

**Test Cases**:
1. Attempt NextRound with miners count > MaximumMinersCount - should fail
2. Attempt NextRound with miners count < SupposedMinersCount - should fail  
3. Attempt NextRound with different miner count than current round (when not IsMinerListJustChanged) - should fail
4. Legitimate NextRound with proper miner count - should succeed

### Proof of Concept

**Initial State**:
- Chain running with 17 miners (SupposedMinersCount)
- MaximumMinersCount set to 25 via governance
- Attacker is Miner #5 in current round

**Attack Steps**:

1. Attacker waits until it's their turn to produce the NextRound block (when extra block producer role is assigned to them)

2. Attacker's modified node generates malicious `NextRoundInput`:
```
NextRoundInput {
  RealTimeMinersInformation: {
    // Original 17 miners
    "Miner1_pubkey": { Order: 1, ... },
    ...
    "Miner17_pubkey": { Order: 17, ... },
    // MALICIOUS: Add 10 attacker-controlled miners
    "AttackerMiner1_pubkey": { Order: 18, ... },
    ...
    "AttackerMiner10_pubkey": { Order: 27, ... }
  },
  RoundNumber: currentRound + 1,
  // All InValues are null (satisfies existing validation)
}
```

3. Attacker submits NextRound transaction with this input

4. **Validation Phase** - All checks PASS:
   - `MiningPermissionValidationProvider`: ✓ Attacker is in current round
   - `TimeSlotValidationProvider`: ✓ Correct timing
   - `NextRoundMiningOrderValidationProvider`: ✓ Internal consistency maintained
   - `RoundTerminateValidationProvider`: ✓ Round number incremented, InValues null
   - **Missing**: No check that miner count (27) exceeds MaximumMinersCount (25)

5. **Processing Phase** - Block accepted:
   - `ProcessNextRound` executes without miner count validation
   - Malicious round with 27 miners stored in state
   - Subsequent rounds continue with compromised miner set

**Expected Result**: Transaction should be rejected with "Next round exceeds maximum miners count: 25"

**Actual Result**: Transaction succeeds, consensus now operates with 27 miners (10 controlled by attacker), giving attacker 37% control (10/27). If attacker adds enough miners to reach majority, they achieve full consensus control.

**Success Condition**: After attack, `GetCurrentRoundInformation().RealTimeMinersInformation.Count == 27` and attacker-controlled miners are active participants in consensus, despite exceeding governance-approved maximum.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L72-78)
```csharp
    public override Int32Value GetMaximumMinersCount(Empty input)
    {
        return new Int32Value
        {
            Value = Math.Min(GetAutoIncreasedMinersCount(), State.MaximumMinersCount.Value)
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-88)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-71)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

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
        }

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
                    .AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                // Update missed time slots count of one miner.
                MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1)
            };
        }

        // Calculate extra block producer order and set the producer.
        var extraBlockProducerOrder = CalculateNextExtraBlockProducerOrder();
        var expectedExtraBlockProducer =
            nextRound.RealTimeMinersInformation.Values.FirstOrDefault(m => m.Order == extraBlockProducerOrder);
        if (expectedExtraBlockProducer == null)
            nextRound.RealTimeMinersInformation.Values.First().IsExtraBlockProducer = true;
        else
            expectedExtraBlockProducer.IsExtraBlockProducer = true;

        BreakContinuousMining(ref nextRound);

        nextRound.ConfirmedIrreversibleBlockHeight = ConfirmedIrreversibleBlockHeight;
        nextRound.ConfirmedIrreversibleBlockRoundNumber = ConfirmedIrreversibleBlockRoundNumber;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```
