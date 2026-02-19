# Audit Report

## Title
Missing Miner Order Validation in NextTerm Allows Mining Schedule Manipulation

## Summary
The NextTerm consensus transition lacks validation of miner Order values in the provided Round object. A malicious miner producing a NextTerm block can arbitrarily modify the Order assignments for the next term, bypassing the protocol's deterministic order assignment mechanism. This allows manipulation of the mining schedule, giving attackers favorable time slots and breaking consensus integrity guarantees.

## Finding Description

The AEDPoS consensus protocol expects miner Order values to be deterministically assigned by sorting miners by their public key's first byte in descending order and assigning sequential positions. [1](#0-0) 

However, the NextTerm validation flow contains a critical gap: `NextTermInput.Create()` simply copies the `RealTimeMinersInformation` dictionary from the provided Round object without any validation of Order correctness. [2](#0-1) 

When validating NextTerm behavior in `ValidateBeforeExecution`, the validation provider list for NextTerm only includes `RoundTerminateValidationProvider` beyond the basic providers (MiningPermissionValidationProvider, TimeSlotValidationProvider, ContinuousBlocksValidationProvider). [3](#0-2) 

The `RoundTerminateValidationProvider` only validates that the round number and term number increment correctly, and that InValues are null - it does NOT validate Order consistency. [4](#0-3) 

The `TimeSlotValidationProvider` calls `CheckRoundTimeSlots()` to validate time slot spacing, but this method orders miners by the PROVIDED Order values without verifying they match the expected deterministic assignment. [5](#0-4) 

Finally, in `ProcessNextTerm`, the provided Round is directly added to state via `AddRoundInformation(nextRound)` without any additional Order validation. [6](#0-5) 

**Attack Scenario:**
1. Malicious miner's turn to produce NextTerm block arrives
2. Miner calls `GetConsensusExtraDataForNextTerm` which generates a Round with correct deterministic Orders [7](#0-6) 
3. Before including in block header, attacker modifies Order values (e.g., assigns themselves Order 1, swaps with other miners)
4. Attacker ensures ExpectedMiningTimes remain evenly spaced to pass CheckRoundTimeSlots
5. Block is broadcast with malicious consensus extra data
6. Validation passes because no validator checks Order correctness
7. ProcessNextTerm executes, storing corrupted Order assignments for entire next term
8. Mining schedule is now manipulated according to attacker's modifications

## Impact Explanation

This vulnerability has **HIGH** severity impact due to direct consensus integrity violation:

**Consensus Mechanism Compromise**: The fundamental guarantee of deterministic, fair miner ordering based on cryptographic public key sorting is completely bypassed. The protocol assumes Order values follow the deterministic assignment, and all mining schedule logic depends on this invariant.

**Mining Schedule Manipulation**: An attacker can:
- Assign themselves the earliest Order positions (Order 1, 2) to mine first blocks of each round
- Swap Orders with colluding miners to create favorable mining sequences  
- Manipulate which miners get extra block producer privileges
- Potentially cause timing conflicts where honest miners miss their slots due to incorrect Order expectations

**Protocol-Wide Impact**: Once corrupted Orders are stored in state, they affect:
- All round progression for the entire term (typically 7 days)
- Time slot calculations for every miner
- Extra block producer selection
- Mining reward distribution expectations

**No Self-Correcting Mechanism**: The corrupted Orders persist for the full term duration. There is no automatic recovery - the protocol will use the manipulated values until the next term transition, which could be exploited again.

## Likelihood Explanation

This vulnerability has **MODERATE-HIGH** likelihood of exploitation:

**Attacker Requirements Met**: The attacker must be an authorized miner eligible to produce the NextTerm block. This is not a high barrier since:
- Term transitions occur regularly (every 7 days by default)
- Any miner in the current term rotation can produce the NextTerm block when conditions are met
- The protocol explicitly allows any qualified miner to trigger term transitions

**Low Technical Complexity**: Exploitation requires:
1. Standard miner capabilities (already authorized to produce blocks)
2. Parsing and modifying a protobuf Round object (straightforward)
3. Ensuring ExpectedMiningTimes maintain valid spacing (simple arithmetic)
4. No cryptographic bypasses or complex state manipulation needed

**No Detection During Validation**: The malicious Orders pass all validation checks because:
- No validator compares Orders against expected deterministic assignment
- No validator calls `GetVictories()` to verify the miner list
- TimeSlotValidationProvider accepts any Orders as long as time spacing is valid
- The VRF random number check protects randomness but not the Round structure itself

**Economic Incentive**: Attackers gain:
- Earlier mining positions → more blocks produced → higher rewards
- Ability to frontrun transactions (MEV extraction)
- Increased influence over block production
- Potential to disadvantage competing miners

## Recommendation

Add a validation provider that verifies Order assignments match the expected deterministic sorting:

```csharp
public class NextTermOrderValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        
        // Get expected miner list from victories
        var expectedMiners = GetExpectedMinerList(validationContext);
        
        // Verify miner list matches
        if (!ValidateMinerList(providedRound, expectedMiners))
        {
            validationResult.Message = "Miner list does not match expected victories";
            return validationResult;
        }
        
        // Verify Orders match deterministic assignment
        var sortedMiners = expectedMiners.OrderByDescending(m => m[0]).ToList();
        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var expectedOrder = i + 1;
            var actualOrder = providedRound.RealTimeMinersInformation[sortedMiners[i]].Order;
            if (actualOrder != expectedOrder)
            {
                validationResult.Message = $"Order mismatch for miner {sortedMiners[i]}: expected {expectedOrder}, got {actualOrder}";
                return validationResult;
            }
        }
        
        validationResult.Success = true;
        return validationResult;
    }
}
```

Then add this provider to the NextTerm validation flow in `AEDPoSContract_Validation.cs`:
```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new NextTermOrderValidationProvider());
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

## Proof of Concept

This vulnerability requires testing within the AElf consensus test framework. A proof-of-concept would:

1. Set up a consensus test with multiple miners
2. Advance to term transition condition
3. Have a malicious miner produce NextTerm block
4. Before submitting, modify the Order values in the generated Round object
5. Submit the block and verify it passes validation
6. Confirm the corrupted Orders are stored in state and affect subsequent mining schedule

The test would demonstrate that modified Order values pass validation and are accepted, proving the lack of Order validation in the NextTerm flow.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-31)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/NextTermInput.cs (L7-23)
```csharp
    public static NextTermInput Create(Round round, ByteString randomNumber)
    {
        return new NextTermInput
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L89-91)
```csharp
            case AElfConsensusBehaviour.NextTerm:
                validationProviders.Add(new RoundTerminateValidationProvider());
                break;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
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
