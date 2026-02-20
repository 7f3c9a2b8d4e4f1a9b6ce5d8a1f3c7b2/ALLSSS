# Audit Report

## Title
Missing Miner Order Validation in NextTerm Allows Mining Schedule Manipulation

## Summary
The AEDPoS consensus contract fails to validate miner Order values during NextTerm transitions. While the protocol expects Orders to be deterministically assigned by sorting miners' public keys, no validation enforces this during NextTerm block processing. A malicious miner producing a NextTerm block can arbitrarily modify Order assignments, manipulating the mining schedule for an entire term (~7 days) and breaking consensus integrity guarantees.

## Finding Description

The AEDPoS protocol deterministically assigns miner Order values by sorting public keys by their first byte in descending order: [1](#0-0) [2](#0-1) 

However, during NextTerm transitions, the validation flow contains a critical gap. When a miner produces a NextTerm block, `NextTermInput.Create()` simply copies the `RealTimeMinersInformation` dictionary from the provided Round object without validating Order correctness: [3](#0-2) 

The validation logic in `ValidateBeforeExecution` demonstrates a critical asymmetry. For NextRound behavior, it includes `NextRoundMiningOrderValidationProvider`, but for NextTerm it only adds `RoundTerminateValidationProvider`: [4](#0-3) 

The `RoundTerminateValidationProvider` only validates round/term number increments and null InValues, completely omitting Order validation: [5](#0-4) 

The `TimeSlotValidationProvider` calls `CheckRoundTimeSlots()`, which orders miners by the PROVIDED Order values without verifying they match the expected deterministic assignment: [6](#0-5) 

Finally, `ProcessNextTerm` directly stores the provided Round to state via `AddRoundInformation` without any Order validation: [7](#0-6) [8](#0-7) 

**Attack Scenario:**
1. Malicious miner calls `GetConsensusExtraDataForNextTerm` which generates correct deterministic Orders via `GenerateFirstRoundOfNextTerm`
2. Before broadcasting the block, attacker modifies Order values in the consensus extra data (e.g., assigns themselves Order 1)
3. Attacker ensures `ExpectedMiningTimes` remain properly spaced to pass `CheckRoundTimeSlots`
4. Block is validated - no validator checks Order correctness against deterministic assignment
5. The VRF check only validates the random number, not the Round structure: [9](#0-8) 

6. `ProcessNextTerm` executes, storing corrupted Orders for the entire next term
7. Mining schedule is now manipulated according to attacker's modifications

## Impact Explanation

This vulnerability has **HIGH** severity impact:

**Consensus Integrity Violation**: The protocol's fundamental guarantee of deterministic, fair miner ordering is completely bypassed. The mining schedule mechanism relies on Order values to determine time slots. Since `IsCurrentMiner` checks `ExpectedMiningTime` which is calculated based on Order, manipulated Orders directly corrupt mining schedules.

**Mining Schedule Manipulation**: An attacker can:
- Assign themselves Order 1 to become the extra block producer and mine first in each round (first miner with `i==0` becomes extra block producer per the generation logic)
- Swap Orders with colluding miners to create favorable mining sequences
- Disadvantage competing miners by assigning them late Order positions
- Mine more blocks → earn higher rewards

**Protocol-Wide Persistence**: Once corrupted Orders are stored in state, they affect all round progression for the entire term (typically 7 days). There is no self-correcting mechanism - the protocol uses the manipulated values until the next term transition, which could be exploited again.

**Reward Misallocation**: Earlier Order positions produce more blocks, resulting in unfair reward distribution that violates the protocol's economic fairness guarantees.

## Likelihood Explanation

This vulnerability has **MODERATE-HIGH** likelihood of exploitation:

**Low Attacker Barrier**: The attacker must be an authorized miner eligible to produce the NextTerm block. Term transitions occur regularly (every 7 days by default), and any miner in the current term can produce the NextTerm block when conditions are met. This is not a privileged position.

**Low Technical Complexity**: Exploitation requires:
1. Standard miner capabilities (already possessed)
2. Parsing and modifying a protobuf Round object (straightforward serialization/deserialization)
3. Maintaining valid time slot spacing (simple arithmetic to keep intervals consistent)
4. No cryptographic bypasses or complex state manipulation needed

**No Detection**: The malicious Orders pass all validation checks because:
- No validator compares Orders against the expected deterministic assignment from `GetVictories`
- `TimeSlotValidationProvider` only validates time spacing, accepting any Order values
- The VRF random number verification protects randomness but not the Round structure
- No validator calls `GenerateFirstRoundOfNewTerm` to regenerate and compare expected Orders

**Economic Incentive**: Attackers gain earlier mining positions leading to more blocks produced, higher rewards, MEV extraction opportunities, and increased influence over block production.

## Recommendation

Add Order validation to the NextTerm validation flow, similar to how NextRound includes `NextRoundMiningOrderValidationProvider`. Create a new validator that:

1. Retrieves the expected miner list via `GetVictories()` (or reuses current miners if on side chain)
2. Regenerates the expected first round with deterministic Order assignment using `MinerList.GenerateFirstRoundOfNewTerm`
3. Compares the provided Order values against the expected deterministic Orders
4. Rejects the block if Orders don't match

Add this validator to the NextTerm case in `ValidateBeforeExecution`:

```csharp
case AElfConsensusBehaviour.NextTerm:
    validationProviders.Add(new NextTermMiningOrderValidationProvider()); // Add Order validation
    validationProviders.Add(new RoundTerminateValidationProvider());
    break;
```

The new `NextTermMiningOrderValidationProvider` should verify that each miner's Order matches the position they would receive from the deterministic sorting algorithm.

## Proof of Concept

A proof of concept would involve:

1. Setting up an AEDPoS test environment with multiple miners
2. Reaching a NextTerm transition point
3. As the NextTerm block producer, calling `GetConsensusExtraDataForNextTerm` to generate correct consensus data
4. Modifying the Order values in the returned Round (e.g., swapping Order 1 and Order 5)
5. Adjusting `ExpectedMiningTimes` to maintain proper spacing
6. Broadcasting the block with manipulated consensus extra data
7. Observing that the block is accepted and the manipulated Orders are stored in state
8. Verifying that subsequent mining in the new term follows the manipulated Order schedule rather than the expected deterministic schedule

The test would demonstrate that no validation rejects the manipulated Order values, confirming the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L15-19)
```csharp
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L30-31)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L75-81)
```csharp
        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```
