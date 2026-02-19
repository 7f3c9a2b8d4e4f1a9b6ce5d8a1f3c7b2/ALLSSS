# Audit Report

## Title
Missing Miner Order Validation in NextTerm Allows Mining Schedule Manipulation

## Summary
The AEDPoS consensus contract lacks validation of miner `Order` values during NextTerm transitions. While the protocol expects deterministic Order assignment based on public key sorting, the validation flow does not verify this constraint. A malicious miner proposing a NextTerm block can manipulate Order values to favor their mining schedule, violating consensus integrity.

## Finding Description

The AEDPoS consensus mechanism assigns miner orders deterministically by sorting miners by the first byte of their public key in descending order. [1](#0-0) 

However, when a miner proposes a NextTerm block, the `NextTermInput.Create()` method simply copies the `RealTimeMinersInformation` without any validation. [2](#0-1) 

During validation, the `ValidateBeforeExecution` method for NextTerm behavior only adds `RoundTerminateValidationProvider` beyond basic validators. [3](#0-2) 

Critically, `RoundTerminateValidationProvider` only validates round and term number progression, NOT the Order values. [4](#0-3) 

The `TimeSlotValidationProvider` checks time slot spacing using the PROVIDED Order values without verifying they match the expected deterministic assignment. [5](#0-4) 

Notably, NextRound behavior includes `NextRoundMiningOrderValidationProvider` for order validation, [6](#0-5)  but NextTerm does not have equivalent Order validation despite also requiring deterministic Order assignment.

The consensus extra data is generated correctly in `GetConsensusExtraDataForNextTerm`, [7](#0-6)  but a malicious miner running modified node software can alter the Order values before including them in the block header. When other nodes validate the block, they do not regenerate the expected Round and compare Order values.

Finally, `ProcessNextTerm` directly uses the provided Round without additional Order validation. [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This vulnerability breaks fundamental consensus assumptions:

1. **Mining Schedule Integrity Violated**: Attackers can swap Order values to assign themselves earlier mining positions (e.g., Order 1 instead of Order 7), gaining unfair advantage in block production sequence.

2. **Consensus Determinism Broken**: The protocol's deterministic Order assignment based on public key sorting is bypassed, allowing arbitrary scheduling.

3. **Repeated Exploitation**: The attack can be executed at every term transition (typically every 7 days), providing persistent advantage.

4. **Network-Wide Impact**: All network participants are affected as the mining schedule governs when each miner produces blocks, impacting transaction ordering, MEV opportunities, and block rewards.

5. **Validation Asymmetry**: The existence of order validation for NextRound but not NextTerm suggests this is an oversight rather than intentional design, indicating the validation gap is a genuine security issue.

## Likelihood Explanation

**MODERATE-HIGH Likelihood**:

1. **Accessible Precondition**: Any current miner has the opportunity to exploit this during their turn to propose the NextTerm block, which occurs periodically in the consensus rotation.

2. **Technical Feasibility**: While exploitation requires running modified node software to alter consensus extra data before block inclusion, this is within the capabilities of sophisticated mining operators.

3. **Low Detection Risk**: The malicious Order values pass all existing validation checks. There is no mechanism to detect that Order values don't match the expected deterministic assignment.

4. **Economic Incentive**: Miners have strong motivation to gain favorable mining positions for increased block rewards and MEV extraction opportunities.

5. **Regular Opportunity**: Term transitions occur regularly (default ~7 days), providing repeated exploitation windows.

## Recommendation

Add Order validation for NextTerm similar to how NextRound has mining order validation. Implement a validator that:

1. Regenerates the expected miner list from the Election contract (via `TryToGetVictories`)
2. Sorts miners by first byte of public key in descending order
3. Verifies that each miner's Order value in the provided Round matches the expected deterministic position
4. Rejects blocks where Order values don't match the expected sequence

Example validation logic:
```csharp
public class NextTermMinerOrderValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var providedRound = validationContext.ProvidedRound;
        
        // Get expected miner list and generate expected order
        var expectedMinerList = GetExpectedMinersForNextTerm();
        var expectedRound = expectedMinerList.GenerateFirstRoundOfNewTerm(...);
        
        // Verify each miner's Order matches expected
        foreach (var miner in providedRound.RealTimeMinersInformation)
        {
            if (!expectedRound.RealTimeMinersInformation.ContainsKey(miner.Key) ||
                expectedRound.RealTimeMinersInformation[miner.Key].Order != miner.Value.Order)
            {
                return new ValidationResult { Message = "Invalid miner Order in NextTerm" };
            }
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Then add this validator to the NextTerm validation flow in `ValidateBeforeExecution`.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test network with multiple miners
2. Modifying a miner's node to alter Order values in the NextTerm consensus extra data before block production
3. Broadcasting the block with manipulated Order values
4. Observing that the block passes validation and is accepted by the network
5. Confirming the manipulated Order values are stored in state, corrupting the mining schedule

The test would verify that:
- `NextTermInput.Create()` accepts arbitrary Order values without validation
- `ValidateBeforeExecution` for NextTerm passes despite incorrect Order values
- `ProcessNextTerm` applies the manipulated Order values to state
- Subsequent mining follows the manipulated schedule rather than the deterministic schedule

This demonstrates that no code path validates Order correctness during NextTerm, allowing mining schedule manipulation.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-46)
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
