# Audit Report

## Title
Mining Order Manipulation via Incomplete NextRound Validation

## Summary
The AEDPoS consensus contract fails to validate that the `Order` field in the next round correctly corresponds to miners' cryptographically-determined `FinalOrderOfNextRound` values from the current round. A malicious block producer can arbitrarily manipulate the mining order to control block production sequence, bypassing the intended randomness-based ordering mechanism and gaining unfair rewards.

## Finding Description

The vulnerability exists in the validation logic for NextRound transitions. When a miner produces a block to transition to the next round, the validation critically fails to verify mining order integrity through cross-round comparison.

**Broken Validation Logic:**

The `NextRoundMiningOrderValidationProvider` checks that the count of miners with `FinalOrderOfNextRound > 0` equals the count with `OutValue != null` in the **provided round** (which is the next round being proposed). [1](#0-0) 

However, in a properly-generated next round, both `FinalOrderOfNextRound` and `OutValue` should be 0/null for all miners since they haven't mined yet in that round. This means the validation always passes trivially (0 == 0) and validates nothing meaningful about the `Order` field assignment.

**Expected Behavior:**

The legitimate `GenerateNextRoundInformation` method demonstrates how the next round should be constructed - it sets each miner's `Order` in the next round based on their `FinalOrderOfNextRound` from the current round. [2](#0-1) 

**Missing Validation:**

No validation enforces this critical mapping. The validation context provides both `BaseRound` (current round) and `ProvidedRound` (next round) for comparison. [3](#0-2) 

However, `NextRoundMiningOrderValidationProvider` never performs cross-round validation to verify that `ProvidedRound.Order` matches `BaseRound.FinalOrderOfNextRound`.

**Order Field Determines Mining Sequence:**

The `CheckRoundTimeSlots` method validates that mining intervals are consistent when miners are ordered by the `Order` field. [4](#0-3) 

However, it does **not** validate that `Order` values themselves are correct or match the cryptographically-determined assignments from the previous round.

**Direct Storage Without Re-validation:**

The `ProcessNextRound` method directly converts the `NextRoundInput` to a `Round` object and stores it without re-validating or regenerating the Order assignments. [5](#0-4) 

The `AddRoundInformation` method simply stores the round data directly to state without any validation. [6](#0-5) 

**Attack Execution:**

A malicious miner selected to produce the NextRound block can:
1. Call `GetConsensusExtraDataForNextRound` to generate the legitimate next round structure [7](#0-6) 
2. Modify the `Order` field for each miner (e.g., set their own Order=1)
3. Recalculate `ExpectedMiningTime` values to maintain consistent intervals
4. Keep `FinalOrderOfNextRound=0` and `OutValue=null` as expected for a new round
5. Submit the modified round data

The validation flow adds `NextRoundMiningOrderValidationProvider` for NextRound behavior. [8](#0-7) 

But all validation checks pass despite the Order manipulation because no validator compares against the current round's `FinalOrderOfNextRound` values.

## Impact Explanation

**Critical Consensus Integrity Violation:**

Mining order in AEDPoS is cryptographically determined through signature-based randomness. During the current round, each miner's `FinalOrderOfNextRound` is calculated from their signature hash. [9](#0-8) 

This randomness ensures fair mining distribution. By manipulating the `Order` field, an attacker completely bypasses this security property.

**Concrete Attack Scenarios:**
1. **First-Miner Advantage:** Attacker sets their Order to 1, mining first in the next round to maximize block production rewards and MEV opportunities
2. **Targeted Disadvantaging:** Attacker assigns unfavorable positions to competing miners to reduce their block production opportunities
3. **Extra Block Producer Manipulation:** The extra block producer is calculated based on mining order, enabling additional reward manipulation

**Affected Parties:**
- All honest miners who are assigned incorrect mining positions
- The network due to compromised consensus fairness
- Token holders whose rewards depend on fair mining distribution

**Severity: CRITICAL** - This breaks a fundamental consensus invariant and enables direct reward theft through preferential positioning.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an active block producer/miner in the current round
- Must be selected to produce the block that triggers NextRound transition (happens regularly in miner rotation)
- Standard mining node capabilities - no special privileges needed beyond normal miner role

**Attack Complexity: LOW**

The attack requires only simple field manipulation:
1. Obtain legitimate next round structure via `GetConsensusExtraDataForNextRound`
2. Modify Order fields to desired values
3. Recalculate ExpectedMiningTime values (simple arithmetic)
4. Submit the modified round

**Feasibility:**
- Attacker selection for NextRound block production happens regularly in rotation
- No external monitoring exists to detect Order manipulation before storage
- The validation passes all checks as demonstrated in code analysis

**Detection Difficulty:**
Low - manipulation is stored on-chain and observable, but requires comparing current round's `FinalOrderOfNextRound` to next round's `Order`, which normal monitoring may not check.

**Economic Rationality:**
Highly profitable - first mining position grants additional blocks, rewards, and MEV opportunities. Cost is zero beyond normal mining operations.

**Probability: HIGH** - Attack is practical, repeatable, and profitable for any malicious miner.

## Recommendation

Add cross-round validation in `NextRoundMiningOrderValidationProvider` to verify that the `Order` field in the next round matches the `FinalOrderOfNextRound` values from the current round:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var providedRound = validationContext.ProvidedRound;
    var baseRound = validationContext.BaseRound;
    
    // Verify that Order in next round matches FinalOrderOfNextRound in current round
    foreach (var miner in baseRound.RealTimeMinersInformation)
    {
        var pubkey = miner.Key;
        var currentRoundMiner = miner.Value;
        
        // If miner mined in current round, verify their order assignment
        if (currentRoundMiner.FinalOrderOfNextRound > 0)
        {
            if (!providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            {
                validationResult.Message = $"Miner {pubkey} missing in next round.";
                return validationResult;
            }
            
            var nextRoundMiner = providedRound.RealTimeMinersInformation[pubkey];
            if (nextRoundMiner.Order != currentRoundMiner.FinalOrderOfNextRound)
            {
                validationResult.Message = $"Invalid Order for miner {pubkey}. Expected {currentRoundMiner.FinalOrderOfNextRound}, got {nextRoundMiner.Order}.";
                return validationResult;
            }
        }
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

## Proof of Concept

A test demonstrating the vulnerability would:
1. Setup a current round with miners having `FinalOrderOfNextRound` values set
2. Create a malicious NextRoundInput with manipulated `Order` fields
3. Submit the NextRound transaction
4. Verify that validation passes despite the manipulation
5. Confirm the manipulated order is stored in state

The test would show that a miner can arbitrarily set their own `Order=1` in the next round, even when their `FinalOrderOfNextRound` in the current round was a different value, and all validations pass successfully.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L15-21)
```csharp
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L22-27)
```csharp
    public Round BaseRound { get; set; }

    /// <summary>
    ///     Round information included in the consensus header extra data.
    /// </summary>
    public Round ProvidedRound => ExtraData.Round;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-124)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);

        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });

        // Only clear old round information when the mining status is Normal.
        var roundNumberToRemove = round.RoundNumber.Sub(AEDPoSContractConstants.KeepRounds);
        if (
            roundNumberToRemove >
            1 && // Which means we won't remove the information of the first round of first term.
            GetMaximumBlocksCount() == AEDPoSContractConstants.MaximumTinyBlocksCount)
            State.Rounds.Remove(roundNumberToRemove);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
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

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-44)
```csharp
        var sigNum = signature.ToInt64();

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
