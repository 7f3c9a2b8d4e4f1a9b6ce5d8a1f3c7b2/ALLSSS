# Audit Report

## Title
NextRoundMiningOrderValidationProvider Validates Wrong Round Object, Enabling Consensus Manipulation

## Summary
The `NextRoundMiningOrderValidationProvider` contains a critical logic error where it validates `providedRound` (the next round being proposed) instead of `baseRound` (the current round). Since the next round contains freshly generated `MinerInRound` objects with default field values (`FinalOrderOfNextRound=0`, `OutValue=null`), the validation check always evaluates to `0 == 0` and passes. This allows a malicious miner to submit a fabricated `NextRoundInput` with manipulated miner orders, extra block producer designation, or miner list composition, which will be stored as the new consensus state without proper verification.

## Finding Description

The vulnerability exists in the validation logic for round termination transactions. When an honest miner terminates a round, they should respect the `FinalOrderOfNextRound` values that miners established during the current round by producing blocks. The `NextRoundMiningOrderValidationProvider` was intended to enforce this constraint.

**Root Cause:**

The validation provider retrieves the wrong round object for validation: [1](#0-0) 

The `providedRound` comes from `validationContext.ProvidedRound`, which is defined as: [2](#0-1) 

This `ExtraData.Round` represents the NEXT round being proposed, not the current round. When the next round is generated, it creates fresh `MinerInRound` objects: [3](#0-2) 

These fresh objects only contain `Pubkey`, `Order`, `ExpectedMiningTime`, `ProducedBlocks`, and `MissedTimeSlots`. Critically, they do NOT contain `FinalOrderOfNextRound` or `OutValue` fields - these remain at their default values (0 and null).

**Why Current Round Should Be Checked:**

During the current round, miners establish their next-round order by calling UpdateValue, which sets `FinalOrderOfNextRound`: [4](#0-3) 

The validation comment explicitly states it should check the current round: [5](#0-4) 

**Exploitation Path:**

1. The `NextRound` method is publicly accessible: [6](#0-5) 

2. It directly converts and stores the user-provided input: [7](#0-6) 

3. The other validators provide insufficient protection:
   - `RoundTerminateValidationProvider` only checks round number and null InValues: [8](#0-7) 
   
   - `TimeSlotValidationProvider` only checks time slot equality: [9](#0-8) 
   
   - `MiningPermissionValidationProvider` only checks sender is in current round: [10](#0-9) 

A malicious miner can craft a `NextRoundInput` with manipulated orders, designate themselves as extra block producer, or adjust timestamps within valid intervals, and it will pass all validations.

## Impact Explanation

This vulnerability breaks a critical consensus invariant: **miners cannot arbitrarily manipulate their position in the next round**. The impact includes:

1. **Unfair Reward Distribution**: By placing themselves in order 1 or designating themselves as extra block producer, an attacker maximizes their block production opportunities and rewards at the expense of honest miners.

2. **Consensus Centralization**: Repeated exploitation allows one miner to control disproportionate mining slots, reducing network decentralization.

3. **Transaction Ordering Manipulation**: Priority positions enable timing attacks and potential transaction censorship in critical time slots.

4. **Bootstrap Vulnerability**: During initial rounds when monitoring is less established, corrupted consensus state can persist and compound across subsequent rounds.

The severity is HIGH because it directly violates consensus fairness, has immediate economic impact through reward theft, and affects all network participants.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must be an active miner (realistic in a DPoS system)
- Must understand the round structure and protobuf format (moderate technical knowledge)
- Must produce blocks at appropriate timing to trigger round termination

**Attack Complexity:** MEDIUM
- Monitor current round state to extract valid parameters
- Craft `NextRoundInput` with round number = current + 1
- Ensure time slots pass `CheckRoundTimeSlots()` (equal intervals)
- Set all `InValue` fields to null
- Submit with manipulated miner orders or extra block producer

**Feasibility:** HIGH
The validation is completely ineffective (always evaluating `0 == 0`), and no other validators check miner list correctness or order generation logic. The public nature of `NextRound` method combined with ineffective validation makes this readily exploitable.

The probability is HIGH for any round transition and CRITICAL during bootstrap/early rounds when fewer honest miners are monitoring consensus state.

## Recommendation

Fix the validation to check the current round instead of the provided round:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    var baseRound = validationContext.BaseRound; // Use current round, not provided round
    
    // Verify that miners who set FinalOrderOfNextRound in current round
    // match those who produced blocks (have OutValue set)
    var minersWithFinalOrder = baseRound.RealTimeMinersInformation.Values
        .Where(m => m.FinalOrderOfNextRound > 0).Select(m => m.Pubkey).ToHashSet();
    var minersWithOutValue = baseRound.RealTimeMinersInformation.Values
        .Where(m => m.OutValue != null).Select(m => m.Pubkey).ToHashSet();
    
    if (!minersWithFinalOrder.SetEquals(minersWithOutValue))
    {
        validationResult.Message = "Invalid FinalOrderOfNextRound: mismatch with miners who produced blocks.";
        return validationResult;
    }
    
    // Additionally verify that the proposed next round respects these FinalOrderOfNextRound values
    var providedRound = validationContext.ProvidedRound;
    foreach (var minerInBaseRound in baseRound.RealTimeMinersInformation.Values)
    {
        if (minerInBaseRound.FinalOrderOfNextRound > 0)
        {
            var minerPubkey = minerInBaseRound.Pubkey;
            if (!providedRound.RealTimeMinersInformation.ContainsKey(minerPubkey) ||
                providedRound.RealTimeMinersInformation[minerPubkey].Order != minerInBaseRound.FinalOrderOfNextRound)
            {
                validationResult.Message = $"Miner {minerPubkey} order does not match FinalOrderOfNextRound.";
                return validationResult;
            }
        }
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test chain with multiple miners
2. Allowing miners to establish `FinalOrderOfNextRound` values during a normal round via UpdateValue transactions
3. Having a malicious miner submit a `NextRound` transaction with:
   - Swapped miner orders (e.g., placing themselves as order 1 instead of their assigned order)
   - Modified extra block producer designation
4. Observing that the transaction succeeds despite violating established miner orders
5. Verifying that the manipulated round structure is stored in state

The core issue is verified by examining the validation logic which checks fresh `MinerInRound` objects with default values, causing `distinctCount == 0` and `count(OutValue != null) == 0` to always satisfy the equality check.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L11-12)
```csharp
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L14-17)
```csharp
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ConsensusValidationContext.cs (L27-27)
```csharp
    public Round ProvidedRound => ExtraData.Round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L161-166)
```csharp
    public override Empty NextRound(NextRoundInput input)
    {
        SupplyCurrentRoundInformation();
        ProcessConsensusInformation(input);
        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-57)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```
