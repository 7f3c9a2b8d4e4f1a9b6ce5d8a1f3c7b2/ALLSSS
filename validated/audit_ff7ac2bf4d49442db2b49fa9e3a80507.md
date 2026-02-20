# Audit Report

## Title
Missing Miner List Validation in NextRound/NextTerm Enables Consensus DoS via Bloated RealTimeMinersInformation Dictionary

## Summary
The AEDPoS consensus contract fails to validate that the miner list in submitted `NextRound` or `NextTerm` inputs matches the current round's miner list. A malicious miner can inject a `Round` object with an arbitrarily large `RealTimeMinersInformation` dictionary, causing excessive gas consumption during subsequent consensus operations and leading to denial of service.

## Finding Description

The consensus contract's validation system for `NextRound` behavior does not verify that the miner keys in the provided round match the current round's miner keys. [1](#0-0) 

The validation only includes `NextRoundMiningOrderValidationProvider` which validates internal consistency within the provided round: [2](#0-1) 

And `RoundTerminateValidationProvider` which only checks round number increment and InValue nullness: [3](#0-2) 

Neither validator compares `providedRound.RealTimeMinersInformation.Keys` against `baseRound.RealTimeMinersInformation.Keys`.

The `NextRoundInput.ToRound()` method directly copies the `RealTimeMinersInformation` dictionary without filtering: [4](#0-3) 

The bloated round is then stored directly to state without validation: [5](#0-4) 

When subsequent miners produce blocks, `RevealSharedInValues` iterates through the entire bloated `previousRound.RealTimeMinersInformation` dictionary with OrderBy and nested `First()` searches: [6](#0-5) 

The bloat persists across rounds because `GenerateNextRoundInformation` derives the next round from the current round's miner information: [7](#0-6) 

Fake miners with `SupposedOrderOfNextRound == 0` are included in `GetNotMinedMiners()` and propagated to subsequent rounds: [8](#0-7) 

## Impact Explanation

This vulnerability enables a **consensus-level denial of service attack**:

1. **Excessive Gas Consumption**: The O(n*m) complexity in `RevealSharedInValues` with nested `First()` calls causes exponential gas consumption as the bloated dictionary size increases

2. **Blocked Round Transitions**: Legitimate miners cannot successfully produce NextRound blocks due to gas exhaustion, preventing consensus progression

3. **Persistent Disruption**: The malicious miner list propagates to all subsequent rounds within the term through `GenerateNextRoundInformation`, creating sustained disruption until a `NextTerm` transition occurs

4. **Critical Invariant Violation**: The consensus system's fundamental assumption that `RealTimeMinersInformation` contains only legitimate current miners is violated, compromising consensus integrity

Even moderate dictionary inflation (100-1000 fake entries) could cause significant performance degradation while potentially fitting within transaction size limits given minimal data per entry.

## Likelihood Explanation

**High Likelihood** - The attack is straightforward and within the consensus threat model:

1. **Attacker Profile**: Any current miner with block production rights can execute this attack, which is explicitly within the threat model for malicious authorized participants

2. **Low Complexity**: The attacker simply crafts a `NextRoundInput` with inflated `RealTimeMinersInformation` and includes it in their block through the consensus extra data mechanism

3. **No Protection**: Zero validation exists to prevent this - the contract trusts block producers to provide legitimate miner lists without verification

4. **Practical Feasibility**: While transaction size limits provide some bound, protobuf's compact map encoding allows hundreds of fake miner entries within reasonable transaction sizes

## Recommendation

Add explicit miner list composition validation in the `NextRound` and `NextTerm` validation paths:

1. Create a new validator `MinerListCompositionValidationProvider` that checks:
   - `providedRound.RealTimeMinersInformation.Keys.Count() == baseRound.RealTimeMinersInformation.Keys.Count()`
   - All keys in `providedRound.RealTimeMinersInformation.Keys` exist in `baseRound.RealTimeMinersInformation.Keys`

2. Add this validator to the validation chain in `ValidateBeforeExecution` for both `NextRound` and `NextTerm` behaviors

3. For `NextTerm`, validate that the provided miner list matches the election results from the Election contract

4. Consider adding explicit assertions in `AddRoundInformation` that validate miner count does not exceed `MaximumMinersCount` and keys match expected miners

## Proof of Concept

A proof of concept would demonstrate:
1. Creating a malicious NextRoundInput with 100+ fake miner entries in RealTimeMinersInformation
2. Submitting this through a NextRound transaction from a legitimate miner
3. Observing successful validation and storage of the bloated round
4. Measuring gas consumption in subsequent RevealSharedInValues calls showing exponential growth
5. Demonstrating that legitimate NextRound block production fails due to gas limits

The core vulnerability is the complete absence of miner list composition validation between the provided round and current round in the consensus validation system.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L84-87)
```csharp
            case AElfConsensusBehaviour.NextRound:
                // Is sender's order of next round correct?
                validationProviders.Add(new NextRoundMiningOrderValidationProvider());
                validationProviders.Add(new RoundTerminateValidationProvider());
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L29-34)
```csharp
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L25-53)
```csharp
        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();

            var sharedParts = anotherMinerInPreviousRound.DecryptedPieces.Values.ToList()
                .Select(s => s.ToByteArray()).ToList();

            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-56)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L131-135)
```csharp
    private List<MinerInRound> GetNotMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound == 0).ToList();
    }
```
