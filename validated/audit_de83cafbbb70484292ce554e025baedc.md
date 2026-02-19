# Audit Report

## Title
Incomplete Secret Sharing State Validation Allows Consensus Manipulation via Injected NextRound Data

## Summary
The `ValidationForNextRound()` function only validates that `InValue` is null for miners in the next round, but fails to verify that other secret sharing fields (`OutValue`, `Signature`, `EncryptedPieces`, `DecryptedPieces`, `PreviousInValue`) are also in their initial null/empty state. This allows a malicious extra block producer to inject fake secret sharing data into the next round, compromising consensus randomness and mining order determination.

## Finding Description

The vulnerability exists in the round termination validation logic. The validation only checks that `InValue` is null but the `MinerInRound` protobuf message contains multiple secret sharing fields that should also be validated: [1](#0-0) [2](#0-1) 

When `NextRound` is called, the `NextRoundInput` is directly converted to `Round` via `ToRound()` without sanitization: [3](#0-2) [4](#0-3) 

The converted round is then stored directly in state: [5](#0-4) 

A legitimately generated next round only initializes basic fields and leaves all secret sharing fields null/empty: [6](#0-5) 

However, injected fake data is subsequently used in consensus operations:

1. **RevealSharedInValues** reads `DecryptedPieces` from the previous round to reconstruct `PreviousInValue`: [7](#0-6) 

2. **CalculateNextExtraBlockProducerOrder** uses `Signature` to determine the extra block producer: [8](#0-7) 

When generating the next round, this method looks for the first miner (by Order) with a non-null Signature. By injecting fake Signatures for miners who don't mine, an attacker can control which Signature value is used for extra block producer selection, as the fake Signature would be found before legitimate miners' Signatures.

## Impact Explanation

The vulnerability enables a malicious extra block producer to manipulate consensus integrity through two primary attack vectors:

1. **Bias Extra Block Producer Selection**: By injecting a specific `Signature` value for miners with low order numbers who may not mine in the round, the attacker can influence `CalculateNextExtraBlockProducerOrder()` to use the fake Signature instead of legitimate miners' Signatures. This determines which miner becomes the extra block producer for the subsequent round, allowing potential collusion or strategic positioning.

2. **Manipulate Consensus Randomness**: By injecting coordinated fake `DecryptedPieces` data, the attacker can control what `PreviousInValue` gets revealed for miners through `RevealSharedInValues()`. Since `InValue` is the foundation of consensus randomness in the secret sharing protocol, this breaks the unpredictability guarantees.

The severity is **High** because it directly compromises consensus integrity, a critical invariant of the blockchain. While it doesn't immediately steal funds, it enables manipulation of block production, which could be leveraged for secondary attacks like MEV extraction, targeted censorship of transactions, or favorable block production scheduling.

## Likelihood Explanation

**Attacker Capabilities**: The attacker must be an active miner who becomes the extra block producer for a round. Since extra block producer selection rotates based on consensus mechanisms, any malicious miner will periodically obtain this role.

**Attack Complexity**: Low to Medium
- The attacker only needs to craft a malicious `NextRoundInput` with fake secret sharing data
- The entry point is the public `NextRound` method which is called by extra block producers
- No complex cryptographic operations or timing attacks required

**Feasible Preconditions**:
- Attacker is part of the active miner set (realistic for a motivated adversary)
- Attacker's turn to produce the extra block (happens regularly in rotation)
- No additional permissions or compromised keys needed beyond normal miner status

The likelihood is **High** because the attack is straightforward, requires only standard miner privileges, and has multiple opportunities for execution.

## Recommendation

Extend the `ValidationForNextRound()` method to validate that ALL secret sharing fields are in their initial null/empty state, not just `InValue`. The validation should check:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Validate all secret sharing fields are null/empty
    foreach (var miner in extraData.Round.RealTimeMinersInformation.Values)
    {
        if (miner.InValue != null)
            return new ValidationResult { Message = "InValue must be null in next round." };
        if (miner.OutValue != null)
            return new ValidationResult { Message = "OutValue must be null in next round." };
        if (miner.Signature != null)
            return new ValidationResult { Message = "Signature must be null in next round." };
        if (miner.PreviousInValue != null)
            return new ValidationResult { Message = "PreviousInValue must be null in next round." };
        if (miner.EncryptedPieces.Count > 0)
            return new ValidationResult { Message = "EncryptedPieces must be empty in next round." };
        if (miner.DecryptedPieces.Count > 0)
            return new ValidationResult { Message = "DecryptedPieces must be empty in next round." };
    }

    return new ValidationResult { Success = true };
}
```

## Proof of Concept

A proof of concept would require setting up an AElf testnet with multiple miners and demonstrating:

1. Attacker becomes extra block producer for round N
2. Attacker crafts a `NextRoundInput` for round N+1 with:
   - Legitimate basic fields (Pubkey, Order, ExpectedMiningTime, etc.)
   - Fake `Signature` value for miner at order 1 (e.g., a controlled hash)
   - Fake `DecryptedPieces` for multiple miners
3. Call `NextRound` with this malicious input
4. Observe that validation passes (only `InValue` is checked)
5. Round N+1 is stored with the fake data
6. When round N+2 is generated, verify that:
   - `CalculateNextExtraBlockProducerOrder()` uses the fake Signature
   - The resulting extra block producer order is different from what it would be with legitimate data
   - This demonstrates the attacker's ability to manipulate consensus

The test would need access to the contract's internal state to verify the fake data was stored and used in subsequent calculations.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-123)
```csharp
    private int CalculateNextExtraBlockProducerOrder()
    {
        var firstPlaceInfo = RealTimeMinersInformation.Values.OrderBy(m => m.Order)
            .FirstOrDefault(m => m.Signature != null);
        if (firstPlaceInfo == null)
            // If no miner produce block during this round, just appoint the first miner to be the extra block producer of next round.
            return 1;

        var signature = firstPlaceInfo.Signature;
        var sigNum = signature.ToInt64();
        var blockProducerCount = RealTimeMinersInformation.Count;
        var order = GetAbsModulus(sigNum, blockProducerCount) + 1;
        return order;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L13-54)
```csharp
    private void RevealSharedInValues(Round currentRound, string publicKey)
    {
        Context.LogDebug(() => "About to reveal shared in values.");

        if (!currentRound.RealTimeMinersInformation.ContainsKey(publicKey)) return;

        if (!TryToGetPreviousRoundInformation(out var previousRound)) return;

        var minersCount = currentRound.RealTimeMinersInformation.Count;
        var minimumCount = minersCount.Mul(2).Div(3);
        minimumCount = minimumCount == 0 ? 1 : minimumCount;

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
    }
```
