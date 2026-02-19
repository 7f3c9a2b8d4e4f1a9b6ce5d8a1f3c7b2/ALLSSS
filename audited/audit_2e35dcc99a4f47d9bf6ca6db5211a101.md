### Title
Incomplete Secret Sharing State Validation Allows Consensus Manipulation via Injected NextRound Data

### Summary
The `ValidationForNextRound()` function only validates that `InValue` is null for miners in the next round, but fails to verify that other secret sharing fields (`OutValue`, `Signature`, `EncryptedPieces`, `DecryptedPieces`, `PreviousInValue`) are also in their initial null/empty state. This allows a malicious extra block producer to inject fake secret sharing data into the next round, compromising consensus randomness and mining order determination.

### Finding Description

The vulnerability exists in the round termination validation logic: [1](#0-0) 

The validation only checks that `InValue` is null (line 32), but the `MinerInRound` protobuf message contains multiple secret sharing fields: [2](#0-1) 

When `NextRound` is called, the `NextRoundInput` is directly converted to `Round` via `ToRound()` without sanitization: [3](#0-2) 

The converted round is then stored directly in state: [4](#0-3) [5](#0-4) 

A legitimately generated next round only initializes basic fields and leaves all secret sharing fields null/empty: [6](#0-5) 

However, injected fake data is subsequently used in consensus operations:

1. **RevealSharedInValues** reads `DecryptedPieces` from the previous round to reconstruct `PreviousInValue`: [7](#0-6) 

2. **CalculateNextExtraBlockProducerOrder** uses `Signature` to determine the extra block producer: [8](#0-7) 

3. **ApplyNormalConsensusData** uses `Signature` to calculate mining order for subsequent rounds: [9](#0-8) 

### Impact Explanation

The vulnerability enables a malicious extra block producer to:

1. **Manipulate Consensus Randomness**: By injecting coordinated fake `OutValue` and `DecryptedPieces` data, the attacker can control what `PreviousInValue` gets revealed for miners in subsequent rounds. Since `InValue` is the foundation of consensus randomness, this breaks the unpredictability guarantees of the secret sharing protocol.

2. **Bias Extra Block Producer Selection**: By injecting a specific `Signature` value in round N, the attacker can influence the calculation of `CalculateNextExtraBlockProducerOrder()` in round N+1, potentially ensuring a chosen miner (possibly themselves or a colluding party) becomes the extra block producer.

3. **Manipulate Mining Order**: The injected `Signature` also affects `SupposedOrderOfNextRound` calculation, allowing the attacker to influence which miners get favorable time slots in future rounds.

4. **Protocol Integrity Violation**: The secret sharing scheme is designed to ensure that no single party can manipulate or predict the shared secrets. This vulnerability completely bypasses that security model by allowing arbitrary secret sharing state to be injected.

The severity is **High** because it directly compromises consensus integrity, a critical invariant of the blockchain. While it doesn't immediately steal funds, it enables manipulation of block production, which could be leveraged for secondary attacks like MEV extraction, targeted censorship of transactions, or setting up conditions for double-spend attacks.

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be an active miner who becomes the extra block producer for a round. Since extra block producer selection rotates based on consensus mechanisms, any malicious miner will periodically obtain this role.

**Attack Complexity**: Low to Medium
- The attacker only needs to craft a malicious `NextRoundInput` with fake secret sharing data
- The entry point is the public `NextRound` method which is called by extra block producers
- No complex cryptographic operations or timing attacks required

**Feasible Preconditions**:
- Attacker is part of the active miner set (realistic for a motivated adversary)
- Attacker's turn to produce the extra block (happens regularly in rotation)
- No additional permissions or compromised keys needed beyond normal miner status

**Detection Difficulty**: The injected fake data would be stored in the blockchain state and appear in the `Round` structure. However, distinguishing legitimate from malicious data without the validation checks is difficult, especially since the fields could contain plausible-looking hash values.

**Economic Rationality**: The attack cost is minimal (just the transaction fee for calling NextRound). The potential gains from manipulating consensus could be substantial through MEV opportunities, favorable block production slots, or strategic transaction ordering.

The likelihood is **High** because the attack is straightforward, requires only standard miner privileges, and has multiple opportunities for execution.

### Recommendation

**Immediate Fix**: Extend the validation in `ValidationForNextRound()` to verify ALL secret sharing fields are in their initial state:

```csharp
private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
        return new ValidationResult { Message = "Incorrect round number for next round." };

    // Verify all secret sharing fields are null/empty for next round
    foreach (var minerInfo in extraData.Round.RealTimeMinersInformation.Values)
    {
        if (minerInfo.InValue != null)
            return new ValidationResult { Message = "InValue must be null in next round." };
        
        if (minerInfo.OutValue != null)
            return new ValidationResult { Message = "OutValue must be null in next round." };
        
        if (minerInfo.Signature != null)
            return new ValidationResult { Message = "Signature must be null in next round." };
        
        if (minerInfo.PreviousInValue != null)
            return new ValidationResult { Message = "PreviousInValue must be null in next round." };
        
        if (minerInfo.EncryptedPieces != null && minerInfo.EncryptedPieces.Count > 0)
            return new ValidationResult { Message = "EncryptedPieces must be empty in next round." };
        
        if (minerInfo.DecryptedPieces != null && minerInfo.DecryptedPieces.Count > 0)
            return new ValidationResult { Message = "DecryptedPieces must be empty in next round." };
    }

    return new ValidationResult { Success = true };
}
```

**Additional Safeguards**:
1. Add similar validation for `NextTerm` behavior
2. Add invariant checks in `AddRoundInformation` to prevent storing rounds with unexpected secret sharing state
3. Add comprehensive unit tests that attempt to inject each type of fake secret sharing data and verify rejection

**Test Cases**:
- Test NextRound with non-null OutValue → should be rejected
- Test NextRound with non-empty EncryptedPieces → should be rejected  
- Test NextRound with non-empty DecryptedPieces → should be rejected
- Test NextRound with non-null Signature → should be rejected
- Test NextRound with non-null PreviousInValue → should be rejected
- Test legitimate NextRound with all fields null/empty → should be accepted

### Proof of Concept

**Initial State**: 
- Blockchain at round N with normal consensus operations
- Malicious miner M is the extra block producer of round N

**Attack Steps**:

1. **Craft Malicious NextRoundInput**: Miner M generates the next round information but injects fake secret sharing data:
   ```
   NextRoundInput:
     - RoundNumber: N+1
     - For each miner in next round:
       * InValue: null (passes validation)
       * OutValue: Hash("fake_out_value_X")  ← INJECTED
       * Signature: Hash("fake_signature_X")  ← INJECTED
       * EncryptedPieces: { "minerA": 0x1234... }  ← INJECTED
       * DecryptedPieces: { "minerB": 0x5678... }  ← INJECTED
   ```

2. **Submit Transaction**: Miner M calls `NextRound(maliciousNextRoundInput)`

3. **Validation Bypass**: The validation at line 32 only checks InValue == null, which passes. All other injected fields are not validated.

4. **State Storage**: The malicious round data is converted via `ToRound()` and stored in `State.Rounds[N+1]`

5. **Exploitation in Round N+2**: 
   - When miners produce blocks in round N+2, `RevealSharedInValues` reads from round N+1
   - It uses the fake `DecryptedPieces` to reconstruct fake `PreviousInValue` for miners
   - `CalculateNextExtraBlockProducerOrder` uses the fake `Signature` from round N+1 to select extra block producer for round N+2
   - Mining order calculations use the fake signatures, giving attacker influence over consensus

**Expected Result**: Validation should reject the NextRoundInput for containing non-null secret sharing fields

**Actual Result**: Validation passes, malicious data is stored, and subsequently used in consensus operations, allowing attacker to manipulate randomness and mining order

**Success Condition**: The attack succeeds if the malicious NextRoundInput is accepted and stored with fake secret sharing data that influences subsequent consensus rounds.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L99-115)
```csharp
    /// <summary>
    ///     Will force to generate a `Change` to tx executing result.
    /// </summary>
    /// <param name="round"></param>
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L25-56)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-47)
```csharp
    public Round ApplyNormalConsensusData(string pubkey, Hash previousInValue, Hash outValue, Hash signature)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey)) return this;

        RealTimeMinersInformation[pubkey].OutValue = outValue;
        RealTimeMinersInformation[pubkey].Signature = signature;
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;

        var minersCount = RealTimeMinersInformation.Count;
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

        return this;
    }
```
