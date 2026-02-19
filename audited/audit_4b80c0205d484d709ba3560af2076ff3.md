### Title
Missing On-Chain Validation of SupposedOrderOfNextRound Allows Miners to Manipulate Next Round Position

### Summary
The `SupposedOrderOfNextRound` field in `UpdateValueInput` is not validated on-chain against the deterministic calculation formula. Miners can provide arbitrary order values that are accepted without verification, allowing them to manipulate their position in the next round and break the fairness of the consensus ordering mechanism.

### Finding Description

The vulnerability exists in the consensus update validation flow. The `supposedOrderOfNextRound` is calculated off-chain using the formula at [1](#0-0) , but this calculation is never verified on-chain.

**Root Cause:**

When miners submit their consensus data via `UpdateValue`, the validation only checks `OutValue`, `Signature`, and `PreviousInValue` at [2](#0-1) . The `SupposedOrderOfNextRound` field is completely trusted without recalculation.

**Why Protections Fail:**

1. **No recalculation during validation**: The validation providers in [3](#0-2)  do not include any check that recalculates or verifies the `SupposedOrderOfNextRound` value against the signature.

2. **Direct state update without verification**: The `ProcessUpdateValue` function at [4](#0-3)  directly assigns the provided `SupposedOrderOfNextRound` to state without any validation.

3. **Circular validation in after-execution check**: The `RecoverFromUpdateValue` method at [5](#0-4)  copies the order values from the provided round without validation, creating a circular check where the system validates that the state matches the header, but both were derived from the same unvalidated input.

4. **Next round generation uses manipulated values**: The next round order is determined by `FinalOrderOfNextRound` values at [6](#0-5) , which are set from the unvalidated `SupposedOrderOfNextRound`.

### Impact Explanation

**Consensus Integrity Violation:**

Miners can arbitrarily choose their position in the next mining round, completely breaking the deterministic and fair ordering mechanism that is fundamental to the AEDPoS consensus. A malicious miner can:

1. Always position themselves first (order = 1) to maximize MEV extraction opportunities
2. Coordinate with other malicious miners to arrange favorable consecutive positions
3. Use `TuneOrderInformation` to push honest miners to unfavorable positions
4. Gain unfair advantages in block production timing

**Who Is Affected:**

- All honest miners lose the fair randomness guarantee of mining order
- Users suffer from potential MEV extraction and censorship
- The blockchain's consensus fairness and security guarantees are compromised

**Severity Justification:**

This is a **High severity** vulnerability because it directly violates the consensus integrity invariant. While it doesn't lead to direct fund theft, it undermines the fundamental fairness of the consensus mechanism, which is critical for blockchain security. The last miner(s) in each round have maximum control to set the order for the entire next round.

### Likelihood Explanation

**Attacker Capabilities:**

Any miner can exploit this vulnerability by simply modifying the `SupposedOrderOfNextRound` field in their consensus extra data generation. The attacker needs:
- Standard miner infrastructure (already possessed)
- Ability to modify off-chain consensus data generation logic
- No special privileges beyond being an active miner

**Attack Complexity:**

The attack is straightforward:
1. Generate valid signature (normal operation)
2. Modify `SupposedOrderOfNextRound` to desired value
3. Submit `UpdateValue` transaction
4. Validation passes (only checks signature, not order)

**Feasibility Conditions:**

- Miners near the end of the current round have more control (later transactions override earlier ones)
- Single malicious miner can manipulate their own position
- Colluding miners can arrange arbitrary ordering
- No detection mechanism exists to identify this manipulation

**Economic Rationality:**

The attack cost is negligible (standard block production cost), while benefits include:
- MEV extraction from favorable positions
- Censorship capabilities through position control
- Competitive advantages in transaction ordering

### Recommendation

**Code-Level Mitigation:**

Add on-chain validation to recalculate and verify `SupposedOrderOfNextRound` in the `UpdateValueValidationProvider`:

```csharp
// In UpdateValueValidationProvider.ValidateHeaderInformation()
private bool ValidateSupposedOrderOfNextRound(ConsensusValidationContext validationContext)
{
    var minerInRound = validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
    
    // Recalculate expected order
    var signature = minerInRound.Signature;
    var sigNum = signature.ToInt64();
    var minersCount = validationContext.PreviousRound.RealTimeMinersInformation.Count;
    var expectedOrder = GetAbsModulus(sigNum, minersCount) + 1;
    
    // Verify provided value matches expected calculation
    if (minerInRound.SupposedOrderOfNextRound != expectedOrder)
    {
        return false;
    }
    
    return true;
}
```

**Invariant Checks:**

Add validation at [7](#0-6)  to include the order calculation check before returning success.

**Test Cases:**

Add regression tests that verify:
1. Correct `SupposedOrderOfNextRound` is accepted
2. Incorrect `SupposedOrderOfNextRound` is rejected
3. Modified order values fail validation
4. TuneOrderInformation conflicts are properly validated

### Proof of Concept

**Required Initial State:**
- Active consensus round with multiple miners
- Attacker is an active miner in current round

**Transaction Steps:**

1. **Normal consensus extra data generation**:
   - Attacker generates valid signature as per [8](#0-7) 
   - Signature calculation: `previousRound.CalculateSignature(previousInValue)`
   - Expected order would be: `(signature % minersCount) + 1`

2. **Malicious modification**:
   - Instead of using calculated order (e.g., 5), attacker sets `SupposedOrderOfNextRound = 1`
   - Crafts `TuneOrderInformation` to push current position-1 miner elsewhere
   - Generates `UpdateValueInput` with modified values

3. **Transaction submission**:
   - Submit `UpdateValue` transaction
   - Validation at [9](#0-8)  only checks signature, outValue, previousInValue - PASSES
   - `ProcessUpdateValue` at [10](#0-9)  applies malicious order value

4. **Next round generation**:
   - When next round is generated via [11](#0-10) 
   - Attacker's `FinalOrderOfNextRound = 1` is used to set their position
   - Attacker successfully becomes first miner in next round

**Expected vs Actual Result:**
- **Expected**: Attacker gets position based on signature calculation (e.g., order 5)
- **Actual**: Attacker gets chosen position (order 1)

**Success Condition:**
The attacker's next round order matches their chosen value instead of the deterministically calculated value, demonstrating successful manipulation of mining order.

### Notes

The predictability aspect mentioned in the original question (miners can predict their position) is actually EXPECTED behavior - the signature-based calculation is intentionally deterministic. However, the critical vulnerability is that miners can MANIPULATE (not just predict) their position because the on-chain system never verifies that the calculation was performed correctly. This breaks the fundamental fairness guarantee of the consensus mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L21-21)
```csharp
        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L10-49)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Only one Out Value should be filled.
        if (!NewConsensusInformationFilled(validationContext))
            return new ValidationResult { Message = "Incorrect new Out Value." };

        if (!ValidatePreviousInValue(validationContext))
            return new ValidationResult { Message = "Incorrect previous in value." };

        return new ValidationResult { Success = true };
    }

    /// <summary>
    ///     Check only one Out Value was filled during this updating.
    /// </summary>
    /// <param name="validationContext"></param>
    /// <returns></returns>
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }

    private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var publicKey = validationContext.SenderPubkey;

        if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) return true;

        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;

        var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;

        return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L77-83)
```csharp
        switch (extraData.Behaviour)
        {
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
```csharp
    private void ProcessUpdateValue(UpdateValueInput updateValueInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(updateValueInput.ActualMiningTime);
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;

        // Just add 1 based on previous data, do not use provided values.
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        if (IsSecretSharingEnabled())
        {
            PerformSecretSharing(updateValueInput, minerInRound, currentRound, _processingBlockMinerPubkey);
        }

        foreach (var tuneOrder in updateValueInput.TuneOrderInformation)
            currentRound.RealTimeMinersInformation[tuneOrder.Key].FinalOrderOfNextRound = tuneOrder.Value;

        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L24-27)
```csharp
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```
