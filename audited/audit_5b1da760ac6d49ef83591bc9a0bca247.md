### Title
Missing Signature Verification Allows Miners to Manipulate Mining Order Through Arbitrary Signature Values

### Summary
The `NewConsensusInformationFilled()` function and the entire `UpdateValue` validation flow fail to verify that the provided `Signature` field matches the expected value calculated from `previousRound.CalculateSignature(PreviousInValue)`. This allows any miner to provide arbitrary signature values, including reused signatures from previous rounds, enabling them to manipulate their mining position in the next round and break the randomness/fairness guarantees of the AEDPoS consensus mechanism.

### Finding Description

The vulnerability exists in the UpdateValue validation flow. The `NewConsensusInformationFilled()` function only verifies that `OutValue` and `Signature` are not null and contain data: [1](#0-0) 

The entire validation provider never checks if the signature is correctly calculated. The `ValidatePreviousInValue()` method only validates that the `PreviousInValue` hashes to the previous round's `OutValue`: [2](#0-1) 

During normal consensus extra data generation, signatures are supposed to be calculated deterministically using `CalculateSignature()`: [3](#0-2) 

The `CalculateSignature()` method XORs the in-value with all signatures from the previous round, making each round's signatures deterministically derived: [4](#0-3) 

However, no validation code verifies that the provided signature matches this expected calculation. The signature is directly applied to the round without verification: [5](#0-4) 

The signature value directly determines the miner's order in the next round through a modulo operation: [6](#0-5) 

The validation context is created with a `BaseRound` that has already been modified by `RecoverFromUpdateValue()`, destroying any ability to compare against the original state: [7](#0-6) 

The recovery operation blindly overwrites the signature without validation: [8](#0-7) 

### Impact Explanation

**Consensus Integrity Compromise:**
- Miners can compute arbitrary signature values to achieve desired mining positions in the next round (position = `GetAbsModulus(signature.ToInt64(), minersCount) + 1`)
- A miner can systematically ensure they always mine first (position 1) or at any other advantageous position
- This breaks the core randomness guarantee of AEDPoS consensus

**Fairness Violation:**
- Honest miners following the protocol get random positions based on correctly calculated signatures
- Malicious miners can manipulate positions to maximize block rewards and MEV opportunities
- Over multiple rounds, malicious miners gain significant unfair advantage in block production frequency and timing

**Economic Impact:**
- Malicious miners capture disproportionate block rewards by controlling when they mine
- Ability to mine at predictable positions enables front-running and MEV extraction
- Undermines the economic security model where mining order should be unpredictable

**Network Security:**
- If multiple colluding miners exploit this, they can coordinate their positions to dominate block production
- Reduces effective decentralization of the network
- Opens path to censorship attacks by controlling block production sequence

### Likelihood Explanation

**Reachable Entry Point:**
The attack uses the standard `UpdateValue` public method that any miner can call during their time slot: [9](#0-8) 

**Attacker Capabilities:**
- Any active miner in the consensus set can execute this attack
- Requires only ability to construct `UpdateValueInput` with custom signature value
- No special permissions or contract state manipulation needed beyond being a valid miner

**Attack Complexity:**
1. Miner determines desired position P in next round (e.g., position 1 to mine first)
2. Computes required signature S where `GetAbsModulus(S.ToInt64(), minersCount) + 1 == P`
3. Constructs `UpdateValueInput` with correctly calculated `OutValue` and `PreviousInValue` but arbitrary `Signature = S`
4. Submits transaction during their time slot
5. Validation passes because no signature verification exists
6. Miner's next round order is set to desired position P

**Feasibility:**
- Attack executable in every round by any miner
- No detection mechanism exists since the signature field is never verified
- Cost is zero beyond normal mining transaction fees
- Success rate is 100% given the lack of validation

**Economic Rationality:**
- Block rewards and MEV opportunities justify the exploit
- First miner in a round has significant advantages
- Costs are negligible (only gas for one transaction)
- Benefits compound over multiple rounds

### Recommendation

Add signature verification to the `UpdateValueValidationProvider` class:

```csharp
private bool ValidateSignature(ConsensusValidationContext validationContext)
{
    var publicKey = validationContext.SenderPubkey;
    
    // Skip if not in previous round (first round case)
    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true;
    
    var providedSignature = validationContext.ProvidedRound.RealTimeMinersInformation[publicKey].Signature;
    var previousInValue = validationContext.ProvidedRound.RealTimeMinersInformation[publicKey].PreviousInValue;
    
    // Signature should equal CalculateSignature(PreviousInValue)
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    
    return providedSignature == expectedSignature;
}
```

Add this check to `ValidateHeaderInformation()`:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    if (!NewConsensusInformationFilled(validationContext))
        return new ValidationResult { Message = "Incorrect new Out Value." };

    if (!ValidatePreviousInValue(validationContext))
        return new ValidationResult { Message = "Incorrect previous in value." };
    
    // NEW CHECK:
    if (!ValidateSignature(validationContext))
        return new ValidationResult { Message = "Invalid signature - does not match expected calculation." };

    return new ValidationResult { Success = true };
}
```

**Additional Recommendations:**
- Add integration tests that attempt to submit UpdateValue with manipulated signatures
- Consider adding signature verification also in `ProcessUpdateValue` as defense-in-depth
- Document the signature calculation invariant in code comments

### Proof of Concept

**Initial State:**
- Current round R with 5 miners
- Attacker is Miner A in the consensus set
- Attacker wants to be position 1 in round R+1

**Attack Steps:**

1. **Miner A's time slot arrives in round R**
   - Normal process: generate `InValue_R`, compute `OutValue_R = Hash(InValue_R)`
   - Normal process: compute `Signature_R = previousRound.CalculateSignature(InValue_{R-1})`

2. **Attacker computes desired signature**
   - Iterate signature values S until `GetAbsModulus(S.ToInt64(), 5) + 1 == 1`
   - Example: if S.ToInt64() % 5 == 0, then position = 1

3. **Attacker submits UpdateValue with manipulated signature**
   ```
   UpdateValueInput {
       OutValue: Hash(InValue_R),  // Correct
       PreviousInValue: InValue_{R-1},  // Correct  
       Signature: <computed S to get position 1>,  // MANIPULATED
       ... other fields ...
   }
   ```

4. **Validation passes**
   - `NewConsensusInformationFilled()` checks Signature != null ✓
   - `ValidatePreviousInValue()` checks Hash(InValue_{R-1}) == OutValue_{R-1} ✓
   - NO signature verification exists ✓
   
5. **State update executes**
   - `ProcessUpdateValue()` sets `minerInRound.Signature = <manipulated S>`
   - `ApplyNormalConsensusData()` calculates `supposedOrderOfNextRound = GetAbsModulus(S.ToInt64(), 5) + 1 = 1`
   - Miner A's `FinalOrderOfNextRound` is set to 1

6. **Result in round R+1**
   - Miner A mines at position 1 (first)
   - Honest miners get positions based on their correct signatures
   - Attacker can repeat this every round to always mine first

**Expected vs Actual:**
- **Expected:** Miner A gets random position based on cryptographically secure signature calculation
- **Actual:** Miner A always gets position 1 (or any desired position) by manipulating signature value

**Success Condition:** 
Miner A successfully mines at position 1 in round R+1, confirming they controlled their mining order through signature manipulation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L27-33)
```csharp
    private bool NewConsensusInformationFilled(ConsensusValidationContext validationContext)
    {
        var minerInRound =
            validationContext.ProvidedRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        return minerInRound.OutValue != null && minerInRound.Signature != null &&
               minerInRound.OutValue.Value.Any() && minerInRound.Signature.Value.Any();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L35-49)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L12-13)
```csharp
        RealTimeMinersInformation[pubkey].OutValue = outValue;
        RealTimeMinersInformation[pubkey].Signature = signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-60)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L16-17)
```csharp
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
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
