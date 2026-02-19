### Title
Replacement Miner Can Manipulate Mining Order Through Unvalidated PreviousInValue

### Summary
When a replacement miner (not present in previous round) produces a block, they can provide an arbitrary `PreviousInValue` that bypasses validation and directly influences signature calculation. This signature determines their mining order in the next round, allowing the attacker to gain an unfair advantage by computing and selecting the most favorable position offline.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** 

When `GetConsensusExtraDataToPublishOutValue` processes a miner's consensus data, it checks whether the miner exists in the previous round at line 80. For replacement miners (e.g., those replacing evil miners or manually replaced candidates), this check fails, causing execution to fall through to the else block where the attacker-provided `triggerInformation.PreviousInValue` is accepted without validation. [2](#0-1) 

The signature calculated at line 92 uses this unvalidated input: `signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue)`. The `CalculateSignature` method XORs the input value with all miners' signatures from the previous round. [3](#0-2) 

**Validation Bypass:**

The validation logic in `UpdateValueValidationProvider` explicitly returns `true` (passes validation) when the miner's pubkey is not found in the previous round, performing NO validation on the provided `PreviousInValue`. [4](#0-3) 

**Impact Chain:**

The manipulated signature directly determines the miner's position in the next round through `ApplyNormalConsensusData`, which converts the signature to an integer and calculates `supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1`. This becomes the miner's `FinalOrderOfNextRound`. [5](#0-4) 

### Impact Explanation

**Consensus Integrity Violation:** The mining order in AEDPoS consensus determines WHEN each miner produces blocks in the round. By manipulating their signature calculation, a replacement miner can:

1. **Position Manipulation:** Choose mining position 1 (earliest) to see and order transactions first, enabling MEV (Miner Extractable Value) opportunities
2. **Timing Advantage:** Control their expected mining time slot, potentially avoiding overlap with network congestion or coordinating with other activities
3. **Unfair Competition:** Gain systematic advantage over honest miners who use legitimate values

**Affected Parties:** 
- All honest miners competing for favorable positions
- Users whose transactions may be front-run or reordered
- Overall consensus fairness and predictability

**Severity Justification:** HIGH - This violates the core consensus invariant that "miner schedule integrity" must be maintained. Mining order should be deterministic and unpredictable, not manipulable by individual miners.

### Likelihood Explanation

**Attacker Capabilities:**
- Control over their node software to modify `AElfConsensusTriggerInformation` construction
- Ability to compute hash functions offline
- No special permissions beyond being a valid replacement miner

**Preconditions:**
Replacement miners are a regular occurrence in AEDPoS through two mechanisms:
1. **Automatic replacement:** Evil miners (those missing ≥ tolerable time slots) are automatically replaced during round generation
2. **Manual replacement:** Candidate admins can manually replace pubkeys via `ReplaceCandidatePubkey` [6](#0-5) 

**Attack Complexity:** LOW
1. Offline compute: For each candidate `PreviousInValue`, calculate resulting signature and mining order
2. Select optimal value that yields position 1 (or other favorable position)
3. Modify node to inject chosen `PreviousInValue` into trigger information
4. Produce block normally - contract accepts without validation

**Detection Difficulty:** Very difficult - the manipulated value appears as legitimate consensus data, and there's no baseline to compare against since the miner wasn't in the previous round.

**Economic Rationality:** The cost is negligible (computational time for hash calculations) while the benefit is significant (optimal mining position, potential MEV, timing advantages).

### Recommendation

**Immediate Fix:**

Modify `UpdateValueValidationProvider.ValidatePreviousInValue` to properly validate replacement miners:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    // For replacement miners, validate using deterministic fake value
    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey))
    {
        if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) 
            return true;
        
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
        
        // Validate against expected fake value
        var expectedFakeValue = HashHelper.ComputeFrom(publicKey.Append(Context.CurrentHeight.ToString()));
        return previousInValue == expectedFakeValue;
    }

    // Existing validation for normal miners
    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) return true;
    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    var providedPreviousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (providedPreviousInValue == Hash.Empty) return true;
    
    return HashHelper.ComputeFrom(providedPreviousInValue) == previousOutValue;
}
```

**Alternative Approach:**

Modify `GetConsensusExtraDataToPublishOutValue` to FORCE the fakePreviousInValue path for replacement miners, ignoring any provided `triggerInformation.PreviousInValue`:

```csharp
// Lines 72-108 modification
if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
{
    // If miner not in previous round, force fake value path
    if (!previousRound.RealTimeMinersInformation.ContainsKey(pubkey))
    {
        var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
        signature = previousRound.CalculateSignature(fakePreviousInValue);
    }
    else if (triggerInformation.PreviousInValue != null && triggerInformation.PreviousInValue != Hash.Empty)
    {
        // Normal path for existing miners
        // ... existing validation logic ...
    }
    // ... rest of logic ...
}
```

**Test Cases:**
1. Verify replacement miner cannot provide custom PreviousInValue
2. Verify replacement miner signature matches expected fake value calculation
3. Verify normal miners still function correctly with existing validation
4. Integration test: replacement miner should get deterministic mining order, not manipulable order

### Proof of Concept

**Initial State:**
- Current round N contains miner with pubkey "ReplacementMiner" (not in round N-1)
- Previous round N-1 contains only original miners
- ReplacementMiner is producing their first block in round N

**Attack Steps:**

1. **Offline Computation Phase:**
   ```
   For i = 1 to 1000:
       candidateValue = Hash(random_seed + i)
       signature = CalculateSignature(previousRound, candidateValue)
       order = (signature.ToInt64() % minerCount) + 1
       if order == 1:  // Optimal position found
           attackValue = candidateValue
           break
   ```

2. **Block Production Phase:**
   - Modify node's `AEDPoSTriggerInformationProvider` to inject `attackValue` as `PreviousInValue`
   - Call `GetConsensusExtraData` with modified trigger information
   - Contract executes line 80 check: `previousRound.RealTimeMinersInformation.ContainsKey("ReplacementMiner")` → FALSE
   - Execution goes to line 89: `previousInValue = triggerInformation.PreviousInValue` (attacker's value)
   - Line 92: `signature = previousRound.CalculateSignature(attackValue)`

3. **Validation Phase:**
   - `UpdateValueValidationProvider.ValidatePreviousInValue` called
   - Line 40: Returns `true` immediately (no validation for replacement miner)

4. **Order Assignment Phase:**
   - `ApplyNormalConsensusData` called with manipulated signature
   - Line 21: `supposedOrderOfNextRound = GetAbsModulus(signature.ToInt64(), minersCount) + 1`
   - Result: Mining order = 1 (attacker's chosen position)

**Expected vs Actual:**
- **Expected:** Replacement miner gets deterministic mining order based on protocol-defined fake value
- **Actual:** Replacement miner gets mining order of their choice through value manipulation

**Success Condition:** Attacker achieves position 1 (or any desired position) in next round through PreviousInValue selection, while honest replacement miners get random positions.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L55-134)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataToPublishOutValue(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.

        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
            if (triggerInformation.PreviousInValue != null &&
                triggerInformation.PreviousInValue != Hash.Empty)
            {
                Context.LogDebug(
                    () => $"Previous in value in trigger information: {triggerInformation.PreviousInValue}");
                // Self check.
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
                else
                {
                    previousInValue = triggerInformation.PreviousInValue;
                }

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
            }
            else
            {
                var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
                {
                    var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
                    if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
                else
                {
                    // This miner appears first time in current round, like as a replacement of evil miner.
                    signature = previousRound.CalculateSignature(fakePreviousInValue);
                }
            }
        }

        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);

        Context.LogDebug(
            () => "Previous in value after ApplyNormalConsensusData: " +
                  $"{updatedRound.RealTimeMinersInformation[pubkey].PreviousInValue}");

        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;

        // Update secret pieces of latest in value.
        
        if (IsSecretSharingEnabled())
        {
            UpdateLatestSecretPieces(updatedRound, pubkey, triggerInformation);
        }

        // To publish Out Value.
        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = updatedRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L125-157)
```csharp
    {
        var height = new Int64Value();
        height.MergeFrom(input.Value);
        return GetRandomHash(height).ToBytesValue();
    }

    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

        if (!TryToGetCurrentRoundInformation(out var currentRound) ||
            !currentRound.RealTimeMinersInformation.ContainsKey(input.OldPubkey)) return new Empty();

        // If this candidate is current miner, need to modify current round information.
        var realTimeMinerInformation = currentRound.RealTimeMinersInformation[input.OldPubkey];
        realTimeMinerInformation.Pubkey = input.NewPubkey;
        currentRound.RealTimeMinersInformation.Remove(input.OldPubkey);
        currentRound.RealTimeMinersInformation.Add(input.NewPubkey, realTimeMinerInformation);
        if (currentRound.ExtraBlockProducerOfPreviousRound == input.OldPubkey)
            currentRound.ExtraBlockProducerOfPreviousRound = input.NewPubkey;
        State.Rounds[State.CurrentRoundNumber.Value] = currentRound;

        // Notify Treasury Contract to update replacement information. (Update from old record.)
        State.TreasuryContract.RecordMinerReplacement.Send(new RecordMinerReplacementInput
        {
            OldPubkey = input.OldPubkey,
            NewPubkey = input.NewPubkey,
            CurrentTermNumber = State.CurrentTermNumber.Value
        });

        return new Empty();
    }
```
