### Title
Byzantine Miner Can Replay Another Miner's OutValue/Signature Due to Missing Cryptographic Binding Validation

### Summary
The `NewConsensusInformationFilled()` validation function only verifies that `OutValue` and `Signature` fields are non-null and non-empty, but does not validate that these values are cryptographically bound to the submitting miner's identity. A Byzantine miner can intercept and copy another miner's valid `OutValue` and `Signature` from block headers or network traffic, then submit them as their own in an `UpdateValue` transaction, bypassing all consensus validation checks.

### Finding Description

The vulnerability exists in the consensus validation flow for `UpdateValue` operations:

**Root Cause:** [1](#0-0) 

The `NewConsensusInformationFilled()` function only performs existence checks on `OutValue` and `Signature`, verifying they are non-null and contain data. There is no cryptographic verification that:
1. The `OutValue` was derived from this specific miner's `InValue`
2. The `Signature` belongs to this specific miner
3. These values are unique and not copied from another miner

**How Consensus Data Should Work:** [2](#0-1) 

Each miner should generate their own unique `OutValue = hash(InValue)` where `InValue` is derived from their private key signature. However, the current `InValue` is never submitted in the `UpdateValueInput`. [3](#0-2) 

**Processing Without Verification:** [4](#0-3) 

The `ProcessUpdateValue()` function directly assigns the submitted `OutValue` and `Signature` from the input without any cryptographic verification that these values were computed by the submitting miner.

**No Duplicate Detection:**
Based on codebase analysis, there is no validation to detect if multiple miners submit identical `OutValue`/`Signature` pairs. The system assumes each miner will honestly compute their own unique values.

**Attack Execution Path:**
1. Byzantine miner M1 monitors network traffic or block headers
2. M1 observes when honest miner M2 produces a block containing M2's valid `OutValue` and `Signature`
3. M1 extracts these values and creates their own `UpdateValueInput` with M2's copied data
4. M1 submits the transaction during their time slot
5. Validation passes because `NewConsensusInformationFilled()` only checks non-null/non-empty
6. M1's round information is updated with M2's consensus data [5](#0-4) 

The copied `Signature` directly affects the `SupposedOrderOfNextRound` calculation, allowing the Byzantine miner to manipulate consensus ordering.

### Impact Explanation

**Consensus Integrity Breach:**
- Byzantine miners can bypass the cryptographic guarantees of the AEDPoS consensus mechanism
- The entire premise of unique `InValue` generation using private keys is undermined
- Multiple miners can have identical `OutValue`/`Signature` pairs, breaking the randomness and uniqueness assumptions

**Round Ordering Manipulation:** [6](#0-5) 

The `SupposedOrderOfNextRound` is calculated from `signature.ToInt64()`. If a Byzantine miner copies another miner's signature, they obtain the same supposed order, causing:
- Order conflicts that must be resolved
- Disruption of the fair random ordering mechanism
- Potential for coordinated attacks by multiple Byzantine miners

**Randomness Generation Compromise:**
The consensus random number generation relies on unique signatures from each miner. Replayed signatures undermine this randomness, affecting:
- Next round miner ordering
- Any downstream systems relying on consensus randomness

**Affected Parties:**
- All honest miners participating in consensus
- Chain security and liveness guarantees
- Any applications depending on consensus randomness or ordering

### Likelihood Explanation

**Attacker Capabilities:**
- Byzantine miner with valid mining credentials (must be in the miner list)
- Ability to monitor network traffic or read block headers (publicly available)
- Standard transaction submission capabilities

**Attack Complexity: LOW**
1. Read block header or intercept consensus gossip messages (public data)
2. Extract `OutValue` and `Signature` from another miner's block
3. Create `UpdateValueInput` with copied values
4. Submit transaction during attacker's time slot
5. No cryptographic operations required beyond normal transaction signing

**Feasibility Conditions:**
- Attacker must be a registered miner (feasible - miners are elected/selected)
- Network observation capability (trivial - block headers are public)
- Timing: Must submit during their assigned time slot (normal mining operation)

**Detection Difficulty:**
Currently no detection mechanism exists since:
- No uniqueness checks on `OutValue`/`Signature` across miners
- Validation only checks non-null/non-empty
- No logging or monitoring of duplicate consensus data

**Economic Rationality:**
- Attack cost: Negligible (just observation + transaction submission)
- Benefit: Disruption of consensus, potential ordering manipulation
- No stake slashing for this behavior (not detected as malicious)

### Recommendation

**Immediate Fix - Add Cryptographic Binding Validation:**

1. **Submit Current InValue in UpdateValueInput:**
   Modify the protobuf definition to include the current `InValue` field in `UpdateValueInput`, then validate:
   ```
   Assert(HashHelper.ComputeFrom(updateValueInput.InValue) == updateValueInput.OutValue, 
          "OutValue must be hash of InValue");
   ```

2. **Validate InValue Uniqueness:**
   Add validation in `UpdateValueValidationProvider.NewConsensusInformationFilled()`:
   ```
   - Check that InValue is signed by the miner's public key
   - Verify no other miner in the current round has the same InValue/OutValue
   - Ensure Signature is deterministically derived from InValue and previous round data
   ```

3. **Add Duplicate Detection:**
   In validation context, check across all miners:
   ```
   foreach (var miner in currentRound.RealTimeMinersInformation) {
       if (miner.Key != senderPubkey && 
           miner.Value.OutValue == providedOutValue) {
           return ValidationResult { Message = "Duplicate OutValue detected" };
       }
   }
   ```

4. **Cryptographically Bind Signature to Miner:**
   The current "signature" is just a hash-based XOR operation. Consider:
   - Using actual ECDSA signatures over the consensus data
   - Binding the signature to the miner's public key cryptographically
   - Verifying signature ownership during validation

**Additional Hardening:**
- Log and monitor for duplicate `OutValue`/`Signature` submissions
- Add slash conditions for miners submitting replayed consensus data
- Implement round-based InValue commitment/reveal scheme

### Proof of Concept

**Initial State:**
- Blockchain with N miners including Byzantine miner M1 and honest miner M2
- Current round R with miners scheduled in order
- M2 scheduled to mine at time T1
- M1 scheduled to mine at time T2 > T1

**Attack Sequence:**

1. **Observation Phase (Block T1):**
   - M2 produces block at time T1
   - M2's block header contains: `Round.RealTimeMinersInformation[M2.pubkey].OutValue = H1`, `Round.RealTimeMinersInformation[M2.pubkey].Signature = S1`
   - M1 observes and extracts H1 and S1 from block header

2. **Replay Attack (Time T2):**
   - M1 creates `UpdateValueInput`:
     ```
     OutValue = H1 (copied from M2)
     Signature = S1 (copied from M2)  
     PreviousInValue = M1's legitimate previous InValue
     RoundId = current round ID
     ActualMiningTime = T2
     [other fields...]
     ```
   - M1 submits `UpdateValue(input)` transaction

3. **Validation Bypass:** [7](#0-6) 
   
   - `NewConsensusInformationFilled()` checks: `OutValue != null && Signature != null` → **PASS** (copied values are non-null)
   - `ValidatePreviousInValue()` checks only M1's previous round data → **PASS** (M1's previous data can be valid)
   - No check that OutValue = hash(M1's InValue) → **MISSING**
   - No check for duplicate OutValue across miners → **MISSING**

4. **State Corruption:** [8](#0-7) 
   
   - M1's round information is updated with M2's `OutValue` and `Signature`
   - Both M1 and M2 now have identical `Signature` values
   - Next round order calculation: `GetAbsModulus(S1.ToInt64(), minersCount)` produces same result for both miners
   - Order conflict occurs or consensus ordering is disrupted

**Expected Result:** Validation should reject M1's transaction because OutValue/Signature don't match M1's InValue

**Actual Result:** Transaction succeeds, M1's consensus data is set to M2's values, consensus integrity is compromised

### Notes

The vulnerability stems from treating `OutValue` and `Signature` as mere data fields rather than cryptographic proofs. The AEDPoS design assumes honest computation but lacks enforcement. The `InValue` generation is secure (using private key signatures off-chain), but the on-chain validation never verifies the relationship between submitted `OutValue`/`Signature` and the miner's unique `InValue`. This creates a critical gap where Byzantine miners can copy other miners' valid consensus data without detection.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L55-69)
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
```

**File:** protobuf/aedpos_contract.proto (L194-221)
```text
message UpdateValueInput {
    // Calculated from current in value.
    aelf.Hash out_value = 1;
    // Calculated from current in value and signatures of previous round.
    aelf.Hash signature = 2;
    // To ensure the values to update will be apply to correct round by comparing round id.
    int64 round_id = 3;
    // Publish previous in value for validation previous signature and previous out value.
    aelf.Hash previous_in_value = 4;
    // The actual mining time, miners must fill actual mining time when they do the mining.
    google.protobuf.Timestamp actual_mining_time = 5;
    // The supposed order of mining for the next round.
    int32 supposed_order_of_next_round = 6;
    // The tuning order of mining for the next round, miner public key -> order.
    map<string, int32> tune_order_information = 7;
    // The encrypted pieces of InValue.
    map<string, bytes> encrypted_pieces = 8;
    // The decrypted pieces of InValue.
    map<string, bytes> decrypted_pieces = 9;
    // The amount of produced blocks.
    int64 produced_blocks = 10;
    // The InValue in the previous round, miner public key -> InValue.
    map<string, aelf.Hash> miners_previous_in_values = 11;
    // The irreversible block height that miner recorded.
    int64 implied_irreversible_block_height = 12;
    // The random number.
    bytes random_number = 13;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-265)
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

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-22)
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

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L46-50)
```csharp
        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());
```
