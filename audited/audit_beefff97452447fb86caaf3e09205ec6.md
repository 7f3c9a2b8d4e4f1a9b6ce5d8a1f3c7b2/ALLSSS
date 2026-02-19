### Title
Miners Can Submit Arbitrary OutValues Breaking Consensus Randomness Due to Missing Verification

### Summary
The `ApplyNormalConsensusData()` function accepts `outValue` without verifying it equals the hash of the secret `inValue`. Miners can call the public `UpdateValue` method directly with arbitrary `outValue` and `signature` values, bypassing the honest consensus data generation flow. This allows manipulation of next-round mining order, breaking the verifiable randomness guarantee of the AEDPoS consensus mechanism.

### Finding Description

**Root Cause:** [1](#0-0) 

The function directly assigns the provided `outValue` to the miner's round information without any cryptographic verification that it was correctly derived from a secret `inValue`.

**Attack Entry Point:** [2](#0-1) 

`UpdateValue` is a public RPC method that any miner can call directly with custom `UpdateValueInput` data.

**Processing Path:** [3](#0-2) 

The `ProcessUpdateValue` function directly accepts and stores the `outValue` and `signature` from the user-provided input without verification.

**Insufficient Validation:** [4](#0-3) 

The validator only checks that `outValue` and `signature` are non-empty, not that they are correctly computed. [5](#0-4) 

The `ValidatePreviousInValue` function only validates the PREVIOUS round's values (checking `Hash(previousInValue) == previousOutValue`), not the current round's `outValue` being submitted.

**Exploitation Mechanism:** [6](#0-5) 

The submitted `signature` value is converted to an integer and used to determine the miner's supposed order in the next round via modulo arithmetic. By controlling the signature value, an attacker controls their mining position.

**Deferred Validation Failure:** [7](#0-6) 

The system explicitly permits miners to NOT reveal their `previousInValue` in subsequent rounds, meaning there's no enforcement mechanism to catch fake `outValue` submissions even after the fact.

**Honest Flow Bypassed:**

In the honest flow, the system computes `outValue` correctly: [8](#0-7) 

However, miners can bypass this by calling `UpdateValue` directly with their own crafted values instead of using the system-generated transaction.

### Impact Explanation

**Consensus Integrity Compromise:**
- The `outValue` and `signature` are critical to the AEDPoS randomness mechanism for determining next-round miner ordering
- By submitting arbitrary values, miners can manipulate their position in the mining schedule
- This breaks the verifiable randomness guarantee that prevents miners from gaining unfair advantages

**Concrete Harm:**
- **Mining Order Manipulation**: Attackers can engineer favorable positions (e.g., always mining first, avoiding unfavorable slots)
- **Block Production Advantage**: Consistent favorable positioning increases block rewards and MEV opportunities
- **Protocol Trust Erosion**: The consensus mechanism's cryptographic guarantees are violated
- **Cascading Effects**: Manipulated ordering affects Last Irreversible Block (LIB) calculations and cross-chain synchronization

**Affected Parties:**
- Honest miners who follow proper consensus rules are disadvantaged
- The network suffers from compromised randomness in consensus
- Users relying on fair block production and timing

**Severity Justification:**
Critical severity because it violates a core cryptographic invariant of the consensus protocol. The verifiable randomness property is fundamental to fair consensus operation, and its breach allows systematic gaming of the mining schedule.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current miner list (achievable through legitimate election)
- Must have the technical ability to craft custom transactions (standard capability)
- No special privileges beyond being a validator are required

**Attack Complexity:**
- **Low**: Attacker simply needs to:
  1. Observe the honest `UpdateValueInput` generation
  2. Craft a custom `UpdateValueInput` with desired `signature` value
  3. Submit via direct `UpdateValue` call instead of using system-generated transaction
  4. Choose not to reveal `previousInValue` in next round (explicitly permitted)

**Feasibility Conditions:**
- Miner must be in the current active set (normal operational state)
- Must be their designated time slot (automatic during normal mining)
- All validation checks pass because none verify current-round `outValue` correctness

**Detection Constraints:**
- The VRF verification at process time only validates the `randomNumber` field, not the `outValue`: [9](#0-8) 

The VRF and `outValue` are separate randomness mechanisms with no cross-validation.

**Probability Assessment:**
High likelihood. Any rational miner with profit-maximizing intent can execute this attack at every mining opportunity with near certainty of success, as there are no cryptographic or economic barriers preventing exploitation.

### Recommendation

**Immediate Mitigation:**

1. **Require InValue Revelation:** Modify the protocol to require miners to submit their current `inValue` alongside `outValue` in the `UpdateValueInput`: [10](#0-9) 

Add an `in_value` field and validate `Hash(in_value) == out_value` during processing.

2. **Add Current-Round Verification:** In `ProcessUpdateValue`, add validation:
```
Assert(HashHelper.ComputeFrom(updateValueInput.InValue) == updateValueInput.OutValue, 
       "OutValue must be hash of InValue");
```

3. **Enforce Secret Sharing Verification:** When secret sharing is enabled, verify that decrypted pieces reconstruct to an `inValue` matching the submitted `outValue`.

4. **Remove Optional Revelation:** Change the policy to REQUIRE `previousInValue` revelation: [7](#0-6) 

Make this mandatory rather than permissible, with penalties for non-revelation.

**Alternative Design:**

Consider integrating the VRF `randomNumber` mechanism with the `outValue` mechanism, or replace the `inValue/outValue` scheme entirely with VRF-based ordering to ensure cryptographic verifiability.

**Test Cases:**

1. Test that `UpdateValue` with `outValue ≠ Hash(inValue)` is rejected
2. Test that miners who don't reveal `previousInValue` face penalties
3. Test that secret sharing reconstruction is validated against submitted values
4. Fuzz test signature manipulation attempts

### Proof of Concept

**Initial State:**
- Attacker is an elected miner in the current round's miner list
- Current round is in progress, attacker's time slot is upcoming

**Attack Sequence:**

1. **Observation Phase:**
   - Attacker observes honest consensus flow would compute:
   - `outValue = Hash(realInValue)`
   - `signature = CalculateSignature(previousInValue)`

2. **Value Manipulation:**
   - Attacker selects desired `nextRoundPosition` (e.g., position 1)
   - Reverse-engineers `signature` value: `targetSignature = (nextRoundPosition - 1) + k * minersCount` for any integer k
   - Selects arbitrary `fakeOutValue` unrelated to any real `inValue`

3. **Transaction Crafting:**
   - Constructs `UpdateValueInput`:
     - `out_value = fakeOutValue` 
     - `signature = Hash(targetSignature)` (crafted value)
     - `previous_in_value` = valid hash from previous round (passes validation)
     - `round_id`, `actual_mining_time`, etc. = correct values
     - `random_number` = valid VRF proof (for separate VRF check)

4. **Direct Submission:**
   - Calls `UpdateValue(crafted_input)` directly instead of using system-generated transaction

5. **Validation Bypass:**
   - `ValidateConsensusBeforeExecution` passes all checks:
     - Mining permission ✓ (is in miner list)
     - Time slot ✓ (correct timing)
     - Continuous blocks ✓ (not exceeded)
     - `UpdateValueValidationProvider` ✓ (only checks previous round and non-empty values)
   - VRF verification passes ✓ (separate from `outValue`)

6. **State Corruption:**
   - `ProcessUpdateValue` stores fake values:
   - `minerInRound.OutValue = fakeOutValue`
   - `minerInRound.Signature = targetSignature`
   - Next round order is calculated using attacker's chosen signature

7. **Next Round:**
   - Attacker chooses NOT to reveal `previousInValue` (explicitly permitted)
   - No penalty or detection occurs
   - Attacker mines in their chosen favorable position

**Expected vs Actual Result:**

- **Expected:** Attacker should only be able to submit `outValue = Hash(secretInValue)`, maintaining randomness
- **Actual:** Attacker successfully submits arbitrary `outValue` and `signature`, gaining mining position advantage

**Success Condition:**
Attacker's `supposedOrderOfNextRound` equals their targeted position, computed from their crafted `signature` value rather than cryptographically derived value, demonstrating complete control over next-round positioning.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L12-12)
```csharp
        RealTimeMinersInformation[pubkey].OutValue = outValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L98-102)
```csharp
    public override Empty UpdateValue(UpdateValueInput input)
    {
        ProcessConsensusInformation(input);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L76-78)
```csharp
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-245)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L67-67)
```csharp
        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
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
