### Title
Signature Manipulation Vulnerability in Extra Block Producer Selection

### Summary
The first miner producing a block in a round can manipulate their signature value by providing an arbitrary `PreviousInValue` that fails validation but is still used for signature calculation. This allows the attacker to influence the modulo operation that determines the next round's extra block producer, ensuring they or an ally receives this privileged role and its associated rewards.

### Finding Description

The vulnerability exists in the signature calculation flow when a miner produces a block. The issue spans two files:

**Location 1: Signature Calculation** [1](#0-0) 

When a miner provides `triggerInformation.PreviousInValue`, a self-check validates whether it hashes to their previous `OutValue`. If validation fails, the `previousInValue` variable is set to `Hash.Empty`, but critically, the signature is still calculated using the unvalidated `triggerInformation.PreviousInValue`:

The signature calculation uses the miner-supplied value regardless of validation failure.

**Location 2: Signature Storage** [2](#0-1) 

The method calls `ApplyNormalConsensusData` with `previousInValue` (Hash.Empty after failed validation) but `signature` (calculated from the arbitrary value).

**Location 3: Validation Bypass** [3](#0-2) 

The validation explicitly passes when `PreviousInValue` is `Hash.Empty`, allowing the manipulated signature to be accepted.

**Location 4: Extra Block Producer Selection** [4](#0-3) 

The manipulated signature from the first miner is used to determine the extra block producer order through modulo arithmetic.

**Root Cause:**
The signature calculation at line 92 of `GetConsensusExtraDataToPublishOutValue` uses `triggerInformation.PreviousInValue` directly, even after the self-check detects it's invalid. The validation system allows `Hash.Empty` as a valid `PreviousInValue`, creating a bypass where the attacker's chosen value affects the signature but the stored value passes validation.

**Signature Calculation Formula:** [5](#0-4) 

The signature is computed as `XOR(inValue, XOR(all_previous_round_signatures))`. Since all previous round signatures are public and fixed, an attacker can try different `inValue` choices offline to find one that produces a desired modulo result.

### Impact Explanation

**Direct Impact:**
- The extra block producer receives additional mining rewards compared to regular block producers
- The attacker can systematically ensure they or a colluding ally becomes the extra block producer every round they mine first
- This breaks the intended randomness and fairness of the consensus mechanism

**Reward Misallocation:**
- Extra block production privileges are meant to be randomly distributed among miners
- The attacker gains disproportionate rewards over honest miners
- Over multiple rounds, this creates cumulative advantage and unfair wealth concentration

**Consensus Integrity:**
- The deterministic and unpredictable nature of extra block producer selection is a core security property
- Manipulation undermines trust in the consensus mechanism
- Other miners may lose confidence in the fairness of the system

**Affected Parties:**
- Honest miners who lose potential extra block producer opportunities
- The overall network through degraded consensus fairness
- Token holders through improper reward distribution

### Likelihood Explanation

**Attacker Capabilities:**
- Any miner can execute this attack when they are first to produce a block in a round
- No special privileges beyond normal mining participation are required
- The attack is entirely client-side with no on-chain detection mechanism

**Attack Complexity:**
The attack is computationally trivial:
1. Retrieve all signatures from the previous round (public blockchain data)
2. Compute `aggregated_sigs = XOR(all_previous_signatures)`
3. For each candidate value X, calculate `signature_X = XOR(X, aggregated_sigs)`
4. Find X where `(signature_X.ToInt64() % minerCount) + 1` equals the attacker's desired order
5. Provide X as `PreviousInValue` when producing the block

With typical miner counts (20-50 miners), finding a suitable X requires testing only dozens of values, which takes milliseconds on modern hardware.

**Feasibility Conditions:**
- Attacker must be the first miner to produce a block in a round (probability = 1/minerCount per round)
- No special timing requirements or race conditions
- Works consistently across all rounds and terms
- No economic cost beyond normal mining operations

**Detection Difficulty:**
- The attack leaves no on-chain evidence distinguishing it from legitimate missed previous round participation
- `PreviousInValue = Hash.Empty` is treated as a valid state for miners who didn't mine in the previous round
- Monitoring tools cannot differentiate between legitimate and malicious Hash.Empty usage

**Probability:**
HIGH - Every time an attacker is first to mine in a round, they can execute this attack with near certainty.

### Recommendation

**Immediate Fix:**
Modify the signature calculation logic to enforce strict validation:

1. In `GetConsensusExtraDataToPublishOutValue`, change the signature calculation to use the validated `previousInValue` variable instead of `triggerInformation.PreviousInValue`:

```csharp
// After self-check (lines 80-90)
if (previousInValue != Hash.Empty) {
    signature = previousRound.CalculateSignature(previousInValue);
} else {
    // Use deterministic fallback
    signature = previousRound.CalculateSignature(
        HashHelper.ComputeFrom(pubkey.Append(previousRound.RoundNumber.ToString()))
    );
}
```

2. Remove the validation bypass in `UpdateValueValidationProvider` - make `Hash.Empty` trigger an error instead of passing validation if the miner existed in the previous round and should have a valid `OutValue`.

3. Add explicit validation in `UpdateValueValidationProvider` that checks if the signature matches the expected value:

```csharp
// Validate signature matches expected calculation
if (validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) {
    var expectedSignature = validationContext.PreviousRound.CalculateSignature(previousInValue);
    var actualSignature = extraData.Round.RealTimeMinersInformation[publicKey].Signature;
    if (actualSignature != expectedSignature) {
        return new ValidationResult { Message = "Signature does not match expected value." };
    }
}
```

**Invariant to Enforce:**
For any miner M producing a block in round N:
- If M existed in round N-1 with non-null OutValue
- Then M's Signature in round N must equal `CalculateSignature(Hash(their_revealed_InValue))`
- And `Hash(their_revealed_InValue) == their_OutValue_from_round_N-1`

**Test Cases:**
1. Test that a miner providing incorrect `PreviousInValue` has their block rejected
2. Test that signature calculation uses only validated values
3. Test that extra block producer selection cannot be influenced by manipulated signatures
4. Regression test ensuring legitimate miners who missed previous rounds can still participate

### Proof of Concept

**Initial State:**
- Round N-1 has completed with 21 miners
- Attacker M1 produced a block in round N-1 with `OutValue_N-1 = Hash(InValue_N-1)`
- All signatures from round N-1 are public: `{Sig1, Sig2, ..., Sig21}`
- Round N begins, M1 has order 1 (first to mine)

**Attack Execution:**

**Step 1:** M1 computes offline:
```
aggregated_sigs = XOR(Sig1, Sig2, ..., Sig21)
target_order = 1  // M1 wants to be extra block producer again
```

**Step 2:** M1 searches for X:
```
for each candidate X:
    signature_X = XOR(X, aggregated_sigs)
    order = (signature_X.ToInt64() % 21) + 1
    if order == target_order:
        chosen_X = X
        break
```

**Step 3:** M1 produces block with:
```
triggerInformation.InValue = new_random_value
triggerInformation.PreviousInValue = chosen_X  // NOT the real InValue_N-1
```

**Step 4:** Contract processes block:
- Self-check fails: `Hash(chosen_X) != OutValue_N-1`
- Sets `previousInValue = Hash.Empty`
- BUT calculates `signature = CalculateSignature(chosen_X)`
- Stores: `PreviousInValue = Hash.Empty`, `Signature = based_on_chosen_X`

**Step 5:** Validation passes:
- `UpdateValueValidationProvider` sees `PreviousInValue == Hash.Empty`
- Returns `true` (line 46)

**Step 6:** Round N+1 generation:
- `CalculateNextExtraBlockProducerOrder()` retrieves M1's signature (based on chosen_X)
- Computes: `order = (signature.ToInt64() % 21) + 1 = target_order`
- M1 becomes extra block producer

**Expected vs Actual:**
- **Expected:** Extra block producer randomly selected from all miners
- **Actual:** M1 deterministically becomes extra block producer through signature manipulation

**Success Condition:**
M1 is assigned `IsExtraBlockProducer = true` in round N+1 through their manipulated signature value, while honest miners using legitimate `PreviousInValue` would have resulted in a different extra block producer.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L74-92)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```
