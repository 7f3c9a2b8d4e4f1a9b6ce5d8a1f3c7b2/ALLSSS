# Audit Report

## Title
VRF Manipulation via Invalid PreviousInValue Leading to Mining Order Control

## Summary
A critical logic error in the AEDPoS consensus contract allows malicious miners to manipulate their mining order in subsequent rounds. When a miner provides an invalid `PreviousInValue` that fails validation, the code correctly stores `Hash.Empty` but incorrectly calculates the signature using the original invalid value. This signature directly determines the miner's position in the next round, breaking the VRF (Verifiable Random Function) fairness guarantee.

## Finding Description

The vulnerability exists in the `GetConsensusExtraDataToPublishOutValue()` method where signature calculation occurs outside the validation scope, allowing miners to arbitrarily choose their next-round mining position.

**The Critical Bug:**

When a miner produces a block, they should reveal their `PreviousInValue` which must hash to their previously committed `OutValue`. The self-check validation occurs at: [1](#0-0) 

When validation fails, `previousInValue` is correctly set to `Hash.Empty`. However, the signature calculation occurs **outside** this validation block: [2](#0-1) 

This means the signature is always calculated from `triggerInformation.PreviousInValue` regardless of whether validation passed. The mismatched values (previousInValue=Hash.Empty, signature calculated from invalid value) are then passed to `ApplyNormalConsensusData`: [3](#0-2) 

**Why the Signature Matters:**

In `ApplyNormalConsensusData`, the signature directly determines the miner's position in the next round: [4](#0-3) [5](#0-4) [6](#0-5) 

**Why Existing Protections Fail:**

The validation system explicitly allows `PreviousInValue = Hash.Empty` to pass: [7](#0-6) 

This design was intended for legitimate edge cases (first round, new miners), but it also permits the exploited scenario. The validation checks the **stored** value (Hash.Empty after failed validation), not the original value used for signature calculation.

**Mining Order Assignment:**

When generating the next round, miners are ordered by their `FinalOrderOfNextRound` value: [8](#0-7) 

The order directly determines each miner's `ExpectedMiningTime`, with lower order numbers receiving earlier mining slots.

**Attack Execution:**

1. Attacker (an authorized miner) computes off-chain: for various `candidateValue` inputs, calculate signature using: [9](#0-8) 

2. Convert each signature to determine resulting order using modulo arithmetic
3. Select the `candidateValue` that produces the desired order (e.g., order=1 for first position)
4. Submit block with this chosen invalid `PreviousInValue`
5. Self-check fails → `previousInValue` stored as `Hash.Empty` (passes validation)
6. Signature calculated from invalid value → controls next round position

**No Penalty Applied:**

The system explicitly permits miners not to publish their in values: [10](#0-9) 

Since the attacker provides a valid `InValue` for the current round, their `OutValue` is set normally, so no `MissedTimeSlots` penalty is applied.

## Impact Explanation

**Consensus Integrity Violation:**
- The AEDPoS consensus mechanism relies on VRF to ensure fair, unpredictable mining order
- Allowing miners to choose arbitrary values instead of revealing committed secrets breaks verifiable randomness
- This violates a core consensus invariant that mining positions should be determined by revealed secrets, not chosen by miners

**Concrete Harms:**
- Malicious miners can consistently position themselves at order 1 (first position) in every round
- Earlier mining positions provide multiple advantages:
  - Higher certainty of successful block production (less network risk)
  - Transaction ordering control and MEV (Miner Extractable Value) opportunities
  - Consistent first-position status provides systemic advantage over honest miners
  
**Affected Parties:**
- Honest miners lose fair chances at early positions, reducing their expected rewards
- The entire consensus fairness guarantee is compromised
- Users expecting fair transaction ordering may be exploited through MEV extraction

**Severity Assessment:**
Medium severity because:
1. Breaks a critical consensus invariant (verifiable randomness)
2. Requires attacker to be an authorized miner (limited but realistic attack surface)
3. Does not directly steal funds but provides systemic competitive advantage
4. Exploitable in every round with minimal computational cost
5. Undermines long-term consensus decentralization and fairness

## Likelihood Explanation

**Attacker Prerequisites:**
- Must be an authorized miner in the current round (achievable through legitimate election/staking)
- Can compute hash operations off-chain (no special cryptographic capabilities required)

**Attack Complexity:**
- LOW: Attacker computes `CalculateSignature(candidateValue)` for various candidate values off-chain
- Converts signatures to integers and calculates modulo to determine resulting order
- Selects the value producing desired `FinalOrderOfNextRound` (e.g., order=1)
- Submits block with chosen invalid `PreviousInValue`

**Feasibility Factors:**
- Entry point is the standard block production flow (UpdateValue behavior)
- No additional permissions needed beyond being an active miner
- Computationally trivial (just hash operations and modulo arithmetic)
- Can be repeated every round indefinitely
- No randomness or unpredictability prevents the attack

**Detection Difficulty:**
- `PreviousInValue = Hash.Empty` is allowed by design for legitimate cases, making malicious use indistinguishable from edge cases
- No penalty mechanism exists for this behavior in the consensus contract
- No alerts or monitoring beyond debug logging
- Attack leaves minimal forensic evidence

**Probability:** HIGH for any motivated miner seeking consistent early positions and competitive advantages.

## Recommendation

**Root Cause:** The signature is calculated using the unvalidated `triggerInformation.PreviousInValue` rather than the validated `previousInValue` variable.

**Fix:** Move the signature calculation inside the validation block to ensure it only uses validated values:

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
        // Calculate signature from Hash.Empty when validation fails
        signature = previousRound.CalculateSignature(Hash.Empty);
    }
    else
    {
        previousInValue = triggerInformation.PreviousInValue;
        // Only calculate from actual value when validation passes
        signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
    }
}
else
{
    // Handle the null/empty case separately
    var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
    if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && previousRound.RoundNumber != 1)
    {
        var appointedPreviousInValue = previousRound.RealTimeMinersInformation[pubkey].InValue;
        if (appointedPreviousInValue != null) fakePreviousInValue = appointedPreviousInValue;
    }
    signature = previousRound.CalculateSignature(fakePreviousInValue);
}
```

Alternatively, add explicit validation that the signature matches the stored `previousInValue` after `ApplyNormalConsensusData` to detect manipulation attempts.

## Proof of Concept

A complete proof of concept would require:
1. Setting up a test AElf chain with multiple miners
2. Having one miner implement the off-chain computation to find a `PreviousInValue` that produces order=1
3. Submitting a block with this manipulated value
4. Verifying that the miner receives order=1 in the next round despite providing an invalid `PreviousInValue`

The test would demonstrate that:
- The self-check validation fails (line 80-86 of AEDPoSContract_GetConsensusBlockExtraData.cs)
- The `previousInValue` is stored as `Hash.Empty`
- The signature is still calculated from the invalid value (line 92)
- The resulting `FinalOrderOfNextRound` matches the attacker's desired value
- No penalty is applied to the miner

## Notes

This vulnerability breaks a fundamental assumption of VRF-based consensus: that mining order is determined by previously committed, verifiable random values. By allowing signature calculation from unvalidated inputs while validation only checks stored values, the system creates a disconnect that enables order manipulation. The explicit allowance of `Hash.Empty` in validation was designed for legitimate bootstrap/edge cases but inadvertently enables this exploit path.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L80-86)
```csharp
                if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) &&
                    HashHelper.ComputeFrom(triggerInformation.PreviousInValue) !=
                    previousRound.RealTimeMinersInformation[pubkey].OutValue)
                {
                    Context.LogDebug(() => "Failed to produce block at previous round?");
                    previousInValue = Hash.Empty;
                }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L13-13)
```csharp
        RealTimeMinersInformation[pubkey].Signature = signature;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L44-44)
```csharp
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L45-46)
```csharp
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-33)
```csharp
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```
