# Audit Report

## Title
VRF Manipulation via Invalid PreviousInValue Leading to Mining Order Control

## Summary
A critical logic flaw in the AEDPoS consensus contract allows malicious miners to manipulate their mining order in subsequent rounds by providing invalid `PreviousInValue` data. The vulnerability stems from signature calculation occurring outside the self-check validation block, enabling miners to choose arbitrary values that produce favorable signatures while bypassing the verification mechanism.

## Finding Description

The vulnerability exists in the `GetConsensusExtraDataToPublishOutValue()` method where consensus data is generated during block production. The AEDPoS consensus mechanism relies on a VRF-like scheme where miners commit to a secret value (`InValue`) by publishing its hash (`OutValue`), then reveal the `InValue` in subsequent rounds as `PreviousInValue`.

**The Critical Flaw:**

When a miner produces a block, the code performs a self-check to verify that the provided `PreviousInValue` hashes to the previously committed `OutValue`. [1](#0-0) 

However, the signature calculation occurs **outside** this validation block, unconditionally using the provided (potentially invalid) value: [2](#0-1) 

This creates a critical disconnect: when the self-check fails, `previousInValue` is set to `Hash.Empty`, but the `signature` variable is calculated from `triggerInformation.PreviousInValue` (the invalid value). Both values are then passed to `ApplyNormalConsensusData`: [3](#0-2) 

**How Signature Controls Mining Order:**

In `ApplyNormalConsensusData`, the signature directly determines the miner's position in the next round through modulo arithmetic: [4](#0-3) 

This `supposedOrderOfNextRound` becomes the `FinalOrderOfNextRound`: [5](#0-4) 

**Why Validation Fails to Prevent This:**

The `UpdateValueValidationProvider` explicitly allows `previousInValue == Hash.Empty` to pass validation: [6](#0-5) 

This was designed for legitimate edge cases (first rounds, new miners), but it also permits the exploit scenario. Crucially, there is **no validation** that verifies the stored signature matches what it should be for the given `previousInValue`.

**How Order Determines Mining Time:**

When the next round is generated, miners are ordered by their `FinalOrderOfNextRound`: [7](#0-6) 

The order directly determines `ExpectedMiningTime`, giving earlier positions to miners with lower order numbers. Lower orders mine earlier in the round, providing significant advantages.

**Attack Execution:**

1. Attacker (authorized miner) computes `CalculateSignature(candidateValue)` off-chain for various candidate values
2. The `CalculateSignature` method is deterministic: [8](#0-7) 
3. Attacker selects a `candidateValue` where `GetAbsModulus(signature.ToInt64(), minersCount) + 1 == 1` (for position 1)
4. Attacker submits block with this chosen invalid `PreviousInValue`
5. Self-check fails → `previousInValue` becomes `Hash.Empty`
6. Signature is calculated from the invalid value
7. Block passes validation (Hash.Empty is allowed)
8. The manipulated signature sets `FinalOrderOfNextRound`
9. Next round generation places attacker at desired position

## Impact Explanation

**Broken Security Guarantees:**
- **VRF Fairness Violated**: The consensus mechanism relies on verifiable randomness to ensure fair, unpredictable mining order. This vulnerability allows miners to choose their position instead of deriving it from committed secrets.
- **Mining Order Manipulation**: Malicious miners can consistently secure position 1 (earliest mining slot) in every round.

**Concrete Harms:**
- **Transaction Ordering Control**: First miners can reorder transactions within blocks for MEV extraction
- **Higher Block Production Certainty**: Earlier positions have less network propagation risk
- **Consensus Unfairness**: Honest miners lose their fair chance at early positions, undermining the egalitarian principles of the consensus mechanism
- **Systemic Advantage Accumulation**: Consistent early positions compound over time

**Severity Assessment - Medium:**
- Breaks a critical consensus invariant (verifiable randomness)
- Requires attacker to be an authorized miner (limited attack surface)
- Does not directly steal funds but provides persistent systemic advantage
- Exploitable in every round with minimal computational cost

## Likelihood Explanation

**Attacker Requirements:**
- Must be an authorized miner in the current round (achievable through normal staking/election)
- Can perform hash computations off-chain (trivial)
- No special cryptographic capabilities needed

**Attack Complexity: LOW**
- Computing different signature values is computationally cheap
- Selection of favorable value is straightforward
- Standard block production flow is the entry point
- No additional permissions or special transactions required

**Detection Difficulty:**
- `PreviousInValue = Hash.Empty` is legitimately allowed by the protocol for edge cases
- No penalty mechanism exists for failed self-checks
- Evil miner detection only checks missed time slots: [9](#0-8) 
- Only debug logging occurs for self-check failures, no alerts or permanent records

**Feasibility: HIGH**
- Any motivated miner seeking competitive advantage can execute this
- Can be repeated every round indefinitely
- No blockchain state changes required before attack
- Works under all normal consensus conditions

## Recommendation

**Fix the Logic Flaw:**

Move the signature calculation **inside** the validation block so it only uses the validated `previousInValue`:

```csharp
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
    // Calculate signature from valid previousInValue
    signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
}
```

**Additional Protections:**

1. **Add Signature Verification**: In validation providers, verify that stored signature matches `CalculateSignature(previousInValue)`
2. **Penalty Mechanism**: Track miners who frequently submit invalid `PreviousInValue` and penalize them
3. **Explicit Logging**: Log failed self-checks prominently for monitoring

## Proof of Concept

The vulnerability can be demonstrated by showing that a miner can:
1. Provide an invalid `PreviousInValue` that doesn't hash to their previous `OutValue`
2. Have the block accepted by validation
3. Achieve a specific `FinalOrderOfNextRound` value based on their chosen invalid input
4. Be placed in their desired position in the next round

A test would need to:
- Set up a previous round with a miner who has a known `OutValue`
- Provide a `PreviousInValue` that doesn't hash to that `OutValue` but produces a desired signature
- Call `GetConsensusExtraDataToPublishOutValue` and verify the block is created
- Call validation and verify it passes
- Generate the next round and verify the miner is placed in the manipulated position

The core issue is verifiable through code inspection: the signature calculation at line 92 of `AEDPoSContract_GetConsensusBlockExtraData.cs` occurs outside the validation block (lines 80-90), allowing invalid values to influence consensus order.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L80-90)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L42-44)
```csharp
        RealTimeMinersInformation[pubkey].SupposedOrderOfNextRound = supposedOrderOfNextRound;
        // Initialize FinalOrderOfNextRound as the value of SupposedOrderOfNextRound
        RealTimeMinersInformation[pubkey].FinalOrderOfNextRound = supposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-36)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```
