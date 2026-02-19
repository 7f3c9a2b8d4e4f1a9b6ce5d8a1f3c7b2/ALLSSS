# Audit Report

## Title
Miners Can Manipulate Next Round Mining Order Through Invalid PreviousInValue

## Summary
Miners can manipulate their mining position in the next consensus round by providing arbitrary `previousInValue` that fails validation. The validation correctly rejects the invalid value, but the signature calculation still uses the attacker-controlled input, allowing miners to brute-force favorable mining positions without detection.

## Finding Description

The vulnerability exists in the consensus extra data generation flow where signature calculation uses miner-provided `previousInValue` even when validation fails. [1](#0-0) 

When a miner provides an invalid `previousInValue` through the trigger information:

1. **Validation Rejects Invalid Value**: The validation at lines 80-86 correctly detects that `HashHelper.ComputeFrom(triggerInformation.PreviousInValue)` does not match the previous round's `OutValue`, and sets the local variable `previousInValue = Hash.Empty`.

2. **Signature Uses Invalid Value**: However, at line 92, the signature is calculated using `previousRound.CalculateSignature(triggerInformation.PreviousInValue)` - the ORIGINAL attacker-controlled value, not the validated `Hash.Empty`.

3. **Signature Determines Mining Order**: This signature is then passed to `ApplyNormalConsensusData`: [2](#0-1) 

The signature directly determines `supposedOrderOfNextRound` via modulus operation (line 21), which becomes the miner's `FinalOrderOfNextRound`.

4. **Validation Allows Empty PreviousInValue**: During block validation, the `UpdateValueValidationProvider` explicitly allows `Hash.Empty`: [3](#0-2) 

Line 46 returns `true` when `previousInValue == Hash.Empty`, bypassing any validation that the signature matches the stored `previousInValue`.

5. **Next Round Uses Manipulated Order**: When the next round is generated, miners are ordered by `FinalOrderOfNextRound`: [4](#0-3) 

The signature calculation mechanism is: [5](#0-4) 

This means a miner can:
- Retrieve `previousRound` state (public blockchain data)
- Brute-force values `X` where `CalculateSignature(X) % minersCount + 1 == desiredOrder`
- Submit crafted `X` as `PreviousInValue` in trigger information
- Achieve desired mining position while validation passes

## Impact Explanation

**Critical Consensus Integrity Compromise**: This vulnerability breaks the fundamental consensus invariant that miners cannot choose their mining schedule position. The impact includes:

1. **Front-running Advantages**: Miners can position themselves first in the round to collect maximum transaction fees from high-value transactions.

2. **Strategic Timing Control**: Miners can select specific time slots that align with external events or coordinate with other protocol actions.

3. **Unfair Resource Allocation**: Mining order directly affects block production opportunities, reward distribution, and network influence.

4. **Protocol-Wide Effect**: Every consensus participant is affected as the randomness of mining order - a core security property of AEDPoS - is compromised.

5. **Compounding Effect**: Multiple miners exploiting this simultaneously could completely distort the intended fair distribution of mining opportunities.

The severity is HIGH because it fundamentally undermines consensus fairness without requiring any special privileges beyond being an active miner.

## Likelihood Explanation

**High Likelihood - Trivially Exploitable**:

1. **Accessible Entry Point**: `GetConsensusExtraData` is a public ACS4 interface method that any miner calls during block production: [6](#0-5) 

2. **Attacker Control**: While the trigger information provider retrieves `PreviousInValue` from cache, the actual input to the contract is prepared off-chain and fully controlled by the miner: [7](#0-6) 

A malicious miner can simply modify the `PreviousInValue` field before calling the contract.

3. **Trivial Computation**: The attack requires only:
   - Reading public blockchain state (`previousRound`)
   - Offline brute-force to find desired signature
   - Simple XOR operation to reverse-engineer required `previousInValue`

4. **Undetectable**: The failed validation appears identical to a legitimate scenario where a miner "forgot" their previous round InValue or didn't participate in the previous round.

5. **Strong Economic Incentive**: Better mining positions translate directly to higher transaction fees and strategic advantages.

6. **No Mitigation**: There is no validation that verifies the signature was correctly derived from the stored `previousInValue`.

## Recommendation

**Fix the signature calculation logic to use the validated `previousInValue` variable instead of the raw trigger information:**

```csharp
// In GetConsensusExtraDataToPublishOutValue, after the validation block:
if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
{
    if (triggerInformation.PreviousInValue != null &&
        triggerInformation.PreviousInValue != Hash.Empty)
    {
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
        
        // FIX: Use the validated previousInValue, not the raw input
        signature = previousRound.CalculateSignature(previousInValue);  
    }
    else
    {
        // ... existing fallback logic
    }
}
```

This ensures that if validation fails and sets `previousInValue = Hash.Empty`, the signature is calculated from `Hash.Empty`, not from the attacker-controlled invalid value.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a test with multiple miners in a round
2. Having an attacker miner call `GetConsensusExtraData` with a crafted `PreviousInValue` that:
   - Fails validation (doesn't hash to their previous `OutValue`)
   - Produces a signature that gives them mining order 1 in the next round
3. Observing that the validation passes (returns success)
4. Verifying that when the next round is generated, the attacker has position 1
5. Comparing with an honest miner who cannot control their position

The key assertion is: `updatedRound.RealTimeMinersInformation[attackerPubkey].FinalOrderOfNextRound == 1` when the attacker provides a crafted value that produces the desired signature, even though their `PreviousInValue` in the stored round is `Hash.Empty`.

## Notes

This vulnerability specifically affects the AEDPoS consensus mechanism's use of VRF-like properties for mining order determination. The issue is that there's a disconnect between:
- The `previousInValue` stored in the Round state (validated, set to `Hash.Empty` on failure)  
- The `signature` calculation input (uses raw, unvalidated trigger information)

The validation provider correctly checks the stored `previousInValue` but has no way to verify that the `signature` was calculated from it, creating the exploitation window. This is a subtle but critical flaw in the consensus data validation flow.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L74-93)
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
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-21)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L26-37)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L56-59)
```csharp
    public override BytesValue GetConsensusExtraData(BytesValue input)
    {
        return GetConsensusBlockExtraData(input);
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L53-68)
```csharp
        if (hint.Behaviour == AElfConsensusBehaviour.UpdateValue)
        {
            var newInValue = _inValueCache.GetInValue(hint.RoundId);
            var previousInValue = _inValueCache.GetInValue(hint.PreviousRoundId);
            Logger.LogDebug($"New in value {newInValue} for round of id {hint.RoundId}");
            Logger.LogDebug($"Previous in value {previousInValue} for round of id {hint.PreviousRoundId}");
            var trigger = new AElfConsensusTriggerInformation
            {
                Pubkey = Pubkey,
                InValue = newInValue,
                PreviousInValue = previousInValue,
                Behaviour = hint.Behaviour
            };

            return trigger.ToBytesValue();
        }
```
