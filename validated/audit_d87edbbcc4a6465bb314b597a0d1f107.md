# Audit Report

## Title
Last Miner InValue Grinding Attack - Mining Order Manipulation

## Summary
The AEDPoS consensus mechanism's `UpdateValueValidationProvider` only validates backward hash consistency but fails to enforce unbiased generation of the current `InValue` commitment. This allows the last miner in each round to grind their `InValue` selection to manipulate mining order in subsequent rounds, violating the protocol's randomness guarantee.

## Finding Description

The AEDPoS consensus implements a commit-reveal scheme where miners commit `OutValue = Hash(InValue)` in round N and reveal `InValue` in round N+1. The validation provider only checks that the revealed `PreviousInValue` hashes to the previously committed `PreviousOutValue`: [1](#0-0) 

**Critical Gap**: There is NO validation of the randomness or generation method of the CURRENT `InValue` being committed. The contract cannot enforce how `InValue` was generated—it only verifies hash consistency.

The revealed `InValue` is XORed with all signatures from the previous round to calculate the miner's signature, which determines their mining order in the next round: [2](#0-1) [3](#0-2) 

The mining order for the next round is calculated from the signature value using modulo arithmetic: [4](#0-3) [5](#0-4) 

**Attack Execution:**
When a miner mines last in round N:
1. All K-1 other miners have already published their signatures for round N on-chain
2. The attacker calculates their own signature for round N (deterministic from their `PreviousInValue_{N-1}`)
3. The attacker now knows ALL K signatures for round N
4. The attacker tries different `InValue_N` candidates offline
5. For each candidate: `Signature_{N+1} = XOR(InValue_N, all_round_N_signatures)`
6. Calculate `order_{N+2} = (Signature_{N+1}.ToInt64() % K) + 1`
7. Select the `InValue_N` that produces the most favorable order (e.g., order 1)
8. Commit `OutValue_N = Hash(chosen_InValue_N)` in round N
9. Reveal the chosen `InValue_N` in round N+1

The contract computes OutValue from the provided InValue but never validates its generation: [6](#0-5) 

While the protocol includes off-chain InValue generation logic using signatures, this is not cryptographically enforced on-chain: [7](#0-6) 

The VRF validation (lines 75-81) applies to a separate `RandomNumber` field and does not constrain InValue selection.

## Impact Explanation

**Consensus Integrity Violation**: This breaks the fundamental randomness guarantee of the consensus protocol. The protocol assumes miners cannot know all other inputs before committing their own value, but the last miner violates this assumption.

**Concrete Harm:**
- The last miner systematically obtains better mining positions (e.g., order 1) more frequently than probability allows
- Better positions mean more block production opportunities and higher mining rewards over time
- The advantage compounds across many rounds, creating significant economic imbalance
- Honest miners following the protocol are disadvantaged
- Network decentralization is compromised as the attacking miner gains disproportionate influence
- Block reward distribution becomes unfairly skewed toward the attacker

**Severity**: Medium - Requires being last in mining order (1/K probability per round), but the attack is cheap to execute, extremely hard to detect (chosen InValue appears random), and accumulates significant advantage over time. While it doesn't directly steal funds, it manipulates a critical consensus invariant and reward distribution mechanism.

## Likelihood Explanation

**High Likelihood:**
- Any elected miner can execute this attack when they mine last (probability 1/K per round)
- Computational cost is minimal (only offline hash calculations)
- No complex timing requirements or coordination needed
- Can be trivially automated in modified mining software
- Detection is extremely difficult since the chosen `InValue` appears as random as any legitimate value
- On-chain validation only checks hash consistency, not generation method or statistical properties
- No VRF or commitment scheme prevents InValue grinding
- Statistical analysis to detect bias would require extensive data collection and is inconclusive for individual rounds

The attack is straightforward, practical, and profitable for any technically capable miner.

## Recommendation

Implement a Verifiable Random Function (VRF) or commit-commit-reveal scheme to enforce unbiased InValue generation:

**Option 1 - VRF-based InValue:**
Require miners to generate InValue using a VRF with their previous block's signature as input, and verify the VRF proof on-chain. This makes InValue deterministic yet unpredictable until revealed.

**Option 2 - Commit-Commit-Reveal:**
Add an additional commitment phase where miners must commit to their InValue commitment (commit to the OutValue) even earlier, before seeing other miners' current round signatures.

**Option 3 - Threshold Cryptography:**
Use threshold signatures where no single miner can compute the final randomness alone, requiring cooperation from a threshold of miners.

The validation should verify cryptographic proofs that InValue was generated correctly, not just check hash consistency.

## Proof of Concept

```csharp
// PoC demonstrating the grinding attack
[Fact]
public async Task LastMinerCanGrindInValueForBetterOrder()
{
    // Setup: Initialize consensus with K miners
    var miners = GenerateMiners(5); // K = 5
    await InitializeConsensus(miners);
    
    // Round N: First 4 miners mine honestly
    var roundN = await GetCurrentRound();
    for (int i = 0; i < 4; i++)
    {
        await MineBlock(miners[i], GenerateHonestInValue());
    }
    
    // Attacker is last miner - collect all K-1 signatures
    var allSignatures = roundN.RealTimeMinersInformation.Values
        .Where(m => m.Signature != null)
        .Select(m => m.Signature)
        .ToList();
    
    // Grind InValue to get order 1 in round N+2
    Hash bestInValue = null;
    int bestOrder = int.MaxValue;
    
    for (int attempt = 0; attempt < 10000; attempt++)
    {
        var candidateInValue = GenerateRandomHash(attempt);
        
        // Calculate signature for round N+1
        var signatureN1 = XorWithAllSignatures(candidateInValue, allSignatures);
        
        // Calculate order for round N+2
        var orderN2 = (Math.Abs(signatureN1.ToInt64()) % 5) + 1;
        
        if (orderN2 < bestOrder)
        {
            bestOrder = orderN2;
            bestInValue = candidateInValue;
        }
        
        if (bestOrder == 1) break; // Found optimal order
    }
    
    // Attacker mines with ground InValue
    await MineBlock(miners[4], bestInValue);
    
    // Verify attacker gets better order than probability allows
    // With honest behavior, P(order=1) = 1/5 = 20%
    // With grinding, attacker achieves order=1 nearly 100% of attempts
    var nextNextRound = await AdvanceRounds(2);
    var attackerOrder = nextNextRound.RealTimeMinersInformation[miners[4]]?.Order;
    
    attackerOrder.ShouldBe(1); // Attacker successfully manipulated order
}
```

---

**Notes:**
- This vulnerability exists because on-chain validation cannot distinguish between honestly generated and maliciously ground InValue commitments
- The attack exploits the information asymmetry where the last miner sees all other signatures before committing
- The separate VRF mechanism for random numbers does not protect against InValue grinding
- Secret sharing helps reveal missing InValues but does not constrain InValue generation for active miners
- Statistical detection would require long-term analysis and cannot prevent individual attack instances

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L65-69)
```csharp
        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L92-92)
```csharp
                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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
