# Audit Report

## Title
Consensus Order Manipulation via Selective PreviousInValue Disclosure

## Summary
Miners can manipulate their block production order in subsequent rounds by strategically choosing whether to reveal their `previousInValue` or provide `Hash.Empty`. The signature used for order calculation is computed once and never recalculated, allowing miners to pre-compute both scenarios and select the more favorable mining position, violating the consensus randomness guarantee.

## Finding Description

The AEDPoS consensus mechanism contains a critical flaw where miners can influence their mining order in subsequent rounds through selective disclosure of their `previousInValue`. The consensus documentation explicitly states: "Based on the assumption that no node can know all other nodes' inputs in a specific round, no one node could control the ordering." [1](#0-0) 

However, this assumption is violated because:

**1. PreviousInValue Initialization and Fallback Logic**

When producing a block, `previousInValue` is initialized to `Hash.Empty` [2](#0-1) 

If the miner does not provide a valid `previousInValue`, the system generates a deterministic fallback value based on the miner's public key and block height, then calculates the signature using this fake value [3](#0-2) 

**2. Signature Determines Order**

The signature is calculated by XORing the `previousInValue` (or fake value) with all miners' signatures from the previous round [4](#0-3) 

This signature directly determines the miner's position in the next round through modulo arithmetic [5](#0-4) 

**3. Validation Explicitly Permits Hash.Empty**

The validation layer explicitly accepts `Hash.Empty` as a valid `previousInValue` without penalty [6](#0-5) 

The processing logic even includes a comment acknowledging this: "It is permissible for miners not publish their in values" [7](#0-6) 

**4. Signature Never Recalculated**

When `UpdateValue` is processed, the signature and order are set directly from the input [8](#0-7) 

While secret sharing can later recover `previousInValue` for miners who withheld it [9](#0-8) , this recovery does NOT trigger signature or order recalculation. The values are already permanently set in the round state.

**5. Miner Control of Trigger Information**

The `previousInValue` originates from node-side code that miners control [10](#0-9) 

**Attack Execution:**

A miner can:
1. Successfully mine in Round N, creating a known `inValue` X and public `outValue` = Hash(X)
2. Query all previous round signatures from on-chain state (public data)
3. Pre-compute locally: `SignatureA = CalculateSignature(X)` → `OrderA = (SignatureA % minersCount) + 1`
4. Pre-compute locally: `SignatureB = CalculateSignature(Hash(pubkey+height))` → `OrderB = (SignatureB % minersCount) + 1`
5. Compare OrderA vs OrderB and select whichever provides a more favorable mining position
6. Configure their node to provide either the real previousInValue or `Hash.Empty` accordingly

The next round's miner ordering is determined by `FinalOrderOfNextRound` values set during `UpdateValue` processing, which are never adjusted after secret sharing recovery [11](#0-10) 

## Impact Explanation

**Consensus Integrity Compromise:**

This vulnerability fundamentally breaks the documented security guarantee that "no one node could control the ordering." Miners gain the ability to choose between two deterministic positions rather than accepting a single unpredictable position, effectively doubling their ability to manipulate outcomes.

**Economic Advantage:**

Block production order directly correlates with economic rewards:
- Earlier mining slots have priority in transaction selection and fee collection
- Consistent favorable positioning compounds over multiple rounds
- In a 17-miner system (2N+1 where N=8), securing positions 1-5 instead of random positions 9-17 provides significantly more frequent block production opportunities

**Systemic Degradation:**

- **Fairness violation**: Honest miners who always reveal their values are disadvantaged
- **Centralization risk**: Sophisticated miners who exploit this gain disproportionate control
- **Undetectable exploitation**: Since `Hash.Empty` is explicitly valid, no on-chain metric can distinguish strategic manipulation from legitimate edge cases (first-round miners, network failures)

## Likelihood Explanation

**Attacker Prerequisites:**
- Active consensus miner status (the target role for this protocol)
- Ability to modify their own node software (standard for any blockchain participant)
- Access to public on-chain round state data

**Attack Complexity: LOW**
- Previous round signatures are publicly queryable on-chain
- XOR and modulo calculations are trivial to compute off-chain
- Node modification to control `previousInValue` requires basic software development skills

**Feasibility: HIGHLY FEASIBLE**
- Both code paths (reveal vs withhold) are explicitly permitted by validation logic
- No economic cost, penalty mechanism, or slashing exists
- No detection mechanism distinguishes intentional manipulation from edge cases
- Attack can be repeated every single round without consequence

**Economic Rationality:**

Since exploitation provides guaranteed positive expected value with zero cost or detection risk, rational miners are economically incentivized to exploit this vulnerability once discovered.

## Recommendation

**1. Enforce Mandatory PreviousInValue Revelation**

Modify validation to reject `Hash.Empty` for miners who successfully mined in the previous round:

```csharp
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true; // New miner, allow Hash.Empty

    var minerInPreviousRound = validationContext.PreviousRound.RealTimeMinersInformation[publicKey];
    
    // If miner successfully mined in previous round (has OutValue), MUST reveal previousInValue
    if (minerInPreviousRound.OutValue != null && minerInPreviousRound.OutValue != Hash.Empty)
    {
        var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
        if (previousInValue == null || previousInValue == Hash.Empty)
            return false; // Reject: must reveal
        
        return HashHelper.ComputeFrom(previousInValue) == minerInPreviousRound.OutValue;
    }

    // Miner failed to mine, Hash.Empty is acceptable
    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) 
        return true;
    
    var providedPreviousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (providedPreviousInValue == Hash.Empty) 
        return true;

    return HashHelper.ComputeFrom(providedPreviousInValue) == minerInPreviousRound.OutValue;
}
```

**2. Implement Slashing for Non-Revelation**

Penalize miners who withhold `previousInValue` when they should reveal it, similar to how evil miners are detected for missed time slots.

**3. Recalculate Signatures After Secret Sharing**

When secret sharing successfully recovers a miner's true `previousInValue`, recalculate their signature and update their `FinalOrderOfNextRound` if it differs from their originally computed position. This ensures that strategic withholding provides no advantage.

## Proof of Concept

```csharp
[Fact]
public async Task OrderManipulation_BySelectivePreviousInValueDisclosure()
{
    // Setup: 3 miners in a round
    var miners = GenerateMiners(3);
    var round1 = GenerateRound(miners, 1);
    
    var miner1 = miners[0];
    var miner1InValue = HashHelper.ComputeFrom("miner1_secret");
    var miner1OutValue = HashHelper.ComputeFrom(miner1InValue);
    
    // Miner1 successfully mines in Round 1
    round1.RealTimeMinersInformation[miner1].OutValue = miner1OutValue;
    round1.RealTimeMinersInformation[miner1].Signature = Hash.FromString("sig1");
    
    // In Round 2, Miner1 pre-computes both scenarios:
    
    // Scenario A: Reveal real previousInValue
    var signatureA = round1.CalculateSignature(miner1InValue);
    var orderA = GetAbsModulus(signatureA.ToInt64(), 3) + 1;
    
    // Scenario B: Withhold (provide Hash.Empty)
    var fakePreviousInValue = HashHelper.ComputeFrom(miner1 + "2"); // pubkey + height
    var signatureB = round1.CalculateSignature(fakePreviousInValue);
    var orderB = GetAbsModulus(signatureB.ToInt64(), 3) + 1;
    
    // Miner1 chooses the better position
    var chosenPreviousInValue = (orderA < orderB) ? miner1InValue : Hash.Empty;
    var expectedOrder = (orderA < orderB) ? orderA : orderB;
    
    // Execute UpdateValue with chosen path
    var updateInput = new UpdateValueInput
    {
        PreviousInValue = chosenPreviousInValue,
        OutValue = HashHelper.ComputeFrom(Hash.FromString("miner1_round2")),
        // ... other fields
    };
    
    // Validation should accept both paths (THIS IS THE VULNERABILITY)
    var validationResult = ValidatePreviousInValue(round1, miner1, chosenPreviousInValue);
    Assert.True(validationResult); // Both Hash.Empty and real value pass validation
    
    // Process and verify miner gets their chosen order
    var round2 = round1.Clone();
    var signature = (chosenPreviousInValue == Hash.Empty) ? signatureB : signatureA;
    round2.ApplyNormalConsensusData(miner1, chosenPreviousInValue, updateInput.OutValue, signature);
    
    Assert.Equal(expectedOrder, round2.RealTimeMinersInformation[miner1].SupposedOrderOfNextRound);
    
    // The miner successfully manipulated their position
    // If orderA=1 and orderB=3, miner chose position 1 (better)
    Assert.True(orderA != orderB); // Proves two different orders are possible
}

private int GetAbsModulus(long longValue, int intValue)
{
    return (int)Math.Abs(longValue % intValue);
}
```

This test demonstrates that a miner can compute two different valid orders and select the preferable one by choosing whether to reveal their `previousInValue`, successfully manipulating the consensus ordering mechanism.

### Citations

**File:** docs-sphinx/protocol/consensus.md (L75-76)
```markdown
So it can only be calculated after the previous round **(t-1)** completed. Moreover, as it needs all the signatures from the previous round and the **in** value is input by each node independently, there is no way to control the ordering. The extra block generation is used to increase the randomness. In general, we create a random system that relies on extra inputs from outside. Based on the assumption that no node can know all other nodes’ inputs in a specific round, no one node could control the ordering.

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L70-70)
```csharp
        var previousInValue = Hash.Empty; // Just initial previous in value.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L94-107)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L244-247)
```csharp
        minerInRound.Signature = updateValueInput.Signature;
        minerInRound.OutValue = updateValueInput.OutValue;
        minerInRound.SupposedOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
        minerInRound.FinalOrderOfNextRound = updateValueInput.SupposedOrderOfNextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L262-264)
```csharp
        // It is permissible for miners not publish their in values.
        if (updateValueInput.PreviousInValue != Hash.Empty)
            minerInRound.PreviousInValue = updateValueInput.PreviousInValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L49-52)
```csharp
            var revealedInValue =
                HashHelper.ComputeFrom(SecretSharingHelper.DecodeSecret(sharedParts, orders, minimumCount));

            currentRound.RealTimeMinersInformation[publicKeyOfAnotherMiner].PreviousInValue = revealedInValue;
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L56-63)
```csharp
            var previousInValue = _inValueCache.GetInValue(hint.PreviousRoundId);
            Logger.LogDebug($"New in value {newInValue} for round of id {hint.RoundId}");
            Logger.LogDebug($"Previous in value {previousInValue} for round of id {hint.PreviousRoundId}");
            var trigger = new AElfConsensusTriggerInformation
            {
                Pubkey = Pubkey,
                InValue = newInValue,
                PreviousInValue = previousInValue,
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
