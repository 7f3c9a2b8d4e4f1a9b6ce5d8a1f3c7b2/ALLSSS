# Audit Report

## Title
Replacement Miner Can Manipulate Mining Order Through Arbitrary PreviousInValue Injection

## Summary
The AEDPoS consensus contract fails to validate `PreviousInValue` for replacement miners appearing for the first time. This allows attackers to inject arbitrary values that directly control their signature calculation, enabling them to manipulate their mining order in the next round through offline brute-forcing, breaking the consensus mechanism's fairness and randomness guarantees.

## Finding Description

The vulnerability exists in the `GetConsensusExtraDataToPublishOutValue()` function where validation logic for `PreviousInValue` is bypassed for replacement miners due to a flawed conditional check. [1](#0-0) 

When a miner provides `triggerInformation.PreviousInValue`, the code uses an AND condition that checks both (1) if the miner existed in the previous round AND (2) if the hash validation fails. For replacement miners who are appearing for the first time, `previousRound.RealTimeMinersInformation.ContainsKey(pubkey)` returns false, causing the entire condition to short-circuit to false. This bypasses the hash validation entirely and causes the code to accept the arbitrary value in the else block, then use it to calculate the miner's signature.

The validation provider confirms this bypass by immediately returning `true` if the miner doesn't exist in the previous round, bypassing all subsequent validation checks. [2](#0-1) 

The arbitrary `PreviousInValue` is then used to calculate the signature through XOR operations with all current miners' signatures. [3](#0-2) 

This signature directly determines the miner's order in the next round through modular arithmetic. [4](#0-3) 

The intended fallback mechanism that should generate a deterministic `fakePreviousInValue` for replacement miners is only used when no `PreviousInValue` is provided in the trigger information. [5](#0-4) 

An attacker controlling their node software can preemptively provide their own `PreviousInValue` in the trigger information, taking the earlier code path where validation is skipped for new miners.

## Impact Explanation

**Critical Consensus Integrity Violation**: The AEDPoS consensus mechanism is designed to ensure unpredictable and fair mining order through cryptographic randomness. This vulnerability allows attackers to deterministically choose their position.

**Concrete Harms**:

1. **Mining Order Manipulation**: Attacker can brute-force offline to select any desired mining position (1 through N) by trying different `PreviousInValue` candidates until the resulting signature produces their target order via the formula `(signature % minersCount) + 1`.

2. **Extra Block Producer Influence**: When an attacker achieves Order 1 in any round, their manipulated signature is used to determine the extra block producer for the following round. [6](#0-5) 

3. **Reward Advantage**: Extra block producers mine additional blocks, increasing their `ProducedBlocks` counter which directly determines mining reward shares through the `CalculateShares` function. [7](#0-6) 

4. **Fairness Violation**: Honest miners lose fair competition for mining positions while the attacker gains systematic advantage in mining order selection.

**Severity: HIGH** - This breaks a fundamental consensus invariant (randomness/fairness of miner ordering), enables reward manipulation, and has no detection mechanism.

## Likelihood Explanation

**Attack Prerequisites**:
- Attacker must be selected as a replacement miner (occurs regularly when miners are marked as evil for missing time slots)
- Attacker controls their node software to modify trigger information (standard assumption for consensus security)

**Attack Complexity: LOW**
- All previous round signatures are publicly available on-chain
- Simple XOR operations and modular arithmetic
- Offline brute-forcing with no time pressure before mining slot
- For 21 miners: ~10-11 attempts average to find Order 1
- Formula: Try different `PreviousInValue` values until `(XOR(PreviousInValue, all_previous_signatures) % minersCount) + 1` equals desired order

**Feasibility: HIGH**
- Evil miner replacement is a regular occurrence in the protocol
- No special permissions beyond being an authorized candidate
- No timing constraints (computation done before mining slot)
- Attack is indistinguishable from legitimate consensus data

**Detection: NONE**
- No on-chain mechanism validates randomness of PreviousInValue for replacement miners
- Manipulated signatures appear legitimate
- No monitoring for order manipulation patterns

**Probability: MEDIUM-HIGH** - Replacement opportunities occur regularly during normal consensus operation.

## Recommendation

Fix the validation logic to properly validate `PreviousInValue` for replacement miners. The validation should not be bypassed simply because a miner is new to the round. Instead:

1. For replacement miners appearing for the first time, enforce the use of the deterministic `fakePreviousInValue` by rejecting any provided `PreviousInValue` in the trigger information
2. Modify the validation logic to check if a miner is a replacement miner and enforce that they cannot provide arbitrary `PreviousInValue`
3. Add validation in `UpdateValueValidationProvider` to verify that replacement miners only use the deterministic fallback value

Suggested fix for `GetConsensusExtraDataToPublishOutValue`:

```csharp
if (triggerInformation.PreviousInValue != null && triggerInformation.PreviousInValue != Hash.Empty)
{
    // For replacement miners (not in previous round), reject provided PreviousInValue
    if (!previousRound.RealTimeMinersInformation.ContainsKey(pubkey))
    {
        Context.LogDebug(() => "Replacement miner cannot provide PreviousInValue");
        previousInValue = Hash.Empty;
        var fakePreviousInValue = HashHelper.ComputeFrom(pubkey.Append(Context.CurrentHeight.ToString()));
        signature = previousRound.CalculateSignature(fakePreviousInValue);
    }
    else if (HashHelper.ComputeFrom(triggerInformation.PreviousInValue) != 
             previousRound.RealTimeMinersInformation[pubkey].OutValue)
    {
        Context.LogDebug(() => "Failed to produce block at previous round?");
        previousInValue = Hash.Empty;
    }
    else
    {
        previousInValue = triggerInformation.PreviousInValue;
        signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
    }
}
```

## Proof of Concept

A test demonstrating this vulnerability would:

1. Set up a consensus round with active miners
2. Mark one miner as evil (missed time slots)
3. Register a replacement miner (attacker)
4. Have the replacement miner provide a crafted `PreviousInValue` in their trigger information
5. Verify that the contract accepts this arbitrary value without validation
6. Calculate that the resulting signature produces the attacker's desired mining order in the next round
7. Demonstrate that by brute-forcing different `PreviousInValue` values offline, the attacker can achieve any target order (e.g., Order 1 to influence extra block producer selection)

The PoC would confirm that the validation bypass allows deterministic control over mining order, breaking consensus fairness guarantees.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L80-92)
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

                signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L94-108)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L19-21)
```csharp
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L789-821)
```csharp
        var averageProducedBlocksCount = CalculateAverage(previousTermInformation.Last().RealTimeMinersInformation
            .Values
            .Select(i => i.ProducedBlocks).ToList());
        // Manage weights of `MinerBasicReward`
        State.ProfitContract.AddBeneficiaries.Send(new AddBeneficiariesInput
        {
            SchemeId = State.BasicRewardHash.Value,
            EndPeriod = previousTermInformation.Last().TermNumber,
            BeneficiaryShares =
            {
                previousTermInformation.Last().RealTimeMinersInformation.Values.Select(i =>
                {
                    long shares;
                    if (State.IsReplacedEvilMiner[i.Pubkey])
                    {
                        // The new miner may have more shares than his actually contributes, but it's ok.
                        shares = i.ProducedBlocks;
                        // Clear the state asap.
                        State.IsReplacedEvilMiner.Remove(i.Pubkey);
                    }
                    else
                    {
                        shares = CalculateShares(i.ProducedBlocks, averageProducedBlocksCount);
                    }

                    return new BeneficiaryShare
                    {
                        Beneficiary = GetProfitsReceiver(i.Pubkey),
                        Shares = shares
                    };
                })
            }
        });
```
