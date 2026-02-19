# Audit Report

## Title
Signature Manipulation Vulnerability in Extra Block Producer Selection

## Summary
A miner can manipulate their cryptographic signature used for extra block producer selection by providing an arbitrary `PreviousInValue` that bypasses validation. This allows the attacker to predetermine which miner receives the privileged extra block producer role and its associated rewards, breaking the fairness and randomness of the consensus mechanism.

## Finding Description

The vulnerability exists in the AEDPoS consensus mechanism where a miner's signature directly determines the extra block producer selection for the next round. The flaw allows a miner to manipulate their signature while bypassing validation through a design inconsistency.

**The Attack Flow:**

1. **Signature Calculation with Unvalidated Input**: When a miner produces a block, the method performs a self-check to validate `triggerInformation.PreviousInValue`. If the validation fails (the provided value doesn't hash to the expected `OutValue`), the code sets `previousInValue = Hash.Empty` to indicate failure. However, the signature calculation on line 92 still uses the original unvalidated `triggerInformation.PreviousInValue`: [1](#0-0) 

2. **Storage Separation**: The method then stores both values - the sanitized `previousInValue` (Hash.Empty) and the manipulated `signature`: [2](#0-1) 

3. **Validation Bypass**: The validation logic explicitly allows `Hash.Empty` as a valid `PreviousInValue`, which enables the attack: [3](#0-2) 

4. **Signature Storage and Impact**: The manipulated signature is stored in the round data and used to determine the miner's next round order: [4](#0-3) 

5. **Extra Block Producer Selection**: The signature of the first miner (by order) who produces a block determines which miner becomes the extra block producer in the next round: [5](#0-4) 

6. **Attack Vector**: Miners control their node software, specifically the trigger information provider that supplies the `PreviousInValue`: [6](#0-5) 

**Exploitation Steps:**
1. Attacker modifies their node's `AEDPoSTriggerInformationProvider` to return arbitrary `PreviousInValue`
2. Compute all previous round signatures (public blockchain data)
3. Try different `PreviousInValue` values X offline
4. Calculate `signature = XOR(X, XOR(all_previous_signatures))` for each X
5. Find X where `(signature.ToInt64() % minerCount) + 1` equals desired extra block producer order
6. Use that X when producing a block
7. Contract stores `Hash.Empty` (passes validation) but uses manipulated signature
8. Signature determines extra block producer selection

The signature calculation uses XOR operations on the `InValue` and aggregated signatures: [7](#0-6) 

## Impact Explanation

**Consensus Fairness Breach**: The extra block producer role is meant to be randomly and fairly distributed among miners based on unpredictable cryptographic signatures. This vulnerability allows a miner to predetermine the outcome, breaking a core security property of the consensus mechanism.

**Reward Misallocation**: Extra block producers receive additional rewards compared to regular block producers. By manipulating selection, attackers gain disproportionate rewards over honest miners, creating unfair wealth accumulation.

**Systemic Impact**: If multiple miners exploit this, the consensus mechanism degrades from a fair, random system to one where rewards are determined by who can best manipulate signatures. This undermines network trust and could drive honest miners away.

**Cumulative Advantage**: Over many rounds, even a small edge in becoming extra block producer compounds into significant economic advantage, especially for miners who frequently produce the first block in a round.

## Likelihood Explanation

**HIGH Likelihood** - This attack is highly feasible:

1. **Attacker Prerequisites**: Any miner can execute this by modifying their open-source node software. No special privileges, timing attacks, or race conditions required.

2. **Computational Triviality**: With typical miner counts (20-50), finding a suitable `PreviousInValue` requires testing only dozens of values. The XOR operations are computationally trivial and take milliseconds.

3. **Opportunity Frequency**: While an attacker must be the first-by-order miner to produce a block, this occurs regularly. A miner with 5% of mining slots has this opportunity ~5% of rounds.

4. **Detection Impossibility**: The attack is indistinguishable from legitimate cases where a miner didn't participate in the previous round. Using `Hash.Empty` for `PreviousInValue` is a valid state, so there's no on-chain evidence of manipulation.

5. **No Economic Barriers**: The attack has no cost beyond normal mining operations. No tokens to stake, no transactions to pay for - just node software modification.

## Recommendation

**Fix the Signature Calculation Logic**: The signature should be calculated using the validated `previousInValue` (after sanitization), not the raw `triggerInformation.PreviousInValue`.

Change line 92 in `AEDPoSContract_GetConsensusBlockExtraData.cs`:

```csharp
// Before (vulnerable):
signature = previousRound.CalculateSignature(triggerInformation.PreviousInValue);

// After (fixed):
signature = previousRound.CalculateSignature(previousInValue);
```

This ensures that if validation fails and `previousInValue` is set to `Hash.Empty`, the signature is also calculated from `Hash.Empty`, maintaining consistency. The attacker can no longer inject arbitrary values into the signature calculation while passing validation.

**Additional Hardening**: Consider adding explicit validation that `Hash.Empty` is only acceptable when the miner genuinely didn't participate in the previous round (check against historical round data).

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up an AElf testnet with multiple miners
2. Modifying one miner's `AEDPoSTriggerInformationProvider` to return arbitrary `PreviousInValue` values
3. Having that miner produce the first block in a round
4. Observing that they can control which miner becomes the extra block producer in the next round
5. Verifying the manipulated `PreviousInValue` passes validation (stored as `Hash.Empty`)
6. Confirming the signature (calculated from arbitrary value) determines extra block producer order

The test would validate:
- Signature calculated from arbitrary `PreviousInValue` (line 92)
- Stored `previousInValue` is `Hash.Empty` (line 85)
- Validation passes (line 46 of UpdateValueValidationProvider)
- Extra block producer order matches attacker's prediction (lines 118-122 of Round_Generation)

## Notes

This vulnerability specifically affects miners who are first-by-order to produce blocks in a round. The impact scales with the miner's participation rate and could be coordinated among colluding miners to monopolize extra block producer rewards. The fix is straightforward but critical for consensus fairness.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L111-112)
```csharp
        var updatedRound = currentRound.ApplyNormalConsensusData(pubkey, previousInValue,
            outValue, signature);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L13-21)
```csharp
        RealTimeMinersInformation[pubkey].Signature = signature;
        if (RealTimeMinersInformation[pubkey].PreviousInValue == Hash.Empty ||
            RealTimeMinersInformation[pubkey].PreviousInValue == null)
            RealTimeMinersInformation[pubkey].PreviousInValue = previousInValue;

        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L110-122)
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
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/AEDPoSTriggerInformationProvider.cs (L53-67)
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
