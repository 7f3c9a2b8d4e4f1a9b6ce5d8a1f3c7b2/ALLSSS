# Audit Report

## Title
Insufficient Entropy Validation in UpdateValue Consensus Data Allows Mining Order Manipulation

## Summary
The AEDPoS consensus validation only checks that `OutValue` and `Signature` byte arrays are non-empty using `.Any()`, without verifying their cryptographic validity. This allows malicious miners to submit arbitrary consensus values and manipulate their mining position in subsequent rounds while evading accountability by never revealing their `InValue`.

## Finding Description

The vulnerability exists in the consensus validation pipeline where miners can bypass the commitment-reveal scheme by providing arbitrary `OutValue` and `Signature` values that pass only superficial validation.

**Insufficient Validation:** The `NewConsensusInformationFilled()` function only verifies that byte arrays contain at least one element, not their cryptographic validity. [1](#0-0) 

A byte array of all zeros or any arbitrary data passes this check. The system never verifies that `OutValue` equals `Hash(InValue)` or that `Signature` was properly computed via `CalculateSignature()`.

**Reveal Evasion:** The `ValidatePreviousInValue()` function explicitly allows miners to set `previousInValue = Hash.Empty`, providing an escape path to avoid revealing their committed value. [2](#0-1) 

**Mining Order Manipulation:** The `Signature` value directly determines mining order through integer conversion and modulo operation. [3](#0-2)  An attacker can choose a signature value to position themselves favorably (e.g., mining first or at strategic moments).

**Direct Copy Without Verification:** The `RecoverFromUpdateValue` function copies provided values directly into the validation context without cryptographic verification. [4](#0-3) 

**No Penalties:** The system only handles miners who completely failed to mine (`OutValue == null`) but does not penalize miners who mined with invalid consensus data. [5](#0-4) 

**Legitimate Path Comparison:** During honest block production, `OutValue` is cryptographically computed as `Hash(InValue)` and `Signature` is computed via `CalculateSignature(PreviousInValue)`. [6](#0-5)  However, validation does not enforce these cryptographic relationships.

## Impact Explanation

**1. Mining Order Manipulation:** Attackers can control their position in the next round's mining schedule by choosing arbitrary `Signature` values. The signature conversion to Int64 and modulo operation makes mining order deterministic from the signature. [7](#0-6)  This enables consistent positioning at advantageous slots for front-running or MEV extraction.

**2. Consensus Randomness Corruption:** The `CalculateSignature` function aggregates miner signatures through XOR operations to generate randomness. [8](#0-7)  By submitting controlled signature values, attackers can bias this randomness, affecting all systems that depend on consensus-generated random numbers.

**3. Commitment-Reveal Scheme Broken:** AEDPoS relies on a commitment-reveal mechanism where miners commit to `OutValue = Hash(InValue)` and later reveal `InValue`. The lack of cryptographic validation and explicit allowance of `Hash.Empty` as `previousInValue` breaks this fundamental security property, eliminating cryptographic accountability.

All network participants are affected as consensus integrity is compromised. Honest miners face unfair competition, and predictable mining order enables timing-based attacks.

## Likelihood Explanation

**Attack Complexity:** Low. The attacker only needs to:
1. Set `OutValue` to arbitrary bytes (e.g., `[0]`) that pass `.Any()` check
2. Calculate and set `Signature` to a value where `signature.ToInt64() % minersCount + 1` equals their desired position
3. In the next round, set `PreviousInValue = Hash.Empty` (explicitly allowed by validation)

**Attacker Capabilities:** Any miner in the current miner list can execute this attack with full control over their block's consensus extra data.

**Detection:** Difficult to detect because:
- `Hash.Empty` for `PreviousInValue` is explicitly allowed by validation logic [9](#0-8) 
- No on-chain mechanism tracks miners who consistently avoid reveals
- The system only penalizes complete failure to mine, not invalid consensus data submission [10](#0-9) 

**Economic Rationality:** The attack provides competitive advantages (favorable mining slots, consensus influence) with no penalties, making it economically rational for profit-maximizing miners.

## Recommendation

Implement cryptographic validation of consensus values:

1. **Verify OutValue Commitment:** When `PreviousInValue` is revealed, verify that `Hash(PreviousInValue) == PreviousOutValue` from the previous round, rejecting blocks that fail this check.

2. **Verify Signature Computation:** Recalculate the expected signature using `previousRound.CalculateSignature(PreviousInValue)` and verify it matches the provided signature.

3. **Enforce Reveals:** Do not allow `Hash.Empty` as `PreviousInValue` after the first round. Miners who fail to reveal should face penalties (missed time slots, slashing, or exclusion from future rounds).

4. **Track Reveal History:** Maintain on-chain state tracking miners who consistently avoid reveals and apply escalating penalties.

5. **Enhanced Entropy Validation:** Add minimum entropy requirements for `OutValue` and `Signature` byte arrays to prevent trivial values like all-zeros.

## Proof of Concept

A malicious miner can manipulate their mining order by:
1. Producing a block in Round N with `OutValue = Hash.FromByteArray(new byte[] {0})` and `Signature` chosen so `signature.ToInt64() % minersCount + 1 = desiredPosition`
2. In Round N+1, setting `PreviousInValue = Hash.Empty` to avoid revealing that `OutValue` was not legitimately computed
3. The validation passes because `.Any()` returns true for non-empty arrays and `Hash.Empty` is explicitly allowed
4. The miner successfully positions themselves at their chosen mining slot without cryptographic accountability

This can be repeated every round, giving persistent mining order control.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-22)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
        var sigNum = signature.ToInt64();

        var supposedOrderOfNextRound = GetAbsModulus(sigNum, minersCount) + 1;

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Recover.cs (L8-33)
```csharp
    public Round RecoverFromUpdateValue(Round providedRound, string pubkey)
    {
        if (!RealTimeMinersInformation.ContainsKey(pubkey) ||
            !providedRound.RealTimeMinersInformation.ContainsKey(pubkey))
            return this;

        var minerInRound = RealTimeMinersInformation[pubkey];
        var providedInformation = providedRound.RealTimeMinersInformation[pubkey];
        minerInRound.OutValue = providedInformation.OutValue;
        minerInRound.Signature = providedInformation.Signature;
        minerInRound.PreviousInValue = providedInformation.PreviousInValue;
        minerInRound.ImpliedIrreversibleBlockHeight = providedInformation.ImpliedIrreversibleBlockHeight;
        minerInRound.ActualMiningTimes.Add(providedInformation.ActualMiningTimes);

        foreach (var information in providedRound.RealTimeMinersInformation)
        {
            RealTimeMinersInformation[information.Key].SupposedOrderOfNextRound =
                information.Value.SupposedOrderOfNextRound;
            RealTimeMinersInformation[information.Key].FinalOrderOfNextRound =
                information.Value.FinalOrderOfNextRound;
            RealTimeMinersInformation[information.Key].PreviousInValue =
                information.Value.PreviousInValue;
        }

        return this;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L171-221)
```csharp
    private void SupplyCurrentRoundInformation()
    {
        var currentRound = GetCurrentRoundInformation(new Empty());
        Context.LogDebug(() => $"Before supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
        var notMinedMiners = currentRound.RealTimeMinersInformation.Values.Where(m => m.OutValue == null).ToList();
        if (!notMinedMiners.Any()) return;
        TryToGetPreviousRoundInformation(out var previousRound);
        foreach (var miner in notMinedMiners)
        {
            Context.LogDebug(() => $"Miner pubkey {miner.Pubkey}");

            Hash previousInValue = null;
            Hash signature = null;

            // Normal situation: previous round information exists and contains this miner.
            if (previousRound != null && previousRound.RealTimeMinersInformation.ContainsKey(miner.Pubkey))
            {
                // Check this miner's:
                // 1. PreviousInValue in current round; (means previous in value recovered by other miners)
                // 2. InValue in previous round; (means this miner hasn't produce blocks for a while)
                previousInValue = currentRound.RealTimeMinersInformation[miner.Pubkey].PreviousInValue;
                if (previousInValue == null)
                    previousInValue = previousRound.RealTimeMinersInformation[miner.Pubkey].InValue;

                // If previousInValue is still null, treat this as abnormal situation.
                if (previousInValue != null)
                {
                    Context.LogDebug(() => $"Previous round: {previousRound.ToString(miner.Pubkey)}");
                    signature = previousRound.CalculateSignature(previousInValue);
                }
            }

            if (previousInValue == null)
            {
                // Handle abnormal situation.

                // The fake in value shall only use once during one term.
                previousInValue = HashHelper.ComputeFrom(miner);
                signature = previousInValue;
            }

            // Fill this two fields at last.
            miner.InValue = previousInValue;
            miner.Signature = signature;

            currentRound.RealTimeMinersInformation[miner.Pubkey] = miner;
        }

        TryToUpdateRoundInformation(currentRound);
        Context.LogDebug(() => $"After supply:\n{currentRound.ToString(Context.RecoverPublicKey().ToHex())}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L65-93)
```csharp
        Assert(triggerInformation.InValue != null, "In value should not be null.");

        var outValue = HashHelper.ComputeFrom(triggerInformation.InValue);
        var signature =
            HashHelper.ConcatAndCompute(outValue, triggerInformation.InValue); // Just initial signature value.
        var previousInValue = Hash.Empty; // Just initial previous in value.

        if (TryToGetPreviousRoundInformation(out var previousRound) && !IsFirstRoundOfCurrentTerm(out _))
        {
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L110-115)
```csharp
    public Hash CalculateSignature(Hash inValue)
    {
        return HashHelper.XorAndCompute(inValue,
            RealTimeMinersInformation.Values.Aggregate(Hash.Empty,
                (current, minerInRound) => HashHelper.XorAndCompute(current, minerInRound.Signature)));
    }
```
