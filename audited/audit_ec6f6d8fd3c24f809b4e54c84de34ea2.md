# Audit Report

## Title
Consensus Signature Manipulation via PreviousInValue Bypass

## Summary
Miners can bypass the cryptographic commitment scheme in AEDPoS consensus by providing `Hash.Empty` for `PreviousInValue`, forcing the contract to calculate signatures using a deterministic fake value instead of their actual committed InValue. This allows miners to choose between two different signature values and manipulate their mining order in subsequent rounds, breaking the randomness guarantees of the consensus protocol.

## Finding Description

The AEDPoS consensus protocol uses a cryptographic commitment scheme where miners generate a random `InValue`, publish `OutValue = Hash(InValue)`, and later reveal `InValue` as `PreviousInValue` in the next round. This value is critical for signature calculation, which determines mining order.

**Validation Bypass:**
The validation explicitly allows `Hash.Empty` for `PreviousInValue` without penalty: [1](#0-0) 

**Fake Value Calculation:**
When `PreviousInValue` is null or `Hash.Empty`, the contract computes a fake value based on the miner's public key and block height: [2](#0-1) 

The code attempts to use `appointedPreviousInValue` from the previous round's stored `InValue`, but for actively mining nodes, this field is null. The `InValue` field is only populated for miners who missed their turn: [3](#0-2) 

This is confirmed by the fact that `InValue` is only set in one location in the entire codebase - specifically for miners who didn't mine (line 213).

**Signature Impact:**
The signature calculated with either the real or fake `PreviousInValue` directly determines the miner's order in the next round through a modulo operation: [4](#0-3) 

This order is then used to assign actual mining positions in the next round: [5](#0-4) 

**Attack Execution:**
A rational miner can:
1. Pre-compute `sig_real = previousRound.CalculateSignature(cached_real_InValue)`
2. Pre-compute `sig_fake = previousRound.CalculateSignature(Hash(pubkey || currentHeight))`
3. Calculate resulting orders: `order = (sig % minersCount) + 1`
4. Choose whichever provides a more favorable mining position
5. If choosing fake path: provide `Hash.Empty` for `PreviousInValue` when producing the block

The validation passes, and the miner gains their preferred order without consequences.

## Impact Explanation

This vulnerability breaks a fundamental security property of AEDPoS consensus: **unpredictable and non-manipulable mining order assignment**.

**Direct Harm:**
- Miners can optimize their mining positions for MEV extraction (favorable timing for transaction inclusion/ordering)
- Potential for censorship attacks by manipulating which miner processes sensitive transactions
- Coordination among multiple miners could amplify these effects
- Creates a Nash equilibrium where rational miners must exploit this to remain competitive

**Consensus Integrity:**
The cryptographic commitment scheme (InValue/OutValue) exists specifically to prevent miners from manipulating randomness. This bypass completely defeats that security mechanism, allowing miners to effectively choose between two random values instead of being bound to their original commitment.

**Severity: HIGH** - Violates core consensus security assumptions. While the fake value is deterministic (not arbitrary), the ability to choose between two options provides meaningful strategic advantage in a competitive mining environment.

## Likelihood Explanation

**Attacker Capability:**
Any miner participating in consensus can execute this attack. The only requirement is controlling their own off-chain `InValue` cache population, which is entirely under their control.

**Attack Complexity: LOW**
- All computation can be done off-chain before producing a block
- Previous round state is publicly available on-chain
- No special permissions or state manipulation required
- Simply providing `Hash.Empty` or not caching the value triggers the exploit

**Economic Incentive:**
- **Cost:** Zero (just don't cache a value or provide `Hash.Empty`)
- **Benefit:** Improved block production scheduling, MEV opportunities
- **Detection:** Difficult - appears identical to legitimate cache misses
- **Nash Equilibrium:** In competitive environments, all rational miners would adopt this strategy to avoid being disadvantaged

**Probability: HIGH** - The combination of zero cost, direct benefit, and no effective countermeasures makes this highly likely to be exploited by rational actors.

## Recommendation

Implement strict validation to prevent the fake value path from being exploited:

**Option 1: Require Valid PreviousInValue**
Modify the validation to reject `Hash.Empty` unless it's genuinely the first time the miner is producing a block in a term. Verify against previous round participation:

```csharp
// In UpdateValueValidationProvider.cs
private bool ValidatePreviousInValue(ConsensusValidationContext validationContext)
{
    var extraData = validationContext.ExtraData;
    var publicKey = validationContext.SenderPubkey;

    if (!validationContext.PreviousRound.RealTimeMinersInformation.ContainsKey(publicKey)) 
        return true; // First time mining

    if (extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue == null) 
        return false; // Must provide PreviousInValue if was in previous round

    var previousInValue = extraData.Round.RealTimeMinersInformation[publicKey].PreviousInValue;
    if (previousInValue == Hash.Empty)
        return false; // Reject Hash.Empty for active miners

    var previousOutValue = validationContext.PreviousRound.RealTimeMinersInformation[publicKey].OutValue;
    return HashHelper.ComputeFrom(previousInValue) == previousOutValue;
}
```

**Option 2: Neutralize Fake Path Impact**
If the fake path must be maintained for legitimate fallback scenarios, ensure it doesn't provide strategic advantage by using the same signature for all miners using the fake path, or by not allowing the fake signature to determine mining order.

**Option 3: Add Penalties**
Implement slashing or reputation penalties for miners who use the fake value path when they could have provided their real `PreviousInValue`, making the attack economically unviable.

## Proof of Concept

A proof of concept would demonstrate:

1. Miner participates in Round N, publishing `OutValue_N`
2. In Round N+1, miner queries previous round state
3. Miner computes both possible signatures and resulting orders
4. Miner provides `Hash.Empty` for `PreviousInValue` if fake path yields better order
5. Validation passes, miner obtains preferred position in Round N+2

The test would show that a miner can consistently choose their more favorable mining order option by strategically providing or withholding their `PreviousInValue`, giving them a measurable advantage over honest miners who always reveal their committed values.

**Note:** A complete executable test would require access to the full AElf testing framework and contract deployment environment, including the ability to simulate multiple miners and round transitions. The core logic flow has been verified through static analysis of the production contract code.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/UpdateValueValidationProvider.cs (L46-46)
```csharp
        if (previousInValue == Hash.Empty) return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L169-221)
```csharp
    ///     To fill up with InValue and Signature if some miners didn't mined during current round.
    /// </summary>
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L18-21)
```csharp
        var minersCount = RealTimeMinersInformation.Count;
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
