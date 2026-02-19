# Audit Report

## Title
Binary Choice in Mining Order Calculation Allows Consensus Manipulation

## Summary
Miners can manipulate their position in the next round by choosing whether to provide their `PreviousInValue` during block production. This binary choice results in different signature calculations that determine mining order, allowing malicious miners to select more favorable positions and undermining the fairness guarantees of the AEDPoS consensus mechanism.

## Finding Description

The vulnerability exists in how the AEDPoS consensus contract calculates signatures for determining next-round mining order when miners produce blocks.

When a miner produces a block in `GetConsensusExtraDataToPublishOutValue`, the system has two code paths for calculating the signature that determines their next-round position:

**Path 1 (Provide PreviousInValue):** If the miner provides their `PreviousInValue` in the trigger information, the signature is calculated using that value. [1](#0-0) 

**Path 2 (Omit PreviousInValue):** If the miner provides `null` or `Hash.Empty`, the system computes a `fakePreviousInValue` based on the miner's pubkey and current block height. [2](#0-1) 

The root cause is that `InValue` is never stored on-chain for miners who produce blocks successfully - it's only set for miners who **miss** their time slots. [3](#0-2) 

During normal block production via `ProcessUpdateValue`, the `InValue` field is never assigned. [4](#0-3) 

This means the on-chain check at line 99 to retrieve `appointedPreviousInValue` from the previous round will always find `null` for miners who mined normally, causing the system to fall back to the predictable `fakePreviousInValue`.

The calculated signature directly determines mining order in the next round. [5](#0-4) 

The signature is computed by XORing the provided `inValue` with all previous miners' signatures. [6](#0-5) 

Critically, the validation system explicitly allows miners to omit their `PreviousInValue` by accepting `Hash.Empty` as valid. [7](#0-6) 

The code even includes a comment stating this is intentional: "It is permissible for miners not publish their in values." [8](#0-7) 

**Attack Execution:**
1. Miner has their `PreviousInValue` cached locally from the previous round (stored via `SecretSharingService`) [9](#0-8) 
2. Before block production, the miner computes both possible orders:
   - `orderA = GetAbsModulus(CalculateSignature(cachedPreviousInValue).ToInt64(), minersCount) + 1`
   - `orderB = GetAbsModulus(CalculateSignature(Hash(pubkey + currentHeight)).ToInt64(), minersCount) + 1`
3. The miner modifies their node software or cache to control which value gets provided [10](#0-9) 
4. They select whichever option gives them a better position in the next round

## Impact Explanation

This vulnerability directly compromises the **consensus integrity** of the AEDPoS protocol by allowing miners to manipulate their scheduling position.

**Specific Harms:**
1. **MEV Extraction**: Earlier mining positions allow miners to be first to process transactions, enabling front-running and other MEV opportunities
2. **Fairness Violation**: The AEDPoS design assumes random, unpredictable mining order based on cryptographic secrets. This binary choice breaks that assumption
3. **Competitive Disadvantage**: Honest miners who always provide their `PreviousInValue` consistently are disadvantaged against attackers who strategically choose
4. **Extra Block Producer Bias**: Mining order affects selection for the extra block producer role, which has additional privileges [11](#0-10) 

The attack can be repeated every round by any active miner, systematically biasing the consensus schedule over time.

**Severity: HIGH** - Violates core consensus fairness guarantees and enables systematic manipulation by any miner.

## Likelihood Explanation

**Attacker Capabilities:**
- Must be an active miner in the current round (legitimate participant)
- Requires running modified node software to control `PreviousInValue` provision
- Can predict the block height at which they'll mine based on their time slot

**Attack Feasibility:**
- **Technical Barrier**: Moderate - requires modifying `AEDPoSTriggerInformationProvider` or manipulating the local cache
- **Economic Cost**: Zero - no on-chain penalty for omitting `PreviousInValue`
- **Detection Risk**: None - validation explicitly allows `Hash.Empty`, making malicious omission indistinguishable from legitimate cache misses
- **Repeatability**: High - can be executed every round

**Probability: MEDIUM-HIGH** - While requiring custom software is a barrier, any technically capable miner can implement this attack, and the lack of detection mechanisms means it offers pure upside with no risk.

## Recommendation

**Short-term Fix:**
Require miners to always provide their `PreviousInValue` when it should be available. Implement on-chain tracking of whether a miner produced a block in the previous round, and reject blocks that omit `PreviousInValue` when the miner should have it.

**Implementation:**
```csharp
// In GetConsensusExtraDataToPublishOutValue
if (triggerInformation.PreviousInValue == null || triggerInformation.PreviousInValue == Hash.Empty)
{
    // Check if miner produced block in previous round
    if (previousRound.RealTimeMinersInformation.ContainsKey(pubkey) && 
        previousRound.RealTimeMinersInformation[pubkey].OutValue != null)
    {
        // Miner produced block in previous round, should have PreviousInValue
        Assert(false, "PreviousInValue required for miners who produced blocks in previous round.");
    }
    // Otherwise allow fakePreviousInValue for legitimate cases (first round, missed previous round, etc.)
}
```

**Long-term Fix:**
Store the `InValue` on-chain for all miners who produce blocks (not just missed miners), eliminating the need for miners to self-report their `PreviousInValue`. This removes the binary choice entirely.

## Proof of Concept

This vulnerability requires understanding the complete consensus flow across multiple rounds. A test would need to:

1. Set up a multi-miner consensus round
2. Have a miner produce a block normally in round N (generating and caching their InValue locally)
3. In round N+1, demonstrate that the miner can compute two different possible orders by either:
   - Providing their cached PreviousInValue from round N
   - Omitting it and forcing the system to use Hash(pubkey + currentHeight)
4. Show that both options pass validation
5. Demonstrate that the resulting orders are different and predictable

The test would require mocking the cache behavior in `AEDPoSTriggerInformationProvider` to simulate both scenarios, then verifying that `ApplyNormalConsensusData` produces different `SupposedOrderOfNextRound` values based on which path is taken.

## Notes

While the claim describes miners "choosing block heights," this is inaccurate - miners must mine during their assigned time slots enforced by `TimeSlotValidationProvider`. However, the core vulnerability remains valid: miners have a binary choice (provide or omit `PreviousInValue`) that affects their next-round position, and they can compute both outcomes offline to select the more favorable option.

The system's design intentionally allows omitting `PreviousInValue` to handle legitimate cases (node restarts, first-time miners, cache losses), but this creates an exploitable choice mechanism that undermines consensus fairness. The lack of any mechanism to distinguish malicious omission from legitimate cases makes this attack undetectable.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L74-92)
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L238-285)
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

        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }

        if (!TryToUpdateRoundInformation(currentRound)) Assert(false, "Failed to update round information.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ApplyNormalConsensusData.cs (L8-47)
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

        return this;
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

**File:** src/AElf.Kernel.Consensus.AEDPoS/Application/SecretSharingService.cs (L39-61)
```csharp
    public async Task AddSharingInformationAsync(SecretSharingInformation secretSharingInformation)
    {
        try
        {
            var selfPubkey = (await _accountService.GetPublicKeyAsync()).ToHex();

            if (!secretSharingInformation.PreviousRound.RealTimeMinersInformation.ContainsKey(selfPubkey)) return;

            var newInValue = await GenerateInValueAsync(secretSharingInformation);
            Logger.LogDebug(
                $"Add in value {newInValue} for round id {secretSharingInformation.CurrentRoundId}");
            _inValueCache.AddInValue(secretSharingInformation.CurrentRoundId, newInValue);

            if (secretSharingInformation.PreviousRound.RealTimeMinersInformation.Count == 1) return;

            await CollectPiecesWithSecretSharingAsync(secretSharingInformation, newInValue, selfPubkey);
            RevealPreviousInValues(secretSharingInformation, selfPubkey);
        }
        catch (Exception e)
        {
            Logger.LogError(e, "Error in AddSharingInformationAsync.");
        }
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-50)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
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

        // Set miners' information of miners missed their time slot in current round.
        var occupiedOrders = minersMinedCurrentRound.Select(m => m.FinalOrderOfNextRound).ToList();
        var ableOrders = Enumerable.Range(1, minersCount).Where(i => !occupiedOrders.Contains(i)).ToList();
        for (var i = 0; i < minersNotMinedCurrentRound.Count; i++)
        {
            var order = ableOrders[i];
            var minerInRound = minersNotMinedCurrentRound[i];
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minersNotMinedCurrentRound[i].Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp
```
