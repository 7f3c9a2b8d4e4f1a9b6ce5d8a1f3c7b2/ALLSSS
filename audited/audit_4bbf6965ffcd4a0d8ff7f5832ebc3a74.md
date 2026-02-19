### Title
Round Transition Block Count Reset Allows Extra Block Producer to Exceed Maximum Block Limit

### Summary
During round transitions, the extra block producer can exploit a block count reset vulnerability to produce up to 17 blocks instead of the intended 8-9 blocks per time slot. The vulnerability occurs because `ProducedTinyBlocks` is reset to 1 and `ActualMiningTimes` is cleared during `NextRound` generation, causing the `IsLastTinyBlockOfCurrentSlot()` function to miscalculate `blocksBeforeCurrentRound` and allow excessive block production.

### Finding Description

The vulnerability exists in the interaction between round generation logic and the tiny block limit calculation.

**Root Cause - State Reset During Round Transition:**

When a miner produces a `NextRound` block to transition rounds, the `GenerateNextRoundInformation` method creates fresh `MinerInRound` objects for the next round without preserving `ActualMiningTimes` or `ProducedTinyBlocks` from the previous round: [1](#0-0) 

After generation, the extra block producer's state is explicitly reset: [2](#0-1) 

This reset causes `ProducedTinyBlocks = 1` and `ActualMiningTimes = [T_nextRound]` (containing only the NextRound block timestamp), losing all record of blocks produced before the round transition.

**Vulnerable Calculation Logic:**

The `IsLastTinyBlockOfCurrentSlot()` function attempts to account for blocks produced before the current round started: [3](#0-2) 

However, after the round transition, `ActualMiningTimes` only contains recent timestamps, so `blocksBeforeCurrentRound` returns 1 (only counting the NextRound block) instead of 9 (accounting for 8 blocks before transition + 1 NextRound block).

**Why Extra Block Producer Gets Special Privileges:**

The consensus behavior provider allows extra block producers to mine additional blocks across round boundaries: [4](#0-3) 

This logic is designed to allow `maximumBlocksCount + blocksBeforeCurrentRound` total blocks, but the calculation becomes incorrect due to the state reset.

**Insufficient Existing Protections:**

The `ContinuousBlocksValidationProvider` only prevents absolute monopolization by tracking a different metric: [5](#0-4) 

This validation checks `BlocksCount < 0` based on miner count, not per-slot limits, and does not prevent the round transition exploit.

### Impact Explanation

**Direct Harm:**
- A malicious extra block producer can produce **17 blocks instead of 8-9** per time slot (112% excess)
- Monopolizes mining rewards, earning approximately **188% of intended rewards** for that slot
- Repeated exploitation: Extra block producer role rotates, allowing different miners to exploit this in successive rounds

**Protocol-Level Damage:**
- **Centralization Risk**: Miners are incentivized to time their blocks to become extra block producers for increased rewards
- **Mining Reward Misallocation**: Total block rewards exceed intended distribution, affecting tokenomics
- **Consensus Integrity**: Violates the invariant that miners should produce at most `maximumBlocksCount` (8) blocks per time slot, as defined in: [6](#0-5) 

**Who is Affected:**
- Honest miners receive reduced relative rewards
- Token holders face inflation from excess mining rewards
- Network decentralization is compromised

**Severity Justification: HIGH**
- Direct fund impact through reward misallocation
- Consensus integrity violation (blocks produced exceed design limit)
- Affects core consensus mechanism functionality

### Likelihood Explanation

**Attacker Capabilities:**
- Only requires being selected as extra block producer (rotates among all miners)
- No special permissions or compromised keys needed
- Natural part of normal consensus operation

**Attack Complexity: LOW**
- Straightforward execution: simply continue producing tiny blocks after NextRound
- No complex timing requirements or race conditions
- Automated mining software can easily implement this

**Feasibility Conditions:**
- Extra block producer role is assigned deterministically via signature-based selection: [7](#0-6) 

- Every miner will eventually become extra block producer
- No external preconditions required

**Detection Constraints:**
- Difficult to detect as blocks are valid and pass all existing validations
- Appears as normal tiny block production within miner's time slot
- No invalid signatures or consensus rule violations

**Economic Rationality:**
- Cost: Normal block production computational costs
- Benefit: 188% of normal rewards for that slot
- Highly profitable with minimal additional cost

**Probability Assessment: HIGH**
- Will occur naturally when miners optimize for maximum blocks/rewards
- Repeatable every round by different extra block producers
- No operational barriers to exploitation

### Recommendation

**Primary Fix - Preserve Historical Block Count:**

Modify `IsLastTinyBlockOfCurrentSlot()` to correctly account for all blocks produced across round transitions:

1. **Track persistent block count**: Add a field to preserve the total blocks produced before round transition:
   - In `MinerInRound` protobuf, add `int64 produced_blocks_before_current_round`
   - During `GenerateNextRoundInformation`, populate this field with the extra block producer's total `ActualMiningTimes.Count` from the previous round

2. **Update calculation logic** in `TinyBlockCommandStrategy.IsLastTinyBlockOfCurrentSlot()`:
   - Instead of: `var blocksBeforeCurrentRound = MinerInRound.ActualMiningTimes.Count(t => t < roundStartTime);`
   - Use: `var blocksBeforeCurrentRound = MinerInRound.ProducedBlocksBeforeCurrentRound;`
   - This directly uses the preserved count rather than recalculating from reset timestamps

**Alternative Fix - Explicit Validation:**

Add validation in `ProcessTinyBlock` and `ProcessUpdateValue`: [8](#0-7) 

Add check:
```
var totalBlocksInExtendedSlot = minerInRound.ProducedTinyBlocks;
if (currentRound.ExtraBlockProducerOfPreviousRound == _processingBlockMinerPubkey) {
    var maxAllowed = GetMaximumBlocksCount() + minerInRound.ProducedBlocksBeforeCurrentRound;
    Assert(totalBlocksInExtendedSlot <= maxAllowed, "Exceeded maximum blocks for extended slot");
}
```

**Invariant Enforcement:**

Add explicit assertion that extra block producers cannot exceed total limit:
- Maximum blocks per extended slot = `maximumBlocksCount` (extra slot before round) + `maximumBlocksCount` (regular slot in new round)
- Assert this limit in both consensus command generation and processing

**Test Cases:**

1. Test extra block producer produces exactly `maximumBlocksCount` blocks before and after round transition
2. Test that producing `maximumBlocksCount + 1` blocks after NextRound fails validation
3. Test round transition correctly preserves block count for limit calculation

### Proof of Concept

**Initial State:**
- Round R1 active, miner M selected as extra block producer for R1
- `maximumBlocksCount = 8` (AEDPoSContractConstants.MaximumTinyBlocksCount)
- Miner M has mining slot before R2 starts

**Exploitation Steps:**

**Phase 1: Mine Maximum Blocks in Extra Slot (Before Round R2)**

1. M produces UpdateValue block at timestamp T1 (round R1):
   - State: `R1.M.ProducedTinyBlocks = 1`, `R1.M.ActualMiningTimes = [T1]`

2. M produces 7 TinyBlocks at T2-T8 (all timestamps < R2.GetRoundStartTime()):
   - State: `R1.M.ProducedTinyBlocks = 8`, `R1.M.ActualMiningTimes = [T1...T8]`
   - Check passes: `IsLastTinyBlockOfCurrentSlot()` returns true when `ProducedTinyBlocks == 8`

**Phase 2: Execute Round Transition (NextRound Block)**

3. M produces NextRound block at T_next:
   - `GenerateNextRoundInformation` executes, creating fresh MinerInRound
   - **CRITICAL**: State reset occurs:
     * `R2.M.ProducedTinyBlocks = 1` (reset from 8)
     * `R2.M.ActualMiningTimes = [T_next]` (previous [T1...T8] lost)
   - `R2.GetRoundStartTime() = T_next + miningInterval`

**Phase 3: Exploit - Produce Excess Blocks in New Round**

4. M produces TinyBlock at T9 (timestamp >= R2.GetRoundStartTime()):
   - Behavior check passes (line 71-76 of ConsensusBehaviourProviderBase):
     * `ActualMiningTimes.Count = 1`, `blocksBeforeCurrentRound = 1`
     * Check: `1 + 1 < 8 + 1` → `2 < 9` ✓ (allows TinyBlock)
   - State: `R2.M.ProducedTinyBlocks = 2`, `R2.M.ActualMiningTimes = [T_next, T9]`

5. M continues producing TinyBlocks T10-T16 (8 total blocks in R2):
   - Each passes `IsLastTinyBlockOfCurrentSlot()` check until `ProducedTinyBlocks = 9`
   - Calculation error: `blocksBeforeCurrentRound = 1` (should be 9)
   - Check: `ProducedTinyBlocks (2-8) == 1 + 8`? → False until ProducedTinyBlocks = 9
   - Final state: `R2.M.ProducedTinyBlocks = 9`, `R2.M.ActualMiningTimes = [T_next, T9...T16]`

**Expected vs Actual Result:**

**Expected Behavior:**
- Extra block producer should produce maximum 9 blocks total:
  - 8 blocks in extra slot before round transition
  - 1 NextRound block
  - 0 additional blocks (already at limit)

**Actual Result (Exploited):**
- Total blocks produced: **17 blocks**
  - 8 blocks before round transition [T1-T8]
  - 1 NextRound block [T_next]
  - 8 additional blocks after transition [T9-T16]
- **Excess: 8 blocks (88% over limit)**

**Success Condition:**
- Verify `ActualMiningTimes` contains 17 entries total across the two rounds
- Miner receives mining rewards for 17 blocks instead of intended 8-9
- No validation failure occurs despite exceeding `maximumBlocksCount`

### Notes

The vulnerability stems from an architectural assumption that `ActualMiningTimes` would preserve historical data across round transitions. The design intent was for `blocksBeforeCurrentRound` to count all blocks produced in the extra slot, but the implementation resets this data structure. The fix requires either preserving the count explicitly or adding validation that directly checks total blocks produced by the extra block producer across the extended time slot.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L194-196)
```csharp
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TinyBlockCommandStrategy.cs (L59-62)
```csharp
            if (CurrentBlockTime < roundStartTime) return producedBlocksOfCurrentRound == _maximumBlocksCount;

            var blocksBeforeCurrentRound = MinerInRound.ActualMiningTimes.Count(t => t < roundStartTime);
            return producedBlocksOfCurrentRound == blocksBeforeCurrentRound.Add(_maximumBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L71-79)
```csharp
                if (CurrentRound.ExtraBlockProducerOfPreviousRound ==
                    _pubkey && // Provided pubkey terminated previous round
                    !CurrentRound.IsMinerListJustChanged && // & Current round isn't the first round of current term
                    _minerInRound.ActualMiningTimes.Count.Add(1) <
                    _maximumBlocksCount.Add(
                        blocksBeforeCurrentRound) // & Provided pubkey hasn't mine enough blocks for current round.
                   )
                    // Then provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-24)
```csharp
        if (validationContext.ProvidedRound.RoundNumber > 2 && // Skip first two rounds.
            validationContext.BaseRound.RealTimeMinersInformation.Count != 1)
        {
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L299-309)
```csharp
    private void ProcessTinyBlock(TinyBlockInput tinyBlockInput)
    {
        TryToGetCurrentRoundInformation(out var currentRound);

        var minerInRound = currentRound.RealTimeMinersInformation[_processingBlockMinerPubkey];
        minerInRound.ActualMiningTimes.Add(tinyBlockInput.ActualMiningTime);
        minerInRound.ProducedBlocks = minerInRound.ProducedBlocks.Add(1);
        minerInRound.ProducedTinyBlocks = minerInRound.ProducedTinyBlocks.Add(1);

        Assert(TryToUpdateRoundInformation(currentRound), "Failed to update round information.");
    }
```
