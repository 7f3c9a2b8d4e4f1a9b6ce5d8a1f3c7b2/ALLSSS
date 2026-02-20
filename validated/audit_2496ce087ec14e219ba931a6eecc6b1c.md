# Audit Report

## Title
Off-By-One Error in Continuous Block Production Limit Allows Miners to Exceed Maximum Consecutive Blocks

## Summary
An off-by-one error in the AEDPoS consensus validation logic allows miners to produce 9 consecutive blocks instead of the intended maximum of 8. The validation check uses `BlocksCount < 0` instead of `BlocksCount <= 0`, enabling any miner to gain a 12.5% unfair advantage in consecutive block production and rewards.

## Finding Description

The vulnerability exists in two critical locations where the `BlocksCount` field is checked to prevent excessive continuous block production.

**Location 1: Block Validation**

The `ContinuousBlocksValidationProvider` only rejects blocks when `BlocksCount < 0`, allowing `BlocksCount == 0` to pass validation. [1](#0-0) 

**Location 2: Command Generation**

The `GetConsensusCommand` method similarly only forces `NextRound` behavior when `BlocksCount < 0`, allowing command generation at `BlocksCount == 0`. [2](#0-1) 

**Root Cause:**

The `BlocksCount` field represents remaining blocks allowed and starts at `MaximumTinyBlocksCount - 1` (which is 7, since `MaximumTinyBlocksCount = 8`). [3](#0-2) 

When the same miner produces consecutive blocks, `BlocksCount` decrements by 1 after each block: [4](#0-3) 

**Execution Flow:**
1. **Block 1:** `BlocksCount` initialized to 7
2. **Blocks 2-8:** `BlocksCount` decrements from 6 to 0, validations pass (`not < 0`)
3. **Block 9 (BUG):** `BlocksCount = 0`, validation check `0 < 0` evaluates to FALSE, validation PASSES
4. **After Block 9:** `BlocksCount` decrements to -1
5. **Block 10:** `BlocksCount = -1`, validation check `-1 < 0` evaluates to TRUE, validation FAILS

The validation occurs before block execution in the `ValidateBeforeExecution` method: [5](#0-4) 

This off-by-one error allows miners to produce exactly one extra consecutive block beyond the intended limit.

## Impact Explanation

**Consensus Fairness Violation:**
- Miners can produce 9 consecutive blocks instead of the intended maximum of 8, representing a 12.5% increase in consecutive block production capacity
- Violates the core protocol invariant designed to prevent any single miner from dominating block production
- Creates systematic unfair advantage in block production power distribution

**Reward Misallocation:**
- Each extra block produced grants additional mining rewards to the exploiting miner
- This advantage accumulates over time as miners repeatedly hit the limit
- Undermines the fair reward distribution mechanism fundamental to consensus integrity

**Protocol Integrity:**
The continuous block limit exists specifically to prevent centralization issues from one miner producing too many consecutive blocks. The comment in the code explicitly states this purpose: [6](#0-5) 

**Severity: Medium** - While not causing direct fund theft or complete consensus breakdown, this vulnerability provides systematic unfair advantage, violates protocol invariants, and undermines consensus fairness guarantees.

## Likelihood Explanation

**Highly Likely to Occur:**

**Reachable Entry Point:**
Any active miner in the consensus pool can trigger this vulnerability through normal block production operations. No special permissions or privileged access required beyond being an elected miner.

**Minimal Preconditions:**
- Miner must be in the current consensus round (normal operational requirement)
- No additional special conditions or configurations needed
- Occurs naturally during standard consecutive block production

**Deterministic Exploitation:**
- Miners simply produce blocks consecutively until `BlocksCount` reaches 0
- The flawed validation logic automatically permits the 9th block
- No complex transaction sequences, timing manipulations, or state exploits required
- Completely reproducible and deterministic

**Economic Incentive:**
- Zero additional cost beyond normal mining operations
- Direct financial benefit from extra block reward
- No risk of detection since the behavior is permitted by the validation logic itself
- Rational miners will naturally exploit this during high transaction fee periods

**No Detection Mechanism:**
- The system has no monitoring to flag this as abnormal behavior
- Appears as legitimate consecutive block production within the protocol
- Cannot be distinguished from normal operations without manual audit

**Probability: High** - This vulnerability will be triggered naturally whenever any miner produces the maximum consecutive blocks. The deterministic nature and economic incentives make exploitation inevitable during normal network operation.

## Recommendation

Change the validation condition from `BlocksCount < 0` to `BlocksCount <= 0` in both locations:

**Fix for Location 1 (ContinuousBlocksValidationProvider):**
```csharp
if (latestPubkeyToTinyBlocksCount != null &&
    latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
    latestPubkeyToTinyBlocksCount.BlocksCount <= 0)  // Changed from < 0
{
    validationResult.Message = "Sender produced too many continuous blocks.";
    return validationResult;
}
```

**Fix for Location 2 (GetConsensusCommand):**
```csharp
if (currentRound.RealTimeMinersInformation.Count != 1 &&
    currentRound.RoundNumber > 2 &&
    State.LatestPubkeyToTinyBlocksCount.Value != null &&
    State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
    State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount <= 0)  // Changed from < 0
    return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
        Context.CurrentBlockTime);
```

This ensures that when `BlocksCount` reaches 0 (meaning no more blocks should be allowed), the validation properly rejects further consecutive blocks and forces a round transition.

## Proof of Concept

The vulnerability can be demonstrated by tracing the state transitions:

```
Initial state: State.LatestPubkeyToTinyBlocksCount.Value = null
MaximumTinyBlocksCount = 8

Block 1 by Miner A:
  - Validation: null check, passes
  - After processing: BlocksCount = 7

Block 2 by Miner A:
  - Validation: 7 < 0? FALSE, passes
  - After processing: BlocksCount = 6

Blocks 3-8 by Miner A:
  - BlocksCount: 5, 4, 3, 2, 1, 0 (all pass validation)

Block 9 by Miner A (BUG):
  - Validation: 0 < 0? FALSE, passes ← SHOULD FAIL
  - After processing: BlocksCount = -1
  - Result: 9th consecutive block produced

Block 10 by Miner A:
  - Validation: -1 < 0? TRUE, fails
  - Block rejected
```

The miner successfully produces 9 consecutive blocks instead of the intended maximum of 8, gaining a 12.5% unfair advantage in block production and rewards.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L13-23)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L29-35)
```csharp
        if (currentRound.RealTimeMinersInformation.Count != 1 &&
            currentRound.RoundNumber > 2 &&
            State.LatestPubkeyToTinyBlocksCount.Value != null &&
            State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
            State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0)
            return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
                Context.CurrentBlockTime);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-336)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
    /// <param name="minersCountInTheory"></param>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L337-365)
```csharp
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
    {
        LatestPubkeyToTinyBlocksCount currentValue;
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
        }
        else
        {
            currentValue = State.LatestPubkeyToTinyBlocksCount.Value;
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
            else
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L16-74)
```csharp
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
    {
        // According to current round information:
        if (!TryToGetCurrentRoundInformation(out var baseRound))
            return new ValidationResult { Success = false, Message = "Failed to get current round information." };

        // Skip the certain initial miner during first several rounds. (When other nodes haven't produce blocks yet.)
        if (baseRound.RealTimeMinersInformation.Count != 1 &&
            Context.CurrentHeight < AEDPoSContractConstants.MaximumTinyBlocksCount.Mul(3))
        {
            string producedMiner = null;
            var result = true;
            for (var i = baseRound.RoundNumber; i > 0; i--)
            {
                var producedMiners = State.Rounds[i].RealTimeMinersInformation.Values
                    .Where(m => m.ActualMiningTimes.Any()).ToList();
                if (producedMiners.Count != 1)
                {
                    result = false;
                    break;
                }

                if (producedMiner == null)
                    producedMiner = producedMiners.Single().Pubkey;
                else if (producedMiner != producedMiners.Single().Pubkey) result = false;
            }

            if (result) return new ValidationResult { Success = true };
        }

        if (extraData.Behaviour == AElfConsensusBehaviour.UpdateValue)
            baseRound.RecoverFromUpdateValue(extraData.Round, extraData.SenderPubkey.ToHex());

        if (extraData.Behaviour == AElfConsensusBehaviour.TinyBlock)
            baseRound.RecoverFromTinyBlock(extraData.Round, extraData.SenderPubkey.ToHex());

        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };

        /* Ask several questions: */

        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
```
