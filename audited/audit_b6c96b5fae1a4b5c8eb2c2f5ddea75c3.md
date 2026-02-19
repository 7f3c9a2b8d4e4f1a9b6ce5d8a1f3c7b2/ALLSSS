### Title
Dynamic GetMaximumBlocksCount() Changes Mid-Round Allow Miners to Exceed Tiny Block Limits

### Summary
The `GetConsensusCommand` method calls `GetMaximumBlocksCount()` at command generation time and passes the result to `SideChainConsensusBehaviourProvider` constructor, which stores it for behavior determination. However, when the block is later processed, `GetMaximumBlocksCount()` is called again and may return a different value due to blockchain status changes. This allows miners to produce more tiny blocks than the current dynamically-adjusted limit, defeating the fork-reduction mechanism during blockchain stress periods.

### Finding Description

The vulnerability exists in the consensus command generation and processing flow:

**Command Generation Phase:**
In `GetConsensusCommand`, the method calls `GetMaximumBlocksCount()` and passes the result to the `SideChainConsensusBehaviourProvider` constructor: [1](#0-0) 

The base class constructor stores this value in the `_maximumBlocksCount` field: [2](#0-1) 

The `GetConsensusBehaviour()` method uses this stored value to determine if TinyBlock behavior is allowed: [3](#0-2) 

**Block Processing Phase:**
When the block is processed, `ProcessConsensusInformation` calls `GetMaximumBlocksCount()` again at a later time: [4](#0-3) 

The new value is used to update the tiny block counter in `ResetLatestProviderToTinyBlocksCount`: [5](#0-4) 

**Root Cause:**
`GetMaximumBlocksCount()` dynamically adjusts its return value based on blockchain mining status (Normal/Abnormal/Severe), which can change mid-round as the LIB advances or fails to advance: [6](#0-5) 

The method returns different values based on the distance between current round and LIB round: 8 blocks in Normal status, a reduced count in Abnormal status, or 1 block in Severe status.

**Missing Validation:**
The validation flow does not enforce that `ActualMiningTimes.Count` is less than or equal to the current `GetMaximumBlocksCount()`. The only check is whether `LatestPubkeyToTinyBlocksCount.BlocksCount < 0`, which is a separate counter: [7](#0-6) 

No validation provider checks that the miner's actual produced blocks count respects the current maximum.

### Impact Explanation

**Operational Impact - Consensus Stability Degradation:**

When the blockchain enters Abnormal or Severe status (typically due to LIB not advancing properly), `GetMaximumBlocksCount()` reduces the maximum tiny blocks count to minimize forks. However, miners who received commands before the status change can continue producing blocks using the old higher limit.

**Quantified Impact:**
- Normal status: `MaximumTinyBlocksCount` = 8
- Abnormal status: Reduced to as low as 3 (based on miner participation)
- Severe status: Reduced to 1

A miner could produce 6-8 blocks when the current limit is 3, or 8 blocks when the limit is 1, exceeding the limit by 2-8x.

**Who Is Affected:**
- The entire blockchain network suffers from increased forks during stress periods
- The consensus mechanism's self-healing capability is undermined
- Block finality is delayed as forks proliferate

**Severity Justification - Medium:**
This defeats the fork-reduction mechanism implemented in PR #1952, causing excessive forks precisely when the blockchain is most vulnerable. While it doesn't directly steal funds, it significantly degrades consensus stability during critical periods, potentially leading to extended chain stalls or inconsistencies.

### Likelihood Explanation

**Attack Complexity - Low:**
No special attacker capabilities are required. Any miner can trigger this condition through normal mining operations when blockchain conditions align.

**Feasibility Conditions:**
1. Blockchain must transition from Normal to Abnormal/Severe status mid-round
2. This occurs naturally when LIB doesn't advance properly (common during network issues)
3. Miner requests command before status change, processes block after status change

**Execution Practicality:**
- Entry point: Public `GetConsensusCommand` method (ACS4 interface)
- No special permissions needed beyond being a valid miner
- Timing window: Seconds to minutes between command generation and block processing
- Standard contract execution semantics apply

**Detection/Operational Constraints:**
- Difficult to distinguish from legitimate mining activity
- No on-chain alerts for this condition
- Only detectable through detailed block analysis comparing ActualMiningTimes counts

**Probability Reasoning - Medium:**
The blockchain naturally enters Abnormal/Severe status during network stress, LIB lag, or consensus issues. Given that these conditions occur periodically in production blockchain networks, and that multiple miners operate concurrently, the likelihood of this timing condition occurring is medium.

### Recommendation

**Code-Level Mitigation:**

Add validation in `ValidateBeforeExecution` to enforce the current maximum:

```csharp
// In AEDPoSContract_Validation.cs, add a new validation provider
public class TinyBlockLimitValidationProvider : IHeaderInformationValidationProvider
{
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        if (validationContext.ExtraData.Behaviour != AElfConsensusBehaviour.TinyBlock)
            return new ValidationResult { Success = true };
            
        var minerInRound = validationContext.BaseRound.RealTimeMinersInformation[validationContext.SenderPubkey];
        var currentMaximum = GetMaximumBlocksCount(); // Call to get current limit
        
        if (minerInRound.ActualMiningTimes.Count >= currentMaximum)
        {
            return new ValidationResult 
            { 
                Success = false, 
                Message = $"Miner has reached maximum tiny blocks limit: {currentMaximum}" 
            };
        }
        
        return new ValidationResult { Success = true };
    }
}
```

Register this provider in the validation flow: [8](#0-7) 

**Invariant Checks to Add:**
- Assert `ActualMiningTimes.Count <= GetMaximumBlocksCount()` before processing any TinyBlock behavior
- Add validation in `ProcessTinyBlock` to re-check the current limit
- Consider caching `GetMaximumBlocksCount()` result per round to ensure consistency

**Test Cases:**
1. Test scenario where blockchain transitions from Normal to Abnormal status mid-round
2. Verify miner cannot produce blocks beyond current `GetMaximumBlocksCount()`
3. Test with multiple miners producing blocks concurrently during status changes
4. Verify validation rejects TinyBlock headers that would exceed current limit

### Proof of Concept

**Initial State:**
- Round 10, Block Height 100
- LIB at Round 7 (Normal status)
- `GetMaximumBlocksCount()` = 8
- MinerA: `ActualMiningTimes.Count` = 5
- `LatestPubkeyToTinyBlocksCount` = {Pubkey: "MinerA", BlocksCount: 2}

**Transaction Steps:**

1. **T1 (Command Generation):** MinerA calls `GetConsensusCommand`
   - `GetMaximumBlocksCount()` returns 8 (Normal status)
   - `SideChainConsensusBehaviourProvider` created with `_maximumBlocksCount` = 8
   - Check: `ActualMiningTimes.Count` (5) < 8 → TinyBlock allowed
   - MinerA receives TinyBlock command

2. **T2 (Status Change):** Blockchain enters Abnormal status
   - LIB fails to advance or regresses to Round 5
   - Status calculation: R_LIB + 2 < R < R_LIB + 8 → 7 < 10 < 13 → Abnormal
   - `GetMaximumBlocksCount()` now returns 3

3. **T3 (Block Processing):** MinerA's block is validated and processed
   - Validation: `BlocksCount` (2) >= 0 → passes
   - `ProcessTinyBlock`: `ActualMiningTimes.Count` becomes 6
   - `GetMaximumBlocksCount()` called again, returns 3
   - `ResetLatestProviderToTinyBlocksCount(3)`: BlocksCount = 2 - 1 = 1

**Expected Result:**
MinerA should be rejected for exceeding the maximum of 3 tiny blocks

**Actual Result:**
MinerA successfully produces 6th tiny block, exceeding current limit of 3

**Success Condition:**
`ActualMiningTimes.Count` (6) > `GetMaximumBlocksCount()` (3), yet block is accepted, demonstrating the vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L44-46)
```csharp
            : new SideChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                GetMaximumBlocksCount(),
                Context.CurrentBlockTime).GetConsensusBehaviour();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L26-32)
```csharp
        protected ConsensusBehaviourProviderBase(Round currentRound, string pubkey, int maximumBlocksCount,
            Timestamp currentBlockTime)
        {
            CurrentRound = currentRound;

            _pubkey = pubkey;
            _maximumBlocksCount = maximumBlocksCount;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-79)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;

        Context.LogDebug(() =>
            $"Calculating max blocks count based on:\nR_LIB: {libRoundNumber}\nH_LIB:{libBlockHeight}\nR:{currentRoundNumber}\nH:{currentHeight}");

        if (libRoundNumber == 0) return AEDPoSContractConstants.MaximumTinyBlocksCount;

        var blockchainMiningStatusEvaluator = new BlockchainMiningStatusEvaluator(libRoundNumber,
            currentRoundNumber, AEDPoSContractConstants.MaximumTinyBlocksCount);
        blockchainMiningStatusEvaluator.Deconstruct(out var blockchainMiningStatus);

        Context.LogDebug(() => $"Current blockchain mining status: {blockchainMiningStatus.ToString()}");

        // If R_LIB + 2 < R < R_LIB + CB1, CB goes to Min(T(L2 * (CB1 - (R - R_LIB)) / A), CB0), while CT stays same as before.
        if (blockchainMiningStatus == BlockchainMiningStatus.Abnormal)
        {
            var previousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(1)].Pubkeys;
            var previousPreviousRoundMinedMinerList = State.MinedMinerListMap[currentRoundNumber.Sub(2)].Pubkeys;
            var minersOfLastTwoRounds = previousRoundMinedMinerList
                .Intersect(previousPreviousRoundMinedMinerList).Count();
            var factor = minersOfLastTwoRounds.Mul(
                blockchainMiningStatusEvaluator.SevereStatusRoundsThreshold.Sub(
                    (int)currentRoundNumber.Sub(libRoundNumber)));
            var count = Math.Min(AEDPoSContractConstants.MaximumTinyBlocksCount,
                Ceiling(factor, currentRound.RealTimeMinersInformation.Count));
            Context.LogDebug(() => $"Maximum blocks count tune to {count}");
            return count;
        }

        //If R >= R_LIB + CB1, CB goes to 1, and CT goes to 0
        if (blockchainMiningStatus == BlockchainMiningStatus.Severe)
        {
            // Fire an event to notify miner not package normal transaction.
            Context.Fire(new IrreversibleBlockHeightUnacceptable
            {
                DistanceToIrreversibleBlockHeight = currentHeight.Sub(libBlockHeight)
            });
            State.IsPreviousBlockInSevereStatus.Value = true;
            return 1;
        }

        if (!State.IsPreviousBlockInSevereStatus.Value)
            return AEDPoSContractConstants.MaximumTinyBlocksCount;

        Context.Fire(new IrreversibleBlockHeightUnacceptable
        {
            DistanceToIrreversibleBlockHeight = 0
        });
        State.IsPreviousBlockInSevereStatus.Value = false;

        return AEDPoSContractConstants.MaximumTinyBlocksCount;
    }
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L64-75)
```csharp
        // Add basic providers at first.
        var validationProviders = new List<IHeaderInformationValidationProvider>
        {
            // Is sender in miner list (of base round)?
            new MiningPermissionValidationProvider(),

            // Is this block produced in proper time?
            new TimeSlotValidationProvider(),

            // Is sender produced too many blocks at one time?
            new ContinuousBlocksValidationProvider()
        };
```
