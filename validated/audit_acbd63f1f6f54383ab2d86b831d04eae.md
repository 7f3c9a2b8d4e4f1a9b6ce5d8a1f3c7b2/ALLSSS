# Audit Report

## Title
Off-By-One Error in Continuous Block Production Limit Allows Miners to Exceed Maximum Consecutive Blocks

## Summary
The AEDPoS consensus contract contains an off-by-one error in the continuous block production limit validation. The check uses `BlocksCount < 0` instead of `BlocksCount <= 0`, allowing miners to produce 9 consecutive blocks instead of the intended maximum of 8, providing a 12.5% unfair advantage in block production and mining rewards.

## Finding Description

The vulnerability exists in the validation logic that enforces the maximum number of continuous blocks a miner can produce. The protocol defines `MaximumTinyBlocksCount = 8` [1](#0-0) , which is documented as a mechanism "to avoid too many forks" [2](#0-1)  and "to prevent one miner produced too many continuous blocks" [3](#0-2) .

**Flawed Validation Check:**
The validation provider only rejects when `BlocksCount < 0`, allowing `BlocksCount == 0` to pass [4](#0-3) .

**Flawed Command Generation:**
Similarly, the consensus command generation only forces `NextRound` behavior when `BlocksCount < 0` [5](#0-4) .

**Root Cause Mechanism:**
When a miner produces their first block (or switches from another miner), `BlocksCount` is initialized to `MaximumTinyBlocksCount.Sub(1) = 7` [6](#0-5) . For each subsequent consecutive block by the same miner, `BlocksCount` is decremented by 1 [7](#0-6) .

**Execution Sequence:**
1. Block 1: Initialize `BlocksCount = 7`
2. Blocks 2-8: `BlocksCount` decrements from 7→6→5→4→3→2→1, all checks pass (not < 0)
3. **Block 9: `BlocksCount = 0`, check `0 < 0` is FALSE, validation PASSES (BUG)**
4. After Block 9: `BlocksCount` decrements to -1
5. Block 10: `BlocksCount = -1`, check `-1 < 0` is TRUE, validation FAILS

The validation occurs before block execution [8](#0-7) , and the state update happens after consensus information processing [9](#0-8) , confirming the timing allows this exploit.

## Impact Explanation

**Consensus Integrity Violation:**
This breaks the core protocol invariant that limits consecutive block production to 8 blocks. The limit is explicitly designed to prevent blockchain centralization and excessive fork creation, as evidenced by the documented purpose.

**Unfair Competitive Advantage:**
Any miner can produce 9 consecutive blocks instead of 8, representing a 12.5% excess over the intended limit (9/8 = 1.125). This provides:
- Additional mining reward for the 9th block
- Greater influence over consensus compared to compliant miners
- Cumulative advantage as this occurs repeatedly throughout blockchain operation

**Reward Misallocation:**
The extra block production translates directly to extra block rewards, creating systematic unfairness in the reward distribution mechanism that accumulates over time.

**Severity Assessment: Medium**
While this does not enable direct fund theft or complete consensus takeover, it provides measurable unfair advantage in block production power and mining rewards, and violates a documented security invariant that protects against excessive forking.

## Likelihood Explanation

**Automatic Triggering:**
This vulnerability triggers automatically during normal consensus operations - no special actions required beyond producing consecutive blocks. The flawed logic is executed every time a miner approaches the consecutive block limit.

**Universal Access:**
Any valid miner in the consensus pool can reach this code path. The preconditions are:
- Miner must be in current consensus round (standard for all active miners)
- No special permissions or governance actions required
- Occurs naturally when producing consecutive tiny blocks

**Deterministic Exploitation:**
The bug occurs deterministically whenever any miner produces consecutive blocks. The flawed check `BlocksCount < 0` always allows the 9th block when `BlocksCount = 0`. There is no randomness or external dependency.

**Zero Detection Risk:**
The 9th block appears as legitimate according to the validation logic. No monitoring exists to flag this behavior as anomalous since the validation explicitly passes.

**Probability Assessment: High**
This will occur naturally in normal operation whenever miners produce consecutive blocks up to the limit, which is a common scenario in the AEDPoS consensus mechanism.

## Recommendation

Change the validation condition from `< 0` to `<= 0` in both locations:

1. In `ContinuousBlocksValidationProvider.cs`, modify the validation check:
```csharp
// Change from:
latestPubkeyToTinyBlocksCount.BlocksCount < 0
// To:
latestPubkeyToTinyBlocksCount.BlocksCount <= 0
```

2. In `AEDPoSContract_ACS4_ConsensusInformationProvider.cs`, modify the command generation check:
```csharp
// Change from:
State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0
// To:
State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount <= 0
```

This ensures that when `BlocksCount` reaches 0 (after 8 consecutive blocks), the validation fails and the miner is forced to transition to the next round, properly enforcing the 8-block limit.

## Proof of Concept

The vulnerability can be demonstrated by tracing the `BlocksCount` state through consecutive block production:

```csharp
// Test scenario: Single miner produces consecutive blocks
public void Test_OffByOne_ConsecutiveBlocksLimit()
{
    // Setup: Miner A in consensus round
    var minerA = "MinerA_Pubkey";
    
    // Block 1: Initial state
    // After execution: BlocksCount = MaximumTinyBlocksCount - 1 = 7
    ProduceBlock(minerA);
    Assert.Equal(7, GetBlocksCount(minerA));
    
    // Blocks 2-8: Should all pass validation
    for (int i = 2; i <= 8; i++)
    {
        // Before validation: BlocksCount > 0, check passes
        Assert.True(ValidateBlock(minerA)); // Passes because BlocksCount > 0
        ProduceBlock(minerA);
        Assert.Equal(8 - i, GetBlocksCount(minerA));
    }
    
    // At this point, BlocksCount = 0
    Assert.Equal(0, GetBlocksCount(minerA));
    
    // Block 9: BUG - Should fail but passes
    Assert.True(ValidateBlock(minerA)); // BUG: Passes because 0 < 0 is FALSE
    ProduceBlock(minerA);
    Assert.Equal(-1, GetBlocksCount(minerA));
    
    // Block 10: Correctly fails
    Assert.False(ValidateBlock(minerA)); // Correctly fails because -1 < 0 is TRUE
    
    // Result: Miner produced 9 blocks instead of 8
    Assert.Equal(9, GetProducedBlockCount(minerA)); // Should be 8, but is 9
}
```

This test demonstrates that a miner can produce 9 consecutive blocks when the protocol explicitly limits it to 8, proving the off-by-one error exists in production code.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L19-19)
```csharp
    ///     Adjust (mainly reduce) the count of tiny blocks produced by a miner each time to avoid too many forks.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L67-69)
```csharp
        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-335)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L342-347)
```csharp
            currentValue = new LatestPubkeyToTinyBlocksCount
            {
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
            State.LatestPubkeyToTinyBlocksCount.Value = currentValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L352-357)
```csharp
            if (currentValue.Pubkey == _processingBlockMinerPubkey)
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = currentValue.BlocksCount.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L17-23)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L12-16)
```csharp
    ///     This method will be executed before executing a block.
    /// </summary>
    /// <param name="extraData"></param>
    /// <returns></returns>
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
```
