# Audit Report

## Title
Off-By-One Error in Continuous Block Production Limit Allows Miners to Exceed Maximum Consecutive Blocks

## Summary
The AEDPoS consensus contract contains an off-by-one error where the validation check for continuous block production uses `BlocksCount < 0` instead of `BlocksCount <= 0`. This allows any miner to produce 9 consecutive blocks instead of the intended maximum of 8, providing a 12.5% unfair advantage in block production.

## Finding Description

The vulnerability exists in two critical locations that enforce the continuous block production limit.

**Location 1: Validation Logic**

The `ContinuousBlocksValidationProvider` only rejects blocks when `BlocksCount < 0`, incorrectly allowing `BlocksCount == 0` to pass validation. [1](#0-0) 

**Location 2: Command Generation**

The consensus command generation forces `NextRound` behavior only when `BlocksCount < 0`, using the same incorrect comparison. [2](#0-1) 

**Root Cause**

The `BlocksCount` field tracks remaining blocks allowed for continuous production. The protocol defines a maximum of 8 consecutive blocks. [3](#0-2) 

When a miner first produces a block, `BlocksCount` is initialized to 7 (MaximumTinyBlocksCount - 1). [4](#0-3) 

Each subsequent block by the same miner decrements `BlocksCount` by 1. [5](#0-4) 

**Execution Flow**

The validation runs before block execution. [6](#0-5) 

The decrement occurs in `ResetLatestProviderToTinyBlocksCount` which is called after processing each consensus behavior. [7](#0-6) 

**Attack Sequence:**
1. Block 1: `BlocksCount` initialized to 7 after processing
2. Blocks 2-8: `BlocksCount` decrements from 7→6→5→4→3→2→1, each validation passes (not < 0)
3. **Block 9: `BlocksCount = 0`, check `0 < 0` evaluates to FALSE, validation PASSES** (BUG)
4. After block 9: `BlocksCount` decremented to -1
5. Block 10: `BlocksCount = -1`, check `-1 < 0` evaluates to TRUE, validation FAILS

The miner successfully produces 9 consecutive blocks instead of the intended maximum of 8.

## Impact Explanation

**Consensus Fairness Violation**

The protocol explicitly includes this mechanism "To prevent one miner produced too many continuous blocks". [8](#0-7) 

By allowing 9 blocks instead of 8, this mechanism fails its core purpose of maintaining fair block production distribution among miners.

**Reward Misallocation**

Each extra block produces additional mining rewards, creating a systematic 12.5% advantage (1/8 = 0.125) for any miner exploiting maximum consecutive production. This unfair advantage accumulates over time and violates equitable reward distribution.

**Protocol Invariant Break**

The vulnerability violates the fundamental consensus rule that no miner should produce more than `MaximumTinyBlocksCount` consecutive blocks. This limit exists to maintain decentralization and prevent centralization risks.

## Likelihood Explanation

**Deterministic and Universal**

This vulnerability affects all miners equally and triggers automatically during normal consensus operations. No special manipulation or attack is required.

**Entry Point**

Any miner can reach this code through standard consensus participation. The validation is part of the core consensus flow that validates blocks before execution. [9](#0-8) 

**No Preconditions**

- Requires only being a valid miner in the current round
- No special permissions needed beyond normal miner status
- Occurs naturally when producing consecutive blocks

**Inevitable Occurrence**

Whenever any miner produces the maximum consecutive blocks in their time slot, they will automatically produce 9 blocks instead of 8. The bug is intrinsic to the validation logic and happens during normal protocol operations.

## Recommendation

Change both validation checks from `BlocksCount < 0` to `BlocksCount <= 0`:

**Fix Location 1:** In `ContinuousBlocksValidationProvider.cs` line 19, change:
```csharp
latestPubkeyToTinyBlocksCount.BlocksCount < 0
```
to:
```csharp
latestPubkeyToTinyBlocksCount.BlocksCount <= 0
```

**Fix Location 2:** In `AEDPoSContract_ACS4_ConsensusInformationProvider.cs` line 33, change:
```csharp
State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount < 0
```
to:
```csharp
State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount <= 0
```

This ensures that when `BlocksCount` reaches 0 (after 8 blocks have been produced), the 9th block attempt will be rejected, enforcing the intended maximum of 8 consecutive blocks.

## Proof of Concept

The vulnerability can be demonstrated by tracing the state transitions during consecutive block production:

**Test Scenario:**
1. Miner A produces first block → `BlocksCount = 7` initialized
2. Miner A produces block 2 → Check: `7 < 0`? No → Pass, `BlocksCount = 6`
3. Miner A produces block 3 → Check: `6 < 0`? No → Pass, `BlocksCount = 5`
4. Miner A produces block 4 → Check: `5 < 0`? No → Pass, `BlocksCount = 4`
5. Miner A produces block 5 → Check: `4 < 0`? No → Pass, `BlocksCount = 3`
6. Miner A produces block 6 → Check: `3 < 0`? No → Pass, `BlocksCount = 2`
7. Miner A produces block 7 → Check: `2 < 0`? No → Pass, `BlocksCount = 1`
8. Miner A produces block 8 → Check: `1 < 0`? No → Pass, `BlocksCount = 0`
9. **Miner A produces block 9 → Check: `0 < 0`? No → Pass (VULNERABILITY), `BlocksCount = -1`**
10. Miner A attempts block 10 → Check: `-1 < 0`? Yes → Fail

**Expected behavior:** Miner should be stopped after 8 consecutive blocks
**Actual behavior:** Miner produces 9 consecutive blocks (12.5% advantage)

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L344-346)
```csharp
                Pubkey = _processingBlockMinerPubkey,
                BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(1)
            };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L11-16)
```csharp
    /// <summary>
    ///     This method will be executed before executing a block.
    /// </summary>
    /// <param name="extraData"></param>
    /// <returns></returns>
    private ValidationResult ValidateBeforeExecution(AElfConsensusHeaderInformation extraData)
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
