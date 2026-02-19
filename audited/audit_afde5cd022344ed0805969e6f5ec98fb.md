# Audit Report

## Title
Off-By-One Error in Continuous Block Production Limit Allows Miners to Exceed Maximum Consecutive Blocks

## Summary
The AEDPoS consensus contract contains an off-by-one error where the validation check for continuous block production uses `BlocksCount < 0` instead of `BlocksCount <= 0`. This allows any miner to produce 9 consecutive blocks instead of the intended maximum of 8, providing a 12.5% unfair advantage in block production.

## Finding Description

The vulnerability exists in two critical locations that enforce the continuous block production limit:

**Location 1: Validation Logic**

The `ContinuousBlocksValidationProvider` only rejects blocks when `BlocksCount < 0`, allowing `BlocksCount == 0` to pass validation: [1](#0-0) 

**Location 2: Command Generation**

The consensus command generation forces `NextRound` behavior only when `BlocksCount < 0`: [2](#0-1) 

**Root Cause:**

The `BlocksCount` field tracks remaining blocks allowed. It's initialized to 7 (MaximumTinyBlocksCount - 1): [3](#0-2) [4](#0-3) 

Each subsequent block by the same miner decrements `BlocksCount`: [5](#0-4) 

**Execution Flow:**

The decrement occurs in `ResetLatestProviderToTinyBlocksCount` which is called after processing each consensus behavior: [6](#0-5) 

The validation runs before block execution: [7](#0-6) 

**Attack Sequence:**
1. Block 1: `BlocksCount` initialized to 7
2. Blocks 2-8: `BlocksCount` decrements from 7→6→5→4→3→2→1, each validation passes (not < 0)
3. **Block 9: `BlocksCount = 0`, check `0 < 0` evaluates to FALSE, validation PASSES** (BUG)
4. After block 9: `BlocksCount` decremented to -1
5. Block 10: `BlocksCount = -1`, check `-1 < 0` evaluates to TRUE, validation FAILS

The miner successfully produces 9 consecutive blocks instead of the intended maximum of 8.

## Impact Explanation

**Consensus Fairness Violation:**

The `MaximumTinyBlocksCount` constant defines the protocol's intended limit to prevent any single miner from dominating block production. The comment explicitly states this is "To prevent one miner produced too many continuous blocks": [8](#0-7) 

By allowing 9 blocks instead of 8, this mechanism fails its core purpose.

**Reward Misallocation:**

Each extra block produces additional mining rewards, creating a systematic 12.5% advantage for any miner exploiting maximum consecutive production. This unfair advantage accumulates over time and violates the equitable reward distribution design.

**Protocol Invariant Break:**

The vulnerability violates the fundamental consensus rule that no miner should produce more than `MaximumTinyBlocksCount` consecutive blocks. This limit exists to maintain decentralization and prevent centralization risks.

## Likelihood Explanation

**Deterministic and Universal:**

This vulnerability affects all miners equally and triggers automatically during normal consensus operations. No special manipulation or attack is required.

**Entry Point:**

Any miner can reach this code through standard consensus participation. The validation is part of the core consensus flow triggered on every block: [9](#0-8) 

**No Preconditions:**

- Requires only being a valid miner in the current round
- No special permissions needed
- Occurs naturally when producing consecutive blocks

**Inevitable Occurrence:**

Whenever any miner produces the maximum consecutive blocks in their time slot, they will automatically produce 9 blocks instead of 8. The bug is intrinsic to the validation logic.

## Recommendation

Change both validation checks from `< 0` to `<= 0`:

**Fix Location 1 - ContinuousBlocksValidationProvider.cs:**
```csharp
if (latestPubkeyToTinyBlocksCount != null &&
    latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
    latestPubkeyToTinyBlocksCount.BlocksCount <= 0) // Changed from < 0
{
    validationResult.Message = "Sender produced too many continuous blocks.";
    return validationResult;
}
```

**Fix Location 2 - AEDPoSContract_ACS4_ConsensusInformationProvider.cs:**
```csharp
if (currentRound.RealTimeMinersInformation.Count != 1 &&
    currentRound.RoundNumber > 2 &&
    State.LatestPubkeyToTinyBlocksCount.Value != null &&
    State.LatestPubkeyToTinyBlocksCount.Value.Pubkey == _processingBlockMinerPubkey &&
    State.LatestPubkeyToTinyBlocksCount.Value.BlocksCount <= 0) // Changed from < 0
    return GetConsensusCommand(AElfConsensusBehaviour.NextRound, currentRound, _processingBlockMinerPubkey,
        Context.CurrentBlockTime);
```

This ensures the 9th block (when `BlocksCount == 0`) is correctly rejected, enforcing the true maximum of 8 consecutive blocks.

## Proof of Concept

A proof of concept would demonstrate:
1. Initialize a miner's `BlocksCount` to 7
2. Produce blocks 2-8, showing `BlocksCount` decrements from 7 to 1, all validations pass
3. Produce block 9 with `BlocksCount = 0`, showing validation check `0 < 0 = false` incorrectly passes
4. Attempt block 10 with `BlocksCount = -1`, showing validation check `-1 < 0 = true` correctly fails
5. Confirm 9 blocks were produced instead of 8

The test would need to be implemented in the AElf test framework with access to the consensus contract state to manipulate and verify `BlocksCount` values across consecutive block productions.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L333-337)
```csharp
    /// <summary>
    ///     To prevent one miner produced too many continuous blocks.
    /// </summary>
    /// <param name="minersCountInTheory"></param>
    private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
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
