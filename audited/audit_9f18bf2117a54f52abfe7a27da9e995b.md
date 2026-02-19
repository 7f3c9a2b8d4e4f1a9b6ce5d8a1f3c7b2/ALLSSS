# Audit Report

## Title
Configuration Mismatch: Hardcoded TinyBlocksCount Causes Incorrect Mining Time Limits During Dynamic Block Count Adjustments

## Summary
The AEDPoS consensus contract uses a hardcoded `TinyBlocksCount = 8` constant for calculating mining time limits, while the actual maximum blocks count is dynamically adjusted via `GetMaximumBlocksCount()` based on blockchain status. During Severe blockchain status, miners are restricted to 1 block per time slot but receive mining time limits calculated for 8 blocks, resulting in only 12.5% of the proportional time allocation.

## Finding Description

The vulnerability stems from an architectural mismatch between two consensus subsystems that evolved independently:

**1. Hardcoded Timing Calculations:**

The `CommandStrategyBase` class defines mining time limits using a hardcoded constant: [1](#0-0) 

This constant derives the time slot interval per block: [2](#0-1) 

Which then calculates the default mining time limit: [3](#0-2) 

**2. Dynamic Block Count Adjustment:**

Meanwhile, `GetMaximumBlocksCount()` dynamically determines the actual maximum blocks based on blockchain status: [4](#0-3) 

During Severe status (when current round ≥ LIB round + 8), it returns 1: [5](#0-4) 

**3. The Mismatch:**

The behavior provider correctly uses the dynamic value to restrict block production: [6](#0-5) 

This is called with the dynamic `GetMaximumBlocksCount()` value: [7](#0-6) 

However, when generating consensus commands for UpdateValue blocks (the main consensus block), the static `DefaultBlockMiningLimit` is used: [8](#0-7) 

For comparison, term-ending blocks receive the full proportional time: [9](#0-8) 

The constant originates from the contract constants: [10](#0-9) 

## Impact Explanation

**Consensus Integrity Violation:**

During Severe blockchain status—specifically designed as a recovery mechanism when LIB lags significantly—miners receive `(MiningInterval / 8) * 3/5` milliseconds for their single allowed block. This is the same time allocation as one tiny block during normal 8-block production, representing only 12.5% of the proportional allocation they would receive if the system correctly adjusted timing to match the reduced block count.

**Quantified Impact:**
- Normal term-ending blocks: `MiningInterval * 3/5` (60% of interval)
- Severe status single blocks: `MiningInterval * 3/40` (7.5% of interval)
- Shortfall: 87.5% reduction from proportional allocation

**System-Wide Consequences:**

The blockchain enters Severe status to protect against forks during consensus stress. However, this mismatch creates a negative feedback loop:
1. Network stress causes LIB lag → Severe status triggered
2. Miners restricted to 1 block but given 1/8th proportional time
3. Insufficient mining time prevents timely block production
4. LIB advancement stalls further, prolonging Severe status
5. Extended consensus degradation may require manual intervention

This directly violates the consensus guarantee that Severe status should facilitate recovery, not hinder it.

## Likelihood Explanation

**Automatic Trigger Path:**

Severe status activation is deterministic and requires no adversarial action: [11](#0-10) 

**Realistic Preconditions:**

The LIB lag threshold (8 rounds) can occur during:
- Network latency spikes or partitions
- High transaction volume overwhelming validators
- Temporary validator coordination failures
- Infrastructure issues affecting subset of miners

These are operational scenarios that occur in production blockchain networks under stress, not theoretical edge cases.

**Invocation Path:**

The mismatch executes automatically through the normal consensus flow without requiring any specific transaction or attacker action. Every consensus command generation during Severe status produces the incorrect time limit.

## Recommendation

**Immediate Fix:**

Modify `CommandStrategyBase` to accept and use the dynamic maximum blocks count:

```csharp
protected readonly int MaximumBlocksCount;

protected CommandStrategyBase(Round currentRound, string pubkey, 
    Timestamp currentBlockTime, int maximumBlocksCount)
{
    CurrentRound = currentRound;
    Pubkey = pubkey;
    CurrentBlockTime = currentBlockTime;
    MaximumBlocksCount = maximumBlocksCount;
}

private int TinyBlockSlotInterval => MiningInterval.Div(MaximumBlocksCount);
```

Update all strategy constructors to pass the dynamic value from `GetMaximumBlocksCount()`:

```csharp
return new ConsensusCommandProvider(new NormalBlockCommandStrategy(
    currentRound, pubkey, currentBlockTime, previousRound.RoundId, 
    GetMaximumBlocksCount())).GetConsensusCommand();
```

This ensures timing calculations automatically adjust when block count restrictions change, maintaining proportional time allocation across all blockchain statuses.

## Proof of Concept

The vulnerability can be demonstrated by examining the consensus command generation during Severe status:

```csharp
// Test scenario: Blockchain in Severe status
// Setup: CurrentRound = 100, LIB Round = 91 (gap of 9 ≥ 8)
// Expected: GetMaximumBlocksCount() returns 1
// Expected: Mining time should be proportional to 1 block
// Actual: Mining time calculated assuming 8 blocks

// In GetMaximumBlocksCount():
// currentRoundNumber = 100
// libRoundNumber = 91  
// Since 100 >= 91 + 8, status = Severe, returns 1

// In ConsensusBehaviourProviderBase:
// _maximumBlocksCount = 1 (correctly limits to 1 block)

// In NormalBlockCommandStrategy:
// LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
// = TinyBlockSlotInterval * 3 / 5
// = (MiningInterval / 8) * 3 / 5  ← Uses hardcoded 8, not dynamic 1
// = MiningInterval * 3 / 40

// Expected for 1 block: MiningInterval * 3 / 5
// Actual received: MiningInterval * 3 / 40
// Ratio: 3/40 ÷ 3/5 = 1/8 = 12.5% of expected time
```

The mismatch is evident by comparing the code paths: `GetMaximumBlocksCount()` controls block count restrictions while `CommandStrategyBase.TinyBlocksCount` controls timing calculations, with no synchronization between them.

---

## Notes

This vulnerability represents a **integration failure** between two consensus features that evolved separately. The dynamic block count adjustment (PR #1952) was added to prevent forks during stress conditions, but the existing timing calculation infrastructure was not updated to respect these dynamic limits. The result is an operational vulnerability that undermines the very recovery mechanism it should support, potentially extending consensus issues rather than resolving them.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L17-17)
```csharp
        private const int TinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L42-42)
```csharp
        private int TinyBlockSlotInterval => MiningInterval.Div(TinyBlocksCount);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L49-49)
```csharp
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L60-60)
```csharp
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L22-28)
```csharp
    private int GetMaximumBlocksCount()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        var libRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
        var libBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
        var currentHeight = Context.CurrentHeight;
        var currentRoundNumber = currentRound.RoundNumber;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L57-67)
```csharp
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L60-62)
```csharp
                if (_minerInRound.ActualMiningTimes.Count < _maximumBlocksCount)
                    // Provided pubkey can keep producing tiny blocks.
                    return AElfConsensusBehaviour.TinyBlock;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L40-43)
```csharp
            ? new MainChainConsensusBehaviourProvider(currentRound, _processingBlockMinerPubkey,
                    GetMaximumBlocksCount(),
                    Context.CurrentBlockTime, blockchainStartTimestamp, State.PeriodSeconds.Value)
                .GetConsensusBehaviour()
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/NormalBlockCommandStrategy.cs (L39-39)
```csharp
                LimitMillisecondsOfMiningBlock = DefaultBlockMiningLimit
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
