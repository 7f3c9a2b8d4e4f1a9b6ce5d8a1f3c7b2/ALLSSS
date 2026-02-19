# Audit Report

## Title
Stale Continuous Block Counter Bypasses Severe Status Emergency Limit

## Summary
During Severe emergency status, the AEDPoS consensus system intends to limit block production to 1 block per miner by having `GetMaximumBlocksCount()` return 1. However, the validation system uses a stale `LatestPubkeyToTinyBlocksCount` counter from the previous block's state, and the counter update logic only decrements the existing value when the same miner continues. This allows a miner to produce up to 8 blocks during emergency status instead of the intended 1 block, completely undermining the emergency safety mechanism.

## Finding Description

The AEDPoS consensus contract implements an emergency brake mechanism that triggers when the current round number is dangerously ahead of the Last Irreversible Block (LIB) round number. The vulnerability arises from a timing mismatch between validation and state updates.

**Root Cause - Severe Status Returns 1:**

When the blockchain enters Severe status (current round ≥ LIB round + 8), the emergency limit is set to 1 block: [1](#0-0) 

**Validation Uses Stale Counter:**

The validation occurs BEFORE block execution and uses the counter value from the previous block's state: [2](#0-1) 

The validation provider only rejects blocks when the counter is negative: [3](#0-2) 

**Counter Update Only Decrements:**

After block execution, the counter is updated. When the same miner continues, the counter is merely decremented rather than reset to the new emergency limit: [4](#0-3) 

The new emergency limit (minersCountInTheory = 1) is only applied when a DIFFERENT miner takes over (line 362), not when the same miner continues (line 356).

**Execution Flow:**

1. Validation phase: `ValidateConsensusBeforeExecution` delegates to `ValidateBeforeExecution`: [5](#0-4) 

2. Block executes, then `ProcessConsensusInformation` calls the emergency limit check and counter update: [6](#0-5) 

**Concrete Example:**

- Before Severe status: Miner A has BlocksCount = 7 (from normal limit of 8)
- System enters Severe: `GetMaximumBlocksCount()` now returns 1
- Block N+1: Validation sees 7 (≥ 0, passes) → Execution sets to 6
- Block N+2: Validation sees 6 (≥ 0, passes) → Execution sets to 5
- ... continues through 4, 3, 2, 1, 0
- Block N+8: Validation sees 0 (≥ 0, passes) → Execution sets to -1
- Block N+9: Validation sees -1 (< 0, FAILS)

Result: 8 blocks produced during Severe status instead of 1.

## Impact Explanation

The Severe status emergency mechanism is a critical safety feature designed to prevent chain instability when the Last Irreversible Block falls dangerously behind. The severity threshold is defined as: [7](#0-6) 

When bypassed, the chain continues advancing rapidly despite being 8+ rounds ahead of LIB, which:
- **Increases fork risk:** More blocks ahead of LIB means higher probability of chain reorganization
- **Undermines finality guarantees:** Transaction irreversibility becomes less reliable
- **Defeats emergency response:** The emergency brake becomes 87.5% ineffective (1 block intended vs 8 blocks actual)

The constant defining the normal limit shows this affects up to 7 extra blocks: [8](#0-7) 

## Likelihood Explanation

This vulnerability triggers automatically during normal consensus operations:

**Preconditions (All Realistic):**
1. A miner produces consecutive blocks - common during normal mining
2. Network conditions cause LIB to lag 8+ rounds behind - occurs during network partitions, consensus delays, or validator downtime
3. The same miner continues producing blocks - natural consensus behavior

**No Special Capabilities Required:**
- No privileged access needed
- No transaction manipulation required
- Happens through legitimate mining operations

**Probability: HIGH** - This occurs whenever network issues cause Severe status while a miner is naturally producing consecutive blocks. The vulnerability is architectural and cannot be prevented without code changes.

## Recommendation

Reset the counter to the current emergency limit when updating, rather than just decrementing:

```csharp
private void ResetLatestProviderToTinyBlocksCount(int minersCountInTheory)
{
    LatestPubkeyToTinyBlocksCount currentValue;
    if (State.LatestPubkeyToTinyBlocksCount.Value == null)
    {
        currentValue = new LatestPubkeyToTinyBlocksCount
        {
            Pubkey = _processingBlockMinerPubkey,
            BlocksCount = minersCountInTheory.Sub(1)  // Use new limit
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
                // FIX: Use the minimum of decremented value and new limit
                BlocksCount = Math.Min(currentValue.BlocksCount.Sub(1), minersCountInTheory.Sub(1))
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

This ensures the counter respects the new emergency limit immediately, rather than gradually counting down from the pre-emergency value.

## Proof of Concept

The vulnerability can be demonstrated by tracing the state transitions:

```csharp
// Initial State: Normal mining, Miner A has BlocksCount = 7
// System enters Severe status (R >= R_LIB + 8)
// GetMaximumBlocksCount() now returns 1

// Block N+1 by Miner A:
// - ValidateBeforeExecution sees State.LatestPubkeyToTinyBlocksCount.BlocksCount = 7
// - ContinuousBlocksValidationProvider checks: 7 < 0? NO → Validation PASSES
// - Block executes
// - ResetLatestProviderToTinyBlocksCount(1) is called
// - Same miner continues: BlocksCount = 7 - 1 = 6 (WRONG: should be 0)

// Block N+2 by Miner A:
// - Validation sees BlocksCount = 6
// - Check: 6 < 0? NO → PASSES (WRONG: should fail, only 1 block allowed)
// - Execution: BlocksCount = 5

// Continues for N+3 (4), N+4 (3), N+5 (2), N+6 (1), N+7 (0), N+8 (-1)

// Result: 8 blocks produced during Severe status
// Expected: 1 block
// Violation: 8x bypass of emergency limit
```

The proof demonstrates that the validation's reliance on stale state combined with the decrement-only update logic allows the emergency limit to be bypassed by a factor of 8x, fundamentally undermining the Severe status safety mechanism.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-67)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L117-128)
```csharp
        public int SevereStatusRoundsThreshold => Math.Max(8, _maximumTinyBlocksCount);

        public void Deconstruct(out BlockchainMiningStatus status)
        {
            status = BlockchainMiningStatus.Normal;

            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L52-60)
```csharp
        var validationContext = new ConsensusValidationContext
        {
            BaseRound = baseRound,
            CurrentTermNumber = State.CurrentTermNumber.Value,
            CurrentRoundNumber = State.CurrentRoundNumber.Value,
            PreviousRound = TryToGetPreviousRoundInformation(out var previousRound) ? previousRound : new Round(),
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
            ExtraData = extraData
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-81)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```
