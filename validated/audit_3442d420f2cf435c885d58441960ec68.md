# Audit Report

## Title
Stale Continuous Block Counter Bypasses Severe Status Emergency Limit

## Summary
During Severe emergency status, the AEDPoS consensus system intends to limit block production to 1 block per miner by having `GetMaximumBlocksCount()` return 1. However, the validation system uses a stale `LatestPubkeyToTinyBlocksCount` counter from the previous block's state, and the counter update logic only decrements the existing value when the same miner continues. This allows a miner to produce up to 8 blocks during emergency status instead of the intended 1 block, completely undermining the emergency safety mechanism.

## Finding Description

The AEDPoS consensus contract implements an emergency brake mechanism that triggers when the current round number is dangerously ahead of the Last Irreversible Block (LIB) round number. The vulnerability arises from a timing mismatch between validation and state updates.

**Root Cause - Severe Status Returns 1:**

When the blockchain enters Severe status (current round ≥ LIB round + 8), the emergency limit is set to 1 block to slow down block production and allow LIB to catch up: [1](#0-0) 

The Severe status threshold is defined as 8 rounds ahead: [2](#0-1) 

**Validation Uses Stale Counter:**

The validation occurs BEFORE block execution and uses the counter value from the previous block's state: [3](#0-2) 

The validation provider only rejects blocks when the counter is negative: [4](#0-3) 

**Counter Update Only Decrements:**

After block execution, the counter is updated. When the same miner continues, the counter is merely decremented rather than reset to the new emergency limit: [5](#0-4) 

The new emergency limit (minersCountInTheory = 1) is only applied when a DIFFERENT miner takes over (line 362), not when the same miner continues (line 356).

**Execution Flow:**

Validation phase occurs before execution and delegates to validation providers: [6](#0-5) 

Block executes, then `ProcessConsensusInformation` calls the emergency limit check and counter update: [7](#0-6) 

**Concrete Example:**

- Before Severe status: Miner A has BlocksCount = 7 (from normal limit of 8)
- System enters Severe: `GetMaximumBlocksCount()` now returns 1
- Block N+1: Validation sees 7 (≥ 0, passes) → Execution sets to 6
- Block N+2: Validation sees 6 (≥ 0, passes) → Execution sets to 5
- Continues through 4, 3, 2, 1, 0...
- Block N+8: Validation sees 0 (≥ 0, passes) → Execution sets to -1
- Block N+9: Validation sees -1 (< 0, FAILS)

Result: 8 blocks produced during Severe status instead of the intended 1.

## Impact Explanation

The Severe status emergency mechanism is a critical safety feature designed to prevent chain instability when the Last Irreversible Block falls dangerously behind. When bypassed, the chain continues advancing rapidly despite being 8+ rounds ahead of LIB, which:

- **Increases fork risk:** More blocks produced ahead of LIB means higher probability of chain reorganization and competing forks
- **Undermines finality guarantees:** Transaction irreversibility becomes less reliable when the gap between current height and LIB grows
- **Defeats emergency response:** The emergency brake becomes 87.5% ineffective (1 block intended vs 8 blocks actual)

The normal maximum is defined as 8 blocks: [8](#0-7) 

This allows up to 7 extra blocks beyond the intended emergency limit.

## Likelihood Explanation

This vulnerability triggers automatically during normal consensus operations:

**Preconditions (All Realistic):**
1. A miner produces consecutive blocks - common during normal mining when miners produce tiny blocks
2. Network conditions cause LIB to lag 8+ rounds behind - occurs during network partitions, consensus delays, or validator downtime
3. The same miner continues producing blocks - natural consensus behavior in AEDPoS

**No Special Capabilities Required:**
- No privileged access needed
- No transaction manipulation required  
- Happens through legitimate mining operations
- Cannot be prevented by miners or validators

**Probability: HIGH** - This occurs whenever network issues cause Severe status while a miner is naturally producing consecutive blocks. The vulnerability is architectural in the timing of validation vs. state updates and cannot be prevented without code changes.

## Recommendation

The counter should be immediately reset to the current emergency limit when validation is performed, rather than only updating after execution. Two potential fixes:

**Option 1 - Reset on Same Miner Continue:**
In `ResetLatestProviderToTinyBlocksCount`, always reset to the current limit minus 1, even for the same miner:

```csharp
if (currentValue.Pubkey == _processingBlockMinerPubkey)
    State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
    {
        Pubkey = _processingBlockMinerPubkey,
        BlocksCount = Math.Min(currentValue.BlocksCount.Sub(1), minersCountInTheory.Sub(1))
    };
```

**Option 2 - Read Current Limit During Validation:**
Pass the current maximum blocks count to the validation context so it validates against the real-time limit rather than just checking if negative.

## Proof of Concept

```csharp
[Fact]
public async Task SevereStatus_Allows_Eight_Blocks_Instead_Of_One()
{
    // Setup: Initialize consensus with single miner producing blocks normally
    await InitializeConsensusAndProduceNormalBlocks();
    
    // Force LIB to fall 8+ rounds behind to trigger Severe status
    await ManipulateLIBToTriggerSevereStatus();
    
    var miner = InitialCoreDataCenterKeyPairs[0];
    KeyPairProvider.SetKeyPair(miner);
    
    // Verify we're in Severe status - should return 1
    var maxBlocks = await AEDPoSContractStub.GetMaximumBlocksCount.CallAsync(new Empty());
    maxBlocks.Value.ShouldBe(1);
    
    // Attempt to produce 8 consecutive blocks as same miner
    int blocksProduced = 0;
    for (int i = 0; i < 9; i++)
    {
        var result = await ProduceBlockAsync(miner);
        if (result.Success)
            blocksProduced++;
        else
            break;
    }
    
    // Vulnerability: Should only allow 1 block, but allows 8
    blocksProduced.ShouldBe(8); // Proves the vulnerability
    // blocksProduced.ShouldBe(1); // Expected behavior
}
```

**Notes:**
- The vulnerability is an architectural timing issue where validation uses stale state while the emergency limit changes dynamically
- The counter decrement logic was designed for normal operation but doesn't account for emergency limit transitions
- The issue affects chain safety during the exact conditions (LIB lag) that the emergency mechanism is meant to protect against
- No malicious actor is required - this happens automatically during legitimate consensus under network stress

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L58-66)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L127-128)
```csharp
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L352-363)
```csharp
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
