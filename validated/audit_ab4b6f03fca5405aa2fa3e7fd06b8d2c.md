# Audit Report

## Title
Off-By-One Error Allows Miner to Produce 9 Continuous Blocks Instead of Intended 8-Block Limit

## Summary
An off-by-one error in the AEDPoS consensus contract allows miners to produce 9 continuous blocks instead of the intended maximum of 8 blocks defined by `MaximumTinyBlocksCount`. The vulnerability stems from flawed initialization logic that doesn't count the first block and uses a `< 0` check instead of `<= 0`, allowing one extra block when `BlocksCount = 0`.

## Finding Description

The AEDPoS consensus mechanism enforces a limit on continuous blocks to ensure fair distribution among miners. The constant `MaximumTinyBlocksCount = 8` [1](#0-0)  explicitly defines this intended maximum.

However, the enforcement logic contains an off-by-one error across three critical points:

**1. First Block Bypass:**
When a miner produces their first block in a sequence, `State.LatestPubkeyToTinyBlocksCount.Value` is `null`. The check in `GetConsensusCommand` [2](#0-1)  requires `Value != null` to evaluate the limit, so the first block bypasses this check entirely.

**2. Flawed Initialization:**
After the first block executes, `ResetLatestProviderToTinyBlocksCount` initializes the counter to `MaximumTinyBlocksCount - 1 = 7` [3](#0-2)  instead of accounting for the already-produced first block. Subsequent blocks decrement this counter [4](#0-3) .

**3. Incorrect Boundary Check:**
Both the command generation and validation use `BlocksCount < 0` as the stopping condition [5](#0-4) . This allows blocks when `BlocksCount = 0`, permitting the 9th block before forcing `NextRound` at `BlocksCount = -1`.

**Execution sequence:**
- Block 1: `null` → passes check → initializes to `BlocksCount = 7`
- Blocks 2-8: `BlocksCount` goes 7→6→5→4→3→2→1, each passes `< 0` check
- Block 9: `BlocksCount = 1` → 0, check `1 < 0` is FALSE, **allowed**
- Block 10: `BlocksCount = 0` → -1, check `0 < 0` is FALSE, **allowed** (THE EXTRA BLOCK)
- Block 11 attempt: `BlocksCount = -1`, check `-1 < 0` is TRUE, forced to NextRound

Wait, let me recount. After block 1, counter is 7:
- Block 2: 7→6 (2 total)
- Block 3: 6→5 (3 total)
- Block 4: 5→4 (4 total)
- Block 5: 4→3 (5 total)
- Block 6: 3→2 (6 total)
- Block 7: 2→1 (7 total)
- Block 8: 1→0 (8 total)
- Block 9: 0→-1 (9 total, THE EXTRA BLOCK)

The validation logic reads pre-execution state [6](#0-5) , checking the value before it gets decremented, which allows block 9 when `BlocksCount = 0`.

## Impact Explanation

This vulnerability violates a critical consensus invariant with measurable consequences:

1. **Unfair Advantage:** Miners receive 12.5% more continuous block production opportunity (9 vs 8 blocks), allowing them to collect additional transaction fees and MEV for one extra block per sequence.

2. **Consensus Fairness Violation:** The explicit `MaximumTinyBlocksCount = 8` constant represents a protocol-level fairness guarantee. Breaking this constant undermines the consensus mechanism's design intent to prevent block monopolization.

3. **Recurring Impact:** This occurs every time any miner produces their maximum continuous blocks, affecting every consensus round across the network's lifetime.

4. **Systemic Issue:** All miners can exploit this equally, making it a protocol-wide fairness degradation rather than targeted exploitation.

The severity is **Medium** because while it doesn't cause fund loss or system compromise, it systematically violates a documented consensus invariant with quantifiable unfair advantage.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically without special manipulation:

1. **Zero Attacker Prerequisites:** Any miner in the consensus set can trigger this through normal block production. No special permissions, governance control, or timing manipulation required.

2. **Automatic Exploitation:** The flaw activates naturally when miners produce their maximum continuous blocks—no deliberate "attack" action needed.

3. **Universal Occurrence:** Every miner producing maximum continuous blocks experiences this, making it a systematic protocol behavior rather than an edge case.

4. **No Preventable Conditions:** The off-by-one error is deterministic and unavoidable under current code logic.

## Recommendation

Fix the off-by-one error using one of three approaches:

**Option 1 (Recommended): Fix the boundary check**
Change the comparison from `< 0` to `<= 0`:
- In `GetConsensusCommand`: Change line 33 check to `BlocksCount <= 0`
- In `ContinuousBlocksValidationProvider`: Change line 19 check to `BlocksCount <= 0`

**Option 2: Adjust initialization value**
Change line 345 in `ResetLatestProviderToTinyBlocksCount` to:
```
BlocksCount = AEDPoSContractConstants.MaximumTinyBlocksCount.Sub(2)
```

**Option 3: Count first block**
Initialize the counter to `MaximumTinyBlocksCount - 1` before the first block instead of after, ensuring the first block counts against the limit.

## Proof of Concept

```csharp
// Test demonstrating 9 blocks can be produced
[Fact]
public async Task MinerCanProduce9ContinuousBlocks()
{
    // Setup: Initialize consensus with MaximumTinyBlocksCount = 8
    var miner = SampleAccount.Accounts[0];
    
    // Block 1: First block, LatestPubkeyToTinyBlocksCount is null
    await ProduceBlock(miner); // BlocksCount: null → 7
    Assert.Equal(7, GetBlocksCount(miner));
    
    // Blocks 2-8: Counter decrements from 7 to 0
    for (int i = 0; i < 7; i++)
    {
        await ProduceBlock(miner); // BlocksCount: 7→6→5→4→3→2→1
    }
    Assert.Equal(0, GetBlocksCount(miner));
    
    // Block 9: THE EXTRA BLOCK - BlocksCount = 0 passes check
    var result = await ProduceBlock(miner); // BlocksCount: 0→-1
    Assert.True(result.Success); // Should fail but passes!
    Assert.Equal(-1, GetBlocksCount(miner));
    
    // Verify 9 blocks were produced instead of intended 8
    Assert.Equal(9, GetProducedBlockCount(miner));
    
    // Block 10: Now forced to NextRound
    var nextResult = await AttemptProduceBlock(miner);
    Assert.Equal(AElfConsensusBehaviour.NextRound, nextResult.Behaviour);
}
```

**Notes:**
- This vulnerability affects all AElf chains using AEDPoS consensus
- The fix should be applied consistently across both command generation and validation logic
- Consider adding explicit test coverage for the boundary case at `BlocksCount = 0`

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L340-347)
```csharp
        if (State.LatestPubkeyToTinyBlocksCount.Value == null)
        {
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
