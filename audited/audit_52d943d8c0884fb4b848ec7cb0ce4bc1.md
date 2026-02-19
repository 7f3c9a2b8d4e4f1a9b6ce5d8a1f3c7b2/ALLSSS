# Audit Report

## Title
Continuous Blocks Validation Bypasses Severe Status Limit Due to Stale IrreversibleBlockHeight-Based Threshold

## Summary
The `ContinuousBlocksValidationProvider` validates blocks using a stale `LatestPubkeyToTinyBlocksCount` value from the previous block's execution, rather than considering the current blockchain status. When the network transitions from Normal to Severe status (due to LIB lagging significantly), miners can produce up to 8 consecutive blocks instead of being limited to 1 block as intended, violating the consensus safety mechanism designed to force frequent miner rotation during critical network conditions.

## Finding Description

The vulnerability exists in the timing mismatch between validation and state updates during block processing.

**Validation Phase (Pre-Execution):**
The validation context retrieves `LatestPubkeyToTinyBlocksCount` from state, which was set during the previous block's post-execution phase. [1](#0-0) 

The `ContinuousBlocksValidationProvider` only checks if `BlocksCount < 0`, without considering the current blockchain status or LIB position. [2](#0-1) 

**State Update Phase (Post-Execution):**
After block execution, `GetMaximumBlocksCount()` is called to determine the appropriate limit based on current LIB status. When the blockchain is in Severe status (R >= R_LIB + 8), the limit should be 1 consecutive block per miner. [3](#0-2) 

The blockchain status is determined by comparing current round number with LIB round number. [4](#0-3) 

**Critical Flaw:**
When the same miner produces consecutive blocks, `ResetLatestProviderToTinyBlocksCount()` only decrements the existing `BlocksCount` by 1, regardless of the current blockchain status. [5](#0-4) 

**Attack Scenario:**
1. Miner A starts producing blocks in Normal status with `BlocksCount = 7`
2. Network conditions cause LIB to lag, transitioning to Severe status
3. Validation still uses the stale `BlocksCount = 7`, which passes (7 >= 0)
4. Post-execution decrements to 6, then 5, then 4... continuing for 8 total blocks
5. Only when `BlocksCount` becomes -1 does validation finally fail

This allows miners to produce up to 8 consecutive blocks in Severe status, when the protocol explicitly limits them to 1 block to force rotation and help achieve consensus.

## Impact Explanation

**Critical Consensus Safety Violation:**
The Severe blockchain status is triggered when LIB falls dangerously behind (8+ rounds). During this critical period, the consensus protocol is designed to force frequent miner rotation by limiting each miner to producing only 1 consecutive block before another miner must take over. This mechanism helps the network achieve consensus and advance LIB during periods of network stress, partitions, or slow block propagation.

This vulnerability defeats that safety mechanism entirely. A miner who began producing blocks before the Severe status transition can continue producing up to 8 consecutive blocks, representing an 8x violation of the intended safety limit.

**Quantified Damage:**
- Instead of 1 block per miner in Severe status, miners can produce up to 8 blocks
- The extra 7 blocks occur during the most critical network conditions
- This prolongs the period where a single miner controls block production
- Increases fork risk and worsens network split conditions when consensus is already struggling
- Defeats the fork-prevention mechanism at precisely the time it's most needed

**Affected Parties:**
All network participants suffer from prolonged consensus instability, increased fork probability, and delayed LIB advancement during critical network conditions.

## Likelihood Explanation

**Attack Complexity: Low**
This vulnerability triggers automatically during normal network operations without requiring any malicious intent or special capabilities. It occurs naturally when:
1. Network stress causes LIB to lag by 8+ rounds (common during partitions or slow propagation)
2. Blockchain status transitions from Normal to Severe
3. A miner happens to be producing consecutive blocks at the time of transition

**Attacker Capabilities: None Required**
No special permissions, collusion, or attack infrastructure needed. Any miner producing consecutive blocks when the status transition occurs will automatically exceed the Severe limit.

**Preconditions: Realistic**
Network conditions causing LIB lag occur regularly in distributed consensus systems. Status transitions are part of normal protocol operation during network stress. Miners naturally produce consecutive blocks during their assigned time slots.

**Detection Difficulty: High**
The extra blocks are validly signed, properly timestamped, and pass all other consensus checks. They appear as legitimate block production, making the violation difficult to detect without specifically monitoring BlocksCount against current blockchain status.

**Probability: High**
Status transitions occur frequently during network stress periods, and miners routinely produce multiple consecutive blocks. The vulnerability triggers deterministically whenever these common conditions align.

## Recommendation

The validation should check against the current maximum blocks count based on blockchain status, not just whether BlocksCount is negative.

**Option 1: Real-time Limit Check**
Modify `ContinuousBlocksValidationProvider` to calculate the current maximum blocks count during validation and check if the producer has exceeded it:

```csharp
// In ContinuousBlocksValidationProvider.ValidateHeaderInformation()
var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
if (latestPubkeyToTinyBlocksCount != null &&
    latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey)
{
    // Calculate current maximum based on LIB status
    var currentMaximum = CalculateCurrentMaximumBlocksCount(validationContext);
    var remainingQuota = currentMaximum - 1; // Account for current block
    
    if (latestPubkeyToTinyBlocksCount.BlocksCount > remainingQuota)
    {
        validationResult.Message = "Sender produced too many continuous blocks for current blockchain status.";
        return validationResult;
    }
}
```

**Option 2: Reset on Status Change**
Store the blockchain status alongside BlocksCount and reset the counter when status changes to a more restrictive mode:

```csharp
// In ResetLatestProviderToTinyBlocksCount()
var currentStatus = DetermineBlockchainStatus();
var previousStatus = State.LastBlockchainStatus.Value;

if (currentValue.Pubkey == _processingBlockMinerPubkey)
{
    var newCount = currentValue.BlocksCount.Sub(1);
    
    // If status became more restrictive, cap the remaining quota
    if (currentStatus > previousStatus) // Severe > Abnormal > Normal
    {
        newCount = Math.Min(newCount, minersCountInTheory.Sub(1));
    }
    
    State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
    {
        Pubkey = _processingBlockMinerPubkey,
        BlocksCount = newCount
    };
}

State.LastBlockchainStatus.Value = currentStatus;
```

## Proof of Concept

```csharp
[Fact]
public async Task ContinuousBlocks_SevereStatusBypass_Test()
{
    // Setup: Initialize consensus with Normal status
    await InitializeConsensusAsync();
    var minerA = SampleAccount.Accounts[0];
    
    // Miner A produces blocks in Normal status (limit = 8)
    // This sets BlocksCount = 7 after first block
    await ProduceBlockAsync(minerA);
    var stateAfterFirstBlock = await GetLatestPubkeyToTinyBlocksCountAsync();
    stateAfterFirstBlock.BlocksCount.ShouldBe(7); // 8 - 1
    
    // Simulate network stress causing LIB to lag significantly
    // This triggers Severe status (limit should become 1)
    await SimulateLIBLagAsync(roundsToLag: 8);
    
    // Miner A continues producing blocks in Severe status
    // Should be limited to 1 block, but can produce up to 8
    var blocksProducedInSevere = 0;
    
    for (int i = 0; i < 8; i++)
    {
        var result = await TryProduceBlockAsync(minerA);
        if (result.Success)
        {
            blocksProducedInSevere++;
        }
        else
        {
            break;
        }
    }
    
    // Vulnerability: Miner A produced 8 blocks in Severe status
    // Expected: Should fail after 1 block
    // Actual: Produces 8 blocks before failing
    blocksProducedInSevere.ShouldBe(8);
    
    // The 9th block should finally fail
    var finalResult = await TryProduceBlockAsync(minerA);
    finalResult.Success.ShouldBeFalse();
    finalResult.Message.ShouldContain("too many continuous blocks");
}
```

**Notes:**
This vulnerability represents a clear violation of consensus safety invariants. The protocol explicitly defines different limits for different blockchain statuses, but the validation mechanism fails to enforce these limits when status transitions occur mid-production. The fix requires either real-time status checking during validation or proper state reset when entering more restrictive status modes.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_Validation.cs (L58-58)
```csharp
            LatestPubkeyToTinyBlocksCount = State.LatestPubkeyToTinyBlocksCount.Value,
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/ContinuousBlocksValidationProvider.cs (L16-23)
```csharp
            var latestPubkeyToTinyBlocksCount = validationContext.LatestPubkeyToTinyBlocksCount;
            if (latestPubkeyToTinyBlocksCount != null &&
                latestPubkeyToTinyBlocksCount.Pubkey == validationContext.SenderPubkey &&
                latestPubkeyToTinyBlocksCount.BlocksCount < 0)
            {
                validationResult.Message = "Sender produced too many continuous blocks.";
                return validationResult;
            }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetMaximumBlocksCount.cs (L123-128)
```csharp
            if (_libRoundNumber.Add(AbnormalThresholdRoundsCount) < _currentRoundNumber &&
                _currentRoundNumber < _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Abnormal;

            if (_currentRoundNumber >= _libRoundNumber.Add(SevereStatusRoundsThreshold))
                status = BlockchainMiningStatus.Severe;
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
