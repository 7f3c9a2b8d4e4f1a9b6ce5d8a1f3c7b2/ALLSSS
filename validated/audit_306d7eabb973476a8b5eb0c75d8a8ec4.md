# Audit Report

## Title
Stale Continuous Block Counter Bypasses Severe Status Emergency Limit

## Summary
During Severe emergency status, the AEDPoS consensus contract's validation system uses a stale `LatestPubkeyToTinyBlocksCount` counter from state that was set before the emergency status was detected. This allows miners to continue producing blocks based on their pre-emergency allowance (up to 8 blocks) instead of being immediately limited to 1 block, completely undermining the emergency safety mechanism designed to prevent the chain from advancing too far ahead of the Last Irreversible Block (LIB).

## Finding Description

The AEDPoS consensus implements an emergency brake mechanism where `GetMaximumBlocksCount()` returns 1 when the blockchain enters Severe status (when current round number is at least 8 rounds ahead of the LIB round). [1](#0-0) 

However, the validation logic creates a Time-Of-Check-Time-Of-Use (TOCTOU) vulnerability through the following execution flow:

**Validation Phase (BEFORE Execution):**

When `ValidateConsensusBeforeExecution` is called, it invokes `ValidateBeforeExecution` [2](#0-1)  which creates a `ConsensusValidationContext` containing the **stale** `LatestPubkeyToTinyBlocksCount` value from state. [3](#0-2) 

The `ContinuousBlocksValidationProvider` validates this counter, but only rejects blocks when `BlocksCount < 0`. [4](#0-3) 

**Execution Phase (AFTER Validation):**

After validation passes, the consensus transaction calls `ProcessConsensusInformation`. [5](#0-4) 

Inside `ProcessConsensusInformation`, the system calls `GetMaximumBlocksCount()` which NOW evaluates the current blockchain status and returns 1 for Severe status, then calls `ResetLatestProviderToTinyBlocksCount(1)`. [6](#0-5) 

**The Critical Flaw:**

When `ResetLatestProviderToTinyBlocksCount` is called with the new emergency limit (1), it only **decrements** the existing counter if the same miner continues producing blocks. [7](#0-6) 

The new limit is only applied when a **different** miner takes over. [8](#0-7) 

**Concrete Attack Scenario:**

1. Normal operation: Miner A has been producing consecutive blocks, with `LatestPubkeyToTinyBlocksCount = {Pubkey: A, BlocksCount: 7}` (maximum normal value, since `MaximumTinyBlocksCount = 8`). [9](#0-8) 

2. System enters Severe status due to LIB lag (R >= R_LIB + 8). [10](#0-9) 

3. Miner A produces Block N:
   - Validation reads stale `BlocksCount = 7` from state (passes validation since 7 >= 0)
   - Block executes, `GetMaximumBlocksCount()` returns 1 (Severe limit)
   - `ResetLatestProviderToTinyBlocksCount(1)` decrements: `BlocksCount = 7 - 1 = 6`

4. Miner A produces Block N+1:
   - Validation reads `BlocksCount = 6` (passes)
   - Block executes, decrements to 5

5. This continues until Block N+7:
   - Validation reads `BlocksCount = 0` (still passes)
   - Block executes, decrements to -1

6. Block N+8:
   - Validation reads `BlocksCount = -1` (FINALLY FAILS)

**Result:** Miner A produces 8 blocks during Severe emergency status instead of the intended 1 block limit.

## Impact Explanation

The Severe status is a critical safety mechanism triggered when the blockchain mining status becomes dangerous - specifically when the current round number is at least `SevereStatusRoundsThreshold` (Math.Max(8, MaximumTinyBlocksCount) = 8) rounds ahead of the Last Irreversible Block round. [11](#0-10) 

The system fires an `IrreversibleBlockHeightUnacceptable` event to notify miners not to package normal transactions, and sets `IsPreviousBlockInSevereStatus` to true, clearly indicating this is an emergency condition. [12](#0-11) [13](#0-12) 

**Concrete Harm:**

1. **Chain Safety Compromised:** The emergency limit exists to prevent the chain from advancing too far ahead of the LIB. When bypassed, the chain can continue advancing 8x faster than intended during this critical period, increasing fork risk and chain reorganization vulnerability.

2. **Emergency Response Ineffective:** The system detects the dangerous condition and attempts to limit block production to 1, but the stale counter allows miners to ignore this limit, making the emergency brake mechanism ineffective.

3. **Quantified Violation:** With maximum pre-emergency `BlocksCount = 7`, a miner can produce 8 blocks instead of 1 block during Severe status - an **8x violation** of the emergency safety limit.

4. **Affects All Participants:** Chain instability affects finality guarantees and transaction irreversibility for all network participants, not just the miner producing the blocks.

## Likelihood Explanation

**Preconditions (All Realistic):**

1. **Miner Producing Consecutive Blocks:** This is normal behavior during consensus operation. Any miner can naturally accumulate a non-zero `BlocksCount` value (up to 7) by producing consecutive blocks during normal operation.

2. **System Enters Severe Status:** This occurs when network conditions cause LIB to lag behind the current round by 8+ rounds. Common causes include:
   - Network partitions or connectivity issues
   - Consensus delays where miners fail to produce blocks in their time slots
   - Chain fork scenarios being resolved

3. **Same Miner Continues:** The miner who was producing blocks when Severe status triggers naturally continues attempting to produce blocks - this is expected consensus behavior.

**No Special Permissions Required:**

The vulnerability affects legitimate miners operating normally within consensus rules. No malicious intent or special manipulation is needed - the issue triggers automatically during normal consensus operation when the timing conditions align.

**Probability: HIGH**

This vulnerability will trigger naturally whenever:
- A miner happens to be producing consecutive blocks (common)
- Network conditions cause LIB lag triggering Severe status (occurs during network issues)
- The same miner continues mining (natural behavior)

The issue is architectural and cannot be avoided through operational procedures or external monitoring.

## Recommendation

The validation should check the counter against the current emergency limit, not just against zero. Modify `ContinuousBlocksValidationProvider` to:

1. Call `GetMaximumBlocksCount()` during validation to get the current limit
2. Compare `BlocksCount` against this current limit minus a threshold
3. Reject blocks if the counter would violate the current emergency limit

Alternatively, `ResetLatestProviderToTinyBlocksCount` should immediately reset the counter to the new limit (not decrement from the old value) when the limit changes, especially when entering emergency status.

## Proof of Concept

The vulnerability can be demonstrated by creating a test that:
1. Sets up a miner with `BlocksCount = 7` through normal consecutive block production
2. Advances the LIB lag to trigger Severe status (currentRound >= libRound + 8)
3. Has the same miner continue producing blocks
4. Verifies that 8 blocks are produced before validation fails
5. Confirms that `GetMaximumBlocksCount()` returns 1 during this period

The test would show that despite `GetMaximumBlocksCount()` returning 1, the miner successfully produces 8 blocks due to the stale counter in validation.

## Notes

This is a consensus safety vulnerability that undermines the emergency brake mechanism designed to protect chain stability during LIB lag. The TOCTOU flaw between validation and execution allows the pre-emergency counter value to persist through multiple blocks even after the system has detected the dangerous condition and attempted to impose a stricter limit. This is not a theoretical issue - it will occur naturally during network conditions that cause LIB lag, which are realistic scenarios in a distributed consensus system.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L77-80)
```csharp
    public override ValidationResult ValidateConsensusBeforeExecution(BytesValue input)
    {
        var extraData = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value.ToByteArray());
        return ValidateBeforeExecution(extraData);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L21-87)
```csharp
    private void ProcessConsensusInformation(dynamic input, [CallerMemberName] string callerMethodName = null)
    {
        EnsureTransactionOnlyExecutedOnceInOneBlock();

        Context.LogDebug(() => $"Processing {callerMethodName}");

        /* Privilege check. */
        if (!PreCheck()) Assert(false, "No permission.");

        State.RoundBeforeLatestExecution.Value = GetCurrentRoundInformation(new Empty());

        ByteString randomNumber = null;

        // The only difference.
        switch (input)
        {
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
            case NextTermInput nextTermInput:
                randomNumber = nextTermInput.RandomNumber;
                ProcessNextTerm(nextTermInput);
                break;
            case UpdateValueInput updateValueInput:
                randomNumber = updateValueInput.RandomNumber;
                ProcessUpdateValue(updateValueInput);
                break;
            case TinyBlockInput tinyBlockInput:
                randomNumber = tinyBlockInput.RandomNumber;
                ProcessTinyBlock(tinyBlockInput);
                break;
        }

        var miningInformationUpdated = new MiningInformationUpdated
        {
            // _processingBlockMinerPubkey is set during PreCheck.
            Pubkey = _processingBlockMinerPubkey,
            Behaviour = callerMethodName,
            MiningTime = Context.CurrentBlockTime,
            BlockHeight = Context.CurrentHeight,
            PreviousBlockHash = Context.PreviousBlockHash
        };
        Context.Fire(miningInformationUpdated);
        Context.LogDebug(() => $"Synced mining information: {miningInformationUpdated}");

        // Make sure the method GetMaximumBlocksCount executed no matter what consensus behaviour is.
        var minersCountInTheory = GetMaximumBlocksCount();
        ResetLatestProviderToTinyBlocksCount(minersCountInTheory);

        if (TryToGetCurrentRoundInformation(out var currentRound))
            Context.LogDebug(() =>
                $"Current round information:\n{currentRound.ToString(_processingBlockMinerPubkey)}");

        var previousRandomHash = State.RandomHashes[Context.CurrentHeight.Sub(1)] ?? Hash.Empty;
        Assert(
            Context.ECVrfVerify(Context.RecoverPublicKey(), previousRandomHash.ToByteArray(),
                randomNumber.ToByteArray(), out var beta), "Failed to verify random number.");
        var randomHash = Hash.LoadFromByteArray(beta);
        State.RandomHashes[Context.CurrentHeight] = randomHash;
        Context.LogDebug(() => $"New random hash generated: {randomHash} - height {Context.CurrentHeight}");

        if (!State.IsMainChain.Value && currentRound.RoundNumber > 1) Release();

        // Clear cache.
        _processingBlockMinerPubkey = null;
    }
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L359-363)
```csharp
                State.LatestPubkeyToTinyBlocksCount.Value = new LatestPubkeyToTinyBlocksCount
                {
                    Pubkey = _processingBlockMinerPubkey,
                    BlocksCount = minersCountInTheory.Sub(1)
                };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L6-6)
```csharp
    public const int MaximumTinyBlocksCount = 8;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L61-61)
```csharp
    public BoolState IsPreviousBlockInSevereStatus { get; set; }
```
