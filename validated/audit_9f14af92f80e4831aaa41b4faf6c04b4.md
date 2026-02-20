# Audit Report

## Title
Last Irreversible Block (LIB) Height Stuck at Zero During Round 2 Due to Missing ImpliedIrreversibleBlockHeight Updates in Non-UpdateValue Behaviors

## Summary
The AEDPoS consensus mechanism fails to preserve `ImpliedIrreversibleBlockHeight` values when transitioning from Round 1 to Round 2 via NextRound behavior. When the first miner is offline during Round 1, all Round 2 miners are initialized with `ImpliedIrreversibleBlockHeight = 0`, causing LIB calculation to fail and block finality to remain stuck at height 0 for the entire Round 2, blocking all cross-chain operations and finality-dependent functionality.

## Finding Description

The vulnerability stems from an asymmetry in how consensus behaviors handle the `ImpliedIrreversibleBlockHeight` field across round transitions.

**Root Cause:**

During UpdateValue behavior, `ImpliedIrreversibleBlockHeight` is set to the current block height: [1](#0-0) 

This value is then stored in the miner's round information: [2](#0-1) 

However, TinyBlock, NextRound, and NextTerm behaviors do **not** set this field. [3](#0-2) [4](#0-3) 

**Vulnerable Execution Path:**

1. **Round 1 with First Miner Offline**: The consensus protocol explicitly prevents non-first miners from producing UpdateValue blocks when the first miner hasn't mined yet, to prevent fork blocks: [5](#0-4) 

2. **NextRound Transition Loses Data**: When `GenerateNextRoundInformation` creates Round 2 miner entries, it only copies specific fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots), but **not** `ImpliedIrreversibleBlockHeight`: [6](#0-5) 

3. **LIB Calculation Failure**: During Round 2 UpdateValue blocks, the LIB calculator retrieves miners who mined in the current round, then fetches their `ImpliedIrreversibleBlockHeight` from the **previous round** (Round 1): [7](#0-6) 

4. **Zero Values Filtered Out**: The sorting method explicitly filters out zero values: [8](#0-7) 

5. **Empty List Returns LIB = 0**: When the filtered list is empty, the calculator returns 0: [9](#0-8) 

6. **Update Condition Fails**: The LIB update requires strict inequality, so when both values are 0, no update occurs: [10](#0-9) 

## Impact Explanation

**High Severity - Consensus Finality Denial of Service**

This vulnerability breaks a critical consensus invariant: LIB height must progress monotonically as blocks are produced. The impact includes:

1. **Complete Finality Failure**: Throughout Round 2, no blocks achieve irreversible status, violating the fundamental guarantee of Byzantine fault-tolerant consensus that 2/3+ honest miners confirm finality.

2. **Cross-Chain Operations Halted**: The `IrreversibleBlockFound` event is not fired during Round 2, blocking cross-chain indexing and transfers that depend on finalized block confirmations for safety guarantees.

3. **Extended Duration**: Round 2 duration depends on miner count and mining intervals (e.g., 17 miners × 4-second intervals = ~68 seconds minimum), meaning the finality system is non-functional for a substantial period.

4. **Systemic Risk**: Applications relying on transaction finality (exchanges, payment systems, high-value transfers) cannot obtain irreversibility confirmations, forcing them to either halt operations or accept significantly higher reorg risk.

## Likelihood Explanation

**Medium-High Likelihood During Genesis/Bootstrap Phase**

The trigger condition is realistic and can occur through multiple vectors:

1. **Genesis Initialization Failures**: During initial chain deployment, the first miner may fail to start properly due to:
   - Network configuration issues
   - Node synchronization delays
   - Docker/deployment timing problems
   - Incorrect genesis timestamp configuration

2. **Protocol-Enforced Behavior**: This is **not** an edge case - the consensus protocol explicitly implements the NextRound behavior for non-first miners when the first miner is absent: [11](#0-10) 

3. **Low Attack Complexity**: A malicious actor controlling the first miner slot can trigger this by simply not producing blocks, requiring no sophisticated attack capabilities.

4. **No Recovery Within Round**: Once triggered, the issue persists for the entire Round 2 with no ability to recover until Round 3 begins.

## Recommendation

**Option 1: Preserve ImpliedIrreversibleBlockHeight During Round Transitions**

Modify `GenerateNextRoundInformation` to copy the `ImpliedIrreversibleBlockHeight` field when creating new miner entries:

```csharp
// In Round_Generation.cs, around line 29-36
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight // ADD THIS LINE
};
```

**Option 2: Set ImpliedIrreversibleBlockHeight in NextRound Behavior**

Update `GetConsensusExtraDataForNextRound` to set the field similar to UpdateValue behavior, ensuring continuity across round transitions.

**Option 3: Special Handling for Round 1→2 Transition**

Add explicit logic to handle the case where Round 1 has no UpdateValue blocks, initializing Round 2 miners with a reasonable `ImpliedIrreversibleBlockHeight` value (e.g., current blockchain height or previous LIB).

## Proof of Concept

```csharp
[Fact]
public async Task LIB_Stuck_At_Zero_When_Round1_Has_No_UpdateValue_Test()
{
    // Initialize consensus with multiple miners
    InitializeContracts();
    
    // Simulate Round 1 where first miner (Order=1) is offline
    // Other miners will trigger NextRound behavior per ConsensusBehaviourProviderBase.cs:94-102
    var secondMinerKeyPair = InitialCoreDataCenterKeyPairs[1];
    KeyPairProvider.SetKeyPair(secondMinerKeyPair);
    
    // Advance time past first miner's slot
    BlockTimeProvider.SetBlockTime(BlockchainStartTimestamp.AddSeconds(10));
    
    // Get consensus command - should be NextRound (not UpdateValue)
    var trigger = TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());
    var command = await AEDPoSContractStub.GetConsensusCommand.CallAsync(trigger);
    var hint = AElfConsensusHint.Parser.ParseFrom(command.Hint);
    
    // Verify NextRound behavior is returned (per vulnerability trigger condition)
    hint.Behaviour.ShouldBe(AElfConsensusBehaviour.NextRound);
    
    // Execute NextRound to transition to Round 2
    var nextRoundTrigger = TriggerInformationProvider.GetTriggerInformationForConsensusTransactions(
        new ChainContext(), command.ToBytesValue());
    var nextRoundInput = AElfConsensusTriggerInformation.Parser.ParseFrom(nextRoundTrigger.Value);
    nextRoundInput.RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(secondMinerKeyPair));
    
    var txList = await AEDPoSContractStub.GenerateConsensusTransactions.CallAsync(nextRoundInput.ToBytesValue());
    var nextRoundTx = NextRoundInput.Parser.ParseFrom(txList.Transactions.First().Params);
    await AEDPoSContractStub.NextRound.SendAsync(nextRoundTx);
    
    // Verify we're now in Round 2
    var round2 = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    round2.RoundNumber.ShouldBe(2);
    
    // Check Round 1 miners all have ImpliedIrreversibleBlockHeight = 0
    var round1 = await AEDPoSContractStub.GetPreviousRoundInformation.CallAsync(new Empty());
    foreach (var miner in round1.RealTimeMinersInformation.Values)
    {
        miner.ImpliedIrreversibleBlockHeight.ShouldBe(0); // All zero per Round_Generation.cs:29-36
    }
    
    // Now miners produce UpdateValue blocks in Round 2
    BlockTimeProvider.SetBlockTime(BlockchainStartTimestamp.AddSeconds(20));
    KeyPairProvider.SetKeyPair(secondMinerKeyPair);
    
    var updateTrigger = TriggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());
    var updateCommand = await AEDPoSContractStub.GetConsensusCommand.CallAsync(updateTrigger);
    
    var updateValueTrigger = TriggerInformationProvider.GetTriggerInformationForConsensusTransactions(
        new ChainContext(), updateCommand.ToBytesValue());
    var updateInput = AElfConsensusTriggerInformation.Parser.ParseFrom(updateValueTrigger.Value);
    updateInput.RandomNumber = ByteString.CopyFrom(await GenerateRandomProofAsync(secondMinerKeyPair));
    
    var updateTxList = await AEDPoSContractStub.GenerateConsensusTransactions.CallAsync(updateInput.ToBytesValue());
    var updateValueInput = UpdateValueInput.Parser.ParseFrom(updateTxList.Transactions.First().Params);
    await AEDPoSContractStub.UpdateValue.SendAsync(updateValueInput);
    
    // Get updated round info
    var updatedRound = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // VULNERABILITY: LIB is stuck at 0 because:
    // 1. LIB calculator looks at Round 1 miners (per AEDPoSContract_LIB.cs:24-25)
    // 2. All have ImpliedIrreversibleBlockHeight = 0 (per Round_Generation.cs:29-36)
    // 3. GetSortedImpliedIrreversibleBlockHeights filters out zeros (Round_ImpliedIrreversibleBlockHeight.cs:15)
    // 4. Empty list causes LIB = 0 (AEDPoSContract_LIB.cs:26-30)
    // 5. Update condition fails: 0 < 0 = false (AEDPoSContract_ProcessConsensusInformation.cs:272)
    updatedRound.ConfirmedIrreversibleBlockHeight.ShouldBe(0); // STUCK AT ZERO
    
    // Expected: LIB should have progressed to a non-zero value
    // Actual: LIB remains at 0, blocking all finality-dependent operations
}
```

## Notes

This vulnerability represents a state-transition invariant violation in the consensus finality mechanism. The `ImpliedIrreversibleBlockHeight` field serves as a critical coordination signal between rounds, and its loss during NextRound transitions breaks the monotonicity guarantee of LIB progression. The issue is particularly severe because it's triggered by a protocol-enforced behavior (NextRound when first miner is absent) rather than an edge case, making it a realistic threat during genesis and potentially exploitable by adversarial first miners.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L118-118)
```csharp
        updatedRound.RealTimeMinersInformation[pubkey].ImpliedIrreversibleBlockHeight = Context.CurrentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L155-171)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForTinyBlock(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        currentRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = currentRound
            .RealTimeMinersInformation[pubkey].ProducedTinyBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            currentRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        currentRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = currentRound.GetTinyBlockRound(pubkey),
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-204)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

        nextRound.ExtraBlockProducerOfPreviousRound = pubkey;

        if (!nextRound.RealTimeMinersInformation.Keys.Contains(pubkey))
            // This miner was replaced by another miner in next round.
            return new AElfConsensusHeaderInformation
            {
                SenderPubkey = ByteStringHelper.FromHexString(pubkey),
                Round = nextRound,
                Behaviour = triggerInformation.Behaviour
            };

        RevealSharedInValues(currentRound, pubkey);

        nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks =
            nextRound.RealTimeMinersInformation[pubkey].ProducedBlocks.Add(1);
        Context.LogDebug(() => $"Mined blocks: {nextRound.GetMinedBlocks()}");
        nextRound.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;
        nextRound.RealTimeMinersInformation[pubkey].ActualMiningTimes
            .Add(Context.CurrentBlockTime);

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = nextRound,
            Behaviour = triggerInformation.Behaviour
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L248-248)
```csharp
        minerInRound.ImpliedIrreversibleBlockHeight = updateValueInput.ImpliedIrreversibleBlockHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L272-281)
```csharp
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L94-102)
```csharp
            if (
                // For first round, the expected mining time is incorrect (due to configuration),
                CurrentRound.RoundNumber == 1 &&
                // so we'd better prevent miners' ain't first order (meanwhile he isn't boot miner) from mining fork blocks
                _minerInRound.Order != 1 &&
                // by postpone their mining time
                CurrentRound.FirstMiner().OutValue == null
            )
                return AElfConsensusBehaviour.NextRound;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L29-36)
```csharp
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L24-25)
```csharp
            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-30)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```
