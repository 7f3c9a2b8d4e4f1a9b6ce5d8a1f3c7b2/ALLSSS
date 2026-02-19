# Audit Report

## Title
Last Irreversible Block (LIB) Height Stuck at Zero During Round 2 Due to Missing ImpliedIrreversibleBlockHeight Updates in Non-UpdateValue Behaviors

## Summary
The AEDPoS consensus mechanism only updates the `ImpliedIrreversibleBlockHeight` field during UpdateValue behavior, not during TinyBlock, NextRound, or NextTerm behaviors. When Round 1 completes via NextRound without any UpdateValue blocks (e.g., when the first miner is offline), all Round 2 miners are created with `ImpliedIrreversibleBlockHeight = 0`. This causes the LIB calculation in Round 2 to filter out all Round 1 miners, resulting in an empty list that keeps LIB stuck at 0 throughout the entire Round 2, blocking all finality-dependent operations including cross-chain transfers.

## Finding Description

**Root Cause Analysis:**

The `ImpliedIrreversibleBlockHeight` field is exclusively set during UpdateValue behavior when miners produce blocks. [1](#0-0)  This field is used by the LIB calculator to determine the Last Irreversible Block height based on 2/3+ consensus of miners' reported heights.

However, other consensus behaviors do not update this field:
- **TinyBlock behavior**: Does not set `ImpliedIrreversibleBlockHeight` [2](#0-1) 
- **NextRound behavior**: Does not set `ImpliedIrreversibleBlockHeight` [3](#0-2) 
- **NextTerm behavior**: Does not set `ImpliedIrreversibleBlockHeight` [4](#0-3) 

**Vulnerable Execution Path:**

1. **Round 1 Initialization**: All miners start with `ImpliedIrreversibleBlockHeight = 0` (default protobuf int64 value).

2. **First Miner Offline Scenario**: The consensus behavior logic contains a special rule for Round 1 where non-first miners trigger NextRound if the first miner hasn't produced blocks: [5](#0-4) 

3. **NextRound Generation Without UpdateValue**: When NextRound is triggered, the `GenerateNextRoundInformation` method creates NEW `MinerInRound` objects for Round 2. [6](#0-5)  These new objects only populate specific fields (Pubkey, Order, ExpectedMiningTime, ProducedBlocks, MissedTimeSlots) and do NOT copy or set `ImpliedIrreversibleBlockHeight`, leaving it at the default value of 0.

4. **Round 2 LIB Calculation Failure**: During Round 2, when miners produce UpdateValue blocks, the LIB calculator is invoked. [7](#0-6)  The calculator retrieves miners who mined in the current round, then fetches their `ImpliedIrreversibleBlockHeight` values from the previous round (Round 1).

5. **Empty List After Filtering**: The `GetSortedImpliedIrreversibleBlockHeights` method filters miners with `ImpliedIrreversibleBlockHeight > 0`. [8](#0-7)  Since all Round 1 miners have `ImpliedIrreversibleBlockHeight = 0`, the filtered list is empty.

6. **LIB Set to Zero**: The LIB calculator checks if the count is sufficient for consensus. [9](#0-8)  With an empty list (count = 0 < MinersCountOfConsent), `libHeight` is set to 0 and the function returns early.

7. **LIB Update Condition Fails**: The LIB update logic only updates if the new LIB is strictly higher than the current LIB. [10](#0-9)  Since both `libHeight` and `ConfirmedIrreversibleBlockHeight` are 0, the condition (0 < 0) evaluates to false, and LIB remains stuck at 0 throughout Round 2.

## Impact Explanation

**High Severity - Denial of Service on Consensus Finality:**

This vulnerability creates a critical operational failure in the consensus finality mechanism with the following impacts:

1. **LIB Stuck at Zero**: Throughout the entire Round 2 (potentially hundreds of blocks depending on miner count and mining interval), the Last Irreversible Block height remains at 0, meaning NO blocks are confirmed as irreversible.

2. **Cross-Chain Operations Blocked**: Cross-chain indexing and proof verification systems rely on irreversible block confirmations for safety guarantees. With LIB at 0, cross-chain transfers and state synchronization cannot proceed, effectively halting all cross-chain functionality.

3. **Finality-Dependent Applications Fail**: Any application or service waiting for transaction finality (irreversibility confirmation) will be indefinitely blocked. This includes:
   - High-value transactions requiring finality guarantees
   - Smart contract operations dependent on irreversible state
   - External systems requiring finality proofs

4. **Recovery Requires Full Round**: LIB can only recover in Round 3 when the calculator can reference Round 2's miners who have non-zero `ImpliedIrreversibleBlockHeight` values. This means at least one complete round of operational degradation affecting all finality-dependent functionality.

This constitutes a direct violation of the consensus invariant that LIB must progress monotonically with block production, breaking critical "LIB height rules" that ensure transaction finality.

## Likelihood Explanation

**Medium to High Likelihood During Genesis/Initialization:**

The vulnerability triggers when Round 1 completes without any miner producing an UpdateValue block, which occurs under these conditions:

1. **First Miner Failure**: The miner with Order == 1 in Round 1 must fail to produce blocks due to:
   - Network connectivity issues
   - Node offline/crashed
   - Delayed node startup
   - Configuration errors
   - Malicious behavior (intentional abstention)

2. **Automatic NextRound Trigger**: The consensus protocol itself enforces this behavior - when the first miner hasn't produced blocks (`OutValue == null`), other miners automatically return NextRound behavior to prevent fork blocks. [5](#0-4)  This is not an edge case but a designed protocol mechanism.

3. **Genesis/Initialization Vulnerability Window**: This scenario is most likely during:
   - Initial chain deployment when network connectivity may be unstable
   - Miner node synchronization phase
   - Configuration/deployment errors affecting the first miner
   - Genesis timing issues causing the first miner to miss their slot

**No Sophisticated Attack Required**: This can occur naturally due to network issues or can be trivially induced by a malicious first miner simply going offline during Round 1. Once triggered, it automatically affects the entire Round 2 without requiring further attacker action.

**Realistic Attacker Capabilities**: Any actor controlling the first miner in Round 1 can trigger this by simply not producing blocks, which requires no special privileges beyond being selected as the first miner in the genesis round.

## Recommendation

The fix requires updating `ImpliedIrreversibleBlockHeight` during NextRound generation to preserve values from the current round. Modify the `GenerateNextRoundInformation` method to copy the `ImpliedIrreversibleBlockHeight` field when creating new `MinerInRound` objects:

**In Round_Generation.cs, update the miner creation logic:**

```csharp
// For miners who mined in current round (lines 29-36)
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minerInRound.Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots,
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight  // ADD THIS LINE
};

// For miners who didn't mine (lines 46-55)
nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
{
    Pubkey = minersNotMinedCurrentRound[i].Pubkey,
    Order = order,
    ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
    ProducedBlocks = minerInRound.ProducedBlocks,
    MissedTimeSlots = minerInRound.MissedTimeSlots.Add(1),
    ImpliedIrreversibleBlockHeight = minerInRound.ImpliedIrreversibleBlockHeight  // ADD THIS LINE
};
```

This ensures that even when Round 1 completes via NextRound without UpdateValue blocks, Round 2 miners will have their previous `ImpliedIrreversibleBlockHeight` values carried forward, allowing the LIB calculation to succeed.

**Alternative Approach**: Initialize `ImpliedIrreversibleBlockHeight` to the current `ConfirmedIrreversibleBlockHeight` when creating new rounds, ensuring miners always have a valid baseline value.

## Proof of Concept

```csharp
// Test: LIB Remains Zero When Round 1 Completes Via NextRound Without UpdateValue

[Fact]
public async Task Round2_LIB_Stuck_At_Zero_After_Round1_NextRound_Without_UpdateValue()
{
    // Setup: Initialize consensus with multiple miners
    var initialMiners = new List<string> { "miner1", "miner2", "miner3" };
    await InitializeConsensusAsync(initialMiners);
    
    // Round 1: First miner (miner1) is offline - does NOT produce UpdateValue block
    // Other miners (miner2, miner3) detect this and trigger NextRound
    
    // Simulate miner2 triggering NextRound behavior (as per protocol rules)
    var nextRoundInput = CreateNextRoundInput(currentRound: 1);
    await ConsensusContract.NextRound.SendAsync(nextRoundInput);
    
    // Verify: Round 2 started
    var round2 = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    round2.RoundNumber.ShouldBe(2);
    
    // Verify: All Round 1 miners have ImpliedIrreversibleBlockHeight = 0
    var round1 = await ConsensusContract.GetRoundInformation.CallAsync(new Int64Value { Value = 1 });
    foreach (var miner in round1.RealTimeMinersInformation)
    {
        miner.Value.ImpliedIrreversibleBlockHeight.ShouldBe(0);
    }
    
    // Round 2: miner2 produces UpdateValue block
    var updateValueInput = CreateUpdateValueInput("miner2");
    await ConsensusContract.UpdateValue.SendAsync(updateValueInput);
    
    // Verify: LIB remains stuck at 0 despite blocks being produced
    var libHeight = await ConsensusContract.GetCurrentRoundInformation.CallAsync(new Empty());
    libHeight.ConfirmedIrreversibleBlockHeight.ShouldBe(0);  // VULNERABILITY: LIB stuck at 0
    
    // Expected: LIB should progress to at least block 1
    // Actual: LIB remains at 0 because all Round 1 miners have ImpliedIrreversibleBlockHeight = 0
}
```

**Notes**

This vulnerability represents a critical design oversight in the round transition logic where the `ImpliedIrreversibleBlockHeight` field is not properly propagated during NextRound transitions. The issue is particularly severe because:

1. **Protocol-Level Mechanism**: The NextRound trigger for Round 1 when the first miner fails is a built-in protocol safety mechanism (preventing fork blocks), making this a realistic and expected scenario rather than an edge case.

2. **Genesis Initialization Gap**: The vulnerability is most exploitable during genesis/initialization when network conditions are unpredictable and the first miner is most likely to experience issues.

3. **Cascading Effect**: Once triggered, the failure persists for an entire round affecting all consensus participants and dependent systems without requiring further attacker action.

4. **Cross-Chain Impact**: The LIB mechanism is critical for cross-chain security, so this vulnerability directly compromises the safety of cross-chain asset transfers and state synchronization.

The fix is straightforward and should be implemented by ensuring `ImpliedIrreversibleBlockHeight` is copied during all round generation operations, particularly in `GenerateNextRoundInformation` method. This preserves the continuity of LIB tracking across round boundaries regardless of the consensus behavior that triggers the transition.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L206-220)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextTerm(string pubkey,
        AElfConsensusTriggerInformation triggerInformation)
    {
        var firstRoundOfNextTerm = GenerateFirstRoundOfNextTerm(pubkey, State.MiningInterval.Value);
        Assert(firstRoundOfNextTerm.RoundId != 0, "Failed to generate new round information.");
        if (firstRoundOfNextTerm.RealTimeMinersInformation.ContainsKey(pubkey))
            firstRoundOfNextTerm.RealTimeMinersInformation[pubkey].ProducedTinyBlocks = 1;

        return new AElfConsensusHeaderInformation
        {
            SenderPubkey = ByteStringHelper.FromHexString(pubkey),
            Round = firstRoundOfNextTerm,
            Behaviour = triggerInformation.Behaviour
        };
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L14-16)
```csharp
        var heights = RealTimeMinersInformation.Values.Where(i => specificPublicKeys.Contains(i.Pubkey))
            .Where(i => i.ImpliedIrreversibleBlockHeight > 0)
            .Select(i => i.ImpliedIrreversibleBlockHeight).ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L26-29)
```csharp
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
```
