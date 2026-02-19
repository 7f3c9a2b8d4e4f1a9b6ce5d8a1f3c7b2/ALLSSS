# Audit Report

## Title
Side Chain Term Number State Inconsistency Due to Missing NextTerm Processing

## Summary
Side chains fail to properly update their term number state when miner lists change. While the round data contains incremented term numbers, the global `State.CurrentTermNumber.Value` remains stale because side chains always use `NextRound` behavior instead of `NextTerm`, causing critical state variables to become inconsistent with actual round data.

## Finding Description

The vulnerability stems from an architectural mismatch in how main chains and side chains handle term transitions:

**Main chains** conditionally return `NextTerm` or `NextRound` behavior based on whether a term change is needed: [1](#0-0) 

**Side chains** unconditionally return `NextRound` behavior, with no term change logic: [2](#0-1) 

When a side chain's miner list changes (synchronized from main chain via cross-chain communication), the system generates a "first round of new term" with incremented term number: [3](#0-2) 

This generation method explicitly increments the term number: [4](#0-3) 

However, because the side chain behavior provider returns `NextRound`, the consensus command router processes this through `ProcessNextRound`: [5](#0-4) 

**Critical Issue**: `ProcessNextRound` only updates round information and round number, but never calls `TryToUpdateTermNumber`: [6](#0-5) 

In contrast, `ProcessNextTerm` explicitly updates the term number state: [7](#0-6) 

And sets critical mappings: [8](#0-7) 

## Impact Explanation

This vulnerability creates multiple state inconsistencies:

1. **Term Number Mismatch**: External callers querying the current term number receive stale values: [9](#0-8) 

2. **Validation Context Corruption**: Consensus validation uses incorrect term numbers: [10](#0-9) 

3. **Missing Historical Mappings**: Queries for miner lists by term number fail because `State.MinerListMap[N+1]` and `State.FirstRoundNumberOfEachTerm[N+1]` are never populated.

4. **Miner Statistics Not Reset**: Unlike `ProcessNextTerm` which resets statistics, `ProcessNextRound` allows new miners to inherit stale `MissedTimeSlots` and `ProducedBlocks` values.

**Severity: Medium** - This breaks protocol correctness and state integrity but does not directly enable fund theft or halt block production. It affects cross-contract data consistency and fairness of miner performance tracking on all side chains.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is automatically triggered through normal protocol operation:

**Entry Point**: When main chain miner lists change through elections, the cross-chain contract synchronizes this information to side chains: [11](#0-10) 

This requires no attacker action—it's inherent to how AElf side chains operate. Every time the main chain conducts an election that changes the miner list, all connected side chains experience this state inconsistency. The issue is deterministic and reproducible.

## Recommendation

Side chains should use `NextTerm` behavior when their miner list changes, or alternatively, `ProcessNextRound` should be enhanced to detect when the incoming round has a term change and perform the necessary state updates.

**Option 1**: Modify `SideChainConsensusBehaviourProvider` to check for miner list changes and return `NextTerm` when appropriate.

**Option 2**: Enhance `ProcessNextRound` to detect term changes in the incoming round data and call the same state update logic as `ProcessNextTerm`.

**Option 3**: Create a unified term transition handler that both `ProcessNextRound` and `ProcessNextTerm` can invoke to ensure consistent state updates.

The fix should ensure:
- `State.CurrentTermNumber.Value` is updated to match the round's term number
- `State.FirstRoundNumberOfEachTerm[termNumber]` is populated
- `State.MinerListMap[termNumber]` is updated via `SetMinerList`
- Miner statistics are properly reset for new term

## Proof of Concept

A test demonstrating this vulnerability would:
1. Set up a side chain with initial miner list
2. Simulate main chain miner list change via `UpdateInformationFromCrossChain`
3. Trigger round generation which creates a round with incremented term number
4. Observe that after processing, `State.Rounds[roundNumber].TermNumber` equals N+1
5. Observe that `GetCurrentTermNumber()` still returns N
6. Verify that `State.MinerListMap[N+1]` is null
7. Verify that `State.FirstRoundNumberOfEachTerm[N+1]` is not set

This demonstrates the state inconsistency where round data and global state disagree on the current term number.

## Notes

This is a protocol-level correctness issue affecting all AElf side chains. While it doesn't directly compromise funds or halt consensus, it creates technical debt and incorrect data propagation that could cause integration issues for contracts or services relying on accurate term number information. The issue is particularly problematic because it affects a fundamental consensus state variable that other parts of the system may depend on for correct operation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L16-23)
```csharp
        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-294)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L362-365)
```csharp
    public override Int64Value GetCurrentTermNumber(Empty input)
    {
        return new Int64Value { Value = State.CurrentTermNumber.Value };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L40-42)
```csharp
        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L37-40)
```csharp
            case NextRoundInput nextRoundInput:
                randomNumber = nextRoundInput.RandomNumber;
                ProcessNextRound(nextRoundInput);
                break;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L156-158)
```csharp
        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L173-174)
```csharp
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L190-193)
```csharp
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-38)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
```
