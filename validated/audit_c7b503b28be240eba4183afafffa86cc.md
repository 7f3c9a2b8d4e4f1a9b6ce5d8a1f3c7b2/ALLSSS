# Audit Report

## Title
Side Chain Validator Permanent Control Through Cross-Chain Indexing Censorship

## Summary
Side chain validators have mis-scoped authority over cross-chain indexing operations, which is the sole mechanism for updating their own validator set. This creates a structural vulnerability where colluding validators can maintain indefinite control by refusing to index parent chain consensus data containing validator updates.

## Finding Description

This vulnerability represents a **privilege scoping issue** in AElf's side chain architecture where validators control the mechanism designed to replace them.

**Technical Flow:**

Side chains lack autonomous validator rotation. They depend entirely on cross-chain indexing to synchronize validator updates from the parent chain. However, the cross-chain indexing process itself requires current validator participation, creating a circular dependency. [1](#0-0) 

Side chains never trigger term transitions - they always return `NextRound`, never `NextTerm`. [2](#0-1) 

Side chains do not initialize the Election Contract, removing the election-based validator replacement mechanism available on main chains. [3](#0-2) 

The ONLY mechanism for side chains to update validators is through `IsMainChainMinerListChanged`, which depends on `State.MainChainCurrentMinerList`. [4](#0-3) 

This state variable is exclusively updated by `UpdateInformationFromCrossChain`, which can only be called by the CrossChain contract and only on side chains. [5](#0-4) 

The CrossChain contract only calls `UpdateConsensusInformation` when indexing the last parent chain block containing consensus extra data. [6](#0-5) 

Both `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal` require the caller to be a current miner via `AssertAddressIsCurrentMiner`. [7](#0-6) 

The miner verification delegates to the consensus contract's `CheckCrossChainIndexingPermission`. [8](#0-7) 

This verifies active miner status, closing the circular dependency.

**Why existing protections fail:** [9](#0-8) 

`RecordCandidateReplacement` requires Election Contract sender, which doesn't exist on side chains. [10](#0-9) 

Evil node replacement logic is explicitly main-chain only. [11](#0-10) 

Main chain validator replacement through elections doesn't apply to side chains.

## Impact Explanation

**Critical severity** is justified because:

1. **Permanent Validator Control**: Colluding validators maintain indefinite authority over block production, transaction inclusion, and side chain governance. They can censor transactions, extract MEV, or hold the chain hostage.

2. **Cross-Chain Isolation**: The side chain becomes permanently disconnected from parent chain governance and security updates. Parent chain validator changes cannot propagate to the side chain.

3. **No Non-Destructive Recovery**: [12](#0-11) 
The parent chain's only recourse is `DisposeSideChain`, which terminates the chain rather than replacing validators. This destroys user access to assets rather than recovering control.

4. **Trust Model Violation**: The fundamental security assumption that parent chains govern side chains is broken. Side chains can become autonomous entities controlled by their validators.

All side chain users, dApp developers, and parent chain stakeholders expecting governance authority are affected.

## Likelihood Explanation

**Attack Feasibility:**
- **Preconditions**: Requires validator majority collusion (≥ 51% of validators)
- **Complexity**: Very low - validators simply abstain from calling `ProposeCrossChainIndexing` or `ReleaseCrossChainIndexingProposal` for parent chain consensus data
- **Detection**: Difficult to distinguish from operational issues (network failures, synchronization delays)

**Realistic Scenarios:**
- Side chains with small validator sets (3-7 validators) are especially vulnerable
- Economic incentives could drive capture (extracting value from the side chain exceeds honest operation rewards)
- Validators could claim "technical difficulties" while censoring parent chain updates
- More likely during contentious validator changes where current validators stand to lose their positions

While this requires validator collusion, it represents a **structural weakness** where proper privilege separation is not maintained. The attack is passive (abstention) rather than active, requiring no complex exploit sequences.

## Recommendation

Implement a multi-layered approach to separate cross-chain indexing privileges from validator replacement:

1. **Emergency Override Mechanism**: Allow the `CrossChainIndexingController` (parent chain parliament organization) to directly propose and force-execute cross-chain indexing without requiring current miner approval. This provides a backup path when validators refuse to cooperate.

2. **Automated Watchdog**: Implement automatic detection of cross-chain indexing stalls. If parent chain consensus data hasn't been indexed for N blocks beyond normal thresholds, trigger emergency procedures.

3. **Split Privileges**: Separate the permission to propose cross-chain indexing from the permission to release it. Allow a broader set of actors (e.g., any staker, relayer network) to propose, while keeping release authority with miners. This increases transparency and makes censorship more difficult.

4. **Validator Rotation Timer**: Implement an absolute time-based fallback where if no parent chain validator updates have been indexed within a maximum period, the side chain automatically adopts a default validator set or enters a safe mode requiring parent chain intervention.

## Proof of Concept

The vulnerability exists at the architectural level. A PoC would demonstrate:

1. Deploy a side chain with validators V1, V2, V3
2. Parent chain updates validators to V4, V5, V6 through normal election process
3. Parent chain consensus data contains the new validator set
4. Side chain validators V1, V2, V3 refuse to call `ProposeCrossChainIndexing` or `ReleaseCrossChainIndexingProposal` for this parent chain data
5. Side chain continues operating indefinitely with old validators V1, V2, V3
6. Parent chain can only call `DisposeSideChain` to terminate (not replace) the validators

The core issue is that no amount of parent chain actions can force the side chain validators to index the parent chain data that would replace them, since they control the indexing mechanism itself.

## Notes

This is a **design-level vulnerability** rather than an exploitable code bug. It violates the principle of separation of concerns by granting validators authority over the mechanism that should be able to replace them. While AElf side chains are permissioned/consortium chains where validators are expected to be trusted, the architecture should still maintain proper privilege separation to prevent validator capture scenarios. The existence of `DisposeSideChain` as the only recovery mechanism suggests this scenario was not the intended trust model.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L20-23)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L37-41)
```csharp
        if (input.IsTermStayOne || input.IsSideChain)
        {
            State.IsMainChain.Value = false;
            return new Empty();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L131-135)
```csharp
    public override Empty RecordCandidateReplacement(RecordCandidateReplacementInput input)
    {
        Assert(Context.Sender == State.ElectionContract.Value,
            "Only Election Contract can record candidate replacement information.");

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-343)
```csharp
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }

                isMinerListChanged = true;
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L25-28)
```csharp
    public override BoolValue CheckCrossChainIndexingPermission(Address input)
    {
        return IsCurrentMiner(input);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-64)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-788)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L222-242)
```csharp
    public override Int32Value DisposeSideChain(Int32Value input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var chainId = input.Value;
        var info = State.SideChainInfo[chainId];
        Assert(info != null, "Side chain not found.");
        Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");

        if (TryGetIndexingProposal(chainId, out _))
            ResetChainIndexingProposal(chainId);

        UnlockTokenAndResource(info);
        info.SideChainStatus = SideChainStatus.Terminated;
        State.SideChainInfo[chainId] = info;
        Context.Fire(new Disposed
        {
            ChainId = chainId
        });
        return new Int32Value { Value = chainId };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-302)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
    }

    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```
