# Audit Report

## Title
Side Chain Miner List Synchronization Delay Creates Conflict of Interest Allowing Replaced Miners to Maintain Control

## Summary
The side chain consensus mechanism always uses NextRound behavior, requiring miner list updates to be synchronized from the main chain through a governance-gated cross-chain indexing process. This creates a critical conflict of interest where miners replaced on the main chain (potentially for malicious behavior) must approve their own removal from the side chain, allowing them to maintain unauthorized control during the synchronization delay.

## Finding Description

The vulnerability exists in the asymmetric consensus behavior between main chain and side chains. The main chain can immediately transition to a new term with updated miners, but side chains always use NextRound behavior and rely on cross-chain indexing to learn about miner changes. [1](#0-0) 

Side chain miner list updates depend on checking if the main chain miner list has changed during round generation: [2](#0-1) [3](#0-2) 

The `State.MainChainCurrentMinerList.Value` is only updated when the cross-chain contract invokes `UpdateInformationFromCrossChain`: [4](#0-3) 

However, reaching this update requires a multi-step governance process controlled by the current side chain miners (who are the OLD miners being replaced):

1. A miner must propose cross-chain indexing (only miners have permission): [5](#0-4) [6](#0-5) 

2. Parliament must approve the proposal (parliament members = current side chain miners = OLD miners): [7](#0-6) 

3. A miner must release the proposal: [8](#0-7) 

The proposal has a 120-second expiration period: [9](#0-8) 

The critical flaw is that the OLD miners control every step of the approval process (propose, vote, release) while they are the ones being replaced. If they were removed from the main chain for malicious behavior, they have every incentive to delay or block their own replacement on the side chain.

## Impact Explanation

**Consensus Integrity Violation**: The fundamental security assumption of AElf's cross-chain architecture is that parent and side chains share the same consensus participant set. This synchronization delay breaks that invariant, creating a period where the side chain operates with unauthorized miners.

**Conflict of Interest**: Miners who have been replaced on the main chain (potentially marked as evil miners for malicious behavior) must approve their own removal from the side chain. This creates an inherent conflict of interest where:
- They control 100% of voting power on the side chain initially
- They can vote against proposals or abstain
- They control when (or if) to call `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal`
- They continue earning side chain rewards during the delay

**Potential for Indefinite Control**: Since old miners control the governance process, they can:
- Refuse to propose cross-chain indexing
- Vote against proposals (requiring only 33.33% to block with the 66.67% approval threshold)
- Let proposals expire repeatedly (120-second window)
- Maintain control indefinitely if they constitute a governance majority

**Cross-Chain State Divergence**: The main chain recognizes new miners as authoritative while the side chain operates with old miners, creating inconsistent security assumptions that affect cross-chain transaction validity and merkle proof verification.

This affects core protocol integrity on every main chain term transition, which occurs regularly (typically every few days), making this a critical severity issue.

## Likelihood Explanation

**Automatic Trigger**: The vulnerability manifests automatically whenever the main chain transitions to a new term through its election mechanism. No special attacker capabilities are required—this is inherent in the protocol design.

**No Forcing Mechanism**: There is no automatic or time-based mechanism to force the side chain miner list update. The entire process depends on the cooperation of the miners being replaced.

**Realistic Exploitation**: Old miners who were replaced for poor performance or malicious behavior have strong incentives to:
- Delay the update to continue earning rewards
- Execute attacks on the side chain while they still have control
- Coordinate to block governance approval (only need >33.33% to block)

**High Frequency**: Main chain term changes occur regularly based on the configured period, making this a recurring issue rather than a one-time edge case.

The combination of automatic triggering, lack of forcing mechanism, and strong attacker incentives makes this vulnerability highly likely to be exploited in practice.

## Recommendation

Implement a time-based forcing mechanism that bypasses the governance requirement after a reasonable delay. Possible approaches:

1. **Automatic Synchronization Window**: After detecting a main chain term change, allow a grace period (e.g., 2-4 hours) for governance approval. If the update hasn't been processed by then, automatically update the side chain miner list without requiring governance approval.

2. **Emergency Override**: Allow a trusted contract or multi-sig (separate from current miners) to force miner list synchronization if the delay exceeds a threshold.

3. **Split Authority**: Separate the authority to propose/release cross-chain indexing from the authority to approve it, ensuring old miners cannot unilaterally block their replacement.

4. **Main Chain Authority**: Allow the main chain consensus contract to directly push miner list updates to side chains through a trusted cross-chain message, bypassing side chain governance.

The key principle is to eliminate the conflict of interest where miners being replaced control their own replacement process.

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. **Setup**: Side chain operates with miners {A, B, C}
2. **Main Chain Term Transition**: Main chain replaces miners, new set = {D, E, F}
3. **Side Chain Continues**: Side chain still uses {A, B, C} because `State.MainChainCurrentMinerList.Value` hasn't been updated
4. **Governance Control**: Miners {A, B, C} control ProposeCrossChainIndexing and Parliament approval
5. **Exploitation**: Miners {A, B, C} can:
   - Delay calling `ProposeCrossChainIndexing`
   - Vote against the proposal (need only 34% to block)
   - Refuse to call `ReleaseCrossChainIndexingProposal`
   - Let proposals expire and repeat the cycle
6. **Result**: Old miners maintain unauthorized control indefinitely

The proof of concept would require deploying a test network with main chain and side chain, transitioning the main chain term, and observing that old miners continue producing side chain blocks until they voluntarily complete the cross-chain indexing governance process.

## Notes

This is a fundamental design flaw in the cross-chain consensus synchronization mechanism. While the governance requirement was likely intended to provide security and oversight, it inadvertently creates a worse security vulnerability by giving replaced miners control over their own removal. The 120-second expiration period suggests the designers expected quick processing, but failed to account for the conflict of interest when miners are being replaced.

### Citations

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L349-354)
```csharp
    private bool IsMainChainMinerListChanged(Round currentRound)
    {
        return State.MainChainCurrentMinerList.Value.Pubkeys.Any() &&
               GetMinerListHash(currentRound.RealTimeMinersInformation.Keys) !=
               GetMinerListHash(State.MainChainCurrentMinerList.Value.Pubkeys.Select(p => p.ToHex()));
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-291)
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
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-302)
```csharp
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L613-623)
```csharp
        State.ParliamentContract.CreateOrganizationBySystemContract.Send(
            new CreateOrganizationBySystemContractInput
            {
                OrganizationCreationInput = new Parliament.CreateOrganizationInput
                {
                    ProposalReleaseThreshold = proposalReleaseThreshold,
                    ProposerAuthorityRequired = true,
                    ParliamentMemberProposingAllowed = true
                },
                OrganizationAddressFeedbackMethod = nameof(SetInitialIndexingControllerAddress)
            });
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs (L5-5)
```csharp
    private const int CrossChainIndexingProposalExpirationTimePeriod = 120;
```
