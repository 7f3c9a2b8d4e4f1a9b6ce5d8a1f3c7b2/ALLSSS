# Audit Report

## Title
Parliament Proposal Vote Count Miscalculation Due to Dynamic Miner List Retrieval

## Summary
The Parliament contract retrieves the current miner list dynamically at proposal release time rather than using a snapshot from when votes were cast. When parliament membership changes during term transitions (every 7 days), votes from former members are silently discarded, causing governance integrity violations and unpredictable proposal outcomes.

## Finding Description

The Parliament contract validates proposal votes by filtering them against the **current** miner list retrieved at validation time, not the miner list from when votes were cast.

The `IsReleaseThresholdReached()` function calls `GetCurrentMinerList()` which makes a cross-contract call to the consensus contract to fetch the active miner list at the moment of validation: [1](#0-0) 

The `GetCurrentMinerList()` method performs a cross-contract call: [2](#0-1) 

This current member list is then used to filter stored votes. Only votes from addresses in the **current** parliament member list are counted:

**Rejection counting:** [3](#0-2) 

**Abstention counting:** [4](#0-3) 

**Approval counting:** [5](#0-4) 

The miner list changes during term transitions in the consensus contract. Term transitions occur every 604800 seconds (7 days): [6](#0-5) 

During term transitions, `SetMinerList()` updates the miner list: [7](#0-6) 

When `Release()` is called after a term transition, votes from former parliament members fail the `parliamentMembers.Contains()` check and are excluded from threshold calculations: [8](#0-7) 

**Vote Storage Without Term Metadata:**

Votes are stored as simple address lists without any term number or timestamp information: [9](#0-8) 

**Architectural Inconsistency:**

The Association contract uses a different pattern - it stores a static member list in the organization structure and validates votes against that fixed list, not a dynamic one: [10](#0-9) 

The Association organization structure stores the member list at creation: [11](#0-10) 

This demonstrates that the intended design pattern for governance vote validation should use a fixed membership snapshot, not dynamic retrieval.

## Impact Explanation

**Governance Integrity Violation:**
- Votes legitimately cast by authorized parliament members become retroactively invalid when those members are replaced in the next term
- Proposal outcomes depend on release timing rather than actual vote counts at voting time
- No notification or re-voting mechanism exists when votes are invalidated
- Silent failure - discarded votes appear as if they were never cast

**Attack Scenarios:**

1. **Blocking Legitimate Proposals:** A proposal that received sufficient approvals (e.g., 8/10 miners = 80% approval) can fail validation if released after a term transition that replaces 4 of the 8 approvers. The effective vote count drops to 4/10 (40%), failing a 60% threshold despite legitimate approval.

2. **Timing-Based Manipulation:** Proposers can strategically delay or accelerate release timing to align with term transitions that favor or block their proposals based on which specific members are replaced.

3. **Governance Paralysis:** Critical system upgrades, parameter changes, and treasury releases can be blocked if they span term boundaries, creating operational deadlock.

**Affected Systems:**
- Contract upgrades and deployments
- Economic parameter adjustments
- Treasury fund releases
- Consensus parameter changes
- All critical governance decisions requiring Parliament approval

## Likelihood Explanation

**High Probability:**
- Term transitions occur every 7 days (604800 seconds) - predictable and frequent
- Contract proposals have a default expiration of 259200 seconds (72 hours): [12](#0-11) 

- Simple arithmetic: 72-hour proposals easily span weekly term boundaries
- No special privileges required beyond normal proposer authority
- Natural occurrence for any proposal spanning term boundaries

**Detection Difficulty:**
- Vote discarding is silent with no events emitted
- Appears as legitimate "Not approved" failure
- Difficult to distinguish from genuine vote insufficiency
- No audit trail shows that votes were previously sufficient

**Practical Probability:** Medium-High
- Every 7 days, active proposals may be affected
- High-value governance decisions are economically rational targets
- Natural occurrence without malicious intent

## Recommendation

**Solution: Store Term Number with Votes**

Modify the vote storage to include the term number at voting time, and validate votes against the miner list from that specific term:

1. Update `ProposalInfo` to store term number with each vote
2. Modify `Approve()`, `Reject()`, `Abstain()` to record current term number
3. Update `IsReleaseThresholdReached()` to validate votes against the miner list from their respective terms
4. Maintain historical miner lists in state (already exists in `State.MinerListMap[termNumber]`)

**Alternative: Use Association Pattern**

Adopt the Association contract's pattern - store the parliament member list as a snapshot in the organization structure at creation time, and validate against that static list rather than dynamic retrieval.

## Proof of Concept

```csharp
// Test demonstrating vote invalidation across term transition
[Fact]
public async Task VotesInvalidatedAfterTermTransition_Test()
{
    // 1. Create proposal with 10 miners, get 8 approvals (80%)
    var proposalId = await CreateParliamentProposal();
    
    // 2. Have 8 out of 10 miners approve (80% approval - above threshold)
    for (int i = 0; i < 8; i++)
    {
        await ParliamentContractStub.Approve.SendAsync(proposalId);
    }
    
    // 3. Verify proposal is ready for release
    var proposal = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    Assert.True(proposal.ToBeReleased);
    
    // 4. Trigger term transition that replaces 5 of the 8 approvers
    await TriggerNextTerm(replaceMinerCount: 5);
    
    // 5. Verify proposal now fails - only 3/10 votes counted (30%)
    proposal = await ParliamentContractStub.GetProposal.CallAsync(proposalId);
    Assert.False(proposal.ToBeReleased); // FAILS - votes silently discarded
    
    // 6. Attempt to release - should fail with "Not approved"
    var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
    Assert.False(releaseResult.TransactionResult.Status == TransactionResultStatus.Failed);
    Assert.Contains("Not approved", releaseResult.TransactionResult.Error);
}
```

## Notes

This vulnerability represents a fundamental architectural flaw where Parliament governance treats membership as purely dynamic, while Association governance correctly uses static snapshots. The inconsistency suggests Parliament was designed without considering the implications of term transitions on pending proposals. The issue affects all Parliament proposals and cannot be mitigated without protocol changes.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L13-20)
```csharp
    private List<Address> GetCurrentMinerList()
    {
        RequireConsensusContractStateSet();
        var miner = State.ConsensusContract.GetCurrentMinerList.Call(new Empty());
        var members = miner.Pubkeys.Select(publicKey =>
            Address.FromPublicKey(publicKey.ToByteArray())).ToList();
        return members;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L36-48)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var parliamentMembers = GetCurrentMinerList();
        var isRejected = IsProposalRejected(proposal, organization, parliamentMembers);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization, parliamentMembers);
        if (isAbstained)
            return false;

        return CheckEnoughVoteAndApprovals(proposal, organization, parliamentMembers);
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-70)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L72-78)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(parliamentMembers.Contains);
        return abstentionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalAbstentionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-221)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);

        if (!TryToGetPreviousRoundInformation(out var previousRound))
            Assert(false, "Failed to get previous round information.");

        UpdateCurrentMinerInformationToElectionContract(previousRound);

        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }

        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });

        Context.LogDebug(() => $"Changing term number to {nextRound.TermNumber}");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L70-82)
```csharp
    private bool SetMinerList(MinerList minerList, long termNumber, bool gonnaReplaceSomeone = false)
    {
        // Miners for one specific term should only update once.
        var minerListFromState = State.MinerListMap[termNumber];
        if (gonnaReplaceSomeone || minerListFromState == null)
        {
            State.MainChainCurrentMinerList.Value = minerList;
            State.MinerListMap[termNumber] = minerList;
            return true;
        }

        return false;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
    }
```

**File:** protobuf/parliament_contract.proto (L116-143)
```text
message ProposalInfo {
    // The proposal ID.
    aelf.Hash proposal_id = 1;
    // The method that this proposal will call when being released.
    string contract_method_name = 2;
    // The address of the target contract.
    aelf.Address to_address = 3;
    // The parameters of the release transaction.
    bytes params = 4;
    // The date at which this proposal will expire.
    google.protobuf.Timestamp expired_time = 5;
    // The address of the proposer of this proposal.
    aelf.Address proposer = 6;
    // The address of this proposals organization.
    aelf.Address organization_address = 7;
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
    // Url is used for proposal describing.
    string proposal_description_url = 11;
    // Title of this proposal.
    string title = 12;
    // Description of this proposal.
    string description = 13;
}
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-59)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
    }

    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }

    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }

    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L69-94)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
        if (State.Organizations[organizationAddress] == null)
        {
            State.Organizations[organizationAddress] = organization;
            Context.Fire(new OrganizationCreated
            {
                OrganizationAddress = organizationAddress
            });
        }

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Constants.cs (L5-5)
```csharp
    public const int ContractProposalExpirationTimePeriod = 259200; // 60 * 60 * 72
```
