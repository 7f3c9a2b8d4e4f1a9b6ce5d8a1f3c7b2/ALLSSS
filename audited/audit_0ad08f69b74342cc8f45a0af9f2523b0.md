# Audit Report

## Title
Inconsistent Vote Counting Allows MinimalVoteThreshold Bypass Through Stale Votes from Removed Members

## Summary
The Association contract contains a critical vote counting inconsistency where approval/rejection/abstention counts filter by current membership, but the total vote count used for `MinimalVoteThreshold` validation does not. This allows proposals to pass using stale votes from removed members, undermining governance participation requirements.

## Finding Description

The vulnerability exists in the threshold validation logic when releasing proposals. When members vote, their addresses are recorded in the proposal's vote lists [1](#0-0) . Members can later be removed from the organization through governance action [2](#0-1) .

The critical inconsistency occurs in `CheckEnoughVoteAndApprovals()`:

**Approval counting (filtered)**: The approval count filters votes by current membership only [3](#0-2) 

**Total vote counting (NOT filtered)**: The total vote count includes ALL votes regardless of current membership [4](#0-3) 

The same filtering inconsistency exists for rejection and abstention counts, which also filter by current membership [5](#0-4) .

This inconsistency is invoked during proposal release [6](#0-5) .

## Impact Explanation

**High Severity** - This directly undermines the `MinimalVoteThreshold` governance control, which is a critical security invariant for ensuring adequate participation. Organizations using strict participation requirements can have proposals pass with insufficient current member participation.

**Concrete scenario:**
- Organization with 10 members sets `MinimalVoteThreshold = 6` and `MinimalApprovalThreshold = 4`
- Proposal receives 4 approvals from current members (meets approval threshold)
- 2 additional members vote (any type)
- Organization removes those 2 members via governance
- Proposal passes with only 4 current member votes, bypassing the intended 6-vote minimum

The vulnerability breaks the governance guarantee that at least `MinimalVoteThreshold` current members must participate in a proposal decision.

## Likelihood Explanation

**Medium-High** - While member removal requires governance action (organization address must be sender), this can realistically occur through:

1. **Collusion**: Coordinated members vote then remove themselves
2. **Normal Operations**: Legitimate member removal (reorganization, inactive members) after votes are cast unintentionally triggers the vulnerability

The execution path uses standard contract operations with no special privileges beyond normal organizational governance. The inconsistency is subtle and would not be detected during routine operations.

## Recommendation

Modify `CheckEnoughVoteAndApprovals()` to filter the total vote count by current membership, ensuring consistency with approval/rejection/abstention counting:

Change line 56 in `Association_Helper.cs` from:
```csharp
proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count()
```

To:
```csharp
proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
    .Count(organization.OrganizationMemberList.Contains)
```

This ensures all vote counting logic consistently validates against current organization membership.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Bypass_Via_Removed_Members()
{
    // Setup: Organization with 10 members, MinimalVoteThreshold=6, MinimalApprovalThreshold=4
    var organizationMembers = new[] { Reviewer1, Reviewer2, Reviewer3, Reviewer4, 
                                     Reviewer5, Reviewer6, Reviewer7, Reviewer8, 
                                     Reviewer9, Reviewer10 };
    
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold: 4, 
        minimalVoteThreshold: 6,
        maximalAbstentionThreshold: 2,
        maximalRejectionThreshold: 2,
        Reviewer1,
        organizationMembers);
    
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 1: Get 4 approvals from members 1-4 (meets approval threshold)
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    await ApproveAsync(Reviewer4KeyPair, proposalId);
    
    // Step 2: Get 2 additional votes from members 5-6 (reaches 6 total votes)
    await ApproveAsync(Reviewer5KeyPair, proposalId);
    await ApproveAsync(Reviewer6KeyPair, proposalId);
    
    // Step 3: Remove members 5 and 6 via governance
    var organizationStub = GetAssociationContractTester(organizationAddress);
    await organizationStub.RemoveMember.SendAsync(Reviewer5);
    await organizationStub.RemoveMember.SendAsync(Reviewer6);
    
    // Step 4: Release proposal - should fail with only 4 current member votes
    // but passes due to vulnerability (counts removed members' votes toward MinimalVoteThreshold)
    var result = await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(proposalId);
    
    // BUG: Proposal passes even though only 4 out of 8 current members voted
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Expected: Should require 6 votes from current 8 members, but only 4 current members voted
    // Actual: Passes because removed members' votes still count toward MinimalVoteThreshold
}
```

**Notes:**
- The vulnerability is confirmed by examining the exact code paths
- All vote counting methods filter by current membership EXCEPT the total vote count in `MinimalVoteThreshold` validation
- This creates a logical inconsistency exploitable through normal governance operations
- Organizations cannot trust their `MinimalVoteThreshold` settings to enforce actual participation requirements

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L123-141)
```csharp
    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-201)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L266-280)
```csharp
    public override Empty RemoveMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input);
        Assert(removeResult, "Remove member failed.");
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberRemoved
        {
            OrganizationAddress = Context.Sender,
            Member = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-45)
```csharp
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
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-49)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-57)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```
