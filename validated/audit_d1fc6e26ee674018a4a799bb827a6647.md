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

The total vote count in `CheckEnoughVoteAndApprovals()` should be filtered by current membership to maintain consistency with approval/rejection/abstention counting. Modify the vote threshold check to:

```csharp
var totalVoteCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
                     proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
                     proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
var isVoteThresholdReached = totalVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This ensures that only votes from current members count toward the `MinimalVoteThreshold`, maintaining the governance invariant.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Bypass_Through_RemovedMembers_Test()
{
    // Setup: Organization with 6 members, MinimalVoteThreshold=6, MinimalApprovalThreshold=4
    var minimalApprovalThreshold = 4;
    var minimalVoteThreshold = 6;
    var maximalAbstentionThreshold = 0;
    var maximalRejectionThreshold = 0;
    
    // Create organization with 6 members
    var member4 = Accounts[4].Address;
    var member5 = Accounts[5].Address;
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3, DefaultSender, member4, member5 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = minimalApprovalThreshold,
            MinimalVoteThreshold = minimalVoteThreshold,
            MaximalAbstentionThreshold = maximalAbstentionThreshold,
            MaximalRejectionThreshold = maximalRejectionThreshold
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }
        }
    };
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    
    // Create proposal
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress.Output);
    await TransferToOrganizationAddressAsync(organizationAddress.Output);
    
    // Step 1: Get 4 approvals from current members (meets MinimalApprovalThreshold)
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    await ApproveAsync(DefaultSenderKeyPair, proposalId);
    
    // Step 2: Get 2 additional votes from members who will be removed
    await ApproveAsync(Accounts[4].KeyPair, proposalId);
    await ApproveAsync(Accounts[5].KeyPair, proposalId);
    
    // Verify proposal is ready to release (6 votes meets MinimalVoteThreshold)
    var proposalBefore = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalBefore.ToBeReleased.ShouldBeTrue();
    
    // Step 3: Remove the 2 members through governance action
    var orgStub = GetAssociationContractTester(DefaultSenderKeyPair);
    var removeProposal1 = await CreateAssociationProposalAsync(Reviewer1KeyPair, member4, 
        nameof(orgStub.RemoveMember), organizationAddress.Output);
    await ApproveAsync(Reviewer1KeyPair, removeProposal1);
    await orgStub.Release.SendAsync(removeProposal1);
    
    var removeProposal2 = await CreateAssociationProposalAsync(Reviewer1KeyPair, member5,
        nameof(orgStub.RemoveMember), organizationAddress.Output);
    await ApproveAsync(Reviewer1KeyPair, removeProposal2);
    await orgStub.Release.SendAsync(removeProposal2);
    
    // Step 4: Proposal should NOT be releasable (only 4 current members voted)
    // But due to the bug, it still passes because total vote count includes removed members
    var proposalAfter = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    
    // VULNERABILITY: Proposal is still marked as ToBeReleased despite only 4 current members voting
    proposalAfter.ToBeReleased.ShouldBeTrue(); // This demonstrates the bypass
    
    // The proposal can be released with only 4 current member votes instead of required 6
    var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
    var result = await associationContractStub.Release.SendAsync(proposalId);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

## Notes

This vulnerability demonstrates a fundamental inconsistency in vote counting logic where the system checks different criteria for individual vote types (approval/rejection/abstention) versus total participation. The `MinimalVoteThreshold` parameter is designed to ensure adequate participation from current organization members, but the implementation allows stale votes from removed members to count toward this threshold while not counting toward approval/rejection/abstention thresholds. This creates a governance bypass where the intended participation requirements can be circumvented through strategic member removal after voting.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L130-131)
```csharp
        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L188-188)
```csharp
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-44)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }

    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
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
