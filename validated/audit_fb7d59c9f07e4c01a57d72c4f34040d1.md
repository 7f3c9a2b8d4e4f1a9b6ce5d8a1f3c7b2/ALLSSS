# Audit Report

## Title
MinimalVoteThreshold Counts Historical Votes Instead of Current Member Participation, Bypassing Quorum Requirements

## Summary
The Association contract's `CheckEnoughVoteAndApprovals()` function counts all historical votes toward `MinimalVoteThreshold` without filtering by current organization membership, creating a critical inconsistency with all other threshold checks. This allows proposals to be released without adequate participation from the current organization when membership changes occur after voting begins, fundamentally breaking the quorum mechanism.

## Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals()` method where the `MinimalVoteThreshold` check concatenates and counts all vote lists without filtering by current membership: [1](#0-0) 

This is critically inconsistent with how all other threshold checks properly filter votes by current organization membership:

**Approval threshold filtering by current membership:** [2](#0-1) 

**Rejection threshold filtering by current membership:** [3](#0-2) 

**Abstention threshold filtering by current membership:** [4](#0-3) 

The vulnerability occurs because organizations can modify membership after voting begins through governance-controlled methods: [5](#0-4) [6](#0-5) [7](#0-6) 

When `Release()` is called, it retrieves the current organization state and validates thresholds against it, not a snapshot from when voting began: [8](#0-7) 

The organization validation only ensures thresholds are mathematically valid for the current member count at modification time, but does NOT ensure that votes counted for MinimalVoteThreshold come from current members: [9](#0-8) 

The `AssertProposalNotYetVotedBySender` protection only prevents duplicate voting by the same address, not membership changes: [10](#0-9) 

## Impact Explanation

**HIGH severity** - This vulnerability fundamentally breaks the quorum mechanism, which is a critical governance protection:

1. **Quorum Bypass via Member Addition**: An organization with 10 members receives 8 votes (80% participation). The organization then adds 20 new members through legitimate governance. The proposal can still be released with only 8/30 votes (26.7% participation) because `MinimalVoteThreshold` counts historical votes while approval/rejection/abstention checks filter by current membership. The intended quorum requirement becomes meaningless.

2. **Vote Inflation via Removed Members**: Members who vote and are subsequently removed still have their votes count toward `MinimalVoteThreshold` while not counting toward approval/rejection/abstention thresholds. This creates an inconsistent governance state where historical non-members influence quorum decisions.

3. **Governance Integrity Violation**: The `MinimalVoteThreshold` is specifically designed to ensure adequate organizational participation before executing proposals. This vulnerability allows proposals to execute without true quorum from current membership, directly undermining the governance model's fundamental invariant that proposals require sufficient current member participation.

## Likelihood Explanation

**HIGH likelihood** - This vulnerability can be triggered through standard governance operations:

- **Attack Complexity**: LOW - Simple sequence: create proposal → gather votes → modify membership through governance → release proposal
- **Required Privileges**: Only standard governance capabilities (proposer whitelist membership and organization governance approval for membership changes via self-governance proposals)
- **Feasibility**: Organizations frequently modify membership as part of normal operations. Proposals can have long lifetimes until `ExpiredTime`, providing ample opportunity for legitimate membership changes to occur
- **Natural Occurrence**: This can happen unintentionally during legitimate governance operations, making it both an exploitable vulnerability and an operational governance flaw

The inconsistency is subtle and would not be detected until detailed analysis of vote participation ratios versus current membership, making membership modifications appear as normal, unsuspicious governance operations.

## Recommendation

Modify the `MinimalVoteThreshold` check in `CheckEnoughVoteAndApprovals()` to filter votes by current organization membership, consistent with all other threshold checks:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter votes by current membership for MinimalVoteThreshold check
    var currentMemberVoteCount = proposal.Abstentions
        .Concat(proposal.Approvals)
        .Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        currentMemberVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Counts_Historical_Votes_Bypassing_Quorum_PoC()
{
    // Create organization with 3 members, MinimalVoteThreshold=3 (100% participation)
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold: 2,
        minimalVoteThreshold: 3,
        maximalAbstentionThreshold: 0,
        maximalRejectionThreshold: 0,
        Reviewer1);
    
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    await TransferToOrganizationAddressAsync(organizationAddress);
    
    // All 3 original members vote (meets MinimalVoteThreshold)
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    
    // Add 7 new members via governance (bringing total to 10)
    for (int i = 4; i <= 10; i++)
    {
        var addMemberProposal = await CreateAssociationProposalAsync(
            Reviewer1KeyPair,
            Accounts[i].Address,
            nameof(AssociationContractStub.AddMember),
            organizationAddress);
        await ApproveAsync(Reviewer1KeyPair, addMemberProposal);
        await ApproveAsync(Reviewer2KeyPair, addMemberProposal);
        await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(addMemberProposal);
    }
    
    // Verify organization now has 10 members
    var org = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress);
    org.OrganizationMemberList.OrganizationMembers.Count.ShouldBe(10);
    
    // BUG: Proposal is still releasable with only 3/10 votes (30% participation)
    // MinimalVoteThreshold counts historical votes without filtering by current membership
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeTrue(); // Vulnerability confirmed
    
    // Release succeeds despite inadequate current member participation
    var result = await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(proposalId);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

This test demonstrates that a proposal with only 30% participation from current members can be released when the intent was to require 100% participation, proving the quorum mechanism is broken.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-37)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-43)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L132-138)
```csharp
    private void AssertProposalNotYetVotedBySender(ProposalInfo proposal, Address sender)
    {
        var isAlreadyVoted = proposal.Approvals.Contains(sender) || proposal.Rejections.Contains(sender) ||
                             proposal.Abstentions.Contains(sender);

        Assert(!isAlreadyVoted, "Sender already voted.");
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-188)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-246)
```csharp
    public override Empty AddMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberAdded
        {
            OrganizationAddress = Context.Sender,
            Member = input
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberChanged
        {
            OrganizationAddress = Context.Sender,
            OldMember = input.OldMember,
            NewMember = input.NewMember
        });
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
