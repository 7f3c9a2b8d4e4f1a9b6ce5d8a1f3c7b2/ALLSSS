# Audit Report

## Title
Inconsistent Vote Threshold Counting Allows Proposals to Pass with Fewer Current Members Than Required

## Summary
The Association contract's `CheckEnoughVoteAndApprovals` function applies inconsistent membership filtering when validating proposal thresholds. While approval, rejection, and abstention thresholds filter votes by current organization members, the minimal vote threshold counts all historical votes including those from removed members. This allows proposals to pass with fewer current member votes than the configured threshold requires, undermining governance quorum requirements.

## Finding Description

The vulnerability exists in the threshold validation logic within the Association contract. The function validates four distinct thresholds but applies different counting semantics:

**Approval Threshold** - Filters by current membership: [1](#0-0) 

**Rejection Threshold** - Filters by current membership: [2](#0-1) 

**Abstention Threshold** - Filters by current membership: [3](#0-2) 

**Vote Threshold** - Does NOT filter by membership: [4](#0-3) 

When members are removed via the `RemoveMember` function [5](#0-4) , their addresses remain in the proposal's vote lists. No cleanup mechanism exists to remove historical votes from removed members.

The validation constraint only prevents excessive member removal: [6](#0-5) 

This constraint ensures `MinimalVoteThreshold <= organizationMemberCount` but does NOT prevent counting votes from removed members.

**Critical Evidence**: The Parliament contract correctly implements this logic by filtering the total vote count by current members: [7](#0-6) 

This demonstrates the Association contract's implementation is incorrect.

## Impact Explanation

This vulnerability breaks the fundamental governance invariant that `MinimalVoteThreshold` represents the minimum number of current organization members who must participate in voting.

**Concrete Attack Scenario:**
1. Organization has 10 members
2. Configuration: `MinimalVoteThreshold=8`, `MinimalApprovalThreshold=6`
3. 8 members vote: 6 approve, 2 reject
4. Organization releases a separate proposal to remove 1 rejecting member
5. After removal: 9 members remain (constraint 8≤9 satisfied)
6. Threshold validation for target proposal:
   - `approvedMemberCount` = 6 (current members only) ≥ 6 ✓
   - `rejectionMemberCount` = 1 (removed member excluded)
   - `totalVotes` = 8 (includes removed member's vote) ≥ 8 ✓
7. Proposal passes with only 7 current members voting instead of required 8

**Impact Severity:**
- Governance quorum can be systematically bypassed
- Proposals requiring broad organizational consensus can pass with minority current member participation
- Affects all Association-based governance including multi-signature wallets and organizational decision-making
- The semantic contract with users about threshold meanings is violated

## Likelihood Explanation

**Exploitability: MEDIUM**

The vulnerability requires coordination across multiple governance actions but uses only standard, permissionless operations:

1. Members vote on a target proposal using standard voting methods [8](#0-7) 
2. Organization creates and releases a proposal to remove selected members [5](#0-4) 
3. Target proposal now passes with fewer current member votes

**Feasibility:**
- No special permissions required beyond normal organization membership
- Member removal is a standard governance operation
- Timing is flexible (members vote, then removal happens, then release)
- No external dependencies or race conditions

**Detection Difficulty:**
- Member removal events are visible on-chain [9](#0-8) 
- However, the connection between removal and threshold manipulation is non-obvious
- No automated detection mechanism exists in the contract

The likelihood is realistic because organizations frequently adjust membership through legitimate governance, and this vulnerability can be triggered inadvertently or exploited deliberately.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` function to filter the total vote count by current organization members, consistent with how the Parliament contract implements it:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter total votes by current members
    var isVoteThresholdReached =
        proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
            .Count(organization.OrganizationMemberList.Contains) >=
        organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures that only votes from current organization members count toward the minimal vote threshold, maintaining the governance invariant.

## Proof of Concept

```csharp
[Fact]
public async Task VoteThresholdBypass_RemovedMemberVotesCounted()
{
    // Setup: Create organization with 10 members, MinimalVoteThreshold=8, MinimalApprovalThreshold=6
    var members = GenerateAddresses(10);
    var organization = await CreateOrganization(members, minimalVote: 8, minimalApproval: 6);
    
    // Create target proposal
    var proposalId = await CreateProposal(organization);
    
    // 6 members approve, 2 reject (8 total votes)
    await ApproveProposal(proposalId, members.Take(6));
    await RejectProposal(proposalId, members.Skip(6).Take(2));
    
    // Remove 1 rejecting member (9 members remain, 8≤9 constraint satisfied)
    await RemoveMember(organization, members[6]);
    
    // Verify: Proposal passes with only 7 current member votes
    var canRelease = await CanReleaseProposal(proposalId);
    Assert.True(canRelease); // BUG: Should be false, only 7 current members voted
    
    // Expected: Should require 8 current member votes
    // Actual: Counts removed member's vote, allowing release with 7 current member votes
}
```

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-73)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
```

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-101)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
```
