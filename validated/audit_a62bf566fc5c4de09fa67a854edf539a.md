# Audit Report

## Title
Inconsistent Vote Counting Allows MinimalVoteThreshold Bypass Through Stale Votes from Removed Members

## Summary
The Association contract contains a critical vote counting inconsistency where approval/rejection/abstention counts filter by current membership, but the total vote count used for MinimalVoteThreshold validation does not. This allows proposals to pass using stale votes from members who were removed after voting, effectively bypassing governance participation requirements.

## Finding Description

The vulnerability exists in the threshold validation logic within the Association contract's proposal release mechanism.

When members vote on a proposal via `Approve()`, `Reject()`, or `Abstain()`, their address is added to the respective proposal list and they must be current members at voting time. [1](#0-0) 

Members can later be removed from the organization through `RemoveMember()`, which removes them from `organization.OrganizationMemberList` but does NOT remove their votes from existing proposals. [2](#0-1) 

The root cause is an inconsistency in `CheckEnoughVoteAndApprovals()`:

**Approval counting (filtered):** The approval count filters by current membership using `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)`, only counting votes from members still in the organization. [3](#0-2) 

**Total vote counting (NOT filtered):** The total vote count concatenates all approval/rejection/abstention lists and counts them without filtering by current membership using `proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count()`. [4](#0-3) 

The rejection and abstention counts also filter by current membership, confirming the inconsistent pattern. [5](#0-4) 

**Proof of correct implementation:** The Parliament contract correctly filters the total vote count by current membership using `proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count(parliamentMembers.Contains)`, demonstrating this is an implementation error in Association. [6](#0-5) 

This inconsistency means:
- Votes from removed members **DO NOT** count toward approval/rejection/abstention thresholds
- Votes from removed members **DO** count toward the MinimalVoteThreshold requirement

This breaks the governance security guarantee that MinimalVoteThreshold ensures adequate participation from current organization members.

## Impact Explanation

**Governance Security Control Bypass:** The MinimalVoteThreshold is a critical governance parameter designed to ensure adequate participation before proposals can execute. By allowing stale votes from removed members to count toward this threshold, the contract undermines this security control.

**Concrete Attack Scenario:**
- Organization has 10 members with MinimalVoteThreshold = 6 and MinimalApprovalThreshold = 4
- A proposal receives 4 approvals from current members (meeting approval threshold)
- 2 additional members vote (type irrelevant - approval/rejection/abstention)
- Through governance action, the organization removes those 2 members
- When `Release()` is called:
  - Current member approvals: 4 ≥ 4 ✓ (filtered count)
  - Total votes: 6 ≥ 6 ✓ (unfiltered count includes removed members)
  - Proposal executes successfully
- **Expected behavior:** With only 4 current member votes (out of 8 remaining members), it should fail MinimalVoteThreshold of 6

**Affected Parties:** All organizations using the Association contract for governance, particularly those with strict participation requirements. The vulnerability can be triggered both maliciously and unintentionally during normal member management operations.

**Severity Justification:** High - This directly violates the governance invariant that thresholds should reflect current member participation, allowing proposals to execute without meeting the intended quorum requirements.

## Likelihood Explanation

**Preconditions:**
- A proposal must be created and receive votes
- Members must then be removed from the organization

**Execution Path:**
The vulnerability requires `RemoveMember()` to be called, which is authorized only when `Context.Sender` equals the organization address (governance action). [7](#0-6) 

**Attack Vectors:**
1. **Malicious Collusion:** Multiple organization members coordinate to vote on a proposal, then use governance to remove some members to manipulate the threshold calculation
2. **Unintentional Trigger:** Legitimate member removal during normal operations (removing inactive members, organizational restructuring) after votes are cast inadvertently creates the vulnerability condition

**Practical Execution:** 
- Uses standard contract operations (vote methods, RemoveMember, Release)
- No special privileges required beyond normal organizational governance
- Can occur during routine member management without malicious intent

**Detection Difficulty:** The inconsistency is subtle and would not be apparent during normal operations. Organizations would not realize proposals are passing with insufficient current member participation unless they manually verify vote counts against current membership.

**Overall Probability:** Medium-High - While requiring governance action (not unilateral attacker control), this can occur through both malicious coordination and routine operational changes, making it a realistic threat to governance integrity.

## Recommendation

Modify `CheckEnoughVoteAndApprovals()` to filter the total vote count by current membership, consistent with how approval/rejection/abstention counts are filtered:

Change line 55-57 from:
```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

To:
```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This matches the Parliament contract's correct implementation and ensures all threshold checks consistently use current membership.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Bypass_Through_Removed_Members()
{
    // Setup: Create organization with 10 members
    var members = Enumerable.Range(0, 10).Select(i => Accounts[i].Address).ToList();
    var organizationAddress = await CreateOrganizationAsync(new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList { OrganizationMembers = { members } },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 4,
            MinimalVoteThreshold = 6,
            MaximalRejectionThreshold = 10,
            MaximalAbstentionThreshold = 10
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { members[0] } }
    });

    // Create a proposal
    var proposalId = await CreateProposalAsync(organizationAddress, members[0]);

    // 4 members approve (meets MinimalApprovalThreshold)
    for (int i = 0; i < 4; i++)
        await GetAssociationContractTester(Accounts[i].KeyPair).Approve.SendAsync(proposalId);

    // 2 additional members vote (abstain to reach MinimalVoteThreshold = 6)
    await GetAssociationContractTester(Accounts[4].KeyPair).Abstain.SendAsync(proposalId);
    await GetAssociationContractTester(Accounts[5].KeyPair).Abstain.SendAsync(proposalId);

    // Now remove those 2 members through governance
    var removeProposal1 = await CreateRemoveMemberProposal(organizationAddress, members[4]);
    await ApproveAndRelease(removeProposal1, organizationAddress, 4);
    
    var removeProposal2 = await CreateRemoveMemberProposal(organizationAddress, members[5]);
    await ApproveAndRelease(removeProposal2, organizationAddress, 4);

    // At this point: Only 4 out of 8 current members voted (should fail MinimalVoteThreshold=6)
    // But total votes = 6 (includes removed members), so proposal incorrectly passes
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeTrue(); // BUG: Should be False!

    // Proposal can be released despite insufficient current member participation
    var releaseResult = await GetAssociationContractTester(Accounts[0].KeyPair).Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // VULNERABILITY CONFIRMED
}
```

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-53)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-58)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-101)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
```
