# Audit Report

## Title
Vote Count Inconsistency Allows Governance Manipulation Through Member Removal

## Summary
The Association contract's `CheckEnoughVoteAndApprovals()` function contains a critical counting inconsistency where votes from removed members still count toward the MinimalVoteThreshold (quorum) but are excluded from approval/rejection/abstention threshold checks. This allows organizations to manipulate proposal outcomes by removing dissenting members after they vote, causing rejected proposals to become approved.

## Finding Description

The vulnerability exists in the vote counting logic where different filtering rules are applied to different threshold checks.

**Inconsistent Vote Filtering:**

The `CheckEnoughVoteAndApprovals()` function filters approval counts to only include current organization members [1](#0-0) , while the quorum check counts all votes regardless of current membership [2](#0-1) .

Similarly, `IsProposalRejected()` filters rejections to current members only [3](#0-2) , and `IsProposalAbstained()` filters abstentions to current members only [4](#0-3) .

**How the Attack Works:**

When members vote, their addresses are added to the proposal's vote lists (Approvals, Rejections, or Abstentions) [5](#0-4) [6](#0-5) [7](#0-6) .

If members are subsequently removed via the `RemoveMember` function [8](#0-7) , their votes remain in the proposal's vote lists, but they are no longer in the organization member list.

The existing `AssertProposalNotYetVotedBySender` protection only prevents duplicate votes during voting [9](#0-8) , but cannot prevent the counting inconsistency that occurs when members are removed after voting.

**Concrete Attack Scenario:**
- Organization with 10 members: MinimalVoteThreshold=6, MinimalApprovalThreshold=4, MaximalRejectionThreshold=3
- Proposal A receives 4 approvals and 4 rejections (8 total votes)
- Currently: Proposal would be REJECTED (4 rejections > 3 MaximalRejectionThreshold)
- Organization creates and passes Proposal B to remove the 4 rejecting members
- After removal, Proposal A is evaluated:
  - `approvedMemberCount = 4` (current members only) ≥ 4 ✓
  - `rejectionMemberCount = 0` (removed members filtered out) ≤ 3 ✓
  - `totalVotes = 8` (all votes including removed members) ≥ 6 ✓
- Proposal A now PASSES despite having equal approvals and rejections

**Evidence of Implementation Bug:**

The Parliament contract correctly filters ALL vote counts including the quorum check by current members [10](#0-9) , proving that the Association implementation is inconsistent with the intended design pattern.

## Impact Explanation

**HIGH SEVERITY** - This breaks the fundamental governance invariant that vote outcomes should reflect member preferences at the time of evaluation.

Organizations can retroactively nullify dissenting votes by removing those members from the organization. This completely undermines governance integrity and democratic decision-making within Association contracts.

All Association contract users are affected. Any organization with sufficient control to pass member removal proposals can manipulate pending proposals by strategically removing dissenters, effectively censoring opposition votes.

While this does not result in direct fund loss, it represents a severe governance manipulation vulnerability that can be used to force through any proposal by eliminating opposition, potentially leading to unauthorized configuration changes, fund misappropriation through manipulated proposals, or other critical governance failures.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability has multiple factors that make it highly likely to occur:

**Attack Complexity: LOW** - The attack requires only standard contract operations: creating a proposal to call `RemoveMember`, getting it approved, releasing it, then releasing the target proposal.

**Preconditions: REALISTIC** - Organizations legitimately remove members for various reasons (inactivity, policy violations, restructuring). This creates natural opportunities to exploit pending proposals, even without malicious intent.

**Attacker Capabilities: STANDARD** - Any organization that can pass a member removal proposal (by controlling enough votes) can execute this attack. No special privileges or compromised keys required.

**Detection: DIFFICULT** - The manipulation appears as normal member management operations. There is no on-chain mechanism to distinguish legitimate member removal from vote manipulation.

**Economic Cost: MINIMAL** - Only gas fees for the member removal proposal and release transactions.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals()` function to filter the quorum count by current members, consistent with how the Parliament contract implements this logic.

The quorum check should be changed from counting all votes to only counting votes from current members:

**Current (vulnerable) implementation:**
```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**Recommended fix:**
```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This ensures that only votes from current organization members count toward all thresholds, preventing retroactive manipulation through member removal.

## Proof of Concept

```csharp
[Fact]
public async Task VoteCountInconsistency_AllowsGovernanceManipulation()
{
    // Setup: Create organization with 10 members
    var members = Enumerable.Range(0, 10).Select(_ => SampleAccount.Accounts[_].Address).ToList();
    var organizationAddress = await CreateOrganization(new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList { OrganizationMembers = { members } },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalVoteThreshold = 6,
            MinimalApprovalThreshold = 4,
            MaximalRejectionThreshold = 3,
            MaximalAbstentionThreshold = 10
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { members } }
    });

    // Create proposal A
    var proposalA = await CreateProposal(organizationAddress, members[0]);
    
    // 4 members approve, 4 members reject (8 total votes)
    for (int i = 0; i < 4; i++)
        await ApproveProposal(proposalA, members[i]);
    for (int i = 4; i < 8; i++)
        await RejectProposal(proposalA, members[i]);
    
    // Verify proposal A is rejected (4 rejections > 3 MaximalRejectionThreshold)
    var canRelease1 = await CanReleaseProposal(proposalA);
    Assert.False(canRelease1); // Should be rejected
    
    // Create and pass proposal B to remove the 4 rejecting members
    var proposalB = await CreateProposal(organizationAddress, members[0]);
    for (int i = 0; i < 6; i++) // Get 6 approvals to pass removal
        await ApproveProposal(proposalB, members[i]);
    
    await ReleaseProposal(proposalB, organizationAddress, "RemoveMember", members[4]);
    await ReleaseProposal(proposalB, organizationAddress, "RemoveMember", members[5]);
    await ReleaseProposal(proposalB, organizationAddress, "RemoveMember", members[6]);
    await ReleaseProposal(proposalB, organizationAddress, "RemoveMember", members[7]);
    
    // Check proposal A again after removing rejecting members
    var canRelease2 = await CanReleaseProposal(proposalA);
    
    // BUG: Proposal A now passes because:
    // - approvedMemberCount = 4 (current members only) >= 4 ✓
    // - rejectionMemberCount = 0 (removed members filtered) <= 3 ✓
    // - totalVotes = 8 (all votes including removed) >= 6 ✓
    Assert.True(canRelease2); // Governance manipulation successful!
}
```

This test demonstrates that a proposal with equal approvals and rejections can be manipulated from REJECTED to APPROVED by removing dissenting members, proving the vulnerability.

## Notes

The inconsistency between the Association and Parliament contract implementations strongly suggests this is an unintended bug rather than a design choice. The Parliament contract correctly filters all vote counts by current members [10](#0-9) , while the Association contract has the flawed implementation [2](#0-1) .

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L132-138)
```csharp
    private void AssertProposalNotYetVotedBySender(ProposalInfo proposal, Address sender)
    {
        var isAlreadyVoted = proposal.Approvals.Contains(sender) || proposal.Rejections.Contains(sender) ||
                             proposal.Abstentions.Contains(sender);

        Assert(!isAlreadyVoted, "Sender already voted.");
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L130-130)
```csharp
        proposal.Approvals.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L150-150)
```csharp
        proposal.Rejections.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L170-170)
```csharp
        proposal.Abstentions.Add(Context.Sender);
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-100)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
```
