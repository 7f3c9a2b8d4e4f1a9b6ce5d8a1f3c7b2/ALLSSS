### Title
Vote Count Inconsistency Allows Governance Manipulation Through Member Removal

### Summary
The `CheckEnoughVoteAndApprovals()` function contains a critical counting inconsistency where votes from removed members still count toward the MinimalVoteThreshold (quorum) but are excluded from approval/rejection/abstention threshold checks. This allows organizations to manipulate proposal outcomes by removing dissenting members after they vote, causing rejected proposals to become approved.

### Finding Description

The vulnerability exists in the vote counting logic within `CheckEnoughVoteAndApprovals()`: [1](#0-0) 

The function applies different filtering logic for different threshold checks:

1. **Lines 49, 37, 43**: Approval, rejection, and abstention counts use `.Count(organization.OrganizationMemberList.Contains)`, which filters votes to only include CURRENT organization members.

2. **Line 56**: The MinimalVoteThreshold check uses `.Concat().Count()` on all three vote lists WITHOUT filtering for current membership.

This inconsistency occurs because when members vote, their addresses are added to the proposal's vote lists: [2](#0-1) 

If members are subsequently removed via the `RemoveMember` function: [3](#0-2) 

Their votes remain in the proposal's vote lists, but they are no longer in the organization member list. This causes:
- Their votes to be EXCLUDED from approval/rejection/abstention threshold calculations (filtered out at lines 49, 37, 43)
- Their votes to be INCLUDED in the total vote count for quorum purposes (counted at line 56)

The existing protection `AssertProposalNotYetVotedBySender` only prevents duplicate votes during voting: [4](#0-3) 

But it cannot prevent the counting inconsistency that occurs when members are removed after voting.

### Impact Explanation

**Governance Manipulation**: An organization can force through controversial proposals by removing dissenting members after they vote. This completely undermines the governance integrity.

**Concrete Attack Scenario**:
- Organization with 10 members, thresholds: MinimalVoteThreshold=6, MinimalApprovalThreshold=4, MaximalRejectionThreshold=3
- Proposal receives 4 approvals and 4 rejections (8 total votes)
- Organization removes the 4 rejecting members through a separate proposal
- Original proposal is now evaluated with:
  - `approvedMemberCount = 4` (current members only)
  - `rejectionMemberCount = 0` (removed members filtered out)
  - `totalVotes = 8` (all votes including removed members)
  - Proposal PASSES (4≥4 approvals, 0≤3 rejections, 8≥6 quorum)
- Result: A proposal that should have been rejected (4 approve vs 4 reject) is now approved because rejection votes were nullified

**Who is Affected**: All Association contract users. Organizations with minority opposition can have their dissenting votes erased by simply removing the dissenters from membership.

**Severity**: HIGH - This breaks the fundamental governance invariant that vote outcomes should reflect member preferences at the time of voting.

### Likelihood Explanation

**Attacker Capabilities**: Any organization can execute this attack through standard contract operations. The attacker needs:
1. Sufficient votes to pass a member removal proposal
2. Pending proposals with unfavorable vote distributions

**Attack Complexity**: LOW - Only requires calling existing public methods (`RemoveMember` via proposal execution, then `Release` on the target proposal).

**Feasibility**: HIGH - Organizations legitimately remove members for various reasons (inactivity, policy changes, etc.). This creates opportunities to exploit pending proposals. The organization doesn't even need malicious intent - the side effect occurs automatically whenever members are removed.

**Detection**: DIFFICULT - The manipulation appears as normal member management. There's no on-chain indicator that member removal is being used to manipulate votes.

**Economic Rationality**: The cost is just the gas fees for member removal and proposal release, which is minimal compared to the potential benefit of forcing through favorable proposals.

### Recommendation

**Fix the inconsistency by applying membership filtering to ALL threshold checks**:

Modify line 56 to filter all votes by current membership before counting:

```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
    proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
    proposal.Rejections.Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This ensures votes from removed members are excluded from ALL threshold calculations, maintaining consistent vote counting semantics.

**Additional safeguards**:
1. Consider adding a proposal invalidation mechanism when organization membership changes significantly
2. Add validation that prevents member removal if they have votes on active proposals
3. Emit events when member changes affect pending proposals for transparency

**Test cases to add**:
1. Verify member removal invalidates their votes across all threshold checks
2. Test that proposals cannot be manipulated by removing voters
3. Confirm edge cases where all approvers/rejectors are removed

### Proof of Concept

**Initial State**:
- Organization with 10 members: [M1, M2, M3, M4, M5, M6, M7, M8, M9, M10]
- Thresholds: MinimalVoteThreshold=6, MinimalApprovalThreshold=4, MaximalRejectionThreshold=3

**Step 1**: Create controversial Proposal A
- M1, M2, M3, M4 call `Approve(ProposalA_Hash)`
- M5, M6, M7, M8 call `Reject(ProposalA_Hash)`
- Current vote state: 4 approvals, 4 rejections (should be rejected since 4>3 rejections)

**Step 2**: Create Proposal B to remove rejecting members
- Proposal B calls `RemoveMember(M5)`, `RemoveMember(M6)`, `RemoveMember(M7)`, `RemoveMember(M8)`
- M1, M2, M3, M4, M9, M10 call `Approve(ProposalB_Hash)` (6 approvals)
- M1 calls `Release(ProposalB_Hash)` - succeeds (6≥4 approvals, 6≥6 quorum)

**Step 3**: Attempt to release Proposal A
- M1 calls `Release(ProposalA_Hash)`
- **Expected Result**: Should FAIL because 4 rejections > 3 MaximalRejectionThreshold
- **Actual Result**: SUCCEEDS because:
  - `approvedMemberCount = 4` (M1-M4 still members)
  - `rejectionMemberCount = 0` (M5-M8 removed, filtered out at line 37)
  - `isProposalRejected = FALSE` (0 ≤ 3)
  - `isApprovalEnough = TRUE` (4 ≥ 4)
  - `totalVotes = 8` (all votes counted at line 56)
  - `isVoteThresholdReached = TRUE` (8 ≥ 6)
  - Proposal executes despite being democratically rejected

**Success Condition**: Proposal A executes when it should have been rejected, demonstrating that member removal manipulates vote outcomes.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-59)
```csharp
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L132-138)
```csharp
    private void AssertProposalNotYetVotedBySender(ProposalInfo proposal, Address sender)
    {
        var isAlreadyVoted = proposal.Approvals.Contains(sender) || proposal.Rejections.Contains(sender) ||
                             proposal.Abstentions.Contains(sender);

        Assert(!isAlreadyVoted, "Sender already voted.");
    }
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
