### Title
Inconsistent Vote Threshold Counting Allows Proposals to Pass with Fewer Current Members Than Required

### Summary
The `CheckEnoughVoteAndApprovals` function applies inconsistent membership filtering when validating proposal thresholds. While `MinimalApprovalThreshold`, `MaximalRejectionThreshold`, and `MaximalAbstentionThreshold` count only current organization members' votes, `MinimalVoteThreshold` counts all votes including those from removed members. This semantic inconsistency allows proposals to pass with fewer current member votes than the configured threshold indicates, undermining governance quorum requirements. [1](#0-0) 

### Finding Description

The vulnerability exists in `CheckEnoughVoteAndApprovals` in `Association_Helper.cs`. The function validates proposal release conditions using four thresholds, but applies different counting logic:

**Approval Threshold (Current Members Only):** [2](#0-1) 
Counts only votes from addresses present in `organization.OrganizationMemberList`.

**Rejection Threshold (Current Members Only):** [3](#0-2) 
Counts only rejections from current organization members.

**Abstention Threshold (Current Members Only):** [4](#0-3) 
Counts only abstentions from current organization members.

**Vote Threshold (All Votes - No Membership Filter):** [5](#0-4) 
Concatenates all vote lists and counts total entries without checking current membership.

While duplicate prevention exists across the three lists, this only prevents a single address from appearing in multiple lists, not from being counted after membership removal: [6](#0-5) 

The `RemoveMember` function allows organizations to remove members through governance proposals: [7](#0-6) 

When members are removed after voting, their addresses remain in the proposal's vote lists. The validation constraint `MinimalVoteThreshold <= organizationMemberCount` only prevents removing so many members that the threshold exceeds remaining member count, but doesn't prevent counting votes from removed members. [8](#0-7) 

### Impact Explanation

This vulnerability undermines governance quorum requirements by allowing proposals to pass with lower current member participation than configured:

**Concrete Scenario:**
- Organization: 10 members
- Configuration: MinimalVoteThreshold=8, MinimalApprovalThreshold=6
- 8 members vote: 6 approve, 2 reject
- Organization removes 1 rejecting member (9 members remain, constraint 8≤9 satisfied)
- Threshold validation:
  - `approvedMemberCount` = 6 current members ≥ 6 ✓
  - `rejectionMemberCount` = 1 current member (removed member ignored)
  - Total votes = 8 (includes removed member) ≥ 8 ✓
- Proposal passes with only 7 current members voting, not 8

**Impact Severity:**
- Governance integrity violation: Quorum can be bypassed through strategic member removal
- Proposals requiring broad organizational consensus can pass with minority participation
- The semantic expectation that MinimalVoteThreshold represents current member participation is violated
- Affects all Association-based governance including multi-signature operations

### Likelihood Explanation

**Exploitability:** MEDIUM

**Attack Complexity:**
The scenario requires coordination across two proposals but uses only standard governance operations:
1. Members vote on target proposal
2. Organization approves and releases a separate proposal to remove selected members
3. Target proposal now passes threshold checks with fewer current member votes

**Feasibility Conditions:**
- Organization must approve member removal (standard governance process)
- Timing: Members must vote before removal
- No special permissions beyond normal organization membership required

**Detection Constraints:**
- Member removal operations are visible on-chain through `MemberRemoved` events
- However, the connection between removal and threshold manipulation may not be obvious
- No explicit detection mechanism exists in the contract logic

**Probability Reasoning:**
While this requires organizational action rather than external attack, it represents a genuine governance vulnerability because:
- The threshold semantics imply current member participation requirements
- Strategic member removal can circumvent these requirements
- Multi-step proposals can coordinate removals with target votes
- Organizations may unknowingly trigger this through legitimate member management

### Recommendation

**Primary Fix - Consistent Membership Filtering:**

Modify `CheckEnoughVoteAndApprovals` to filter votes by current membership when counting for `MinimalVoteThreshold`:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // Count only current members' votes for threshold
    var totalCurrentMemberVotes = 
        proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
        proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
        proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        totalCurrentMemberVotes >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

**Invariant Checks:**
Add assertion that total counted votes never exceed current member count to prevent future regressions.

**Test Cases:**
1. Create proposal with N members voting
2. Remove K members who voted (where N-K >= MinimalVoteThreshold)
3. Verify proposal does NOT pass if current member votes < MinimalVoteThreshold
4. Test across all vote types (approve/reject/abstain combinations)
5. Verify proper counting when members are added after voting

### Proof of Concept

**Initial State:**
- Organization created with 10 members: M1 through M10
- Configuration:
  - `MinimalVoteThreshold` = 8
  - `MinimalApprovalThreshold` = 6
  - `MaximalRejectionThreshold` = 3
  - `MaximalAbstentionThreshold` = 3

**Exploitation Steps:**

1. **Create Target Proposal P1:**
   - Proposer creates proposal for organization action
   - Proposal requires release thresholds to be met

2. **Initial Voting (8 members vote):**
   - M1, M2, M3, M4, M5, M6: Call `Approve(P1)` 
   - M7, M8: Call `Reject(P1)`
   - Current state: 6 approvals, 2 rejections, 8 total votes

3. **Member Removal via Governance:**
   - Create and approve proposal P2 to call `RemoveMember(M7)`
   - Validation passes: 9 remaining members, MinimalVoteThreshold=8, constraint 8≤9 satisfied
   - M7 removed from `OrganizationMemberList`

4. **Attempt Release of P1:**
   - Call `Release(P1)`
   - `CheckEnoughVoteAndApprovals` executes:
     - `approvedMemberCount` = 6 (M1-M6 are current members) ≥ 6 ✓
     - `rejectionMemberCount` = 1 (only M8 is current member) ≤ 3 ✓
     - `totalVotes` = 8 (concatenates all lists, includes M7's vote) ≥ 8 ✓
   - Proposal released successfully

**Expected Result:** Proposal should NOT release because only 7 current members voted (6 approvals + 1 rejection from M8), which is less than MinimalVoteThreshold=8.

**Actual Result:** Proposal releases because the total vote count includes M7's vote despite M7 no longer being a member, allowing the threshold to be met with only 7 current member votes.

**Success Condition:** The proposal passes governance thresholds despite fewer current members voting than the configured MinimalVoteThreshold, demonstrating the semantic inconsistency in vote counting.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L42-44)
```csharp
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
```

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-73)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
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
