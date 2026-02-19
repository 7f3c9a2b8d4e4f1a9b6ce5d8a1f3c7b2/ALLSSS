### Title
Member Removal Invalidates Previously Approved Proposals Due to Retroactive Vote Counting

### Summary
The Association contract's `RemoveMember` function allows removal of organization members after they have voted on proposals. The vote counting logic only considers votes from current members, causing previously approved proposals to become permanently unreleasable when voting members are removed. This breaks the governance invariant that approved proposals remain executable.

### Finding Description

The vulnerability exists in the interaction between member removal and vote counting mechanisms:

**Vote Counting Logic** - The proposal release threshold check only counts votes from addresses currently in the organization member list: [1](#0-0) [2](#0-1) [3](#0-2) 

**Member Removal Function** - The `RemoveMember` function removes members and validates only structural organization invariants, not active proposal states: [4](#0-3) 

**Insufficient Validation** - The validation checks structural constraints between thresholds and member count, but does not prevent removal of members who have voted on active proposals: [5](#0-4) 

**Root Cause:** The proposal's approval/rejection/abstention lists store addresses permanently, but the counting logic filters these lists by current membership using `organization.OrganizationMemberList.Contains()`. When a member who has voted is removed, their vote disappears from all threshold calculations retroactively.

### Impact Explanation

**Governance Deadlock:** Proposals that had achieved the required approval threshold become permanently stuck and unreleasable after voting members are removed. The proposal remains valid (not expired) but can never reach the threshold again if enough voting members are removed.

**Concrete Example:**
- Organization: 5 members [A, B, C, D, E]
- Thresholds: MinimalApprovalThreshold=3, MaximalRejectionThreshold=1
- Proposal receives 3 approvals from A, B, C (meets threshold, ready to release)
- Member A is removed via governance action
- New member count: 4 members [B, C, D, E]
- Validation passes: 1 + 3 = 4 ≤ 4 ✓
- Approval count recalculated: only 2 (B, C) - A's vote no longer counts
- Proposal now fails threshold check: 2 < 3 (permanently unreleasable)

**Who is Affected:** All Association organizations, particularly those with active proposals during member transitions. This affects critical governance operations including treasury management, parameter changes, and cross-contract calls.

**Severity Justification:** HIGH - This breaks a fundamental governance invariant (approved proposals remain approved) and can lead to permanent loss of governance capability for critical operations.

### Likelihood Explanation

**Reachable Entry Point:** The `RemoveMember` function is a public method callable through the organization's own governance process: [6](#0-5) 

**Feasible Preconditions:**
- Organization exists with active proposals
- Members vote on proposals
- Organization needs to remove members (normal operation for member turnover, departures, or security)

**Execution Practicality:** 
1. Organization creates and votes on proposal X (reaches approval threshold)
2. Organization creates proposal Y to remove a member who voted on X
3. Proposal Y is approved and released
4. Member is removed via `RemoveMember`
5. Proposal X becomes unreleasable despite having previously met threshold

**Attack Complexity:** Low - Can occur accidentally during normal operations or be exploited maliciously. An organization member could:
- Vote to approve a critical proposal
- Then propose and execute their own removal
- Block the critical proposal from ever executing

**Economic Rationality:** Removing members costs only governance proposal execution fees. The damage (blocked proposals) far exceeds the cost.

### Recommendation

**1. Track Historical Membership for Active Proposals:**
Modify the vote counting logic to check if the voting address was a member at the time of voting, not just at release time. Store a snapshot of the organization state with each proposal or add a timestamp-based membership verification.

**2. Add Active Proposal Check to RemoveMember:**
```csharp
// Before removing a member, check if they have voted on any non-expired proposals
// Reject removal if it would invalidate any active proposals
```

**3. Alternative: Lock Member List During Active Proposals:**
Prevent member removal entirely when proposals are active and not expired. Members can only be removed when no active proposals exist.

**4. Add Validation in Validate Function:**
Extend the validation in `Association_Helper.cs` lines 72-80 to also verify that if there are active proposals, the organization changes don't break their release conditions.

**5. Test Cases:**
- Test member removal after voting
- Test proposal release after member removal
- Test that proposals remain releasable after member changes
- Test threshold validation with active proposals

### Proof of Concept

**Initial State:**
1. Create organization with 5 members: [Address_A, Address_B, Address_C, Address_D, Address_E]
2. Set thresholds: MinimalApprovalThreshold=3, MinimalVoteThreshold=3, MaximalRejectionThreshold=1
3. Validation: MaximalRejectionThreshold(1) + MinimalApprovalThreshold(3) = 4 ≤ 5 ✓

**Transaction Steps:**
1. Create Proposal_1 to transfer tokens from organization
2. Address_A calls `Approve(Proposal_1)` 
3. Address_B calls `Approve(Proposal_1)`
4. Address_C calls `Approve(Proposal_1)`
5. Verify: `GetProposal(Proposal_1).ToBeReleased == true` (3 approvals ≥ threshold)
6. Create Proposal_2 to call `RemoveMember(Address_A)` on organization
7. Address_B, Address_C, Address_D approve and Address_A releases Proposal_2
8. `RemoveMember(Address_A)` executes successfully
9. Organization now has 4 members: [Address_B, Address_C, Address_D, Address_E]
10. Validation passes: 1 + 3 = 4 ≤ 4 ✓

**Expected Result:** 
Proposal_1 should remain releasable since it achieved the required 3 approvals before member removal.

**Actual Result:**
- `GetProposal(Proposal_1).ToBeReleased == false`
- Approval count = 2 (only Address_B and Address_C counted, Address_A's vote excluded)
- Proposal_1 is permanently stuck and cannot be released
- Even if Address_D and Address_E now approve, only 4 approvals total possible but Address_A's approval is lost

**Success Condition:** 
The vulnerability is confirmed when a previously approved proposal becomes unreleasable after removing a voting member, with no mechanism to recover or re-validate the proposal.

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-80)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
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
