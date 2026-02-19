### Title
Inconsistent Vote Counting Allows Governance Bypass Through Member Removal

### Summary
The `IsReleaseThresholdReached` function contains a critical inconsistency where approval, rejection, and abstention counts filter votes by current organization members, but the total vote threshold check counts all votes regardless of membership status. This allows an organization to bypass rejection and abstention thresholds by removing dissenting members after they vote, while still satisfying the minimum vote quorum requirement.

### Finding Description

The vulnerability exists in the vote counting logic within `CheckEnoughVoteAndApprovals` and related helper functions. [1](#0-0) 

Approvals are filtered to only count current organization members. [2](#0-1) 

Rejections are similarly filtered by current membership. [3](#0-2) 

Abstentions are also filtered by current membership.

However, the total vote count for the `MinimalVoteThreshold` check does NOT filter by current membership: [4](#0-3) 

This inconsistency creates a timing-based attack vector. When members are removed via the `RemoveMember` function (which can only be called by the organization itself through a proposal): [5](#0-4) 

The removed members' votes are excluded from rejection/abstention counts but still included in the total vote count. This breaks the governance invariant that rejection and abstention thresholds must be respected based on actual votes cast.

### Impact Explanation

**Governance Bypass**: An organization can release proposals that should be rejected by manipulating the member list. Specifically:

1. A malicious proposal receives sufficient rejections to exceed `MaximalRejectionThreshold`, preventing release
2. The organization executes a separate proposal to remove the rejecting members
3. The rejection count drops to zero (no current members rejected), bypassing the rejection threshold
4. The total vote count remains unchanged, still satisfying `MinimalVoteThreshold`
5. The previously-rejected proposal can now be released with unauthorized actions

**Concrete Example**: 
- Organization: 10 members
- Thresholds: MinimalApprovalThreshold=5, MinimalVoteThreshold=8, MaximalRejectionThreshold=2
- Malicious proposal receives: 5 approvals, 4 rejections (initially blocked: 4 > 2)
- Remove 4 rejecting members
- New counts: 5 approvals (≥5 ✓), 0 rejections (≤2 ✓), 9 total votes (≥8 ✓)
- Proposal releases despite originally failing threshold

This affects all organizations using Association governance and enables execution of proposals that the organization explicitly voted to reject.

### Likelihood Explanation

**Attacker Capabilities**: The attack requires controlling enough members to:
1. Create and pass a proposal to remove dissenting members (needs approval threshold)
2. Create the malicious proposal to be protected

**Attack Complexity**: MEDIUM
- Requires two coordinated proposals
- Both proposals use legitimate governance functions
- No special privileges needed beyond normal member voting rights
- Timing window exists between when proposals receive votes and when they are released

**Feasibility**: HIGH
- All steps use public, documented contract methods
- Member removal is a standard governance operation
- No external dependencies or oracle manipulation required
- Attack leaves clear on-chain evidence but may go unnoticed

**Economic Rationality**: The cost is limited to transaction fees for proposal creation and voting, making it economically viable for any significant governance decision that benefits from bypassing rejection votes.

**Detection**: Difficult - member changes are legitimate governance operations, and the exploit manifests as normal proposal release.

### Recommendation

**Fix the inconsistency** by filtering the total vote count to only include current organization members:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter total votes by current membership
    var totalCurrentMemberVotes = 
        proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains);
    var isVoteThresholdReached =
        totalCurrentMemberVotes >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

**Additional Safeguards**:
1. Add invariant check: When members are removed, verify that no pending proposals would change from rejected to approved status
2. Consider implementing a "vote snapshot" that locks the member list when a proposal is created
3. Add events that log when threshold calculations change due to membership updates

**Test Cases**:
1. Test removing rejecting members cannot cause previously-rejected proposal to become releasable
2. Test removing abstaining members cannot bypass abstention threshold
3. Test that vote threshold decreases proportionally when members who voted are removed
4. Test concurrent proposal execution with member changes

### Proof of Concept

**Initial State**:
- Organization address: `ORG_ADDR`
- Members: A, B, C, D, E, F, G, H, I, J (10 members)
- Thresholds: MinimalApprovalThreshold=5, MinimalVoteThreshold=8, MaximalRejectionThreshold=2

**Attack Sequence**:

1. **Create malicious proposal P1** (by proposer from whitelist):
   - Target: Execute unauthorized token transfer or contract upgrade
   - Result: P1 created with proposal_id `P1_HASH`

2. **Vote on P1**:
   - Members A, B, C, D, E call `Approve(P1_HASH)` → 5 approvals
   - Members F, G, H, I call `Reject(P1_HASH)` → 4 rejections
   - Total: 9 votes

3. **Check P1 status** via `GetProposal(P1_HASH)`:
   - Expected: `to_be_released = false` (rejections: 4 > MaximalRejectionThreshold: 2)
   - Actual: `to_be_released = false` ✓ correctly blocked

4. **Create removal proposal P2** (by proposer from whitelist):
   - For each of F, G, H, I: create proposal to call `RemoveMember(F)`, `RemoveMember(G)`, etc.
   - Get 5+ approvals from members A, B, C, D, E

5. **Release P2 proposals** (by proposers):
   - Execute member removals
   - Organization now has 6 members: A, B, C, D, E, J

6. **Check P1 status again** via `GetProposal(P1_HASH)`:
   - Expected: Should still be blocked (only 5 valid votes from current members < MinimalVoteThreshold: 8)
   - **Actual: `to_be_released = true`** ❌ VULNERABILITY
   - Reason: 
     - Approvals from current members: 5 (≥5) ✓
     - Rejections from current members: 0 (≤2) ✓
     - Total votes (unfiltered): 9 (≥8) ✓

7. **Release P1** (by original proposer):
   - Call `Release(P1_HASH)`
   - Result: Malicious proposal executes despite being rejected by 4 members

**Success Condition**: Proposal P1 releases and executes after being initially rejected due to exceeding MaximalRejectionThreshold, demonstrating the governance bypass.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L37-37)
```csharp
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
