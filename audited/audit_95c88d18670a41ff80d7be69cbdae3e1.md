### Title
Governance Manipulation Through Strategic Member Removal in Association Contract

### Summary
The Association contract filters vote counts to only include current organization members, allowing votes from removed members to be excluded from threshold calculations. [1](#0-0)  This enables an organization to manipulate proposal outcomes by strategically removing members who voted to reject a proposal, causing a previously rejected proposal to become acceptable and eligible for release.

### Finding Description

The vulnerability exists in how the Association contract handles vote counting when organization membership changes.

**Root Cause:**

When members cast votes (approve/reject/abstain), their addresses are stored in the proposal's vote lists. [2](#0-1)  However, when checking if a proposal meets release thresholds, the contract filters these lists to only count votes from current organization members. [1](#0-0) 

The `RemoveMember()` function allows the organization to remove members without any validation against active proposals. [3](#0-2) 

**Execution Path:**
1. Members vote on a proposal, with rejections stored in `proposal.Rejections`
2. `IsProposalRejected()` counts only rejections from current members using `organization.OrganizationMemberList.Contains`
3. When `RemoveMember()` is called, the member is removed from the organization
4. Subsequent calls to `IsProposalRejected()` exclude that member's rejection vote
5. This can reduce the rejection count below `MaximalRejectionThreshold`, allowing release

The same filtering logic applies to approvals [4](#0-3)  and abstentions [5](#0-4) 

Additionally, there's an inconsistency where `MinimalVoteThreshold` counts ALL votes regardless of membership status. [6](#0-5) 

### Impact Explanation

**Direct Governance Impact:**
- Organizations can manipulate proposal outcomes by selectively removing members who voted against their interests
- A proposal that was legitimately rejected can be forced through by removing rejecting members
- Similarly, approved proposals can be blocked by removing approving members
- This completely undermines the integrity of the association governance mechanism

**Affected Parties:**
- Organization members who voted in good faith
- Downstream contracts that rely on association governance decisions
- Any funds or permissions controlled by the organization

**Severity Justification:**
HIGH - This breaks a fundamental governance invariant. The ability to retroactively manipulate vote outcomes by changing membership invalidates the entire purpose of the voting system and can lead to unauthorized execution of proposals that should have been rejected.

### Likelihood Explanation

**Attacker Capabilities:**
An attacker needs control over the organization, which can be achieved through:
- Being an authorized member who can propose and get approval for member removal
- Controlling enough members to pass member removal proposals
- This is within normal operational parameters of an association

**Attack Complexity:**
LOW - The attack requires only standard contract interactions:
1. Wait for a proposal to be in a rejected state
2. Create and pass a proposal to remove a rejecting member
3. Release the original proposal once rejection count drops

**Feasibility:**
- Entry point `RemoveMember()` is accessible to the organization itself [3](#0-2) 
- No checks prevent removal during active proposals
- No snapshots of membership at voting time
- Execution is straightforward with predictable results

**Detection:**
Difficult to detect as member removal is a legitimate governance action. The manipulation only becomes apparent through careful analysis of voting patterns and timing.

### Recommendation

**Code-Level Mitigation:**

1. **Implement Vote Snapshots**: Store organization membership state at the time each vote is cast, and use that snapshot for threshold calculations:
```
// In ProposalInfo, add:
map<address, bool> valid_voters_snapshot;

// In Reject/Approve/Abstain, record:
proposal.valid_voters_snapshot[Context.Sender] = true;

// In vote counting, use:
var rejectionMemberCount = proposal.Rejections.Count(addr => 
    proposal.valid_voters_snapshot.ContainsKey(addr) && 
    proposal.valid_voters_snapshot[addr]);
```

2. **Prevent Member Removal During Active Proposals**: Add validation in `RemoveMember()`:
```
// Check all active proposals before allowing removal
foreach (var proposal in State.Proposals) {
    if (proposal.OrganizationAddress == Context.Sender) {
        Assert(!proposal.Rejections.Contains(input) && 
               !proposal.Approvals.Contains(input) && 
               !proposal.Abstentions.Contains(input),
               "Cannot remove member with active votes");
    }
}
```

3. **Fix MinimalVoteThreshold Inconsistency**: Count only current member votes for threshold:
```
var isVoteThresholdReached = 
    proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
    proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
    proposal.Rejections.Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**Test Cases:**
- Test that removing a rejecting member after voting does not change proposal rejection status
- Test that vote thresholds use consistent membership filtering
- Test that member removal is blocked when member has active votes

### Proof of Concept

**Initial State:**
- Organization with 5 members: A, B, C, D, E
- `MinimalApprovalThreshold = 2`
- `MaximalRejectionThreshold = 1` 
- `MinimalVoteThreshold = 4`

**Transaction Steps:**

1. **Create Proposal**: Proposer A creates proposal P1
2. **Voting Phase**:
   - Member A approves P1 → `proposal.Approvals = [A]`
   - Member B approves P1 → `proposal.Approvals = [A, B]`
   - Member C rejects P1 → `proposal.Rejections = [C]`
   - Member D rejects P1 → `proposal.Rejections = [C, D]`
   - Member E abstains → `proposal.Abstentions = [E]`

3. **Check Status**: 
   - `rejectionMemberCount = 2 > MaximalRejectionThreshold(1)`
   - `IsProposalRejected() = true`
   - Proposal CANNOT be released ✓ (Expected)

4. **Member Manipulation**:
   - Organization executes `RemoveMember(C)` via separate proposal
   - Member C is removed from `organization.OrganizationMemberList`

5. **Check Status Again**:
   - `proposal.Rejections = [C, D]` (still contains C)
   - `rejectionMemberCount = 1` (only D counted, C filtered out)
   - `rejectionMemberCount <= MaximalRejectionThreshold(1)` 
   - `IsProposalRejected() = false`
   - `approvedMemberCount = 2 >= MinimalApprovalThreshold(2)`
   - `totalVotes = 5 >= MinimalVoteThreshold(4)`
   - Proposal CAN now be released ✗ (Vulnerability!)

**Success Condition:**
A proposal that was rejected with 2 rejection votes becomes releasable after removing one rejecting member, even though the member legitimately voted while they were a member. This violates governance integrity.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-39)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L41-45)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-53)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
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

**File:** contract/AElf.Contracts.Association/Association.cs (L143-160)
```csharp
    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Rejections.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Reject),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
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
