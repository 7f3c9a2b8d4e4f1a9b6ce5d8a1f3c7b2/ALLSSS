### Title
Association Contract MinimalVoteThreshold Incorrectly Counts Votes from Removed Members

### Summary
The Association contract's `CheckEnoughVoteAndApprovals` method fails to filter votes by current organization membership when checking `MinimalVoteThreshold`, while all other threshold checks correctly filter by current membership. This allows proposals to pass with votes from removed members counting toward the participation threshold, enabling governance bypass through membership manipulation.

### Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals` method where the MinimalVoteThreshold check counts ALL votes without filtering by current organization membership. [1](#0-0) 

This contrasts with the approval count check in the same function that correctly filters by current membership: [2](#0-1) 

And also differs from rejection and abstention checks that properly filter: [3](#0-2) [4](#0-3) 

**Root Cause:** When members vote via `Approve`, `Reject`, or `Abstain` methods, their addresses are added to proposal vote lists after membership verification: [5](#0-4) 

However, when members are removed via `RemoveMember`, their previous votes remain in active proposals: [6](#0-5) 

The MinimalVoteThreshold check uses raw `.Count()` instead of `.Count(organization.OrganizationMemberList.Contains)`, causing it to count votes from removed members. This is proven to be a bug by comparing with the Parliament contract's correct implementation: [7](#0-6) 

### Impact Explanation

**Governance Integrity Violation:** Proposals can be released with fewer participating current members than the MinimalVoteThreshold requires. This undermines the fundamental governance guarantee that a minimum number of current organization members must participate in proposal decisions.

**Concrete Attack Scenario:**
- Organization has 5 members with MinimalVoteThreshold=5, MinimalApprovalThreshold=3
- Attacker-controlled majority adds 2 temporary members via proposal
- Temporary members cast votes (any type) on a malicious proposal
- Organization removes temporary members via separate proposal
- Only 3 current members approve the malicious proposal
- Proposal passes: 3 current member approvals meet MinimalApprovalThreshold, and 5 total votes (including 2 from removed members) meet MinimalVoteThreshold
- Result: Proposal executes with 60% current member approval instead of requiring 100% participation

**Affected Parties:** Any Association organization that changes membership while having active proposals, potentially allowing minority control through coordinated membership manipulation.

### Likelihood Explanation

**Reachable Entry Point:** Uses public methods (`AddMember`, `RemoveMember`, `Approve`, `Reject`, `Abstain`) accessible through standard proposal execution. [8](#0-7) [6](#0-5) 

**Feasible Preconditions:** Requires ability to pass proposals for adding/removing members, which is possible if:
1. Organization has legitimate membership changes over time (non-malicious scenario)
2. Attacker controls sufficient votes to manipulate membership (malicious scenario)

**Execution Practicality:** All steps are standard contract operations:
1. Create proposal to add members → requires proposer whitelist access
2. Vote and release addition proposal → requires MinimalApprovalThreshold
3. Create target proposal → requires proposer whitelist access
4. Temporary members vote → standard voting
5. Create proposal to remove members → requires proposer whitelist access
6. Vote and release removal proposal → requires MinimalApprovalThreshold
7. Current members vote on target → standard voting
8. Release target proposal → votes from removed members count

**Likelihood Assessment:** MEDIUM - Requires coordination of multiple proposals but uses only standard contract functionality. More likely in organizations with frequent membership changes or where a faction seeks to game governance thresholds.

### Recommendation

**Code Fix:** Change the MinimalVoteThreshold check to filter by current organization membership, matching the implementation in Parliament contract and other threshold checks:

```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**Invariant Check:** Add assertion that all votes counted toward thresholds are from current members.

**Test Cases:**
1. Test that votes from removed members do NOT count toward MinimalVoteThreshold
2. Test proposal release fails if only non-member votes would meet threshold
3. Test membership changes during active proposal lifecycle
4. Regression test matching Parliament contract behavior

### Proof of Concept

**Initial State:**
- Organization address: `OrgAddress`
- Members: [A, B, C, D, E] (5 members)
- Thresholds: MinimalVoteThreshold=5, MinimalApprovalThreshold=3, MaximalRejectionThreshold=1, MaximalAbstentionThreshold=1
- Proposer whitelist: [A]

**Attack Sequence:**

1. **Add Temporary Members:** Member A creates proposal P1 to add members F and G
   - A, B, C approve P1; D abstains
   - P1 releases, executing `AddMember(F)` and `AddMember(G)`
   - Current members: [A, B, C, D, E, F, G] (7 members)

2. **Create Target Proposal:** Member A creates malicious proposal P2 (e.g., change thresholds to enable future attacks)

3. **Temporary Members Vote:** F and G cast Abstain votes on P2
   - P2 state: Abstentions=[F, G], Approvals=[], Rejections=[]

4. **Remove Temporary Members:** Member A creates proposal P3 to remove F and G
   - A, B, C approve P3; D abstains
   - P3 releases, executing `RemoveMember(F)` and `RemoveMember(G)`
   - Current members: [A, B, C, D, E] (5 members)

5. **Current Members Vote:** A, B, C approve P2
   - P2 state: Abstentions=[F, G], Approvals=[A, B, C], Rejections=[]

6. **Release Check (Vulnerable):**
   - `approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains)` = 3 (only A,B,C) ✓ passes MinimalApprovalThreshold=3
   - `totalVotes = proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count()` = 5 (F,G,A,B,C) ✓ passes MinimalVoteThreshold=5
   - P2 can be released

**Expected Result (Secure):** Proposal P2 should FAIL because only 3 current members participated (< MinimalVoteThreshold=5)

**Actual Result (Vulnerable):** Proposal P2 PASSES because removed members F and G's votes still count toward MinimalVoteThreshold

**Success Condition:** Malicious proposal executes with only 60% current member participation instead of the required 100% threshold.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L128-131)
```csharp
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-245)
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
```

**File:** contract/AElf.Contracts.Association/Association.cs (L266-279)
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
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-100)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
```
