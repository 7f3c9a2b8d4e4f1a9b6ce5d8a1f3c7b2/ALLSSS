### Title
Ghost Vote Counting Vulnerability: Removed Members' Votes Still Count Toward MinimalVoteThreshold

### Summary
The Association contract contains a critical inconsistency in vote counting logic. When checking if the MinimalVoteThreshold is reached, the contract counts all votes including those from removed members, but when checking abstention/rejection thresholds, it only counts current members. This allows proposals to pass with insufficient participation from current organization members by exploiting ghost votes from members removed after voting.

### Finding Description

The vulnerability exists in `Association_Helper.cs` where vote counting logic is inconsistent across different threshold checks.

**The Inconsistency:**

At lines 43-44, `IsProposalAbstained()` filters abstentions to only count votes from current organization members: [1](#0-0) 

Similarly, `IsProposalRejected()` at line 37 only counts rejections from current members: [2](#0-1) 

And `CheckEnoughVoteAndApprovals()` at line 49 only counts approvals from current members: [3](#0-2) 

**However**, at lines 56-57, the same `CheckEnoughVoteAndApprovals()` function counts ALL votes (abstentions, approvals, and rejections) without filtering by current membership: [4](#0-3) 

**Root Cause:**

The proposal vote lists (`Abstentions`, `Approvals`, `Rejections`) permanently store all addresses that voted, and these lists are never cleaned when members are removed: [5](#0-4) 

When members are removed via `RemoveMember()`, their past votes remain in the proposal: [6](#0-5) 

The `IsReleaseThresholdReached()` function orchestrates all threshold checks: [7](#0-6) 

**Why Protections Fail:**

Members must be current members when voting (verified by `AssertIsAuthorizedOrganizationMember`): [8](#0-7) 

However, there is no mechanism to invalidate or recount votes after member removal. The unfiltered count at line 56-57 treats removed members' votes as valid participation.

### Impact Explanation

**Concrete Harm:**
- Proposals can execute without sufficient current member participation, violating the organization's governance model
- The MinimalVoteThreshold becomes meaningless as it can be satisfied by ghost votes from removed members
- Malicious majority can manipulate proposal passage by strategically removing dissenting members after they vote

**Quantified Scenario:**
Organization with 10 members, thresholds: MinimalVoteThreshold=8, MinimalApprovalThreshold=6, MaximalAbstentionThreshold=1.
1. Three members abstain
2. Organization removes these three members (7 remain)
3. Six current members approve
4. Actual current participation: 6/7 members (85.7%)
5. Counted participation: 9 votes total (includes 3 ghost votes)
6. Proposal passes MinimalVoteThreshold (9≥8) despite only 6/7 current members voting

**Who Is Affected:**
- All Association-governed organizations
- Any multi-signature operations relying on accurate member participation tracking
- Critical protocol operations (Treasury releases, configuration changes, cross-chain operations)

**Severity Justification:** HIGH
- Breaks fundamental governance invariant that thresholds represent current member participation
- Enables unauthorized proposal execution through governance manipulation
- Affects all Association contracts system-wide

### Likelihood Explanation

**Attacker Capabilities:**
Requires control of a majority of organization members to:
1. Pass proposals to remove specific members
2. Coordinate voting sequences

**Attack Complexity:** MEDIUM
- Requires multiple coordinated transactions
- Must time member removals between voting and release
- Needs to calculate exact thresholds to exploit the gap

**Feasibility Conditions:**
- Works on any active Association organization
- No special permissions beyond normal member voting rights
- All steps use public methods with standard access control

**Detection Constraints:**
- Difficult to detect as votes and member changes appear legitimate separately
- The inconsistency is only visible when comparing filtered vs unfiltered counts
- No events or logs highlight this discrepancy

**Probability:** MEDIUM-HIGH
- Attack is practical for any organization with contentious proposals
- Economically rational when proposal value exceeds coordination cost
- Natural occurrence possible even without malicious intent during normal member turnover

### Recommendation

**Immediate Fix:**

Modify line 56-57 in `Association_Helper.cs` to filter votes by current membership:

```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
    proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
    proposal.Rejections.Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**Invariant Check to Add:**
Add assertion that all vote counting operations consistently filter by current membership status.

**Test Cases:**
1. Create proposal, have members vote, remove voting members, verify proposal cannot pass with ghost votes
2. Test edge case where MinimalVoteThreshold equals current member count
3. Verify all threshold checks (approval, rejection, abstention, vote) use consistent filtering

**Alternative Consideration:**
Implement a `CleanProposalVotes()` function that removes votes from ex-members when members are removed, though filtering is simpler and safer.

### Proof of Concept

**Initial State:**
- Organization created with 10 members: [A, B, C, D, E, F, G, H, I, J]
- Thresholds set: MinimalVoteThreshold=8, MinimalApprovalThreshold=6, MaximalAbstentionThreshold=1, MaximalRejectionThreshold=1
- Proposal X created by authorized proposer

**Attack Sequence:**

1. **Members A, B, C call `Abstain(proposalX)`**
   - proposal.Abstentions = [A, B, C]

2. **Organization executes three proposals to call `RemoveMember(A)`, `RemoveMember(B)`, `RemoveMember(C)`**
   - organization.OrganizationMemberList = [D, E, F, G, H, I, J] (7 members)
   - proposal.Abstentions still = [A, B, C] (unchanged)

3. **Members D, E, F, G, H, I call `Approve(proposalX)`**
   - proposal.Approvals = [D, E, F, G, H, I]

4. **Member D (proposer) calls `Release(proposalX)`**

**Expected Result:**
Proposal should FAIL because:
- Only 6 current members voted (6 < 8 MinimalVoteThreshold)

**Actual Result:**
Proposal PASSES because:
- `IsProposalAbstained()`: abstentionMemberCount = 0 (A, B, C not in current list) ✓
- `IsProposalRejected()`: rejectionMemberCount = 0 ✓
- `CheckEnoughVoteAndApprovals()`: approvedMemberCount = 6 ≥ 6 ✓
- `CheckEnoughVoteAndApprovals()`: total votes = 3 + 6 + 0 = 9 ≥ 8 ✓

**Success Condition:**
Proposal executes despite only 6/7 current members participating, violating the intended 8-vote minimum threshold.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-32)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-49)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L56-57)
```csharp
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

**File:** protobuf/association_contract.proto (L92-96)
```text
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L163-180)
```csharp
    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Abstentions.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Abstain),
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
