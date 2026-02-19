### Title
Time-of-Check-Time-of-Use Vulnerability in Proposal Rejection Count Allows Governance Bypass Through Member Manipulation

### Summary
The `IsProposalRejected()` function recalculates rejection counts using the current organization membership at release time, not the membership snapshot at voting time. This allows attackers to bypass legitimate proposal rejections by removing rejecting members between voting and release, violating critical governance invariants and enabling unauthorized proposal execution.

### Finding Description

The vulnerability exists in the rejection count calculation mechanism. [1](#0-0) 

The root cause is that `IsProposalRejected()` filters the proposal's rejection list against the **current** organization membership using `organization.OrganizationMemberList.Contains()`, rather than using a membership snapshot from when votes were cast. The rejection addresses are stored in the proposal at voting time [2](#0-1) , but are evaluated against potentially modified membership during release.

Organization membership can be modified through three functions that are callable by the organization itself via proposal execution: [3](#0-2) , [4](#0-3) , and [5](#0-4) .

The vulnerable check occurs during proposal release where `IsReleaseThresholdReached()` evaluates the proposal status: [6](#0-5) , and this is enforced during the Release function execution: [7](#0-6) .

There are no protections against membership changes after voting, no membership snapshots captured at proposal creation or voting time, and no locks preventing member removal for proposals with active votes.

### Impact Explanation

**Governance Bypass:** Proposals that were legitimately rejected by the organization can be executed after membership manipulation, completely undermining the multi-signature governance model.

**Concrete Attack Scenario:**
- Organization with 7 members [A,B,C,D,E,F,G], thresholds: MinimalApproval=3, MaximalRejection=3
- Malicious Proposal P1 receives 3 approvals (A,B,C) and 4 rejections (D,E,F,G)
- P1 is correctly rejected (4 > 3)
- Attacker orchestrates legitimate Proposal P2 to remove member D
- After D's removal, P1's rejectionMemberCount recalculates to 3 (only E,F,G remain as members)
- Since 3 is NOT > 3, P1 is no longer rejected and can be released

**Affected Parties:** All Association-based governance organizations, including critical system governance that controls protocol parameters, treasury funds, and cross-chain operations.

**Severity Justification:** CRITICAL - This violates the fundamental governance invariant that rejection decisions should be final and immutable. It enables unauthorized execution of proposals that the organization explicitly rejected, potentially leading to theft of treasury funds, unauthorized protocol changes, or malicious contract calls.

### Likelihood Explanation

**Attacker Capabilities:** Attacker needs either:
1. Ability to influence legitimate member removal proposals (social engineering, waiting for natural membership changes)
2. Control of sufficient votes to pass member removal proposals

**Attack Complexity:** MODERATE
- Requires proposal creation and voting (standard governance operations)
- Requires timing manipulation (waiting between rejection and member removal)
- Does not require any contract exploits or privilege escalation

**Feasibility Conditions:**
- Organizations with moderate member turnover are naturally vulnerable
- Long-lived proposals (before expiration) have extended exploitation windows
- Organizations with lower MaximalRejectionThreshold values are easier to manipulate (fewer members need removal)

**Detection Constraints:** Difficult to detect as all operations appear legitimate - member removals may have valid reasons unrelated to vote manipulation.

**Probability:** HIGH for active organizations with dynamic membership, MODERATE-HIGH overall given that this affects the core governance mechanism used throughout the AElf ecosystem.

### Recommendation

**Immediate Fix:** Implement membership snapshot at proposal creation time:

1. Store organization membership snapshot in `ProposalInfo` when proposal is created
2. Modify vote counting functions to use the snapshot instead of current membership:
   - `IsProposalRejected()` should filter against snapshot
   - `IsProposalAbstained()` should filter against snapshot  
   - `CheckEnoughVoteAndApprovals()` should filter against snapshot

**Code-Level Mitigation:**
```
// In Association_Helper.cs CreateNewProposal():
proposal.MembershipSnapshot = organization.OrganizationMemberList.Clone();

// In IsProposalRejected():
var rejectionMemberCount = proposal.Rejections.Count(proposal.MembershipSnapshot.Contains);
```

**Invariant to Enforce:** Vote weight calculations must use membership composition from proposal creation time, not release time.

**Test Cases:**
1. Create proposal, members vote to reject, remove rejecting member, verify proposal remains rejected
2. Create proposal with approval, remove approving members, verify proposal cannot be released
3. Test edge cases where membership changes exactly at threshold boundaries

### Proof of Concept

**Initial State:**
- Organization Address: `OrgX`
- Members: `[Alice, Bob, Charlie, David, Eve, Frank, George]` (7 members)
- Thresholds: `MinimalApprovalThreshold=3, MaximalRejectionThreshold=3, MinimalVoteThreshold=4`

**Transaction Sequence:**

1. **Create Malicious Proposal P1** (e.g., transfer treasury funds to attacker)
   - Proposer: Alice
   - Target: Treasury contract, method: `Transfer(attacker, 1000000 tokens)`

2. **Voting on P1:**
   - Alice calls `Approve(P1)` → Approvals: [Alice]
   - Bob calls `Approve(P1)` → Approvals: [Alice, Bob]
   - Charlie calls `Approve(P1)` → Approvals: [Alice, Bob, Charlie]
   - David calls `Reject(P1)` → Rejections: [David]
   - Eve calls `Reject(P1)` → Rejections: [David, Eve]
   - Frank calls `Reject(P1)` → Rejections: [David, Eve, Frank]
   - George calls `Reject(P1)` → Rejections: [David, Eve, Frank, George]

3. **Current State of P1:**
   - `approvedMemberCount = 3` (Alice, Bob, Charlie all in membership)
   - `rejectionMemberCount = 4` (David, Eve, Frank, George all in membership)
   - `4 > 3` (MaximalRejectionThreshold) → **Proposal P1 is REJECTED**
   - Alice attempts `Release(P1)` → **FAILS** with "Not approved."

4. **Create Member Removal Proposal P2:**
   - Proposer: Bob
   - Target: OrgX, method: `RemoveMember(David)`
   - Justification: "David leaving organization" (legitimate-sounding reason)

5. **Voting on P2:**
   - Alice, Bob, Charlie, Eve vote to approve P2
   - P2 meets approval threshold and is released
   - `RemoveMember(David)` executes successfully
   - Organization members now: `[Alice, Bob, Charlie, Eve, Frank, George]` (6 members)

6. **Exploit - Release P1 After Membership Change:**
   - Alice calls `Release(P1)`
   - **Re-evaluation at release time:**
     - `approvedMemberCount = 3` (Alice, Bob, Charlie still members) ✓
     - `rejectionMemberCount = 3` (only Eve, Frank, George counted; David removed) 
     - Check: `3 > 3`? → **FALSE** → Proposal is NOT rejected ✓
     - Total votes: 7 >= 4 (MinimalVoteThreshold) ✓
     - Approvals: 3 >= 3 (MinimalApprovalThreshold) ✓
   - **Result: `Release(P1)` SUCCEEDS**
   - Malicious treasury transfer executes

**Expected vs Actual:**
- **Expected:** P1 should remain permanently rejected (4 rejection votes were cast)
- **Actual:** P1 becomes releasable after David's removal (only 3 rejection votes count)

**Success Condition:** Transaction in step 6 succeeds when it should fail, demonstrating that a legitimately rejected proposal can be executed through membership manipulation.

### Notes

This vulnerability also affects the approval and abstention counting mechanisms [8](#0-7)  and [9](#0-8) , which use the same pattern of filtering against current membership. The same TOCTOU vulnerability exists for approval manipulation (removing approving members to prevent release) and abstention manipulation.

The vulnerability is protocol-wide as the Association contract is used throughout AElf's governance infrastructure for Parliament alternatives, system contract governance, and organizational decision-making. The lack of membership snapshots fundamentally breaks the time-binding nature of voting decisions.

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

**File:** contract/AElf.Contracts.Association/Association.cs (L143-161)
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
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-201)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);

        Context.Fire(new ProposalReleased
        {
            ProposalId = input,
            OrganizationAddress = proposalInfo.OrganizationAddress
        });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-246)
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
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberChanged
        {
            OrganizationAddress = Context.Sender,
            OldMember = input.OldMember,
            NewMember = input.NewMember
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
