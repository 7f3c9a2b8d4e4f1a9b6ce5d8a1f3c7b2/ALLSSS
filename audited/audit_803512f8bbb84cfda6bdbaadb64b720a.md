### Title
Retroactive Voting: Newly Added Members Can Vote on Pre-Existing Proposals

### Summary
The Association contract's `AddMember()` function allows organizations to add new members who can immediately vote on proposals that were created before they joined. The proposal approval threshold logic filters votes based on the current organization membership rather than capturing a membership snapshot at proposal creation time, enabling retroactive voting that can manipulate governance outcomes.

### Finding Description

The vulnerability exists in the interaction between member management and proposal voting logic:

**1. Member Addition Without Temporal Restriction:**
The `AddMember()` function adds new members to the organization's current member list without any restrictions on voting eligibility for existing proposals. [1](#0-0) 

**2. Voting Authorization Check:**
When members vote (via `Approve()`, `Reject()`, or `Abstain()`), the only check performed is whether they are in the current organization member list using `AssertIsAuthorizedOrganizationMember()`. [2](#0-1) 

This authorization function only verifies current membership, not membership at proposal creation time: [3](#0-2) 

**3. Root Cause - Threshold Calculation Using Current Membership:**
The critical flaw is in the proposal release threshold checking logic. When determining if a proposal can be released, the code counts votes by filtering them through the **current** organization member list: [4](#0-3) 

The same pattern applies to rejection and abstention counting: [5](#0-4) 

**4. Missing Membership Snapshot:**
The `ProposalInfo` structure stores voter addresses but does NOT capture a snapshot of the organization's member list at proposal creation time: [6](#0-5) 

This design allows votes from newly added members to be counted toward thresholds even though they were not members when the proposal was created.

### Impact Explanation

**Governance Manipulation:**
- Malicious actors can strategically add members after a proposal is created to change its approval status
- A failing proposal can be made to pass by adding friendly members who vote in favor
- A passing proposal can be blocked by adding adversarial members who vote to reject
- This undermines the integrity of the organization's decision-making process

**Attack Scenarios:**
1. **Threshold Gaming**: Organization with 5 members creates a proposal requiring 3 approvals. Only 2 members approve initially. Organization adds 3 new members who immediately vote to approve, reaching threshold retroactively.
2. **Last-Minute Blocking**: A proposal has sufficient approvals to pass. Before release, organization adds new members who vote to reject, pushing rejections over the `MaximalRejectionThreshold`.

**Severity Justification:**
This is a **Medium severity** issue because:
- It requires the organization to call `AddMember()` via proposal execution (authorized action)
- However, it violates the fundamental governance principle that voting rights should be determined at proposal creation time
- It enables manipulation of proposal outcomes without detection
- It affects all Association organizations across the AElf ecosystem

### Likelihood Explanation

**High Likelihood:**

**Attacker Capabilities:**
- The organization itself (via proposal execution) can call `AddMember()`
- This is a normal, intended function of the contract
- No special privileges beyond organization membership required

**Attack Complexity:**
- Low complexity: Create proposal → Add members → New members vote
- Only requires coordination among organization controllers
- No timing constraints or race conditions needed

**Feasibility Conditions:**
- Organization must be able to execute an `AddMember()` proposal
- This is a standard capability by design
- Newly added members just need to call `Approve()`, `Reject()`, or `Abstain()`

**Economic Rationality:**
- Cost is minimal (standard transaction fees)
- Benefit is high (control over proposal outcomes)
- No locked funds or economic penalties

**Detection Constraints:**
- The attack is difficult to detect because `AddMember()` is a legitimate operation
- Voting by new members appears normal in transaction logs
- Only retrospective analysis comparing member join time vs proposal creation time would reveal the issue

### Recommendation

**Code-Level Mitigation:**

1. **Capture Membership Snapshot at Proposal Creation:**
Modify the `ProposalInfo` structure to include the organization member list at creation time:
```protobuf
message ProposalInfo {
    // ... existing fields ...
    OrganizationMemberList eligible_voters = 14; // Snapshot at creation
}
```

2. **Update CreateNewProposal to Store Snapshot:**
When creating proposals, capture and store the current member list: [7](#0-6) 

Add after line 160:
```csharp
EligibleVoters = GetOrganization(input.OrganizationAddress).OrganizationMemberList
```

3. **Modify Authorization Check:**
Update `AssertIsAuthorizedOrganizationMember` to check against the proposal's eligible voters snapshot instead of current organization membership.

4. **Update Threshold Calculations:**
Modify all vote counting logic to filter against `proposal.EligibleVoters` instead of `organization.OrganizationMemberList`:
    - Line 37: `proposal.Rejections.Count(proposal.EligibleVoters.Contains)`
    - Line 43: `proposal.Abstentions.Count(proposal.EligibleVoters.Contains)`
    - Line 49: `proposal.Approvals.Count(proposal.EligibleVoters.Contains)`

**Test Cases:**
1. Create proposal with 5 members, add 2 new members, verify new members CANNOT vote
2. Create proposal, add member, member attempts to vote, verify transaction reverts
3. Create proposal with sufficient approvals, add member who votes reject, verify rejection doesn't count
4. Verify existing members from creation time CAN still vote normally

### Proof of Concept

**Initial State:**
- Organization "OrgA" exists with members: [Alice, Bob, Carol]
- Proposal release threshold: MinimalApprovalThreshold = 2
- MaximalRejectionThreshold = 1

**Attack Sequence:**

1. **T0 - Proposal Creation:**
   - Alice creates Proposal P1 to execute some action
   - Current members: [Alice, Bob, Carol]

2. **T1 - Initial Voting:**
   - Alice votes Approve on P1
   - Approvals: [Alice], Count: 1
   - Proposal cannot be released yet (needs 2 approvals)

3. **T2 - Add New Members:**
   - Organization executes proposal to call `AddMember(Dave)`
   - Organization executes proposal to call `AddMember(Eve)`
   - Current members: [Alice, Bob, Carol, Dave, Eve]

4. **T3 - Retroactive Voting:**
   - Dave calls `Approve(P1)` - **SUCCESS** (should fail but doesn't)
   - Eve calls `Approve(P1)` - **SUCCESS** (should fail but doesn't)
   - Approvals: [Alice, Dave, Eve], Count: 3

5. **T4 - Threshold Check:**
   - `IsReleaseThresholdReached(P1)` called
   - Filters approvals: [Alice, Dave, Eve].Count(CurrentMemberList.Contains)
   - Result: 3 approvals (all three are in current member list)
   - Threshold reached: 3 >= 2 ✓

**Expected Result:**
- Dave and Eve should NOT be able to vote on P1 (created before they joined)
- Proposal should require approvals from original members [Alice, Bob, Carol]

**Actual Result:**
- Dave and Eve CAN vote on P1
- Their votes COUNT toward the approval threshold
- Proposal can be released with votes from non-original members
- **Governance invariant violated: voting eligibility determined retroactively**

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L18-22)
```csharp
    private void AssertIsAuthorizedOrganizationMember(Organization organization, Address member)
    {
        Assert(organization.OrganizationMemberList.Contains(member),
            "Unauthorized member.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-45)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L145-173)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            ToAddress = input.ToAddress,
            OrganizationAddress = input.OrganizationAddress,
            ProposalId = proposalId,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        State.Proposals[proposalId] = proposal;
        Context.Fire(new ProposalCreated
        {
            ProposalId = proposalId,
            OrganizationAddress = input.OrganizationAddress,
            Title = input.Title,
            Description = input.Description
        });
        return proposalId;
    }
```

**File:** protobuf/association_contract.proto (L76-103)
```text
message ProposalInfo {
    // The proposal ID.
    aelf.Hash proposal_id = 1;
    // The method that this proposal will call when being released.
    string contract_method_name = 2;
    // The address of the target contract.
    aelf.Address to_address = 3;
    // The parameters of the release transaction.
    bytes params = 4;
    // The date at which this proposal will expire.
    google.protobuf.Timestamp expired_time = 5;
    // The address of the proposer of this proposal.
    aelf.Address proposer = 6;
    // The address of this proposals organization.
    aelf.Address organization_address = 7;
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
    // Url is used for proposal describing.
    string proposal_description_url = 11;
    // Title of this proposal.
    string title = 12;
    // Description of this proposal.
    string description = 13;
}
```
