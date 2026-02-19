### Title
Retroactive Threshold Manipulation Enables Governance Bypass and Denial of Service

### Summary
The Association contract's proposal evaluation logic uses current organization thresholds rather than thresholds at proposal creation time, allowing malicious actors to manipulate voting thresholds after proposals are created. This enables two critical attack vectors: (1) blocking approved proposals from execution by increasing thresholds, and (2) forcing unapproved proposals to become executable by decreasing thresholds, both undermining governance integrity.

### Finding Description

**Root Cause:**
When a proposal is created, the `ProposalInfo` struct stores only the `organization_address` reference, not a snapshot of the voting thresholds. [1](#0-0) 

The `CreateNewProposal` method confirms this - it stores proposal metadata but does not capture threshold values at creation time. [2](#0-1) 

**Exploitation Path:**
When the `Release` method is called, it fetches the organization from state and evaluates the proposal against the organization's *current* thresholds, not historical ones. [3](#0-2) 

The `IsReleaseThresholdReached` function and its sub-checks (`IsProposalRejected`, `IsProposalAbstained`, `CheckEnoughVoteAndApprovals`) all read threshold values directly from the `organization` parameter passed at evaluation time. [4](#0-3) 

The `ChangeOrganizationThreshold` method allows direct modification of these thresholds in state, affecting all existing proposals retroactively. [5](#0-4) 

**Existing Test Demonstrates Vulnerability:**
The codebase contains a test that explicitly demonstrates this behavior - a proposal with `ToBeReleased = true` becomes `ToBeReleased = false` after thresholds are increased, proving that threshold changes retroactively affect existing proposals. [6](#0-5) 

### Impact Explanation

**Attack Vector 1 - Governance Denial of Service:**
- A critical proposal (e.g., emergency patch, fund recovery) is properly approved under current thresholds
- Before release, an attacker creates and approves a `ChangeOrganizationThreshold` proposal that increases `MinimalApprovalThreshold`, `MinimalVoteThreshold`, or decreases `MaximalRejectionThreshold`/`MaximalAbstentionThreshold`
- The original proposal can no longer be released despite having sufficient approvals when created
- Critical governance actions are permanently blocked without additional re-voting

**Attack Vector 2 - Unauthorized Proposal Execution:**
- A dangerous proposal (e.g., unauthorized fund transfer, malicious contract upgrade) fails to meet approval thresholds
- Attacker creates and approves a `ChangeOrganizationThreshold` proposal that decreases `MinimalApprovalThreshold` or increases `MaximalRejectionThreshold`/`MaximalAbstentionThreshold`
- The originally-rejected proposal suddenly becomes executable
- Malicious actions execute without proper authorization at creation time

**Severity: CRITICAL**
- Violates core governance invariant that proposals should be evaluated against creation-time rules
- Enables unauthorized contract execution or governance paralysis
- No time locks or safeguards prevent threshold manipulation
- Affects all proposals in the organization simultaneously

### Likelihood Explanation

**Reachable Entry Point:**
The `ChangeOrganizationThreshold` method is a standard public interface in the ACS3 governance standard, callable through the organization's proposal mechanism. [5](#0-4) 

**Feasible Preconditions:**
- Attacker needs to be an organization member (or control sufficient members)
- Attacker must be able to create and approve a `ChangeOrganizationThreshold` proposal
- No special privileges beyond normal organization participation required
- Works on any Association organization

**Execution Practicality:**
1. Monitor for high-value proposals in voting phase
2. Create `ChangeOrganizationThreshold` proposal with manipulated thresholds
3. Get organization approval for threshold change (may be easier than the original proposal)
4. Execute threshold change before original proposal is released
5. Original proposal now fails or succeeds based on attacker's goal

**Attack Complexity: LOW**
- Standard contract methods, no exploit code needed
- Race condition between proposal approval and release provides attack window
- Multiple organization members increases likelihood of collusion

**Economic Rationality:**
The cost of creating and approving a threshold change proposal is minimal compared to potential gains from blocking critical proposals or forcing malicious ones through. Gas costs are negligible versus value of governance manipulation.

**Likelihood: HIGH**

### Recommendation

**Immediate Mitigation:**
Modify `ProposalInfo` to store a snapshot of `ProposalReleaseThreshold` at creation time:

```protobuf
message ProposalInfo {
    // ... existing fields ...
    ProposalReleaseThreshold creation_threshold = 14;  // ADD THIS
}
```

**Code Changes Required:**

1. Update `CreateNewProposal` to capture thresholds at creation:
```csharp
var organization = State.Organizations[input.OrganizationAddress];
var proposal = new ProposalInfo {
    // ... existing fields ...
    CreationThreshold = organization.ProposalReleaseThreshold  // ADD THIS
};
```

2. Update all threshold check functions to accept `ProposalReleaseThreshold` from proposal instead of organization:
```csharp
private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
{
    // Use proposal.CreationThreshold instead of organization.ProposalReleaseThreshold
    var isRejected = IsProposalRejected(proposal, organization, proposal.CreationThreshold);
    // ... rest of logic
}
```

3. Update `Release` method to use proposal's stored thresholds:
```csharp
Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**Additional Safeguards:**
- Add event emission when thresholds change showing count of affected active proposals
- Consider time-lock on threshold changes to allow proposal completion
- Document clearly that threshold changes do NOT affect existing proposals (after fix)

**Test Cases:**
- Verify proposal remains releasable after threshold increase
- Verify proposal remains non-releasable after threshold decrease
- Test all four threshold parameters independently
- Add regression test that explicitly forbids the vulnerability demonstrated in the existing test

### Proof of Concept

**Initial State:**
- Organization exists with: MinimalApprovalThreshold=1, MinimalVoteThreshold=1, MaximalAbstentionThreshold=1, MaximalRejectionThreshold=1
- Organization has 3 members: Alice, Bob, Charlie
- Alice is in proposer whitelist

**Attack Sequence (Governance DoS):**

1. **T0:** Alice creates Proposal_A (e.g., emergency fund recovery)
2. **T1:** Alice approves Proposal_A (1/1 threshold met, proposal is ready to release)
3. **T2:** Bob creates Proposal_B to call `ChangeOrganizationThreshold` with MinimalVoteThreshold=2
4. **T3:** Alice approves Proposal_B (1/1 threshold met)
5. **T4:** Bob releases Proposal_B, changing MinimalVoteThreshold from 1 to 2
6. **T5:** Alice attempts to release Proposal_A
   - **Expected:** Proposal_A releases successfully (had sufficient approvals at creation)
   - **Actual:** Transaction reverts with "Not approved." error
   - **Result:** Proposal_A is permanently blocked despite having proper approvals

**Success Condition:**
The existing test explicitly demonstrates this behavior, where `proposal.ToBeReleased` changes from `true` to `false` after threshold modification. [7](#0-6) 

**Verification:**
Run the existing `Change_OrganizationThreshold_Test` which proves that a proposal meeting release criteria becomes non-releasable after threshold increase, confirming the vulnerability.

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-59)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
    }

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

**File:** contract/AElf.Contracts.Association/Association.cs (L203-216)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationThresholdChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerReleaseThreshold = input
        });
        return new Empty();
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L740-787)
```csharp
    public async Task Change_OrganizationThreshold_Test()
    {
        var minimalApproveThreshold = 1;
        var minimalVoteThreshold = 1;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);
        var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
        await ApproveAsync(Reviewer1KeyPair, proposalId);
        var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
        proposal.ToBeReleased.ShouldBeTrue();


        {
            var proposalReleaseThresholdInput = new ProposalReleaseThreshold
            {
                MinimalVoteThreshold = 2
            };

            var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
            var changeProposalId = await CreateAssociationProposalAsync(Reviewer1KeyPair,
                proposalReleaseThresholdInput,
                nameof(associationContractStub.ChangeOrganizationThreshold), organizationAddress);
            await ApproveAsync(Reviewer1KeyPair, changeProposalId);
            var result = await associationContractStub.Release.SendWithExceptionAsync(changeProposalId);
            result.TransactionResult.Error.ShouldContain("Invalid organization.");
        }

        {
            var proposalReleaseThresholdInput = new ProposalReleaseThreshold
            {
                MinimalVoteThreshold = 2,
                MinimalApprovalThreshold = minimalApproveThreshold
            };

            var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
            var changeProposalId = await CreateAssociationProposalAsync(Reviewer1KeyPair,
                proposalReleaseThresholdInput,
                nameof(associationContractStub.ChangeOrganizationThreshold), organizationAddress);
            await ApproveAsync(Reviewer1KeyPair, changeProposalId);
            var result = await associationContractStub.Release.SendAsync(changeProposalId);
            result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            proposal = await associationContractStub.GetProposal.CallAsync(proposalId);
            proposal.ToBeReleased.ShouldBeFalse();
        }
    }
```
