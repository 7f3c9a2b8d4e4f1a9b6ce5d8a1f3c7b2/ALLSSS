### Title
Retroactive Threshold Manipulation Violates Proposal Creation Guarantees in Association Contract

### Summary
The `ChangeOrganizationThreshold()` function allows an organization to modify approval thresholds that retroactively affect all existing pending proposals, making previously releasable proposals unreleasable or vice versa. This violates the fundamental governance invariant that proposals should be evaluated under the rules that existed when they were created and when votes were cast, enabling strategic manipulation of governance outcomes.

### Finding Description

**Root Cause:**

The `ProposalInfo` structure does not store a snapshot of the `ProposalReleaseThreshold` at proposal creation time. [1](#0-0) 

When `Release()` evaluates whether a proposal can be executed, it retrieves the organization's current threshold from state and checks against it, rather than using the threshold that was in effect when the proposal was created or when votes were cast. [2](#0-1) 

The threshold checking logic in `IsReleaseThresholdReached()` uses the organization parameter passed to it, which contains the current threshold values from state. [3](#0-2) 

**Vulnerable Execution Path:**

1. Organization has threshold: MinimalApprovalThreshold = 2, MinimalVoteThreshold = 2
2. Proposal A is created and receives 2 approvals (meets threshold)
3. Organization creates and approves Proposal B to call `ChangeOrganizationThreshold()` with new threshold: MinimalVoteThreshold = 3
4. Proposal B is released, changing the organization's threshold [4](#0-3) 
5. Proposal A (which previously met requirements) now fails the release check because it only has 2 votes but the new threshold requires 3

**Why Protections Fail:**

The `ChangeOrganizationThreshold()` function only validates that the new threshold configuration is valid for the organization structure (correct member counts, no negative values, etc.), but performs no checks on how this affects existing proposals. [5](#0-4) 

The protobuf specification explicitly documents this behavior: "All fields will be overwritten by the input value and this will affect all current proposals of the organization." [6](#0-5) 

### Impact Explanation

**Governance Integrity Violation:**
- Voters cast their votes with the expectation that a specific threshold must be met for execution
- Retroactive threshold changes violate this expectation and can reverse governance decisions that were already made
- Previously approved proposals can be blocked, and previously rejected proposals can be made passable

**Strategic Manipulation:**
- An organization controller can wait for a contentious proposal to accumulate votes, then change thresholds to force a desired outcome
- Could be used to push through malicious proposals that wouldn't pass under original rules
- Could be used to block legitimate proposals after they've been approved

**Affected Parties:**
- All organization members who voted on proposals expecting stable evaluation criteria
- Proposers whose proposals may be arbitrarily blocked
- External contracts/users relying on proposal execution timing

**Severity Justification:**
This is a HIGH severity issue because it directly undermines the governance mechanism's trustworthiness and atomicity. The test suite explicitly validates this behavior occurs, confirming a proposal's `ToBeReleased` status can flip from true to false after threshold changes. [7](#0-6) 

### Likelihood Explanation

**Attacker Capabilities:**
- The attacker must control enough votes within the organization to approve a threshold-changing proposal
- This is realistic for any organization where a majority coalition exists or can be formed

**Attack Complexity:**
- LOW - Requires only standard proposal creation and approval workflow
- No special technical knowledge or exploitation techniques needed
- Simply uses intended contract functionality in a manipulative sequence

**Feasibility Conditions:**
- Organization must have pending proposals that would be affected by threshold changes
- Attacker coalition must have sufficient votes to approve the threshold change proposal
- These are common conditions in active governance systems

**Detection Constraints:**
- Threshold changes are publicly visible through `OrganizationThresholdChanged` events
- However, the retroactive effect on existing proposals may not be immediately obvious to observers
- No built-in protections or warnings exist

**Probability:**
HIGH - This attack is practical whenever there are contentious governance decisions pending, making it likely to occur either maliciously or through ignorant/hasty governance actions.

### Recommendation

**Code-Level Mitigation:**

1. **Store Threshold Snapshot:** Modify `ProposalInfo` to include a snapshot of `ProposalReleaseThreshold` at creation time:
```
message ProposalInfo {
    ...
    acs3.ProposalReleaseThreshold threshold_snapshot = 14;
}
```

2. **Use Snapshot in Release Check:** Modify `Release()` to use the snapshot instead of current organization threshold:
```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    // Use threshold from proposal creation time, not current organization
    var thresholdToUse = proposalInfo.ThresholdSnapshot ?? 
                         State.Organizations[proposalInfo.OrganizationAddress].ProposalReleaseThreshold;
    Assert(IsReleaseThresholdReached(proposalInfo, thresholdToUse, proposalInfo.OrganizationAddress), 
           "Not approved.");
    ...
}
```

3. **Add Invariant Check:** Modify `ChangeOrganizationThreshold()` to warn or restrict changes when pending proposals exist, or require a flag confirming the organization understands the impact.

**Alternative Solution:**
Implement a grace period where threshold changes only affect proposals created AFTER the change, not existing ones. This could be enforced by comparing proposal creation time with threshold change time.

**Test Cases:**
- Verify proposals created before threshold change are evaluated with original threshold
- Verify proposals created after threshold change use new threshold  
- Test edge cases with multiple sequential threshold changes
- Verify threshold changes cannot circumvent proposal expiration times

### Proof of Concept

**Initial State:**
- Organization created with: MinimalApprovalThreshold = 2, MinimalVoteThreshold = 2, 3 members
- Proposal A created to transfer 1000 tokens

**Exploitation Steps:**

1. **Proposal A receives votes:**
   - Member1 calls `Approve(ProposalA)` 
   - Member2 calls `Approve(ProposalA)`
   - Query `GetProposal(ProposalA)` returns `ToBeReleased = true` (2/2 threshold met)

2. **Create threshold change proposal:**
   - Member1 creates ProposalB targeting `ChangeOrganizationThreshold()` with new threshold: MinimalVoteThreshold = 3, MinimalApprovalThreshold = 3

3. **Approve and release threshold change:**
   - All 3 members approve ProposalB
   - Member1 calls `Release(ProposalB)` - succeeds, threshold changes to 3

4. **Verify retroactive impact:**
   - Query `GetProposal(ProposalA)` now returns `ToBeReleased = false` (2/3 threshold not met)
   - Member1 attempts `Release(ProposalA)` - transaction fails with "Not approved" error

**Expected Result:** Proposal A should remain releasable since it met the requirements when votes were cast

**Actual Result:** Proposal A becomes non-releasable due to retroactive threshold change, violating governance guarantees

**Success Condition:** The test explicitly validates this behavior exists and occurs as described. [8](#0-7)

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-81)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
        if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
            return false;
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var organizationMemberCount = organization.OrganizationMemberList.Count();
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
    }
```

**File:** protobuf/acs3.proto (L42-46)
```text
    // Change the thresholds associated with proposals.
    // All fields will be overwritten by the input value and this will affect all current proposals of the organization. 
    // Note: only the organization can execute this through a proposal.
    rpc ChangeOrganizationThreshold(ProposalReleaseThreshold)returns(google.protobuf.Empty) {
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L740-786)
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
```
