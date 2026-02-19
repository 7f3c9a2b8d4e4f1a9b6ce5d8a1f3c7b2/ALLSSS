### Title
Retroactive Threshold Manipulation Allows Governance Rule Changes to Affect Existing Proposals

### Summary
The Association, Parliament, and Referendum contracts allow organization thresholds (MinimalApprovalThreshold, MaximalRejectionThreshold, MaximalAbstentionThreshold) to be modified after proposal creation. When a proposal is released, the contract uses the organization's current thresholds rather than the thresholds that existed at proposal creation time, allowing retroactive manipulation of proposal approval requirements. This violates governance integrity by enabling proposals to pass or fail based on rules different from those in effect when voting occurred.

### Finding Description

When a proposal is created, it stores only the `organization_address` reference, not a snapshot of the organization's thresholds: [1](#0-0) [2](#0-1) 

When the `Release` method is called to execute a proposal, it fetches the organization's current state from storage and checks against current thresholds: [3](#0-2) 

The threshold checking functions all use the `organization` parameter's current threshold values: [4](#0-3) 

Organizations can modify their thresholds through the `ChangeOrganizationThreshold` method: [5](#0-4) 

**Root Cause**: Proposals do not snapshot organization parameters at creation time. Instead, they maintain only a reference to the organization address. When proposal release eligibility is checked, the current organization state is fetched, causing threshold changes to retroactively affect all existing proposals.

**Why Protections Fail**: The `ChangeOrganizationThreshold` method validates only that the new thresholds form a valid configuration. It does not check for or prevent impact on existing proposals. The test suite explicitly demonstrates this behavior: [6](#0-5) 

This test shows a proposal transitioning from `ToBeReleased = true` to `ToBeReleased = false` after the organization's `MinimalVoteThreshold` is increased from 5000 to 20000, confirming that existing proposals use new thresholds.

The same vulnerability exists in Parliament and Referendum contracts: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Governance Integrity Compromise (Critical)**:
- **Retroactive Rule Changes**: Proposals that received sufficient votes under one set of rules can fail to release if thresholds are increased, or conversely, proposals lacking sufficient votes can pass if thresholds are decreased.
- **Strategic Manipulation**: Malicious actors who control proposal creation can:
  1. Create a contentious proposal P1 that would normally fail to meet approval thresholds
  2. Create proposal P2 to lower thresholds (with benign justification)
  3. After P2 passes and lowers thresholds, release P1 which now meets the reduced requirements
  4. Alternatively, raise thresholds to block a nearly-approved opposition proposal
- **Violation of Governance Social Contract**: Participants vote based on the rules in effect at voting time. Retroactively changing these rules undermines trust in the governance system.
- **Impact Scope**: Affects all three core governance contracts (Association, Parliament, Referendum) which control critical protocol operations including contract deployment, parameter changes, and fund allocation.

**Who is Affected**:
- All organization members whose voting decisions were made under different threshold assumptions
- Protocol security, as governance is the ultimate authority for contract upgrades and system parameters
- Stakeholders relying on governance predictability for investment decisions

### Likelihood Explanation

**Attacker Capabilities**:
- Attacker must be an authorized proposer in the organization
- Attacker must successfully pass a `ChangeOrganizationThreshold` proposal, requiring current threshold approval
- Once threshold change is approved, all existing proposals are immediately affected

**Attack Complexity**: Medium
- Not a direct exploit—requires passing governance process first
- However, threshold changes can be justified with legitimate-sounding reasons ("adjusting for organization growth")
- Strategic timing enables manipulation: propose threshold change during low activity periods, then exploit on pending proposals

**Feasibility Conditions**:
- Organization must have `ChangeOrganizationThreshold` enabled (standard configuration)
- Sufficient coordination to pass threshold change proposal
- Existence of other pending proposals to exploit

**Detection Constraints**:
- Threshold changes are visible on-chain via `OrganizationThresholdChanged` events
- However, retrospective impact on existing proposals is not immediately obvious
- No built-in monitoring for proposals affected by threshold changes

**Probability**: High for organizations with active governance, as threshold modifications are legitimate administrative actions that may occur without recognition of their retroactive impact.

### Recommendation

**1. Snapshot Thresholds at Proposal Creation**:

Modify `ProposalInfo` to include threshold snapshot fields. In `Association_Helper.cs` `CreateNewProposal`:

```csharp
var organization = State.Organizations[input.OrganizationAddress];
var proposal = new ProposalInfo
{
    // ... existing fields ...
    OrganizationAddress = input.OrganizationAddress,
    // Add snapshot fields:
    SnapshotMinimalApprovalThreshold = organization.ProposalReleaseThreshold.MinimalApprovalThreshold,
    SnapshotMinimalVoteThreshold = organization.ProposalReleaseThreshold.MinimalVoteThreshold,
    SnapshotMaximalRejectionThreshold = organization.ProposalReleaseThreshold.MaximalRejectionThreshold,
    SnapshotMaximalAbstentionThreshold = organization.ProposalReleaseThreshold.MaximalAbstentionThreshold,
    SnapshotMemberList = organization.OrganizationMemberList.Clone()
};
```

**2. Use Snapshotted Thresholds in Release Logic**:

Modify threshold checking functions to accept snapshotted values instead of fetching current organization state:

```csharp
private bool IsReleaseThresholdReached(ProposalInfo proposal)
{
    var isRejected = IsProposalRejected(proposal);
    if (isRejected) return false;
    var isAbstained = IsProposalAbstained(proposal);
    return !isAbstained && CheckEnoughVoteAndApprovals(proposal);
}

private bool IsProposalRejected(ProposalInfo proposal)
{
    var rejectionMemberCount = proposal.Rejections.Count(proposal.SnapshotMemberList.Contains);
    return rejectionMemberCount > proposal.SnapshotMaximalRejectionThreshold;
}
```

**3. Apply Fix to All Governance Contracts**:

Apply the same snapshotting fix to Parliament and Referendum contracts to maintain consistency across the governance system.

**4. Add Regression Tests**:

Create tests that explicitly verify:
- Threshold changes do not affect existing proposals' release eligibility
- Proposals approved under old thresholds remain approved after threshold increase
- Proposals rejected under old thresholds remain rejected after threshold decrease

### Proof of Concept

**Initial State**:
- Association organization O with 5 members: [M1, M2, M3, M4, M5]
- Initial thresholds: `MinimalApprovalThreshold = 3, MinimalVoteThreshold = 4`
- Current block time: Day 0

**Attack Sequence**:

1. **Attacker creates contentious proposal P1** (Day 0):
   - Proposal to execute sensitive action (e.g., transfer organization funds)
   - Currently, P1 needs 3 approvals out of 4 votes to pass
   - P1 expires on Day 10

2. **Early voting on P1** (Day 0-2):
   - M1 approves, M2 approves (2 approvals)
   - M3 rejects
   - Total: 2 approvals, 1 rejection, 2 abstentions
   - Status: Cannot be released (needs 3 approvals)

3. **Attacker creates threshold change proposal P2** (Day 3):
   - Proposal to call `ChangeOrganizationThreshold`
   - New thresholds: `MinimalApprovalThreshold = 2, MinimalVoteThreshold = 3`
   - Justification: "Reducing threshold to improve governance efficiency"

4. **P2 gets approved** (Day 3-5):
   - M1, M2, M3 approve P2 (meets current 3-approval threshold)
   - P2 is released, thresholds change to new values

5. **P1 is now releasable** (Day 6):
   - P1 still has only 2 approvals, 1 rejection
   - Under NEW thresholds (MinimalApprovalThreshold = 2), P1 can now be released
   - Attacker releases P1 successfully

**Expected Result (Secure Behavior)**:
- P1 should require 3 approvals as specified when it was created
- P1 should remain blocked despite threshold change

**Actual Result (Vulnerable Behavior)**:
- P1 uses new threshold of 2 approvals
- P1 can be released with only 2 approvals
- Attacker successfully executes proposal that should have failed

**Success Condition**: P1 releases with 2 approvals after threshold was lowered from 3 to 2, despite being created under the 3-approval requirement. This demonstrates retroactive threshold manipulation enabling unauthorized proposal execution.

### Citations

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

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L700-761)
```csharp
    public async Task Change_OrganizationThreshold_Test()
    {
        var minimalApproveThreshold = 5000;
        var minimalVoteThreshold = 5000;
        var maximalRejectionThreshold = 10000;
        var maximalAbstentionThreshold = 10000;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, new[] { DefaultSender });
        var proposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
        var keyPair = Accounts[3].KeyPair;
        await ApproveAllowanceAsync(keyPair, minimalApproveThreshold, proposalId);
        await ApproveAsync(Accounts[3].KeyPair, proposalId);
        var proposal = await ReferendumContractStub.GetProposal.CallAsync(proposalId);
        proposal.ToBeReleased.ShouldBeTrue();

        // invalid sender
        {
            var ret =
                await ReferendumContractStub.ChangeOrganizationThreshold.SendWithExceptionAsync(
                    new ProposalReleaseThreshold());
            ret.TransactionResult.Error.ShouldContain("Organization not found");
        }

        {
            var proposalReleaseThresholdInput = new ProposalReleaseThreshold
            {
                MinimalVoteThreshold = 20000
            };

            var changeProposalId = await CreateReferendumProposalAsync(DefaultSenderKeyPair,
                proposalReleaseThresholdInput,
                nameof(ReferendumContractStub.ChangeOrganizationThreshold), organizationAddress,
                ReferendumContractAddress);
            await ApproveAllowanceAsync(keyPair, minimalApproveThreshold, changeProposalId);
            await ApproveAsync(Accounts[3].KeyPair, changeProposalId);
            var referendumContractStub = GetReferendumContractTester(DefaultSenderKeyPair);
            var result = await referendumContractStub.Release.SendWithExceptionAsync(changeProposalId);
            result.TransactionResult.Error.ShouldContain("Invalid organization.");
        }

        {
            var proposalReleaseThresholdInput = new ProposalReleaseThreshold
            {
                MinimalVoteThreshold = 20000,
                MinimalApprovalThreshold = minimalApproveThreshold
            };

            ReferendumContractStub = GetReferendumContractTester(DefaultSenderKeyPair);
            var changeProposalId = await CreateReferendumProposalAsync(DefaultSenderKeyPair,
                proposalReleaseThresholdInput,
                nameof(ReferendumContractStub.ChangeOrganizationThreshold), organizationAddress,
                ReferendumContractAddress);
            await ApproveAllowanceAsync(keyPair, minimalApproveThreshold, changeProposalId);
            await ApproveAsync(Accounts[3].KeyPair, changeProposalId);
            var referendumContractStub = GetReferendumContractTester(DefaultSenderKeyPair);
            var result = await referendumContractStub.Release.SendAsync(changeProposalId);
            result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

            proposal = await referendumContractStub.GetProposal.CallAsync(proposalId);
            proposal.ToBeReleased.ShouldBeFalse();
        }
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-160)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
    }

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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L124-177)
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

    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposerWhiteList = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }

    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }

    public override Empty Release(Hash input)
    {
        var proposal = GetValidProposal(input);
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
        var organization = State.Organizations[proposal.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposal.ToAddress,
            proposal.ContractMethodName, proposal.Params);

        Context.Fire(new ProposalReleased { ProposalId = input });
        State.Proposals.Remove(input);

        return new Empty();
    }
```
