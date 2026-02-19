### Title
Governance Lockout via Extreme Threshold Configuration Enabled by Insufficient Validation Bounds

### Summary
The Parliament contract's threshold validation allows organizations to set extreme values (100% approval requirement with 0% tolerance for abstention/rejection) that effectively lock governance permanently. [1](#0-0)  While hardcoded constants don't prevent threshold adaptation via `ChangeOrganizationThreshold`, [2](#0-1)  the lack of hardcoded upper bounds allows an attacker who temporarily controls governance to permanently lock it by setting mathematically impossible approval requirements.

### Finding Description

The hardcoded constants in Parliament_Constants.cs define initial thresholds but don't prevent adaptation. [3](#0-2)  Organizations can modify thresholds through the `ChangeOrganizationThreshold` method executed via proposal. [2](#0-1) 

The critical vulnerability lies in the validation rules that permit extreme configurations. The `Validate` method enforces: [1](#0-0) 

These constraints allow `MinimalApprovalThreshold = 10000` (100%), `MinimalVoteThreshold = 10000` (100%), `MaximalAbstentionThreshold = 0`, and `MaximalRejectionThreshold = 0`. Test cases explicitly verify this configuration is valid and accepted. [4](#0-3) 

The threshold checking logic uses these values to determine if proposals can be released: [5](#0-4)  and [6](#0-5) 

With 100% approval required and zero tolerance for abstentions/rejections, achieving unanimous consensus becomes mathematically impossible in a decentralized system with independent miners, creating permanent governance lockout.

The emergency response organization provides no protection, as it: (1) requires a proposal to create it, [7](#0-6)  (2) has no override authority for `ChangeOrganizationThreshold`, and (3) can be locked the same way. [8](#0-7) 

### Impact Explanation

**Permanent Governance Lockout**: Once thresholds are set to require 100% approval with zero abstention/rejection tolerance, no future proposal can ever pass. This is because:
- Achieving perfect unanimity among independent miners is practically impossible
- Even a single offline/abstaining miner blocks all proposals
- Network cannot adapt to security incidents, miner changes, or emergency situations
- Critical functions become permanently inaccessible (upgrades, parameter adjustments, security responses)

**Affected Parties**: The entire protocol governance becomes non-functional, impacting all stakeholders who rely on on-chain governance for protocol evolution and emergency response.

**Severity**: High impact (complete governance failure) with medium likelihood results in **Medium to High severity**.

### Likelihood Explanation

**Attacker Capabilities**: Requires controlling 66.67% of current miners (default approval threshold) to pass the malicious threshold change proposal. [3](#0-2) 

**Attack Complexity**: Low - single proposal execution with straightforward parameters.

**Feasibility**: High - the attack requires only temporary control (enough to pass one proposal), then governance remains locked even after attacker loses control. The configuration is explicitly validated as acceptable by the contract. [4](#0-3) 

**Detection**: The threshold change is visible on-chain, but may not be noticed before execution if disguised within a larger proposal batch.

**Economic Rationality**: High value for attacker - permanent protocol disruption with single governance compromise. Cost is achieving temporary 66.67% control, which is within the threat model for high-stakes governance attacks.

### Recommendation

**Add Hardcoded Upper/Lower Bounds**: Modify the `Validate` method to enforce maximum governance safety thresholds:

```csharp
// In Parliament_Helper.cs Validate method, add:
const int MaximumSafeApprovalThreshold = 9000; // 90% max
const int MinimumSafeRejectionTolerance = 500; // 5% min
const int MinimumSafeAbstentionTolerance = 500; // 5% min

Assert(proposalReleaseThreshold.MinimalApprovalThreshold <= MaximumSafeApprovalThreshold,
    "Approval threshold too high for governance safety");
Assert(proposalReleaseThreshold.MaximalRejectionThreshold >= MinimumSafeRejectionTolerance,
    "Rejection tolerance too low for governance safety");
Assert(proposalReleaseThreshold.MaximalAbstentionThreshold >= MinimumSafeAbstentionTolerance,
    "Abstention tolerance too low for governance safety");
```

**Add Emergency Override**: Grant the emergency response organization explicit authority to reset locked organization thresholds to safe defaults, with its own high threshold protection (90%).

**Test Cases**: Add regression tests verifying that extreme configurations (>95% approval, <5% rejection/abstention tolerance) are rejected.

### Proof of Concept

**Initial State**: 
- Parliament organization exists with default thresholds (66.67% approval)
- Attacker controls 67% of current miners (4 out of 6 miners)

**Attack Steps**:

1. Attacker creates proposal calling `ChangeOrganizationThreshold` with parameters:
   - `MinimalApprovalThreshold: 10000`
   - `MinimalVoteThreshold: 10000`
   - `MaximalAbstentionThreshold: 0`
   - `MaximalRejectionThreshold: 0`
   - `OrganizationAddress: [DefaultOrganizationAddress]`

2. Attacker-controlled miners (4 out of 6) call `Approve` on the proposal

3. Attacker calls `Release` on the proposal

4. Proposal executes successfully, changing organization thresholds [2](#0-1) 

**Expected Result**: Proposal should be rejected due to unsafe threshold configuration

**Actual Result**: Proposal succeeds, organization now requires 100% approval with 0% tolerance. [4](#0-3)  All future proposals fail threshold checks in `IsReleaseThresholdReached` because perfect unanimity cannot be achieved. [9](#0-8) 

**Success Condition**: Governance permanently locked - no proposal can achieve 100% approval from all miners with zero abstentions/rejections in a decentralized system.

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L36-48)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var parliamentMembers = GetCurrentMinerList();
        var isRejected = IsProposalRejected(proposal, organization, parliamentMembers);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization, parliamentMembers);
        if (isAbstained)
            return false;

        return CheckEnoughVoteAndApprovals(proposal, organization, parliamentMembers);
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-78)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
    }

    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(parliamentMembers.Contains);
        return abstentionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalAbstentionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L80-92)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached = IsVoteThresholdReached(proposal, organization, parliamentMembers);
        return isVoteThresholdReached;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L142-155)
```csharp
    private bool Validate(Organization organization)
    {
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;

        return proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L314-330)
```csharp
    private void CreateEmergencyResponseOrganization()
    {
        var createOrganizationInput = new CreateOrganizationInput
        {
            ProposalReleaseThreshold = new ProposalReleaseThreshold
            {
                MinimalApprovalThreshold = 9000,
                MinimalVoteThreshold = 9000,
                MaximalAbstentionThreshold = 1000,
                MaximalRejectionThreshold = 1000
            },
            ProposerAuthorityRequired = false,
            ParliamentMemberProposingAllowed = true
        };

        State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L147-160)
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L203-210)
```csharp
    public override Empty CreateEmergencyResponseOrganization(Empty input)
    {
        Assert(State.EmergencyResponseOrganizationAddress.Value == null,
            "Emergency Response Organization already exists.");
        AssertSenderAddressWith(State.DefaultOrganizationAddress.Value);
        CreateEmergencyResponseOrganization();
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L5-9)
```csharp
    private const int DefaultOrganizationMinimalApprovalThreshold = 6667;
    private const int DefaultOrganizationMaximalAbstentionThreshold = 2000;
    private const int DefaultOrganizationMaximalRejectionThreshold = 2000;
    private const int DefaultOrganizationMinimalVoteThresholdThreshold = 7500;
    private const int AbstractVoteTotal = 10000;
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L189-196)
```csharp
            createOrganizationInput.ProposalReleaseThreshold.MinimalApprovalThreshold = 10000;
            createOrganizationInput.ProposalReleaseThreshold.MinimalVoteThreshold = 10000;
            createOrganizationInput.ProposalReleaseThreshold.MaximalAbstentionThreshold = 0;
            createOrganizationInput.ProposalReleaseThreshold.MaximalRejectionThreshold = 0;
            var transactionResult =
                await minerParliamentContractStub.CreateOrganization.SendAsync(createOrganizationInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        }
```
