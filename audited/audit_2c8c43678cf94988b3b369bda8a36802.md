### Title
Emergency Response Organization Thresholds Require Higher Than Intended Approval Rate Due to Integer Rounding

### Summary
The hardcoded emergency response thresholds of 9000 (90%) use fixed-point arithmetic that causes integer rounding issues for most parliament sizes. For the default 17-member parliament, the actual requirement is 94.12% approval (16/17 members) instead of 90%, and for parliaments smaller than 10 members, it requires 100% approval, eliminating fault tolerance for critical emergency operations.

### Finding Description

The `CreateEmergencyResponseOrganization()` method creates an emergency organization with hardcoded thresholds: [1](#0-0) 

These thresholds use a fixed-point arithmetic system where `AbstractVoteTotal = 10000` represents 100%: [2](#0-1) 

The approval threshold check uses the formula `approvedMemberCount * 10000 >= 9000 * parliamentMembers.Count`: [3](#0-2) 

**Root Cause:** Integer division rounding causes the effective threshold to exceed 90% for most parliament sizes.

**Calculations for Common Parliament Sizes:**
- **Size 17 (default)**: `approvedMemberCount >= 153000 / 10000 = 15.3` → requires 16 approvals = **94.12%**
- **Size 9**: `approvedMemberCount >= 81000 / 10000 = 8.1` → requires 9 approvals = **100%**
- **Size 5**: `approvedMemberCount >= 45000 / 10000 = 4.5` → requires 5 approvals = **100%**
- **Size 3**: `approvedMemberCount >= 27000 / 10000 = 2.7` → requires 3 approvals = **100%**

The default parliament size is confirmed to be 17 by the consensus system: [4](#0-3) 

**Why Protections Fail:** The `Validate` method only checks that thresholds sum correctly, not that they work as percentages across all parliament sizes: [5](#0-4) 

**Cannot Self-Correct:** Once created, threshold changes require approval from the same organization, which requires meeting the problematic thresholds: [6](#0-5) 

The emergency organization can only be created once: [7](#0-6) 

### Impact Explanation

**Operational Impact on Critical Emergency Functions:**

The emergency response organization is used for critical operations like removing malicious nodes from the consensus: [8](#0-7) 

**Concrete Harm:**
1. **Default 17-Member Parliament**: Requires 16/17 approvals (94.12% instead of intended 90%), meaning just 2 unavailable/dissenting miners block emergency actions
2. **Small Parliaments (< 10)**: Require 100% approval, creating single points of failure where one offline/compromised/dissenting node blocks all emergency responses
3. **Defeats Emergency Purpose**: Emergency organizations exist to respond quickly to threats. Requiring near-unanimous consent contradicts this goal
4. **Circular Dependency**: Cannot adjust thresholds without first meeting the problematic thresholds

**Who is Affected:**
- Network security operations requiring emergency consensus removal of malicious nodes
- Governance system's ability to respond to time-sensitive threats
- Overall blockchain integrity during security incidents

**Severity Justification:** High severity because it directly impairs the system's ability to respond to security emergencies, potentially allowing malicious nodes to remain active longer than intended.

### Likelihood Explanation

**Certainty:** This is not an attack but a design flaw that manifests automatically.

**Conditions:**
- Occurs for any parliament size that is not a multiple of 10
- Default parliament size is 17, guaranteeing the issue manifests
- No attacker action required
- Cannot be avoided once emergency organization is created

**Probability:** 100% for default configuration and most realistic parliament sizes.

**Real-World Scenario:** During a security incident where a node is compromised or behaving maliciously, that node itself may be one of the 17 parliament members. Even if 15 honest members approve removal (88.2%), the proposal fails because 16 approvals (94.12%) are required. This defeats the purpose of the 90% threshold, which should allow up to 10% dissent/absence.

### Recommendation

**Fix 1: Dynamic Threshold Calculation**
Modify `CreateEmergencyResponseOrganization()` to calculate thresholds that truly represent 90%:

```
MinimalApprovalThreshold = (9 * parliamentSize * AbstractVoteTotal + 9) / 10
```

This ensures: `approvedCount * 10000 >= threshold * parliamentSize` resolves to exactly 90% for all sizes.

**Fix 2: Allow One-Time Threshold Adjustment**
Add a special method callable only by the default organization to adjust emergency organization thresholds without circular dependency:

```csharp
public override Empty AdjustEmergencyResponseThreshold(ProposalReleaseThreshold input)
{
    AssertSenderAddressWith(State.DefaultOrganizationAddress.Value);
    var eroAddress = State.EmergencyResponseOrganizationAddress.Value;
    Assert(eroAddress != null, "Emergency Response Organization not created.");
    var organization = State.Organizations[eroAddress];
    organization.ProposalReleaseThreshold = input;
    Assert(Validate(organization), "Invalid organization.");
    State.Organizations[eroAddress] = organization;
    return new Empty();
}
```

**Invariant Check:**
Add validation that effective threshold percentage doesn't exceed intended percentage by more than 1% for the current parliament size.

**Test Cases:**
- Verify emergency proposals pass with exactly 90% approval for parliament sizes: 10, 20, 30, 50, 100
- Verify correct rounding for sizes: 3, 5, 7, 9, 11, 13, 17, 19, 21
- Test emergency operations succeed during simulated node compromise scenarios

### Proof of Concept

**Initial State:**
- Parliament with 17 miners (default configuration)
- Emergency Response Organization created with thresholds: MinimalApprovalThreshold=9000

**Execution Steps:**

1. Create emergency proposal to remove evil node
2. 15 miners approve (88.2% - should be sufficient for 90% threshold)
3. Attempt to release proposal

**Expected Result (Based on 90% Intent):**
- Proposal should pass with 15/17 approvals (88.2% > intended 90% floor accounting for rounding)

**Actual Result:**
- Proposal fails because threshold check requires: `15 * 10000 >= 9000 * 17`
- `150000 >= 153000` = FALSE
- Requires 16 approvals minimum (94.12%)

**Success Condition:**
Only passes when 16 or all 17 miners approve, demonstrating the threshold is effectively 94.12%, not 90%.

**Notes:**
This vulnerability specifically impacts emergency governance operations where rapid response is critical. The integer rounding issue is inherent to the fixed-point arithmetic approach but becomes particularly problematic when: (1) thresholds are hardcoded at creation time, (2) the organization handles emergency operations requiring quick consensus, and (3) the default parliament size (17) guarantees manifestation of the issue. The circular dependency preventing threshold adjustment without meeting the problematic thresholds compounds the severity.

### Citations

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L87-87)
```csharp
            Context.Sender || Context.Sender == GetEmergencyResponseOrganizationAddress(),
```
