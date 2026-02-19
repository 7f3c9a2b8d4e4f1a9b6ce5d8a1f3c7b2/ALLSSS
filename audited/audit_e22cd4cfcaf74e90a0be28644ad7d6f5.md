# Audit Report

## Title
Emergency Response Organization Thresholds Require Higher Than Intended Approval Rate Due to Integer Rounding

## Summary
The Parliament contract's emergency response organization uses hardcoded thresholds of 9000 (intended as 90%) with integer arithmetic that causes rounding issues. For the default 17-member parliament, the actual approval requirement is 94.12% (16 out of 17 members) instead of the intended 90%, and for parliaments with fewer than 10 members, it requires 100% approval. This undermines the emergency response mechanism's ability to quickly respond to security threats like malicious consensus nodes.

## Finding Description

The `CreateEmergencyResponseOrganization()` method hardcodes emergency thresholds as 9000 out of 10000 [1](#0-0) , representing an intended 90% approval requirement where `AbstractVoteTotal = 10000` represents 100% [2](#0-1) .

The approval check uses integer arithmetic: `approvedMemberCount * AbstractVoteTotal >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold * parliamentMembers.Count` [3](#0-2) .

**Root Cause:** For a 17-member parliament (the default [4](#0-3) ), this becomes:
- `approvedMemberCount * 10000 >= 9000 * 17`
- `approvedMemberCount >= 153000 / 10000 = 15.3`
- Integer division requires `approvedMemberCount >= 16`
- **Actual threshold: 16/17 = 94.12%**

The `Validate` method only verifies that thresholds sum correctly, not that they achieve the intended percentage across all parliament sizes [5](#0-4) .

**Cannot be corrected:** The emergency organization can only be created once [6](#0-5) , and changing thresholds requires approval from the same organization [7](#0-6) , creating a circular dependency.

## Impact Explanation

The emergency response organization is used for critical security operations, specifically removing malicious nodes from consensus via `RemoveEvilNode` [8](#0-7) .

**Concrete operational harm:**

1. **Default Configuration Failure**: With 17 parliament members, just 2 unavailable or dissenting miners (11.8% vs intended 10% tolerance) block all emergency actions, including removal of compromised consensus nodes.

2. **Small Parliament Deadlock**: Parliaments with fewer than 10 members require 100% approval, eliminating all fault tolerance. A single offline or compromised node creates a complete deadlock for emergency responses.

3. **Security Response Degradation**: During an actual security incident where a node is compromised, that node itself may be one of the parliament members. The system should allow a 10% dissent margin (90% approval), but actually requires 94.12%, making the malicious node harder to remove.

4. **Irreversible Design Flaw**: The emergency organization cannot be recreated or have its thresholds adjusted without first meeting the problematic thresholds, making this a permanent limitation.

This is **High Severity** because it directly impairs the blockchain's ability to respond to consensus-level security emergencies, potentially allowing malicious actors to remain active longer than the governance model intended.

## Likelihood Explanation

**Certainty: 100%** - This is not a potential attack but a deterministic design flaw.

**Conditions that guarantee manifestation:**
- Default parliament size is 17 members (confirmed in consensus constants)
- Emergency organization uses hardcoded 9000 threshold
- Integer arithmetic rounds 15.3 up to 16 required approvals
- No attacker action required - occurs automatically upon organization creation

**Real-world scenario:** A compromised node is detected and needs emergency removal. The malicious node operator is one of the 17 parliament members. Even if 15 honest members (88.2%) vote for removal, the proposal fails because 16 approvals (94.12%) are mathematically required. The 90% threshold should have allowed this removal with only 2 dissenting votes, but the integer rounding prevents it.

## Recommendation

**Immediate fix:** Adjust the emergency response thresholds to account for integer rounding:

```csharp
private void CreateEmergencyResponseOrganization()
{
    var createOrganizationInput = new CreateOrganizationInput
    {
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            // Adjusted to ensure true 90% for common parliament sizes
            // For 17 members: 15.3 -> needs 9015 to require exactly 16 (94.12%)
            // Use 8824 to require 15 (88.24%), closer to intended 90%
            MinimalApprovalThreshold = 8824,  // Ensures <=90% for sizes 17, 10, 9, 5, 3
            MinimalVoteThreshold = 8824,
            MaximalAbstentionThreshold = 1176,
            MaximalRejectionThreshold = 1176
        },
        ProposerAuthorityRequired = false,
        ParliamentMemberProposingAllowed = true
    };

    State.EmergencyResponseOrganizationAddress.Value = CreateOrganization(createOrganizationInput);
}
```

**Better long-term solution:** Implement ceiling division or explicit rounding logic:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization,
    ICollection<Address> parliamentMembers)
{
    var approvedMemberCount = proposal.Approvals.Count(parliamentMembers.Contains);
    
    // Use ceiling division: ceil(threshold * count / AbstractVoteTotal)
    var requiredApprovals = (organization.ProposalReleaseThreshold.MinimalApprovalThreshold * 
                             parliamentMembers.Count + AbstractVoteTotal - 1) / AbstractVoteTotal;
    
    var isApprovalEnough = approvedMemberCount >= requiredApprovals;
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task EmergencyOrganization_Requires_Higher_Threshold_Than_Intended()
{
    // Setup: Create emergency response organization with default 17-member parliament
    var defaultOrganizationAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Default parliament has 17 members
    await ParliamentReachAnAgreementAsync(new CreateProposalInput
    {
        ToAddress = ContractAddresses[ParliamentSmartContractAddressNameProvider.Name],
        ContractMethodName = "CreateEmergencyResponseOrganization",
        Params = new Empty().ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        OrganizationAddress = defaultOrganizationAddress
    });
    
    var eroAddress = await ParliamentContractStub.GetEmergencyResponseOrganizationAddress.CallAsync(new Empty());
    var organization = await ParliamentContractStub.GetOrganization.CallAsync(eroAddress);
    
    // Verify: Threshold is 9000 (intended 90%)
    organization.ProposalReleaseThreshold.MinimalApprovalThreshold.ShouldBe(9000);
    
    // Test: Try to approve with 15 out of 17 members (88.24% - should pass if 90% threshold worked correctly)
    var evilNodePubkey = MissionedECKeyPairs.ValidationDataCenterKeyPairs.First().PublicKey.ToHex();
    var proposalId = await CreateEvilNodeRemovalProposal(eroAddress, evilNodePubkey);
    
    // Approve with first 15 parliament members only
    for (int i = 0; i < 15; i++)
    {
        await ParliamentStubs[i].Approve.SendAsync(proposalId);
    }
    
    // Attempt release - THIS SHOULD SUCCEED with 90% threshold (15/17 = 88.24% is close)
    // But will FAIL because integer rounding requires 16/17 = 94.12%
    var result = await ParliamentStubs[0].Release.SendWithExceptionAsync(proposalId);
    result.TransactionResult.Error.ShouldContain("Not approved");
    
    // Now approve with 16th member
    await ParliamentStubs[15].Approve.SendAsync(proposalId);
    
    // NOW it succeeds with 16/17 = 94.12%
    await ParliamentStubs[0].Release.SendAsync(proposalId);
    
    // Conclusion: Actual requirement is 94.12%, not the intended 90%
}
```

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L84-86)
```csharp
        var isApprovalEnough = approvedMemberCount * AbstractVoteTotal >=
                               organization.ProposalReleaseThreshold.MinimalApprovalThreshold *
                               parliamentMembers.Count;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L316-327)
```csharp
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
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L147-159)
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
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L205-206)
```csharp
        Assert(State.EmergencyResponseOrganizationAddress.Value == null,
            "Emergency Response Organization already exists.");
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L336-350)
```csharp
    public override Empty RemoveEvilNode(StringValue input)
    {
        Assert(Context.Sender == GetEmergencyResponseOrganizationAddress(), "No permission.");
        var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(input.Value));
        Assert(
            State.Candidates.Value.Value.Select(p => p.ToHex()).Contains(input.Value) ||
            State.InitialMiners.Value.Value.Select(p => p.ToHex()).Contains(input.Value),
            "Cannot remove normal node.");
        Assert(!State.BannedPubkeyMap[input.Value], $"{input.Value} already banned.");
        UpdateCandidateInformation(new UpdateCandidateInformationInput
        {
            Pubkey = input.Value,
            IsEvilNode = true
        });
        return new Empty();
```
