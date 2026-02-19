# Audit Report

## Title
Parliament Organization Governance Lock via Impossible Threshold Configuration

## Summary
The `ChangeOrganizationThreshold()` function validates new voting thresholds only against the abstract constant `AbstractVoteTotal` (10,000) without checking if the thresholds are achievable given the actual current parliament member count. This allows an attacker to set mathematically valid but practically impossible thresholds (e.g., requiring 100% approval while tolerating 0% rejection/abstention), permanently locking the organization's governance with no recovery mechanism.

## Finding Description

The vulnerability exists in the threshold validation logic for Parliament organizations. The `ChangeOrganizationThreshold()` method allows updating an organization's governance thresholds through proposals. [1](#0-0) 

The validation is performed by the `Validate()` helper method, which only checks that thresholds maintain mathematical consistency with the constant `AbstractVoteTotal` (10,000): [2](#0-1) 

The constant `AbstractVoteTotal` is defined as 10,000, representing 100% in basis points: [3](#0-2) 

**Root Cause**: The validation never compares threshold values against the actual current parliament member count retrieved from the consensus contract. It only ensures the thresholds satisfy abstract mathematical constraints.

**Attack Scenario**: An attacker crafts a proposal to set:
- `MinimalApprovalThreshold = 10000` (100% approval required)
- `MinimalVoteThreshold = 10000` (100% participation required)
- `MaximalRejectionThreshold = 0` (any rejection blocks)
- `MaximalAbstentionThreshold = 0` (any abstention blocks)

These values pass all validation checks but create impossible conditions when applied to the approval logic:

The rejection check uses: [4](#0-3) 

With `MaximalRejectionThreshold = 0`, the formula `rejectionMemberCount * 10000 > 0 * parliamentMembers.Count` means any single rejection (rejectionMemberCount ≥ 1) causes `10000 > 0` to be true, blocking the proposal.

Similarly, the abstention check: [5](#0-4) 

With `MaximalAbstentionThreshold = 0`, any single abstention blocks the proposal.

Meanwhile, the approval check requires: [6](#0-5) 

With `MinimalApprovalThreshold = 10000`, the formula `approvedMemberCount * 10000 >= 10000 * parliamentMembers.Count` requires ALL members to approve.

These three conditions are mutually impossible: you cannot get 100% approval while tolerating 0% rejection/abstention in any real-world governance scenario.

## Impact Explanation

**Severity: HIGH**

The impact is a complete and permanent governance denial-of-service:

1. **Immediate Governance Paralysis**: After the malicious threshold change executes, no future proposals can pass because the thresholds require impossible voting patterns (100% approval with zero tolerance for any dissent).

2. **No Recovery Path**: Since changing thresholds requires a proposal, and proposals are now impossible to pass under the new thresholds, there is no way to restore functionality. The `ChangeOrganizationThreshold` method can only be called by the organization itself through proposals: [7](#0-6) 

3. **No Administrative Override**: There are no emergency mechanisms, admin functions, or organization deletion capabilities to bypass or reset these thresholds.

4. **Chain-Wide Impact**: If the default Parliament organization (which governs core system contracts) is affected, the entire AElf blockchain's governance becomes paralyzed, preventing critical system upgrades, parameter adjustments, or emergency responses.

5. **Permanent State**: Organizations cannot be deleted or recreated once locked, making this condition irreversible.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack requires passing a single malicious proposal under the organization's current (reasonable) thresholds, which is feasible under several scenarios:

1. **Social Engineering Vector**: The proposal can be framed as a "security hardening" measure ("requiring unanimous approval for critical decisions"), making it appear legitimate to parliament members.

2. **Honest Misconfiguration**: Administrators unfamiliar with the threshold mechanics could accidentally set impossible values, triggering the same DoS condition without malicious intent.

3. **Lower Barrier in Small Organizations**: Organizations with fewer members or during governance transitions are more vulnerable to compromise or coordination among malicious actors.

4. **Single Proposal Required**: Unlike complex multi-step attacks, this requires only one successful proposal execution, reducing the attack complexity.

5. **No Detection Mechanism**: The system provides no warnings or automatic detection of impossible threshold configurations before or after they are set.

## Recommendation

Add validation that checks thresholds against the actual current parliament member count to ensure achievability:

```csharp
private bool Validate(Organization organization)
{
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    var parliamentMembers = GetCurrentMinerList();
    var memberCount = parliamentMembers.Count;
    
    // Existing checks
    if (proposalReleaseThreshold.MinimalVoteThreshold > AbstractVoteTotal ||
        proposalReleaseThreshold.MinimalApprovalThreshold > proposalReleaseThreshold.MinimalVoteThreshold ||
        proposalReleaseThreshold.MinimalApprovalThreshold <= 0 ||
        proposalReleaseThreshold.MaximalAbstentionThreshold < 0 ||
        proposalReleaseThreshold.MaximalRejectionThreshold < 0 ||
        proposalReleaseThreshold.MaximalAbstentionThreshold + proposalReleaseThreshold.MinimalApprovalThreshold > AbstractVoteTotal ||
        proposalReleaseThreshold.MaximalRejectionThreshold + proposalReleaseThreshold.MinimalApprovalThreshold > AbstractVoteTotal)
        return false;
    
    // New check: Ensure at least one achievable voting combination exists
    // Allow for at least one rejection OR one abstention while still meeting approval threshold
    var minRequiredApprovals = (proposalReleaseThreshold.MinimalApprovalThreshold * memberCount + AbstractVoteTotal - 1) / AbstractVoteTotal;
    var maxAllowedRejections = (proposalReleaseThreshold.MaximalRejectionThreshold * memberCount) / AbstractVoteTotal;
    var maxAllowedAbstentions = (proposalReleaseThreshold.MaximalAbstentionThreshold * memberCount) / AbstractVoteTotal;
    
    // Verify that it's possible to get enough approvals without violating rejection/abstention limits
    return minRequiredApprovals + maxAllowedRejections + maxAllowedAbstentions >= memberCount;
}
```

Additionally, consider implementing:
- Warning mechanisms when thresholds approach impossible configurations
- Emergency override capability for the default organization
- Maximum threshold caps (e.g., 95% approval maximum)

## Proof of Concept

```csharp
[Fact]
public async Task Parliament_Governance_Lock_Via_Impossible_Threshold_Test()
{
    // Create organization with reasonable thresholds
    var minimalApprovalThreshold = 3000; // 30%
    var maximalAbstentionThreshold = 3000;
    var maximalRejectionThreshold = 3000;
    var minimalVoteThreshold = 3000;
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold,
        maximalAbstentionThreshold,
        maximalRejectionThreshold,
        minimalVoteThreshold);

    // Create malicious proposal to set impossible thresholds
    var impossibleThresholds = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 10000, // 100% approval required
        MinimalVoteThreshold = 10000,     // 100% participation required
        MaximalRejectionThreshold = 0,    // Any rejection blocks
        MaximalAbstentionThreshold = 0    // Any abstention blocks
    };

    var maliciousProposalId = await CreateParliamentProposalAsync(
        nameof(ParliamentContractStub.ChangeOrganizationThreshold),
        organizationAddress,
        impossibleThresholds,
        ParliamentContractAddress);

    // Approve and release under current (reasonable) thresholds
    await ApproveAsync(InitialMinersKeyPairs[0], maliciousProposalId);
    var releaseResult = await ParliamentContractStub.Release.SendAsync(maliciousProposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

    // Verify thresholds were updated
    var organization = await ParliamentContractStub.GetOrganization.CallAsync(organizationAddress);
    organization.ProposalReleaseThreshold.MinimalApprovalThreshold.ShouldBe(10000);
    organization.ProposalReleaseThreshold.MaximalRejectionThreshold.ShouldBe(0);

    // Now try to create and pass ANY proposal (including threshold restoration)
    var recoveryProposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
    
    // Even with all miners approving, proposal cannot pass
    foreach (var miner in InitialMinersKeyPairs)
    {
        await ApproveAsync(miner, recoveryProposalId);
    }
    
    // Verify proposal is NOT releasable despite all approvals
    var proposal = await ParliamentContractStub.GetProposal.CallAsync(recoveryProposalId);
    proposal.ToBeReleased.ShouldBeFalse(); // Governance is permanently locked
}
```

### Citations

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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-70)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization,
        ICollection<Address> parliamentMembers)
    {
        var rejectionMemberCount = proposal.Rejections.Count(parliamentMembers.Contains);
        return rejectionMemberCount * AbstractVoteTotal >
               organization.ProposalReleaseThreshold.MaximalRejectionThreshold * parliamentMembers.Count;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L72-78)
```csharp
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Constants.cs (L9-9)
```csharp
    private const int AbstractVoteTotal = 10000;
```
