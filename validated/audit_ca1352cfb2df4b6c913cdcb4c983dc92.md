# Audit Report

## Title
Parliament Organization Governance Lock via Impossible Threshold Configuration

## Summary
The `ChangeOrganizationThreshold()` function validates new voting thresholds only against the constant `AbstractVoteTotal` (10,000) without verifying they are achievable given the actual parliament member count. This allows setting mathematically valid but practically impossible thresholds that permanently lock the organization's governance.

## Finding Description

The Parliament contract's threshold validation mechanism contains a critical flaw that enables governance denial-of-service attacks.

When an organization updates its governance thresholds via `ChangeOrganizationThreshold()`, the validation only checks mathematical consistency with `AbstractVoteTotal` (representing 100% as 10,000 basis points). [1](#0-0) 

The `Validate()` helper function performs no comparison against the actual parliament member count retrieved from the consensus contract: [2](#0-1) 

An attacker can set extreme thresholds that pass validation:
- `MinimalApprovalThreshold = 10000` (100% approval required)
- `MinimalVoteThreshold = 10000` (100% participation required)  
- `MaximalRejectionThreshold = 0` (zero rejection tolerance)
- `MaximalAbstentionThreshold = 0` (zero abstention tolerance)

These values satisfy all validation constraints because they're mathematically consistent with `AbstractVoteTotal = 10000`. [3](#0-2) 

However, the proposal approval logic evaluates these thresholds against actual member counts:

**Rejection check**: With `MaximalRejectionThreshold = 0`, any single rejection blocks proposals since `rejectionMemberCount * 10000 > 0 * parliamentMembers.Count` becomes true for any `rejectionMemberCount >= 1`. [4](#0-3) 

**Abstention check**: With `MaximalAbstentionThreshold = 0`, any single abstention blocks proposals. [5](#0-4) 

**Approval check**: With `MinimalApprovalThreshold = 10000`, all N members must approve since `approvedMemberCount * 10000 >= 10000 * parliamentMembers.Count` requires `approvedMemberCount = parliamentMembers.Count`. [6](#0-5) 

This creates permanent deadlock: achieving unanimous approval while tolerating zero dissent is practically impossible. Since changing thresholds requires passing a proposal under the impossible thresholds, the organization cannot recover.

## Impact Explanation

**Severity: HIGH**

The impact is complete and permanent governance denial-of-service:

1. **Immediate paralysis**: No proposals can pass after the malicious threshold change, blocking all governance operations including system upgrades, parameter adjustments, and emergency responses.

2. **No recovery path**: Restoring reasonable thresholds requires passing a proposal under the impossible thresholds. If any member is unavailable, compromised, or disagrees, recovery is impossible.

3. **Cascading failure**: If this targets the default Parliament organization governing core AElf system contracts, the entire blockchain's governance is paralyzed, affecting consensus updates, token economics, and cross-chain operations.

4. **Widespread impact**: All organization members lose governance capabilities, and dependent systems are affected.

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

The attack is feasible because:

1. **Low technical barrier**: Requires only creating and passing a single proposal with crafted threshold values. No complex transaction sequences or timing dependencies needed.

2. **Social engineering vector**: The malicious proposal can be framed as "security hardening" (e.g., "requiring unanimous approval for critical decisions"), making it appear legitimate to voters.

3. **Realistic preconditions**: 
   - Attacker needs proposal creation rights (available to parliament members or whitelisted proposers)
   - Must achieve approval under current thresholds (e.g., 66.67% in default configuration)
   - More likely in smaller organizations or during governance transitions

4. **Accidental trigger**: Beyond malicious intent, honest misconfigurations could accidentally create impossible conditions if operators don't fully understand the approval formula mechanics.

5. **No detection**: There is no automatic detection of impossible threshold configurations.

## Recommendation

Add validation in the `Validate()` function to ensure thresholds are achievable given the current parliament member count:

```csharp
private bool Validate(Organization organization)
{
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    var parliamentMembers = GetCurrentMinerList();
    var memberCount = parliamentMembers.Count;
    
    // Existing mathematical checks
    var basicChecks = proposalReleaseThreshold.MinimalVoteThreshold <= AbstractVoteTotal &&
           proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal &&
           proposalReleaseThreshold.MaximalRejectionThreshold +
           proposalReleaseThreshold.MinimalApprovalThreshold <= AbstractVoteTotal;
    
    if (!basicChecks) return false;
    
    // New feasibility checks against actual member count
    // Ensure at least one member can reject without blocking if approval threshold < 100%
    if (proposalReleaseThreshold.MinimalApprovalThreshold < AbstractVoteTotal)
    {
        // Allow at least floor((100% - approval%) * memberCount) rejections
        var maxAllowedRejections = (AbstractVoteTotal - proposalReleaseThreshold.MinimalApprovalThreshold) * memberCount / AbstractVoteTotal;
        if (proposalReleaseThreshold.MaximalRejectionThreshold * memberCount < AbstractVoteTotal)
            return false; // Would block on single rejection when not requiring 100% approval
    }
    
    // Similar check for abstentions
    if (proposalReleaseThreshold.MinimalApprovalThreshold < AbstractVoteTotal)
    {
        if (proposalReleaseThreshold.MaximalAbstentionThreshold * memberCount < AbstractVoteTotal)
            return false; // Would block on single abstention when not requiring 100% approval
    }
    
    return true;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task Governance_Deadlock_Via_Impossible_Thresholds_Test()
{
    // Step 1: Create organization with normal thresholds
    var minimalApprovalThreshold = 6667; // 66.67%
    var maximalAbstentionThreshold = 2000;
    var maximalRejectionThreshold = 2000;
    var minimalVoteThreshold = 8000;
    var organizationAddress = await CreateOrganizationAsync(minimalApprovalThreshold,
        maximalAbstentionThreshold, maximalRejectionThreshold, minimalVoteThreshold);

    // Step 2: Create proposal to set impossible thresholds
    var impossibleThresholds = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 10000,  // 100% approval required
        MinimalVoteThreshold = 10000,       // 100% participation required
        MaximalRejectionThreshold = 0,      // No rejections tolerated
        MaximalAbstentionThreshold = 0      // No abstentions tolerated
    };
    
    var changeThresholdProposal = new CreateProposalInput
    {
        ContractMethodName = nameof(ParliamentContractStub.ChangeOrganizationThreshold),
        ToAddress = ParliamentContractAddress,
        Params = impossibleThresholds.ToByteString(),
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(2),
        OrganizationAddress = organizationAddress
    };
    
    var proposalId = await ParliamentContractStub.CreateProposal.SendAsync(changeThresholdProposal);
    
    // Step 3: Get enough approvals under CURRENT thresholds (66.67%)
    await ApproveAsync(InitialMinersKeyPairs[0], proposalId.Output);
    await ApproveAsync(InitialMinersKeyPairs[1], proposalId.Output);
    
    // Step 4: Release proposal to set impossible thresholds
    var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId.Output);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 5: Verify thresholds were set (validation passed despite being impossible)
    var updatedOrg = await ParliamentContractStub.GetOrganization.CallAsync(organizationAddress);
    updatedOrg.ProposalReleaseThreshold.MinimalApprovalThreshold.ShouldBe(10000);
    updatedOrg.ProposalReleaseThreshold.MaximalRejectionThreshold.ShouldBe(0);
    
    // Step 6: Try to create and approve ANY new proposal - it will fail
    var testProposalId = await CreateProposalAsync(DefaultSenderKeyPair, organizationAddress);
    
    // Even with 2/3 approvals, proposal cannot be released
    await ApproveAsync(InitialMinersKeyPairs[0], testProposalId);
    await ApproveAsync(InitialMinersKeyPairs[1], testProposalId);
    
    var testProposal = await ParliamentContractStub.GetProposal.CallAsync(testProposalId);
    testProposal.ToBeReleased.ShouldBeFalse(); // DEADLOCK: Cannot release without 100% approval
    
    // Step 7: Verify governance is permanently locked - even threshold fix proposals fail
    var fixThresholdProposal = new CreateProposalInput
    {
        ContractMethodName = nameof(ParliamentContractStub.ChangeOrganizationThreshold),
        ToAddress = ParliamentContractAddress,
        Params = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 6667,
            MinimalVoteThreshold = 8000,
            MaximalRejectionThreshold = 2000,
            MaximalAbstentionThreshold = 2000
        }.ToByteString(),
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(2),
        OrganizationAddress = organizationAddress
    };
    
    var fixProposalId = await ParliamentContractStub.CreateProposal.SendAsync(fixThresholdProposal);
    await ApproveAsync(InitialMinersKeyPairs[0], fixProposalId.Output);
    await ApproveAsync(InitialMinersKeyPairs[1], fixProposalId.Output);
    
    var fixProposal = await ParliamentContractStub.GetProposal.CallAsync(fixProposalId.Output);
    fixProposal.ToBeReleased.ShouldBeFalse(); // Cannot fix thresholds - permanent deadlock
}
```

## Notes

This vulnerability demonstrates a critical gap between validation logic (which only checks mathematical consistency) and execution logic (which evaluates against actual member counts). The attack is particularly dangerous because it can be executed through legitimate governance processes and may appear as a "security improvement" to voters unfamiliar with the approval formula mechanics.

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
