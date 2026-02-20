# Audit Report

## Title
Association Contract Threshold Validation Allows Governance Deadlock

## Summary
The `Validate(Organization)` function in the Association contract contains insufficient threshold validation that allows creation of organizations where proposals can enter permanent deadlock states. The validation checks two pairwise sum constraints but fails to verify the combined constraint, enabling proposals that can neither be approved, rejected, nor abstained even after all members vote.

## Finding Description

The root cause lies in the threshold validation logic which performs two independent checks without ensuring the combined constraint is satisfied. [1](#0-0) 

These constraints check:
1. `MaximalAbstentionThreshold + MinimalApprovalThreshold <= organizationMemberCount`
2. `MaximalRejectionThreshold + MinimalApprovalThreshold <= organizationMemberCount`

However, the proposal release logic uses asymmetric inequality operators that create a deadlock vulnerability. The rejection check uses strict inequality [2](#0-1) , the abstention check uses strict inequality [3](#0-2) , while the approval check uses non-strict inequality [4](#0-3) .

Due to the strict inequalities for rejection/abstention versus non-strict for approval, a deadlock occurs when all N members vote with the distribution:
- Approvals = MinimalApprovalThreshold - 1
- Rejections = MaximalRejectionThreshold
- Abstentions = MaximalAbstentionThreshold
- Sum = N (all members voted)

This satisfies the current validation when `MaximalRejectionThreshold + MaximalAbstentionThreshold + MinimalApprovalThreshold = N + 1`.

**Concrete Example:**
- N = 10 members
- MinimalApprovalThreshold = 6
- MaximalRejectionThreshold = 2  
- MaximalAbstentionThreshold = 3

Validation passes (3+6=9≤10, 2+6=8≤10), but sum is 11 = N+1.

When all 10 members vote (5 approvals, 2 rejections, 3 abstentions):
- Not rejected: 2 > 2? NO
- Not abstained: 3 > 3? NO
- Not approved: 5 >= 6? NO
- **Result: DEADLOCK**

## Impact Explanation

**HIGH Severity - Governance DoS**

Organizations with deadlock-prone threshold configurations experience critical governance failure:

1. **Governance Paralysis**: Proposals requiring urgent action cannot be executed or rejected, leaving the organization unable to respond to time-sensitive situations.

2. **Resource Lock**: Proposals remain permanently stuck as the `Release` method will fail the threshold check. [5](#0-4) 

3. **No Recovery Path**: The `ChangeOrganizationThreshold` method requires execution through a proposal. [6](#0-5)  If a threshold-change proposal deadlocks, the organization cannot fix its own broken configuration.

4. **Limited Mitigation**: Only recovery is waiting for proposal expiration via `ClearProposal`. [7](#0-6) 

This violates the governance invariant that organization thresholds must ensure deterministic proposal outcomes when members vote.

## Likelihood Explanation

**HIGH Likelihood - Easily Exploitable**

The vulnerability has high exploitability:

1. **Public Entry Point**: Any user can create an Association organization through the unrestricted `CreateOrganization` method. [8](#0-7) 

2. **No Economic Barrier**: Organization creation requires no staking, approval, or special privileges.

3. **Simple Attack Vector**: Calculate threshold values satisfying `MaximalRejectionThreshold + MaximalAbstentionThreshold + MinimalApprovalThreshold = organizationMemberCount + 1` that pass the current validation.

4. **Accidental Creation**: Legitimate organizations attempting balanced thresholds (e.g., 60% approval requirement, 20% rejection tolerance, 30% abstention tolerance) can inadvertently create deadlock configurations.

5. **Delayed Detection**: Validation passes during creation; deadlock only manifests during voting, making it difficult to detect beforehand.

## Recommendation

Add an additional validation constraint to ensure the sum of all three thresholds cannot create a deadlock scenario:

```csharp
return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
       proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
       proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
       proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
       proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
       proposalReleaseThreshold.MaximalAbstentionThreshold +
       proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
       proposalReleaseThreshold.MaximalRejectionThreshold +
       proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
       // New constraint to prevent deadlock
       proposalReleaseThreshold.MaximalRejectionThreshold +
       proposalReleaseThreshold.MaximalAbstentionThreshold +
       proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
```

This ensures that when all members vote, at least one of the three outcome conditions (approved, rejected, or abstained) must be satisfied.

## Proof of Concept

```csharp
[Fact]
public async Task CreateOrganization_Deadlock_Configuration_Test()
{
    // Create organization with deadlock-prone thresholds
    // N = 10, MinimalApproval = 6, MaximalRejection = 2, MaximalAbstention = 3
    // Sum = 11 = N + 1
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Member1, Member2, Member3, Member4, Member5, 
                                   Member6, Member7, Member8, Member9, Member10 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 6,
            MinimalVoteThreshold = 10,
            MaximalAbstentionThreshold = 3,
            MaximalRejectionThreshold = 2
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Member1 }
        }
    };
    
    // Organization creation succeeds (validation passes)
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    organizationAddress.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Create proposal
    var proposalId = await CreateProposalAsync(organizationAddress.Output);
    
    // Vote with deadlock distribution: 5 approvals, 2 rejections, 3 abstentions
    await ApproveAsync(proposalId, Member1, Member2, Member3, Member4, Member5);
    await RejectAsync(proposalId, Member6, Member7);
    await AbstainAsync(proposalId, Member8, Member9, Member10);
    
    // All 10 members voted, but proposal is in deadlock
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBe(false); // Cannot be released - DEADLOCK!
    
    // Verify counts
    proposal.ApprovalCount.ShouldBe(5);   // Not >= 6 (not approved)
    proposal.RejectionCount.ShouldBe(2);  // Not > 2 (not rejected)
    proposal.AbstentionCount.ShouldBe(3); // Not > 3 (not abstained)
}
```

**Notes:**
- The vulnerability is confirmed through code analysis of the validation and release logic in the Association contract.
- The asymmetric inequality operators (strict for rejection/abstention, non-strict for approval) combined with insufficient validation create a real deadlock scenario.
- This is a governance integrity issue with HIGH impact (DoS) and HIGH likelihood (public access, no barriers).
- Organizations created with these configurations will experience permanent proposal deadlock until expiration.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-39)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L41-45)
```csharp
    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-52)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L77-80)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L69-83)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-188)
```csharp
    public override Empty Release(Hash input)
    {
        var proposalInfo = GetValidProposal(input);
        Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L203-209)
```csharp
    public override Empty ChangeOrganizationThreshold(ProposalReleaseThreshold input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L282-288)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
```
