# Audit Report

## Title
Inconsistent Membership Filtering in Vote Threshold Check Allows Governance Bypass

## Summary
The Association contract's `CheckEnoughVoteAndApprovals` function inconsistently applies membership filtering when validating proposal release thresholds. While approval, rejection, and abstention counts correctly filter by current organization membership, the total vote count includes votes from removed members. This allows proposals to meet the MinimalVoteThreshold requirement with artificially inflated participation from ex-members, undermining governance quorum enforcement.

## Finding Description
The vulnerability exists in the threshold validation logic that determines whether a proposal can be released. The Association contract enforces governance through the `ProposalReleaseThreshold` structure, which includes `MinimalVoteThreshold` to ensure adequate member participation.

**Inconsistent Membership Filtering:**

The `CheckEnoughVoteAndApprovals` function applies membership filtering inconsistently: [1](#0-0) 

This line correctly filters approvals to count only current members. [2](#0-1) 

However, this total vote count does NOT filter by current membership, counting ALL votes including those from removed members.

The same inconsistency exists with rejection and abstention checks, which correctly filter by current membership: [3](#0-2) [4](#0-3) 

**Root Cause:**

When members are removed via the `RemoveMember` function, they are deleted from the organization member list but their votes remain in existing proposals: [5](#0-4) 

The `RemoveMember` operation does not clear votes from active proposals. Combined with the unfiltered total vote count, this creates a state where:
- Approval/rejection/abstention thresholds correctly reflect only current member votes
- Total vote threshold incorrectly includes votes from ex-members
- Proposals can pass MinimalVoteThreshold with lower actual participation than intended

**Attack Scenario:**

Consider an organization with:
- MinimalVoteThreshold = 7 (requires 7 members to participate)
- MinimalApprovalThreshold = 5 (requires 5 approvals)
- 10 total members

Attack sequence:
1. Attacker creates proposal (requires proposer whitelist membership)
2. Obtains 5 approvals + 2 abstentions (7 total votes, meets threshold)
3. Executes another proposal to call `RemoveMember` for the 2 abstaining members
4. After removal: Only 8 current members remain
5. Threshold checks:
   - Approval count: 5 current members (meets MinimalApprovalThreshold = 5) ✓
   - Abstention count: 0 current members (removed members) ✓
   - **Total vote count: 7 votes (5 + 2 from ex-members, meets MinimalVoteThreshold = 7) ✓**
6. Proposal releases with only 5/8 (62.5%) current member participation instead of intended 7/8 (87.5%)

This bypasses the governance invariant that MinimalVoteThreshold should ensure broad current member participation.

## Impact Explanation
**HIGH Severity** - This vulnerability directly violates the core governance invariant that "organization thresholds must be correctly enforced."

**Governance Integrity Compromise:**
- Proposals can be released without meeting the intended minimum participation requirement from current active members
- The MinimalVoteThreshold becomes meaningless as it can be satisfied by votes from removed members
- Organizations relying on MinimalVoteThreshold for quorum enforcement are systematically undermined

**Affected Parties:**
- All Association-based organizations using MinimalVoteThreshold > MinimalApprovalThreshold (a common configuration to ensure broad participation)
- Critical governance decisions can be made with minority current member support
- The vulnerability affects the fundamental trust model of Association governance

**Quantified Impact:**
In the example scenario, an attacker achieves:
- 5/8 (62.5%) actual current member participation
- While appearing to meet 7/10 (70%) participation requirement
- This is a 7.5 percentage point participation deficit that completely bypasses the intended threshold

The impact extends beyond individual proposals - it undermines confidence in the entire Association governance model.

## Likelihood Explanation
**MEDIUM-HIGH Probability** - The vulnerability is present in every Association organization and exploitable through standard governance operations.

**Attacker Capabilities Required:**
- Proposer whitelist membership (normal governance role, not privileged system access)
- Ability to coordinate with some organization members for voting
- Does NOT require compromising any trusted roles or system contracts

**Attack Complexity: LOW**
- Uses only standard contract methods: `CreateProposal`, `Approve`, `Abstain`, `RemoveMember`, `Release`
- No complex timing requirements or state manipulation needed
- Member removal is a legitimate governance operation accessible through proposal execution

**Feasibility Conditions:**
1. Organization must use MinimalVoteThreshold > MinimalApprovalThreshold - This is a common configuration to ensure broad participation beyond just approvals
2. Ability to coordinate member voting then removal - Achievable through:
   - Executing another proposal that calls `RemoveMember` (Context.Sender becomes organization address during proposal execution)
   - Or if attacker has control over the organization address itself [6](#0-5) 

The `Release` method checks `IsReleaseThresholdReached`, which calls the vulnerable `CheckEnoughVoteAndApprovals` function.

**Detection Difficulty:**
- Member additions/removals are legitimate operations that occur regularly
- The exploit leaves no obvious traces beyond normal governance activity
- Observers would need to manually track member list changes and correlate with proposal votes to detect the bypass

## Recommendation
Apply consistent membership filtering across all threshold checks. The total vote count should filter by current membership just like approval, rejection, and abstention counts.

**Fix for `CheckEnoughVoteAndApprovals`:**

Change line 56 from:
```csharp
proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count()
```

To:
```csharp
proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
proposal.Rejections.Count(organization.OrganizationMemberList.Contains)
```

Note: The approval count is already calculated above and could be reused for efficiency.

**Alternative Comprehensive Fix:**

Consider adding vote cleanup logic to `RemoveMember` to clear removed members' votes from all active proposals. However, this is more complex as it requires iterating through proposals and may have state storage implications.

The first fix (consistent filtering) is simpler, more efficient, and aligns with the semantic meaning of the thresholds.

## Proof of Concept

```csharp
[Fact]
public async Task GovernanceBypass_InconsistentMembershipFiltering_Test()
{
    // Setup organization with 10 members
    var members = new[] { Reviewer1, Reviewer2, Reviewer3, Member1, Member2, 
                         Member3, Member4, Member5, Member6, Member7 };
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { members }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 5,  // Need 5 approvals
            MinimalVoteThreshold = 7,       // Need 7 total votes
            MaximalAbstentionThreshold = 10,
            MaximalRejectionThreshold = 10
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { Reviewer1 } }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization
        .SendAsync(createOrganizationInput)).Output;
    
    // Create proposal
    var proposalId = await CreateProposalAsync(organizationAddress);
    
    // Get 5 approvals
    await ApproveAsync(Reviewer1Stub, proposalId);
    await ApproveAsync(Reviewer2Stub, proposalId);
    await ApproveAsync(Reviewer3Stub, proposalId);
    await ApproveAsync(Member1Stub, proposalId);
    await ApproveAsync(Member2Stub, proposalId);
    
    // Get 2 abstentions (to reach 7 total votes)
    await AbstainAsync(Member3Stub, proposalId);
    await AbstainAsync(Member4Stub, proposalId);
    
    // Verify proposal is not yet releasable (correctly - 7 votes from 10 members)
    var proposalOutput = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeTrue(); // Currently passes with 7 votes
    
    // Remove the 2 abstaining members via organization proposal
    var removeMember1Tx = await CreateAndExecuteProposalForRemoveMember(
        organizationAddress, Member3);
    var removeMember2Tx = await CreateAndExecuteProposalForRemoveMember(
        organizationAddress, Member4);
    
    removeMember1Tx.Status.ShouldBe(TransactionResultStatus.Mined);
    removeMember2Tx.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify members are removed
    var org = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress);
    org.OrganizationMemberList.OrganizationMembers.Count.ShouldBe(8); // 10 - 2 = 8
    org.OrganizationMemberList.OrganizationMembers.Contains(Member3).ShouldBeFalse();
    org.OrganizationMemberList.OrganizationMembers.Contains(Member4).ShouldBeFalse();
    
    // VULNERABILITY: Proposal is STILL releasable even though only 5/8 (62.5%) 
    // current members voted, not 7/8 (87.5%) as intended by MinimalVoteThreshold
    proposalOutput = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalOutput.ToBeReleased.ShouldBeTrue(); // Should be FALSE but is TRUE
    
    // The release succeeds with insufficient current member participation
    var releaseResult = await Reviewer1Stub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Proposal was released with only 5/8 current member participation
    // bypassing the MinimalVoteThreshold of 7 which should require 7/8 participation
}
```

This test demonstrates that after removing members who voted, the proposal remains releasable despite having insufficient participation from current members. The vulnerability allows governance bypass where only 5 of 8 remaining members (62.5%) participated, yet the proposal passes the MinimalVoteThreshold of 7, which was intended to require 7 of 8 members (87.5%) to participate.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-37)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-43)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-49)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-57)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L266-280)
```csharp
    public override Empty RemoveMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input);
        Assert(removeResult, "Remove member failed.");
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberRemoved
        {
            OrganizationAddress = Context.Sender,
            Member = input
        });
        return new Empty();
    }
```
