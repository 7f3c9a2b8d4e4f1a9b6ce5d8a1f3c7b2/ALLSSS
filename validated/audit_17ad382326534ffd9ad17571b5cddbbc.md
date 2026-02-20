# Audit Report

## Title
Inconsistent Vote Counting Allows MinimalVoteThreshold Bypass via Member Removal

## Summary
The Association contract contains a critical inconsistency in vote threshold validation where individual vote type checks filter by current membership, but the total vote count for `MinimalVoteThreshold` includes votes from removed members, allowing proposals to satisfy participation requirements with fewer current-member votes than intended.

## Finding Description

The `CheckEnoughVoteAndApprovals()` function in the Association contract applies membership filtering inconsistently across different vote checks. [1](#0-0)  This line correctly filters approval votes by checking if each approver is in the current `OrganizationMemberList`. Similarly, rejection and abstention checks also filter by current membership at [2](#0-1)  and [3](#0-2) .

However, the critical `MinimalVoteThreshold` check fails to apply this filtering: [4](#0-3)  These lines concatenate and count ALL votes without verifying membership, allowing votes from removed members to satisfy the participation threshold.

The root cause is that `RemoveMember()` only updates the membership list without invalidating existing votes: [5](#0-4)  When a member is removed, their votes remain in the proposal's `Approvals`, `Rejections`, or `Abstentions` lists with no mechanism to invalidate or recount them.

The organization validation logic establishes that thresholds must be semantically bound to current membership: [6](#0-5)  This validation enforces that `MinimalVoteThreshold <= organizationMemberCount`, establishing the intent that thresholds represent counts of current members. The unfiltered counting in `CheckEnoughVoteAndApprovals()` directly violates this semantic constraint.

**Concrete Exploit Scenario:**
1. Organization has 10 members with `MinimalVoteThreshold=8`, `MinimalApprovalThreshold=6`
2. Proposal receives 6 approvals and 2 rejections (8 total votes)
3. Organization removes the 2 rejecting members via `RemoveMember()`
4. Organization now has 8 members, proposal still has 8 votes in storage
5. When `Release()` is called:
   - Rejection check: 0 current-member rejections (filtered) → passes
   - Approval check: 6 current-member approvals (filtered) → passes
   - **Vote threshold check: 8 total votes (unfiltered) → passes**
6. Proposal releases despite only 6/8 (75%) current members participating, violating the 8/8 (100%) intended threshold

## Impact Explanation

**Severity: Medium**

This vulnerability has measurable governance impact:

1. **Participation Threshold Bypass**: Proposals can satisfy `MinimalVoteThreshold` with fewer current-member votes than specified. An organization requiring 80% participation can have proposals pass with 60% actual participation by counting removed members' votes.

2. **Strategic Vote Manipulation**: Organizations can remove dissenting voters after they vote. Since rejection/abstention checks filter by current membership [2](#0-1) , removed members' dissenting votes won't block proposals, but their votes still satisfy the participation threshold.

3. **Semantic Invariant Violation**: The validation explicitly enforces [6](#0-5)  that `MinimalVoteThreshold <= organizationMemberCount`, establishing that thresholds must be achievable with current membership. The unfiltered counting breaks this fundamental governance invariant.

The severity is Medium because exploitation requires organization authority to execute `RemoveMember()`, which is a privileged operation requiring the organization itself to call it [7](#0-6) . However, this vulnerability can manifest without malicious intent through legitimate member management operations.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is triggerable through standard governance operations:

**Feasibility:**
- Organizations legitimately add and remove members during normal operations
- Multiple concurrent proposals are common in active organizations  
- Large timing window exists between voting and proposal release
- No detection mechanisms exist since the view method returns unfiltered counts [8](#0-7) 

**Realistic Preconditions:**
- `RemoveMember()` functionality is always available [5](#0-4) 
- Organizations frequently have multiple active proposals
- Timing coordination is achievable given proposal lifetimes
- Membership validation occurs at vote time [9](#0-8) , not at release time

The likelihood is Medium because while member removal is less frequent than voting, it's a standard governance operation that organizations perform. The vulnerability manifests whenever removal occurs with outstanding proposal votes, which is realistic in active governance organizations.

## Recommendation

Apply consistent membership filtering to the `MinimalVoteThreshold` check. Modify `CheckEnoughVoteAndApprovals()` to filter all votes by current membership:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // Apply membership filtering to total vote count
    var currentMemberVoteCount = 
        proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
        proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
        proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        currentMemberVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures that only votes from current members count toward the participation threshold, maintaining the semantic invariant enforced at line 72 of the validation logic.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Bypass_Via_MemberRemoval()
{
    // Setup: Create organization with 10 members, MinimalVoteThreshold=8, MinimalApprovalThreshold=6
    var members = Enumerable.Range(0, 10).Select(_ => SampleAddress.AddressList[_]).ToList();
    var organization = await CreateOrganization(members, minimalVoteThreshold: 8, minimalApprovalThreshold: 6);
    
    // Create proposal
    var proposalId = await CreateProposal(organization);
    
    // 6 members approve, 2 members reject (8 total votes)
    for (int i = 0; i < 6; i++)
        await Approve(proposalId, members[i]);
    for (int i = 6; i < 8; i++)
        await Reject(proposalId, members[i]);
    
    // Remove the 2 rejecting members
    await RemoveMember(organization, members[6]);
    await RemoveMember(organization, members[7]);
    
    // Verify: Organization now has 8 members but proposal still has 8 votes
    var orgInfo = await GetOrganization(organization);
    orgInfo.OrganizationMemberList.Count.ShouldBe(8);
    
    // Attack: Release proposal with only 6/8 current-member votes (should fail but passes)
    var result = await Release(proposalId);
    result.Success.ShouldBeTrue(); // Vulnerability: proposal releases despite insufficient participation
    
    // Expected: MinimalVoteThreshold=8 should require 8 current-member votes
    // Actual: Only 6 current-member votes counted, but 2 removed-member votes bring total to 8
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L37-37)
```csharp
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association.cs (L36-38)
```csharp
            ApprovalCount = proposal.Approvals.Count,
            RejectionCount = proposal.Rejections.Count,
            AbstentionCount = proposal.Abstentions.Count,
```

**File:** contract/AElf.Contracts.Association/Association.cs (L128-128)
```csharp
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);
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
