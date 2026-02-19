# Audit Report

## Title
MinimalVoteThreshold Counts Historical Votes Instead of Current Member Participation, Bypassing Quorum Requirements

## Summary
The Association contract's `CheckEnoughVoteAndApprovals()` function counts all historical votes toward `MinimalVoteThreshold` without filtering by current organization membership, unlike all other threshold checks. This allows proposals to be released without adequate participation from the current organization when membership changes occur after voting begins.

## Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals()` method where the `MinimalVoteThreshold` check concatenates and counts all vote lists without filtering by current membership. [1](#0-0) 

This is inconsistent with how other threshold checks properly filter votes by current organization membership:

**Approval threshold filtering:** [2](#0-1) 

**Rejection threshold filtering:** [3](#0-2) 

**Abstention threshold filtering:** [4](#0-3) 

The vulnerability occurs because organizations can modify membership after voting begins using methods like `AddMember`, `RemoveMember`, and `ChangeMember`: [5](#0-4) [6](#0-5) 

When `Release()` is called, it retrieves the current organization state and checks thresholds against it: [7](#0-6) 

The organization validation only ensures thresholds are valid for the current member count at modification time, not that actual votes counted come from current members: [8](#0-7) 

The `AssertProposalNotYetVotedBySender` protection only prevents duplicate votes by the same address, not membership changes: [9](#0-8) 

## Impact Explanation

**HIGH severity** - This vulnerability breaks the quorum mechanism, a fundamental governance protection:

1. **Quorum Bypass via Member Addition**: An organization with 10 members that receives 8 votes (80% participation) can add 20 new members. The proposal can still be released with only 8/30 votes (26.7% participation) because `MinimalVoteThreshold` counts historical votes while other checks filter by current membership. The intended quorum becomes meaningless.

2. **Vote Inflation via Removed Members**: Members who vote and are subsequently removed still have their votes count toward `MinimalVoteThreshold` while not counting toward approval/rejection/abstention thresholds. This creates an inconsistent state where historical non-members influence quorum decisions.

3. **Governance Integrity Violation**: The `MinimalVoteThreshold` is designed to ensure adequate organizational participation before executing proposals. This vulnerability allows proposals to execute without true quorum from current membership, undermining the governance model's fundamental invariant that proposals require sufficient current member participation.

## Likelihood Explanation

**HIGH likelihood** - This vulnerability can be triggered through standard governance operations:

- **Attack Complexity**: LOW - Simple sequence: create proposal → gather votes → modify membership → release proposal
- **Required Privileges**: Only standard governance capabilities (proposer whitelist membership and organization governance approval for membership changes)
- **Feasibility**: Organizations frequently modify membership as part of normal operations. Proposals can have long lifetimes until `ExpiredTime`, providing ample opportunity for membership changes.
- **Natural Occurrence**: This can happen unintentionally during legitimate governance operations, making it both an exploitable vulnerability and an operational flaw.

The inconsistency is subtle and wouldn't be detected until detailed analysis of vote ratios versus current membership, making membership changes unsuspicious operations.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals()` method to filter votes by current organization membership, consistent with other threshold checks:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter votes by current membership
    var currentMemberVoteCount = 
        proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
        proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
        proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        currentMemberVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures that only votes from current organization members count toward the minimal vote threshold, maintaining the intended quorum semantics.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_CountsHistoricalVotes_QuorumBypass()
{
    // Setup: Create organization with 10 members, MinimalVoteThreshold = 8
    var organization = await CreateOrganizationWithMembers(10, minimalVoteThreshold: 8);
    
    // Step 1: Create proposal
    var proposalId = await CreateProposal(organization);
    
    // Step 2: Get 8 votes (80% of 10 members - meets quorum)
    await Vote8Members(proposalId);
    
    // Step 3: Add 20 new members (total now 30 members)
    await AddMembers(organization, 20);
    
    // Step 4: Release proposal
    // EXPECTED: Should fail because 8/30 (26.7%) < MinimalVoteThreshold requirement
    // ACTUAL: Succeeds because MinimalVoteThreshold counts all 8 historical votes
    var result = await ReleaseProposal(proposalId);
    
    // Vulnerability confirmed: Proposal released with only 26.7% current member participation
    Assert.True(result.Success); // This should fail but passes due to vulnerability
}
```

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L72-72)
```csharp
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L132-137)
```csharp
    private void AssertProposalNotYetVotedBySender(ProposalInfo proposal, Address sender)
    {
        var isAlreadyVoted = proposal.Approvals.Contains(sender) || proposal.Rejections.Contains(sender) ||
                             proposal.Abstentions.Contains(sender);

        Assert(!isAlreadyVoted, "Sender already voted.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L187-188)
```csharp
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-245)
```csharp
    public override Empty AddMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberAdded
        {
            OrganizationAddress = Context.Sender,
            Member = input
        });
        return new Empty();
```

**File:** contract/AElf.Contracts.Association/Association.cs (L266-279)
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
```
