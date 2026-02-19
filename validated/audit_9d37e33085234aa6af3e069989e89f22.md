# Audit Report

## Title
Vote Persistence After Member Removal Enables Governance Manipulation

## Summary
The Association contract's `RemoveMember()` function fails to clean up existing votes on pending proposals, creating a critical inconsistency in threshold calculations. Rejection, abstention, and approval counts filter votes by current membership, but the total vote threshold calculation does not, allowing organizations to bypass `MaximalRejectionThreshold` and `MaximalAbstentionThreshold` protections by strategically removing dissenting members.

## Finding Description

The vulnerability stems from an inconsistency between how individual vote types are counted versus how total votes are counted when determining if a proposal can be released.

The `RemoveMember()` function only modifies the organization's member list without touching existing votes on pending proposals. [1](#0-0) 

When a proposal's release threshold is evaluated, the `IsProposalRejected()` method filters rejection votes by checking if voters are still in the current member list. [2](#0-1)  Similarly, `IsProposalAbstained()` filters abstention votes by current membership. [3](#0-2) 

However, the `CheckEnoughVoteAndApprovals()` method contains a critical flaw. While it correctly filters approval votes by current membership, the total vote count concatenates all vote lists without any membership filtering. [4](#0-3) 

This inconsistency enables the following attack:
1. A proposal receives votes including rejections or abstentions
2. The organization (via another proposal) calls `RemoveMember()` to remove members who voted unfavorably  
3. When the original proposal's `Release()` method evaluates `IsReleaseThresholdReached()`, removed members' rejection/abstention votes no longer count against the respective maximum thresholds
4. However, their votes still count toward the `MinimalVoteThreshold` requirement
5. The proposal can now pass despite having exceeded rejection/abstention limits

## Impact Explanation

This vulnerability completely undermines the Association contract's governance safeguards:

**Direct Governance Bypass**: Organizations can circumvent `MaximalRejectionThreshold` and `MaximalAbstentionThreshold` - two critical protections designed to prevent proposals from passing when too many members oppose or abstain. For example, with 10 members, `MinimalVoteThreshold=7`, `MaximalRejectionThreshold=2`, and `MinimalApprovalThreshold=5`, a proposal with 5 approvals and 3 rejections (8 total votes) would normally fail. By removing the 3 rejecting members, the rejection count becomes 0 while maintaining 8 total votes, allowing the proposal to pass.

**Affected Parties**: All Association organization members and stakeholders relying on Association-based governance for protocol decisions, fund management, or multi-sig operations. This includes token holders, DApp users, and any entities dependent on honest governance outcomes.

**Severity**: This is a critical governance integrity violation. The Association contract's threshold system is designed as a check-and-balance mechanism. By allowing threshold manipulation through membership changes rather than genuine consensus, the vulnerability enables minority factions to force through proposals, fundamentally breaking the governance model.

## Likelihood Explanation

**Attacker Capabilities**: The organization itself (acting through a passed proposal) has the authority to remove members. While this requires initial consensus, once a faction gains sufficient control to pass a single member removal proposal, they can leverage this vulnerability to manipulate subsequent proposals without proper scrutiny.

**Attack Complexity**: Low to medium complexity. The attack requires:
1. Achieving enough votes to pass an initial member removal proposal
2. Timing the removal to occur after unfavorable votes are cast on target proposals
3. Subsequently releasing the manipulated proposal

**Practical Feasibility**: The attack is realistic in organizations where a faction controls slightly above `MinimalApprovalThreshold` but faces opposition. The faction can pass one removal proposal, eliminate the opposition's voting power, then pass subsequent proposals that would have failed under normal circumstances.

**Detection Challenges**: The manipulation is not immediately obvious from on-chain activity and can appear as legitimate governance operations. Only careful analysis of the timing between member removals and proposal releases would reveal the exploitation pattern.

## Recommendation

Implement one of the following fixes:

**Option 1 (Recommended)**: Invalidate votes from removed members by filtering the total vote count consistently:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough = approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // Fix: Filter total votes by current membership
    var totalValidVotes = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
                          proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
                          proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    var isVoteThresholdReached = totalValidVotes >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

**Option 2**: Clean up votes when removing members:

```csharp
public override Empty RemoveMember(Address input)
{
    var organization = State.Organizations[Context.Sender];
    Assert(organization != null, "Organization not found.");
    var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input);
    Assert(removeResult, "Remove member failed.");
    
    // Clean up votes from removed member on all pending proposals
    // (Note: requires indexing proposals by organization or iterating, which may be costly)
    
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

Option 1 is preferred as it's simpler, maintains consistency in the counting logic, and doesn't require expensive proposal iteration.

## Proof of Concept

```csharp
[Fact]
public async Task VotePersistenceExploit_BypassesRejectionThreshold()
{
    // Setup: Organization with 10 members, MinimalVote=7, MaxRejection=2, MinimalApproval=5
    var members = Enumerable.Range(0, 10).Select(_ => SampleAddress.AddressList[_]).ToList();
    var organization = await CreateOrganizationAsync(new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList { OrganizationMembers = { members } },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalVoteThreshold = 7,
            MaximalRejectionThreshold = 2,
            MinimalApprovalThreshold = 5
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { members } }
    });

    // Create target proposal
    var proposalId = await CreateProposalAsync(organization);
    
    // 5 members approve, 3 reject (would normally fail due to rejection threshold)
    for (int i = 0; i < 5; i++) await ApproveAsync(proposalId, members[i]);
    for (int i = 5; i < 8; i++) await RejectAsync(proposalId, members[i]);
    
    // Verify proposal cannot be released (exceeds MaximalRejectionThreshold)
    var proposal1 = await GetProposalAsync(proposalId);
    Assert.False(proposal1.ToBeReleased);
    
    // Exploit: Remove the 3 rejecting members via a second proposal
    var removalProposalId = await CreateProposalAsync(organization, "RemoveMember", members[5]);
    for (int i = 0; i < 5; i++) await ApproveAsync(removalProposalId, members[i]);
    await ReleaseAsync(removalProposalId);
    
    // Similarly remove other rejecting members
    // ... (repeat for members[6] and members[7])
    
    // Now the original proposal can be released despite having 3 rejections
    var proposal2 = await GetProposalAsync(proposalId);
    Assert.True(proposal2.ToBeReleased); // Vulnerability: proposal is now releasable
    Assert.Equal(0, proposal2.RejectionCount); // Rejections no longer counted
    Assert.Equal(8, proposal2.Approvals.Count + proposal2.Rejections.Count + proposal2.Abstentions.Count); // But total votes still 8
}
```

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-59)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;

        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
    }
```
