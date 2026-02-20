# Audit Report

## Title
Vote Counting Inconsistency Enables Governance Manipulation via Member Removal After Voting

## Summary
The Association contract contains a critical vote counting asymmetry where approval/rejection/abstention counts are filtered by current organization members, but the total vote threshold check counts all votes including those from removed members. This enables a majority coalition to manipulate governance outcomes by removing dissenting voters after they vote, converting legitimately rejected proposals into passable ones.

## Finding Description

The vulnerability exists in the `Association_Helper.cs` vote counting logic. The `CheckEnoughVoteAndApprovals` function filters approval counts by current membership [1](#0-0) , while the total vote participation count concatenates all vote lists WITHOUT filtering by current membership [2](#0-1) . Similarly, `IsProposalRejected` [3](#0-2)  and `IsProposalAbstained` [4](#0-3)  both filter their respective vote counts by current members only.

When members are removed via `RemoveMember` [5](#0-4) , the removal updates `organization.OrganizationMemberList` but does NOT clean up or invalidate existing proposal votes. The removed member's address remains in the proposal's vote lists (added via `Approve` [6](#0-5) , `Reject` [7](#0-6) , or `Abstain` methods), but is no longer in the membership list used for filtering.

When `Release` checks `IsReleaseThresholdReached` [8](#0-7) , removed members' votes do NOT count toward approval/rejection/abstention thresholds (filtered out) but STILL count toward the MinimalVoteThreshold (not filtered).

**Attack Execution:**
1. Organization has 10 members with MinimalApprovalThreshold=5, MinimalVoteThreshold=8, MaximalRejectionThreshold=2
2. Proposal A receives: 5 approvals, 3 rejections, 1 abstention (9 total votes)
3. Status: REJECTED because 3 rejections > MaximalRejectionThreshold of 2
4. Majority coalition passes a separate proposal to remove 2 of the 3 rejecting members
5. Organization now has 8 members
6. Proposal A recheck: only 1 rejection (filtered to current members) ≤ 2 threshold → passes rejection check
7. Total votes: still 9 (including removed members' votes) ≥ MinimalVoteThreshold of 8 → passes vote threshold
8. Proposal A is NOW PASSABLE and can be released, executing previously rejected actions

## Impact Explanation

This vulnerability breaks the fundamental governance invariant that proposal outcomes must reflect the consensus of current members at release time. The asymmetric filtering creates an exploitable inconsistency enabling:

- **Retroactive Outcome Manipulation**: A majority coalition can change proposal outcomes after voting has concluded by selectively removing dissenting voters
- **Minority Suppression**: Enables systematic disenfranchisement of opposition members to force through contentious proposals
- **Unauthorized Proposal Execution**: Proposals that were legitimately rejected can be made passable, executing actions that did not have proper member approval

All Association-based organizations are vulnerable. Since Association contracts can control critical protocol operations (treasury management, parameter updates, contract upgrades), this enables unauthorized execution of high-impact governance decisions.

## Likelihood Explanation

**Attacker Profile:** Requires a majority coalition within the organization to control enough votes to pass member removal proposals and coordinate the attack sequence.

**Feasibility:** MEDIUM-HIGH
- All operations are legitimate governance actions accessible via public methods
- Requires coordination between two sequential proposals (removal, then release)
- Must execute within proposal expiration timeframes
- The organization configuration must have thresholds that remain valid after removal (checked by `Validate` [9](#0-8) )
- Majority control requirement is realistic in contentious governance scenarios where a slim majority wants to override strong minority opposition

**Detection:** The attack pattern (member removal followed by release of previously rejected proposal) is detectable on-chain but the individual operations appear legitimate.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` function to filter the total vote count by current organization members, consistent with how approval/rejection/abstention counts are filtered:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter total votes by current members
    var totalVoteCount = proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains);
    var isVoteThresholdReached =
        totalVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

Alternatively, consider invalidating or cleaning up proposal votes when members are removed to maintain consistency.

## Proof of Concept

```csharp
[Fact]
public async Task VoteCountingInconsistency_MemberRemovalManipulation()
{
    // Setup: Create organization with 10 members
    var members = Enumerable.Range(0, 10).Select(_ => SampleAddress.AddressList[_]).ToList();
    var organizationAddress = await CreateOrganizationAsync(
        members,
        minimalApprovalThreshold: 5,
        minimalVoteThreshold: 8,
        maximalRejectionThreshold: 2
    );

    // Step 1: Create proposal
    var proposalId = await CreateProposalAsync(organizationAddress);

    // Step 2: Vote - 5 approvals, 3 rejections, 1 abstention
    for (int i = 0; i < 5; i++)
        await ApproveAsync(proposalId, members[i]);
    for (int i = 5; i < 8; i++)
        await RejectAsync(proposalId, members[i]);
    await AbstainAsync(proposalId, members[8]);

    // Step 3: Verify proposal is REJECTED (3 rejections > 2 threshold)
    var proposalOutput = await GetProposalAsync(proposalId);
    Assert.False(proposalOutput.ToBeReleased); // Should be rejected

    // Step 4: Remove 2 rejecting members
    await RemoveMemberAsync(organizationAddress, members[5]);
    await RemoveMemberAsync(organizationAddress, members[6]);

    // Step 5: Check proposal again - NOW PASSABLE
    proposalOutput = await GetProposalAsync(proposalId);
    Assert.True(proposalOutput.ToBeReleased); // VULNERABILITY: Now passable!

    // Step 6: Release succeeds despite original rejection
    var releaseResult = await ReleaseAsync(proposalId);
    Assert.True(releaseResult.Success); // VULNERABILITY: Rejected proposal executed!
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-44)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-81)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
        if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
            return false;
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var organizationMemberCount = organization.OrganizationMemberList.Count();
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L130-130)
```csharp
        proposal.Approvals.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L150-150)
```csharp
        proposal.Rejections.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L188-188)
```csharp
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
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
