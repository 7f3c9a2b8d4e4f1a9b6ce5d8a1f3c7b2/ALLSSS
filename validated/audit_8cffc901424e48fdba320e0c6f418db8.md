# Audit Report

## Title
In-Flight Proposal Approval Invalidation via Member Removal Causes Governance Denial of Service

## Summary
The Association contract's `RemoveMember` function allows removal of members who have approved pending proposals, causing those proposals to fail release validation even after legitimately achieving the required approval threshold. This occurs because the `Release` function dynamically recalculates approval counts by filtering through the current member list rather than preserving approval validity from the time votes were cast.

## Finding Description

The vulnerability exists in the interaction between member removal and proposal release validation.

When `RemoveMember` is called, it removes a member from `organization.OrganizationMemberList.OrganizationMembers` and updates the state. [1](#0-0)  The validation only ensures the organization itself remains valid (thresholds don't exceed new member count), but does not check for impact on existing proposals.

When `Release` is called later, it retrieves the current organization state and validates approval thresholds. [2](#0-1) 

The critical flaw is in `CheckEnoughVoteAndApprovals`, which counts approvals by filtering `proposal.Approvals` through `organization.OrganizationMemberList.Contains`. [3](#0-2)  If a member who approved is no longer in the organization, their approval is not counted, even though they were a valid member when they approved.

The `Contains` method checks membership against the current state. [4](#0-3) 

**Attack Scenario:**
1. Organization has 5 members: [Alice, Bob, Carol, Dave, Eve] with MinimalApprovalThreshold = 3
2. Proposal P1 is created for a critical governance action
3. Alice, Bob, and Carol approve P1 (3 approvals - threshold met)
4. Before P1 is released, Proposal P2 is created to remove Alice
5. Bob, Carol, and Dave approve P2 (3 approvals - threshold met)
6. P2 is released, removing Alice from the organization
7. When attempting to release P1, the approval count filters through current members: only Bob and Carol remain as members, so approvedMemberCount = 2
8. P1 fails with "Not approved" despite having legitimately achieved the required approvals

## Impact Explanation

**Governance Denial of Service:** This breaks a fundamental governance invariant - a proposal that achieved required approvals should remain executable. Critical proposals become permanently unreleasable if enough approving members are subsequently removed.

**Configuration Lock:** Organizations cannot execute time-sensitive governance actions such as threshold changes, emergency responses, or contract upgrades if approving members are removed before release.

**Operational Deadlock:** An organization could become unable to execute any proposals if coordinated member removal systematically targets all approvers.

This is HIGH severity because it compromises governance integrity and availability. While no funds are directly stolen, the ability to execute governance decisions is a critical protocol guarantee that is violated.

## Likelihood Explanation

**Medium-High Likelihood** - This can occur through both malicious coordination and accidental operational mistakes.

**Attacker Capabilities:** Only requires ability to create and pass proposals for member removal, which is a normal organization capability available to any member in the proposer whitelist.

**Attack Complexity:** LOW - The attack sequence is straightforward and requires no special privileges:
1. Wait for a proposal to accumulate approvals
2. Create RemoveMember proposal(s) targeting members who approved
3. Get those removal proposals approved and released
4. Original proposal now fails threshold check

**Feasibility:** Organizations frequently adjust membership as part of normal operations. There are no technical barriers or warnings that prevent removal of members with outstanding votes on active proposals. The issue manifests only when attempting to release the affected proposal, making it difficult to detect preventatively.

## Recommendation

Implement one of the following solutions:

**Option 1: Prevent removal of members with active votes**
Add a check in `RemoveMember` to prevent removal if the member has voted on any non-expired proposals:

```csharp
public override Empty RemoveMember(Address input)
{
    var organization = State.Organizations[Context.Sender];
    Assert(organization != null, "Organization not found.");
    
    // Check if member has votes on active proposals
    Assert(!HasActiveVotes(input, Context.Sender), 
        "Cannot remove member with votes on active proposals.");
    
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

**Option 2: Snapshot member list at approval time**
Store a snapshot of valid voters when each vote is cast, and validate against that snapshot instead of current membership during release.

**Option 3: Count all historical approvals**
Remove the `.Contains` filter in `CheckEnoughVoteAndApprovals` and count all approvals regardless of current membership status, ensuring that votes remain valid even after membership changes.

## Proof of Concept

```csharp
[Fact]
public async Task ProposalBecomesUnreleasableAfterMemberRemoval()
{
    // Setup: Create organization with 5 members and threshold of 3
    var members = new[] { Alice, Bob, Carol, Dave, Eve };
    var orgAddress = await CreateOrganizationAsync(members, minimalApprovalThreshold: 3);
    
    // Create proposal P1
    var proposalId1 = await CreateProposalAsync(orgAddress, "SomeAction");
    
    // Alice, Bob, Carol approve P1 (meets threshold)
    await ApproveAsync(proposalId1, Alice);
    await ApproveAsync(proposalId1, Bob);
    await ApproveAsync(proposalId1, Carol);
    
    // Verify P1 is ready to release
    var proposal1Info = await GetProposalAsync(proposalId1);
    Assert.True(proposal1Info.ToBeReleased);
    
    // Create proposal P2 to remove Alice
    var proposalId2 = await CreateProposalAsync(orgAddress, "RemoveMember", Alice);
    
    // Bob, Carol, Dave approve P2
    await ApproveAsync(proposalId2, Bob);
    await ApproveAsync(proposalId2, Carol);
    await ApproveAsync(proposalId2, Dave);
    
    // Release P2 (Alice is removed)
    await ReleaseAsync(proposalId2);
    
    // Verify Alice is no longer a member
    var org = await GetOrganizationAsync(orgAddress);
    Assert.False(org.OrganizationMemberList.OrganizationMembers.Contains(Alice));
    
    // Attempt to release P1 - should fail despite having 3 approvals originally
    proposal1Info = await GetProposalAsync(proposalId1);
    Assert.False(proposal1Info.ToBeReleased); // Only 2 current members (Bob, Carol) approved
    
    // Release will revert with "Not approved"
    var exception = await Assert.ThrowsAsync<AssertionException>(
        () => ReleaseAsync(proposalId1)
    );
    Assert.Contains("Not approved", exception.Message);
}
```

## Notes

This vulnerability affects all Association-based governance organizations and represents a fundamental flaw in how proposal validity is determined. The dynamic recalculation of approvals against current membership creates a time-of-check-time-of-use (TOCTOU) vulnerability in the governance mechanism. Organizations should be aware that membership changes can retroactively invalidate pending proposals, and should coordinate member removal carefully with proposal release timing until this issue is addressed.

### Citations

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

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L17-20)
```csharp
    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
    }
```
