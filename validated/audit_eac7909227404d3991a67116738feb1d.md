# Audit Report

## Title
Organization Member List Manipulation Allows Governance Bypass Through Post-Creation Vote Manipulation

## Summary
The Association contract fails to snapshot the organization member list at proposal creation time, allowing dynamic membership changes to manipulate voting outcomes on active proposals. Members added after proposal creation can vote on existing proposals, and removed members' votes can be retroactively invalidated during threshold checks.

## Finding Description

The Association contract contains a critical governance flaw where voting authorization and vote counting both check against the current organization member list rather than a snapshot captured at proposal creation time.

**Flaw 1: Dynamic Authorization Check**

When members vote on proposals, the contract fetches the current organization state [1](#0-0)  and verifies membership against the live member list [2](#0-1) . This means anyone added to the organization after a proposal's creation can immediately vote on that proposal, violating the governance principle that voting rights are determined at proposal creation time.

**Flaw 2: Vote Counting Filters by Current Membership**

During proposal release, the threshold calculation filters all votes by checking if voters still exist in the current member list. Rejections are filtered [3](#0-2) , abstentions are filtered [4](#0-3) , and approvals are filtered [5](#0-4) . If a member is removed from the organization, their previously-cast vote becomes invisible to the threshold calculation, effectively erasing their participation.

**Root Cause: No Member Snapshot**

The ProposalInfo structure only stores a reference to the organization address, not the member list state at creation time [6](#0-5) .

**Attack Vector: Member Modification Functions**

The organization can modify its membership through three functions, all callable by the organization itself via proposal execution: AddMember [7](#0-6) , RemoveMember [8](#0-7) , and ChangeMember [9](#0-8) .

**Exploitation Scenario:**

1. Organization has 5 members (A,B,C,D,E) with thresholds: MinimalApprovalThreshold=2, MaximalRejectionThreshold=1
2. Controversial Proposal P1 is created
3. Voting: A,B approve (2), D,E reject (2) - P1 fails due to rejections > threshold
4. Organization creates Proposal P2 to remove member D
5. P2 passes with A,B,C approving
6. After D's removal, when P1's release is checked, rejection count becomes 1 (only E remains in member list)
7. P1 now passes: rejections(1) ≤ MaximalRejectionThreshold(1), approvals(2) ≥ MinimalApprovalThreshold(2)

Alternatively, new members can be added who then vote on existing proposals they had no stake in when those proposals were created.

## Impact Explanation

This vulnerability enables complete governance bypass with critical consequences:

**Governance Integrity Violation**: The fundamental principle that voting rights and vote weight are fixed at proposal creation time is violated. This makes all governance outcomes potentially unreliable.

**Vote Manipulation**: An organization controlling enough votes to pass one proposal (for membership changes) can manipulate any other pending proposal's outcome by adding favorable members or removing opposing members to invalidate their rejection votes.

**Threshold Circumvention**: The carefully-designed approval/rejection thresholds become meaningless when the effective voter base can be retroactively modified.

**Systemic Impact**: All Association-based governance decisions (treasury allocations, parameter changes, contract upgrades) are affected. This undermines trust in the entire governance framework.

The severity is CRITICAL because it breaks core governance guarantees without requiring any privilege escalation or system compromise.

## Likelihood Explanation

This vulnerability has HIGH likelihood of exploitation:

**Low Barrier to Entry**: Any organization that can pass one proposal (to modify membership) can exploit this. No special privileges or system-level access required.

**Simple Execution**: The attack uses standard, documented functions (AddMember, RemoveMember, CreateProposal, Release). No complex exploitation technique needed.

**Natural Opportunity**: In contested governance scenarios, it's common to have multiple pending proposals with different voting patterns. This creates natural opportunities for manipulation.

**Validation Constraints Are Weak**: The validation logic [10](#0-9)  allows adding members freely (increasing member count loosens constraints) and removing members as long as thresholds remain valid for the new count.

**Detection Difficulty**: Member modifications appear as legitimate governance actions. There's no on-chain indicator distinguishing malicious timing-based manipulation from normal operations.

**Realistic Precondition**: Organizations routinely manage membership changes. The attacker needs only to time these changes strategically around pending proposals.

## Recommendation

Implement member list snapshotting at proposal creation time:

1. **Add snapshot field to ProposalInfo**: Store the complete member list when a proposal is created
2. **Use snapshot for authorization**: Modify AssertIsAuthorizedOrganizationMember to check against the proposal's member snapshot rather than current organization state
3. **Use snapshot for vote counting**: Update IsProposalRejected, IsProposalAbstained, and CheckEnoughVoteAndApprovals to filter votes against the proposal's member snapshot

This ensures voting rights and vote weight are immutably fixed at proposal creation time, preventing retroactive manipulation.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
public async Task Test_MemberRemoval_InvalidatesVotes()
{
    // Setup: Create organization with 5 members, thresholds: MinApproval=2, MaxRejection=1
    var members = new[] { AddressA, AddressB, AddressC, AddressD, AddressE };
    var orgAddress = await CreateOrganizationAsync(members, minApproval: 2, maxRejection: 1);
    
    // Step 1: Create controversial proposal P1
    var proposalP1 = await CreateProposalAsync(orgAddress, "P1");
    
    // Step 2: Vote on P1 - should fail due to 2 rejections > maxRejection(1)
    await ApproveAsync(proposalP1, AddressA);
    await ApproveAsync(proposalP1, AddressB);
    await RejectAsync(proposalP1, AddressD);
    await RejectAsync(proposalP1, AddressE);
    
    // Verify P1 cannot be released (2 rejections > 1 threshold)
    await Assert.ThrowsAsync<Exception>(() => ReleaseAsync(proposalP1));
    
    // Step 3: Create and pass proposal P2 to remove AddressD
    var proposalP2 = await CreateProposalAsync(orgAddress, "RemoveMember", AddressD);
    await ApproveAsync(proposalP2, AddressA);
    await ApproveAsync(proposalP2, AddressB);
    await ApproveAsync(proposalP2, AddressC);
    await ReleaseAsync(proposalP2); // P2 passes
    
    // Step 4: Now P1 can be released - AddressD's rejection no longer counts
    // Only 1 rejection (AddressE) remains, which equals maxRejection threshold
    await ReleaseAsync(proposalP1); // Should succeed - VULNERABILITY DEMONSTRATED
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L127-128)
```csharp
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-246)
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
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new MemberChanged
        {
            OrganizationAddress = Context.Sender,
            OldMember = input.OldMember,
            NewMember = input.NewMember
        });
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L18-22)
```csharp
    private void AssertIsAuthorizedOrganizationMember(Organization organization, Address member)
    {
        Assert(organization.OrganizationMemberList.Contains(member),
            "Unauthorized member.");
    }
```

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

**File:** protobuf/association_contract.proto (L90-90)
```text
    aelf.Address organization_address = 7;
```
