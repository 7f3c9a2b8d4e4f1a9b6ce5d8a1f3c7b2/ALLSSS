# Audit Report

## Title
Association Contract Member List Manipulation Allows Retroactive Vote Invalidation

## Summary
The Association contract's vote counting mechanism uses the current organization member list at release time rather than preserving a snapshot from voting time, allowing votes cast by members to be retroactively invalidated by removing those members before proposal release. This fundamentally breaks the governance invariant that votes should be immutable once cast.

## Finding Description

The Association contract implements a governance system where organization members vote on proposals. However, the design contains a critical flaw: votes are counted against the **current** member list at release time, not the member list that existed when votes were cast.

**Vote Storage During Voting:**

When members vote, their addresses are added to the proposal's vote lists (`Approvals`, `Rejections`, or `Abstentions`) and membership is verified at that specific moment. [1](#0-0) 

**Vote Counting at Release:**

When determining if a proposal can be released, the contract dynamically filters votes against the **current** member list. The rejection counting explicitly filters: [2](#0-1) 

The abstention counting uses the same pattern: [3](#0-2) 

The approval counting also filters dynamically: [4](#0-3) 

**Member List Modification:**

The organization can modify its member list through methods that only the organization address itself can call: [5](#0-4) 

Critically, the `RemoveMember` validation only checks that the organization's thresholds remain mathematically valid with the new member count - it does NOT check for pending proposals or protect existing votes. [6](#0-5) 

**Root Cause:**

The proposal structure only stores the organization address reference, not a snapshot of the member list at proposal creation time: [7](#0-6) 

The vote counting at release time queries the current organization state dynamically, allowing retroactive invalidation of votes when members are removed between voting and release. [8](#0-7) 

## Impact Explanation

This vulnerability breaks the fundamental governance invariant that votes are immutable once cast, enabling manipulation of governance outcomes.

**Attack Scenario 1 - Denying Legitimate Proposals:**
- Organization with 10 members requires 6 approvals
- Proposal X receives approvals from members [A, B, C, D, E, F] (threshold met)
- Before release, organization passes and releases a proposal to remove members [A, B, C, D]
- Organization retains 6 members, validation passes (MinimalApprovalThreshold still ≤ organizationMemberCount)
- When attempting to release Proposal X, only 2 votes count (E and F), failing the threshold of 6
- A legitimate proposal that properly achieved consensus is blocked

**Attack Scenario 2 - Enabling Rejected Proposals:**
- Organization with max rejection threshold of 2
- Proposal Y receives rejections from members [A, B] (should be blocked)
- Organization removes members A and B through governance
- Proposal Y now has 0 counted rejections, bypassing the rejection threshold
- A legitimately rejected proposal can now be released

This affects any association-based governance including contract upgrades, treasury management, and system parameter changes. The impact is **Critical** because it enables direct manipulation of governance outcomes and undermines trust in the entire governance system.

## Likelihood Explanation

**Attacker Requirements:**
- Must control an association organization (either as creator with member support, or by gaining control through legitimate governance)
- Must have sufficient compliant members to pass member modification proposals

**Attack Complexity:** Low to Medium
1. Create or gain control of an association organization
2. Create a target proposal and wait for voting
3. Create and release a member modification proposal before releasing the target proposal
4. Release the target proposal with manipulated vote counts

**Feasibility:** Medium to High depending on organization structure. Organizations with centralized control or majority coalitions can execute this attack. The time window between voting completion and proposal release provides the opportunity for manipulation. While member list changes emit events, events alone do not prevent the attack since the modification is performed through legitimate governance mechanisms.

## Recommendation

Implement a snapshot mechanism that preserves the member list state at proposal creation time or at voting time. Modify the vote counting logic to use the snapshot instead of the current member list.

**Option 1: Store member list snapshot in proposal**
```csharp
// In ProposalInfo structure
repeated aelf.Address member_list_snapshot = 14;

// In CreateNewProposal
proposal.MemberListSnapshot = organization.OrganizationMemberList.OrganizationMembers;

// In vote counting methods
var approvedMemberCount = proposal.Approvals.Count(proposal.MemberListSnapshot.Contains);
```

**Option 2: Block member removal when pending proposals exist**
```csharp
// In RemoveMember method
var hasPendingProposals = State.Proposals.Any(p => 
    p.Value.OrganizationAddress == Context.Sender && 
    p.Value.ExpiredTime > Context.CurrentBlockTime);
Assert(!hasPendingProposals, "Cannot remove members while proposals are pending.");
```

Option 1 is preferred as it maintains vote integrity without restricting legitimate member management.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MemberRemoval_InvalidatesExistingVotes()
{
    // Setup: Create organization with 6 members, threshold of 4 approvals
    var members = new[] { Member1, Member2, Member3, Member4, Member5, Member6 };
    var org = await CreateOrganizationAsync(members, minimalApproval: 4);
    
    // Step 1: Create proposal
    var proposalId = await CreateProposalAsync(org);
    
    // Step 2: Get 4 approvals (meets threshold)
    await ApproveAsync(proposalId, Member1);
    await ApproveAsync(proposalId, Member2);
    await ApproveAsync(proposalId, Member3);
    await ApproveAsync(proposalId, Member4);
    
    // Verify: Proposal should be ready to release
    var proposal = await GetProposalAsync(proposalId);
    proposal.ToBeReleased.ShouldBeTrue();
    
    // Step 3: Remove 2 members who voted
    await RemoveMemberAsync(org, Member1);
    await RemoveMemberAsync(org, Member2);
    
    // Step 4: Check proposal status again
    proposal = await GetProposalAsync(proposalId);
    
    // VULNERABILITY: Proposal is no longer releasable
    // Only 2 votes count now (Member3, Member4), below threshold of 4
    proposal.ToBeReleased.ShouldBeFalse(); // Demonstrates vote invalidation
    
    // Attempting to release will fail
    var result = await ReleaseAsync(proposalId);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Not approved");
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L123-141)
```csharp
    public override Empty Approve(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Approve),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }
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

**File:** protobuf/association_contract.proto (L76-103)
```text
message ProposalInfo {
    // The proposal ID.
    aelf.Hash proposal_id = 1;
    // The method that this proposal will call when being released.
    string contract_method_name = 2;
    // The address of the target contract.
    aelf.Address to_address = 3;
    // The parameters of the release transaction.
    bytes params = 4;
    // The date at which this proposal will expire.
    google.protobuf.Timestamp expired_time = 5;
    // The address of the proposer of this proposal.
    aelf.Address proposer = 6;
    // The address of this proposals organization.
    aelf.Address organization_address = 7;
    // Address list of approved.
    repeated aelf.Address approvals = 8;
    // Address list of rejected.
    repeated aelf.Address rejections = 9;
    // Address list of abstained.
    repeated aelf.Address abstentions = 10;
    // Url is used for proposal describing.
    string proposal_description_url = 11;
    // Title of this proposal.
    string title = 12;
    // Description of this proposal.
    string description = 13;
}
```
