# Audit Report

## Title
Association Governance Bypass via Post-Vote Member List Manipulation

## Summary
The Association contract's rejection threshold enforcement can be bypassed by removing members who voted to reject a proposal after voting has occurred but before the proposal is released. The rejection count is recalculated using the current member list rather than a snapshot at voting time, enabling execution of proposals that should remain permanently rejected.

## Finding Description

The vulnerability exists in the rejection threshold calculation logic. When the `Release` method is called, it invokes `IsReleaseThresholdReached()` to validate the proposal can be executed [1](#0-0) . This function checks if the proposal has been rejected by calling `IsProposalRejected()` [2](#0-1) .

The critical flaw is in how `IsProposalRejected()` counts rejections. It filters the stored rejection addresses against the CURRENT organization member list [3](#0-2) . This creates a time-of-check/time-of-use (TOCTOU) vulnerability because:

1. **At voting time**: When members call `Reject()`, their addresses are permanently stored in `proposal.Rejections` [4](#0-3) 

2. **Between voting and release**: The organization can modify its member list through `RemoveMember`, `AddMember`, or `ChangeMember` methods [5](#0-4) . These functions require only that the sender is the organization itself and contain no validation for active proposals or impact on existing votes.

3. **At release time**: The rejection count is recalculated by filtering stored rejection addresses against the CURRENT (potentially modified) member list, not the member list at voting time.

The organization can call its own member manipulation functions through the virtual call mechanism. When `Release` executes a proposal, it uses `SendVirtualInlineBySystemContract` to call the target method with the organization address as sender [6](#0-5) .

**Attack Sequence:**
- Organization has 10 members, `MaximalRejectionThreshold = 3`
- Proposal A (malicious) receives 6 approvals and 4 rejections (rejected: 4 > 3)
- Create Proposal B targeting `RemoveMember` for one rejector
- Proposal B receives 6 approvals, 3 rejections (passes: 3 ≤ 3)
- Release Proposal B (removes member M)
- Proposal A's rejection count recalculates as 3 (member M no longer counted)
- Release Proposal A (now passes: 3 ≤ 3)

## Impact Explanation

**CRITICAL Severity** - This vulnerability completely undermines the rejection threshold protection mechanism, which is a fundamental governance safeguard in the Association contract.

**Broken Invariant**: The security guarantee that "proposals with rejections exceeding MaximalRejectionThreshold cannot be released" is violated. Once a proposal receives sufficient rejections to be permanently blocked, it should remain blocked regardless of subsequent organization changes.

**Concrete Harm**:
- Organizations can execute arbitrary proposals that were legitimately rejected by sufficient members
- Minority protections are nullified - members who voted to reject actions can have their votes retroactively invalidated
- No external compromise required - legitimate organization mechanisms are misused
- All Association-based governance organizations are affected, particularly those relying on rejection thresholds to prevent harmful actions (fund transfers, parameter changes, permission grants)

The impact is governance integrity breach rather than direct fund loss, but the consequences can be severe depending on what the manipulated proposals control (treasury funds, contract permissions, protocol parameters).

## Likelihood Explanation

**MEDIUM Likelihood** - The attack requires coordination among organization members but is fully executable through normal contract interactions.

**Attacker Profile**: This is not an external attack but rather collusion among organization members who control sufficient votes to pass a member removal proposal. They must meet `MinimalApprovalThreshold` but NOT `MaximalRejectionThreshold + 1` on the removal proposal.

**Preconditions**:
- At least one proposal with excessive rejections exists (target)
- Attackers can create and pass a member manipulation proposal (easier threshold)
- Multiple proposals can be active simultaneously (confirmed - no code prevents this)
- No time restrictions prevent sequential releases

**Attack Complexity**: 
- Create malicious Proposal A that receives excessive rejections
- Create Proposal B targeting RemoveMember/ChangeMember for rejector(s)
- Coordinate votes to pass Proposal B while keeping rejections ≤ threshold
- Release Proposal B first, then Proposal A
- Total cost: transaction fees for 2 proposals + coordination cost

**Detection**: The manipulation creates an audit trail (MemberRemoved events) but may not trigger real-time alerts before the vulnerable proposal is released.

**Economic Rationality**: For high-value governance decisions (e.g., treasury access, protocol upgrades), the benefit of bypassing rejection threshold far exceeds transaction costs.

## Recommendation

Implement vote immutability by capturing a membership snapshot when proposals are created and use that snapshot for all threshold calculations:

**Option 1: Snapshot at Proposal Creation**
- Store the organization member count at proposal creation time
- Calculate all thresholds (approval, rejection, abstention) against this fixed count
- Member list changes after proposal creation don't affect vote counting

**Option 2: Lock Member List During Active Proposals**
- Add check in `RemoveMember`, `AddMember`, `ChangeMember` to verify no active proposals reference this organization
- Reject member modifications if any non-expired proposals exist
- Requires iterating through active proposals (may have gas implications)

**Option 3: Snapshot Voters at Vote Time (Recommended)**
- When counting rejections, only count addresses that were members BOTH at voting time AND at release time (more restrictive)
- Alternatively, validate that no member list changes occurred between vote and release by comparing a hash of the member list
- Add an `organizationMemberListVersion` field that increments on any member change
- Store this version in the proposal and validate it hasn't changed at release time

**Implementation Sketch (Option 3):**
```csharp
// In Organization message, add:
int64 member_list_version = 1;

// In ProposalInfo message, add:
int64 organization_member_list_version_at_creation = 1;

// In RemoveMember/AddMember/ChangeMember, increment:
organization.MemberListVersion++;

// In CreateProposal, capture:
proposal.OrganizationMemberListVersionAtCreation = organization.MemberListVersion;

// In Release, validate:
Assert(proposal.OrganizationMemberListVersionAtCreation == organization.MemberListVersion, 
       "Member list changed during proposal voting period.");
```

This approach prevents any member list manipulation during the lifetime of a proposal without requiring vote snapshots or expensive iteration.

## Proof of Concept

```csharp
[Fact]
public async Task TestRejectionThresholdBypassViaMemberRemoval()
{
    // Setup: 10-member organization with MaximalRejectionThreshold = 3
    var members = new[] { Reviewer1, Reviewer2, Reviewer3, User1, User2, User3, User4, User5, User6, User7 };
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold: 6,
        minimalVoteThreshold: 6,
        maximalAbstentionThreshold: 10,
        maximalRejectionThreshold: 3,
        proposer: Reviewer1,
        members: members
    );
    
    // Step 1: Create Proposal A (malicious) - receives 4 rejections (should be blocked)
    var proposalA = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    await ApproveAsync(Reviewer1KeyPair, proposalA); // 1 approval
    await ApproveAsync(Reviewer2KeyPair, proposalA); // 2 approvals
    await ApproveAsync(Reviewer3KeyPair, proposalA); // 3 approvals
    await ApproveAsync(User1KeyPair, proposalA);     // 4 approvals
    await ApproveAsync(User2KeyPair, proposalA);     // 5 approvals
    await ApproveAsync(User3KeyPair, proposalA);     // 6 approvals
    await RejectAsync(User4KeyPair, proposalA);      // 1 rejection
    await RejectAsync(User5KeyPair, proposalA);      // 2 rejections
    await RejectAsync(User6KeyPair, proposalA);      // 3 rejections
    await RejectAsync(User7KeyPair, proposalA);      // 4 rejections (exceeds threshold!)
    
    // Verify Proposal A is blocked due to excessive rejections
    var proposalAState = await GetProposalAsync(proposalA);
    proposalAState.ToBeReleased.ShouldBeFalse(); // Cannot be released: 4 > 3
    
    // Step 2: Create Proposal B to remove User7 (one of the rejectors)
    var removeInput = User7;
    var proposalB = await CreateProposalAsync(
        Reviewer1KeyPair, 
        organizationAddress,
        "RemoveMember",
        removeInput
    );
    await ApproveAsync(Reviewer1KeyPair, proposalB); // 1 approval
    await ApproveAsync(Reviewer2KeyPair, proposalB); // 2 approvals
    await ApproveAsync(Reviewer3KeyPair, proposalB); // 3 approvals
    await ApproveAsync(User1KeyPair, proposalB);     // 4 approvals
    await ApproveAsync(User2KeyPair, proposalB);     // 5 approvals
    await ApproveAsync(User3KeyPair, proposalB);     // 6 approvals
    await RejectAsync(User4KeyPair, proposalB);      // 1 rejection
    await RejectAsync(User5KeyPair, proposalB);      // 2 rejections
    await RejectAsync(User6KeyPair, proposalB);      // 3 rejections (exactly at threshold)
    
    // Verify Proposal B can be released (rejections = 3 <= 3)
    var proposalBState = await GetProposalAsync(proposalB);
    proposalBState.ToBeReleased.ShouldBeTrue();
    
    // Step 3: Release Proposal B (removes User7 from member list)
    await ReleaseAsync(Reviewer1KeyPair, proposalB);
    
    // Step 4: Verify Proposal A is now releasable (vulnerability!)
    // User7 no longer a member, so rejection count drops from 4 to 3
    var proposalAStateAfter = await GetProposalAsync(proposalA);
    proposalAStateAfter.ToBeReleased.ShouldBeTrue(); // VULNERABILITY: Now can be released!
    proposalAStateAfter.RejectionCount.ShouldBe(3); // Only counts current members
    
    // Step 5: Release Proposal A (governance bypass successful)
    var releaseResult = await ReleaseAsync(Reviewer1KeyPair, proposalA);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // The proposal that was legitimately rejected has been executed!
}
```

This test demonstrates the complete attack: a proposal with 4 rejections (exceeding MaximalRejectionThreshold of 3) becomes releasable after removing one rejecting member, despite the rejection votes being cast when that member was still part of the organization.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L150-151)
```csharp
        proposal.Rejections.Add(Context.Sender);
        State.Proposals[input] = proposal;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L188-188)
```csharp
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L233-280)
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L26-28)
```csharp
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```
