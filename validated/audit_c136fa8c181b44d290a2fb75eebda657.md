# Audit Report

## Title
Governance Manipulation Through Strategic Member Removal in Association Contract

## Summary
The Association contract evaluates proposal thresholds dynamically using current organization membership rather than taking snapshots at voting time. This allows organizations to retroactively manipulate proposal outcomes by removing members who cast unfavorable votes, enabling proposals that were legitimately rejected to become acceptable and executable.

## Finding Description

The vulnerability stems from the Association contract's vote counting mechanism that filters votes based on current membership status rather than membership at the time of voting.

**Root Cause:**

When members vote on a proposal through `Approve()`, `Reject()`, or `Abstain()`, their addresses are permanently added to the proposal's vote lists. [1](#0-0) [2](#0-1) [3](#0-2) 

However, when determining if a proposal can be released, the contract filters these lists to count only votes from current organization members.

The `IsProposalRejected()` method explicitly filters rejections using current membership [4](#0-3)  by using `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)`. Similarly, `IsProposalAbstained()` and `CheckEnoughVoteAndApprovals()` filter abstentions and approvals by current membership. [5](#0-4) [6](#0-5) 

The `RemoveMember()` function allows an organization to remove members with no validation against active proposals. [7](#0-6) 

**Execution Path:**

1. Organization has 10 members with thresholds: MinimalApprovalThreshold=4, MaximalRejectionThreshold=3
2. Proposal A is created and receives 4 approvals and 4 rejections
3. Proposal A is REJECTED (4 rejections > 3 threshold)
4. Approving members create Proposal B to remove one rejecting member
5. Proposal B passes (gets 5 approvals) and is released via the organization's virtual address [8](#0-7) 
6. The targeted member is removed from the organization
7. When checking Proposal A again via `IsReleaseThresholdReached()` [9](#0-8) , only 3 rejections now count (removed member's vote is filtered out)
8. Proposal A is no longer rejected (3 ≤ 3) and can be released

**Additional Issue:**

There's an inconsistency where `MinimalVoteThreshold` counts ALL votes without filtering by membership [10](#0-9) , creating unpredictable behavior when members are removed.

## Impact Explanation

**HIGH Severity** - This vulnerability breaks a fundamental governance invariant: that votes cast in good faith cannot be retroactively invalidated.

**Direct Impacts:**
- Organizations can manipulate proposal outcomes by selectively removing members whose votes are unfavorable
- Proposals that were legitimately rejected by the organization can be forced through
- Approved proposals can be blocked by removing approving members
- This completely undermines the integrity and trustworthiness of the Association governance mechanism

**Affected Parties:**
- Organization members who voted believing their votes were final
- Downstream contracts relying on Association governance decisions
- Any funds, permissions, or system configurations controlled by the organization
- The broader AElf ecosystem's governance credibility

## Likelihood Explanation

**Medium-High Likelihood** - The attack requires organizational control but is otherwise straightforward.

**Attacker Prerequisites:**
- Control sufficient votes to pass a member removal proposal
- This is achievable in organizations with contentious splits (e.g., 6-4 voting patterns)
- Member removal proposals may have different thresholds than other proposals, making this more feasible

**Attack Complexity:**
- LOW - Uses only standard public contract methods
- No special timing requirements
- Predictable and reliable outcome
- Entry point `RemoveMember()` is accessible via proposal execution through the organization's virtual address

**Detection Difficulty:**
- HIGH - Member removal is a legitimate governance action
- Manipulation only becomes apparent through careful analysis of voting patterns and timing
- No on-chain indicators distinguish malicious from legitimate member removal

## Recommendation

Implement a snapshot mechanism that records the organization's membership state at the time votes are cast, and use this snapshot for threshold calculations:

**Option 1: Snapshot at Voting Time**
- Store the voting member's membership status at vote time in the proposal
- Check threshold using only votes from addresses that were members when they voted

**Option 2: Snapshot at Proposal Creation**
- Record the full membership list when the proposal is created
- Use this snapshot for all threshold calculations
- Prevent member changes from affecting existing active proposals

**Option 3: Prevent Member Removal with Active Proposals**
- Add validation in `RemoveMember()` to check if the member has voted on any active (non-expired, non-released) proposals
- Reject removal if such proposals exist

The recommended approach is **Option 1** as it preserves legitimate organizational evolution while preventing retroactive vote manipulation.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
public async Task GovernanceManipulationThroughMemberRemoval()
{
    // Setup: Create organization with 10 members
    // Thresholds: MinimalApprovalThreshold=4, MaximalRejectionThreshold=3
    var members = new[] { Member1, Member2, Member3, Member4, Member5, 
                         Member6, Member7, Member8, Member9, Member10 };
    
    var organizationAddress = await CreateOrganization(members, 
        minApproval: 4, maxRejection: 3);
    
    // Step 1: Create contentious Proposal A
    var proposalA = await CreateProposal(organizationAddress, "ActionA");
    
    // Step 2: Vote on Proposal A - 4 approve, 4 reject
    await Approve(proposalA, Member1, Member2, Member3, Member4);
    await Reject(proposalA, Member5, Member6, Member7, Member8);
    
    // Step 3: Verify Proposal A is REJECTED
    var canReleaseA = await IsReleaseThresholdReached(proposalA);
    Assert.False(canReleaseA); // 4 rejections > 3 threshold
    
    // Step 4: Create Proposal B to remove Member5
    var proposalB = await CreateProposal(organizationAddress, 
        target: AssociationContract, 
        method: "RemoveMember", 
        params: Member5);
    
    // Step 5: Get 5 approvals for Proposal B and release it
    await Approve(proposalB, Member1, Member2, Member3, Member4, Member9);
    await Release(proposalB); // Executes RemoveMember(Member5)
    
    // Step 6: Verify Proposal A can now be released
    canReleaseA = await IsReleaseThresholdReached(proposalA);
    Assert.True(canReleaseA); // VULNERABILITY: Now only 3 rejections count
    
    await Release(proposalA); // Previously rejected proposal now executes!
}
```

## Notes

This vulnerability is particularly concerning because:

1. **It's silent**: Member removal appears as legitimate governance activity
2. **It's retroactive**: Past voting decisions can be invalidated after the fact
3. **It's systemic**: Affects the fundamental trust model of Association-based governance
4. **It applies to all thresholds**: Approvals, rejections, and abstentions are all filtered by current membership

The inconsistency where `MinimalVoteThreshold` counts all votes regardless of membership creates additional edge cases where proposals may behave unpredictably when members are removed.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L130-130)
```csharp
        proposal.Approvals.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L150-150)
```csharp
        proposal.Rejections.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L170-170)
```csharp
        proposal.Abstentions.Add(Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L24-32)
```csharp
    private bool IsReleaseThresholdReached(ProposalInfo proposal, Organization organization)
    {
        var isRejected = IsProposalRejected(proposal, organization);
        if (isRejected)
            return false;

        var isAbstained = IsProposalAbstained(proposal, organization);
        return !isAbstained && CheckEnoughVoteAndApprovals(proposal, organization);
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-37)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-44)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-50)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L56-57)
```csharp
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```
