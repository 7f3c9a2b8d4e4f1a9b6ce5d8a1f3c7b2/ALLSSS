# Audit Report

## Title
Inconsistent Vote Counting Allows Governance Manipulation Through Member Removal

## Summary
The Association contract contains a critical inconsistency in its vote counting logic: approval, rejection, and abstention counts are filtered by current membership, while the total vote count includes all historical votes. This allows organizations to retroactively convert rejected proposals into releasable proposals by removing dissenting members, fundamentally undermining governance integrity.

## Finding Description

The vulnerability exists in the threshold validation logic within the Association contract's helper methods. The contract enforces governance thresholds inconsistently when checking if a proposal can be released.

**The Critical Inconsistency:**

When checking rejection counts, the contract filters by current membership [1](#0-0) 

When checking abstention counts, the contract also filters by current membership [2](#0-1) 

When checking approval counts, the contract filters by current membership [3](#0-2) 

However, when checking the total vote threshold, the contract counts ALL historical votes WITHOUT filtering by membership [4](#0-3) 

**The Exploitation Mechanism:**

The `RemoveMember()` function removes addresses from the organization's member list but does NOT clear their historical votes from existing proposals [5](#0-4) 

The release mechanism validates these thresholds when releasing proposals [6](#0-5) 

**Proof of Correct Implementation:**

The Parliament contract correctly implements this by filtering ALL vote counts including the total count by current membership [7](#0-6) 

This demonstrates that the Association contract's unfiltered total count is a design flaw, not an intentional feature.

## Impact Explanation

**Critical Governance Integrity Violation:**

This vulnerability breaks the fundamental democratic guarantee that a properly rejected proposal remains rejected. Organizations can manipulate governance outcomes by:

1. **Retroactive Legitimization**: Converting legitimately rejected proposals into executable actions
2. **Threshold Circumvention**: Bypassing maximal rejection thresholds designed to protect minority rights
3. **Consensus Invalidation**: Executing proposals that failed to achieve required democratic consensus

**Concrete Attack Scenario:**
- Organization: 10 members (A-J)
- Thresholds: `minimal_approval=4`, `maximal_rejection=3`, `minimal_vote=7`
- Proposal P1: 4 approve (A,B,C,D), 4 reject (E,F,G,H)
- Initial status: 4 rejections > 3 threshold → **REJECTED**
- Action: Pass proposal P2 to remove members E and F
- New status after removal: 
  - Filtered approvals: 4 (A,B,C,D still members) ≥ 4 ✓
  - Filtered rejections: 2 (only G,H still members) ≤ 3 ✓
  - Unfiltered total votes: 8 (4 approvals + 4 rejections) ≥ 7 ✓
  - Result: **RELEASABLE**

The severity is Critical because it undermines the core governance mechanism that organizations rely on for decentralized decision-making.

## Likelihood Explanation

**Medium-High Likelihood:**

**Attack Complexity:** Medium - Requires coordinating two proposals:
1. The target proposal that gets rejected
2. A member removal proposal to eliminate dissenters

**Feasibility:** High - The attack uses only standard, legitimate contract functions. `RemoveMember()` is an intended governance function, and no special privileges beyond normal proposal approval are required. All steps are executable within standard AElf contract semantics.

**Realistic Scenarios:**

1. **Deliberate Manipulation**: A majority coalition can intentionally manipulate governance by removing opposition
2. **Accidental Exploitation**: Organizations naturally remove inactive or malicious members, unintentionally causing old rejected proposals to become valid
3. **Systematic Abuse**: Attackers can systematically bypass rejection thresholds across multiple proposals

**Detection Difficulty:** The behavior appears as normal governance operations with no explicit indicators of exploitation, making it difficult to detect or prevent.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` method to filter the total vote count by current membership, consistent with how approvals, rejections, and abstentions are counted:

```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This ensures all vote counts use the same membership filtering logic, preventing retroactive manipulation through member removal.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
public async Task TestGovernanceManipulationThroughMemberRemoval()
{
    // Setup: Create organization with 10 members and thresholds
    // minimal_approval=4, maximal_rejection=3, minimal_vote=7
    var members = new[] { memberA, memberB, memberC, memberD, memberE, memberF, memberG, memberH, memberI, memberJ };
    var organization = await CreateOrganizationAsync(
        minimalApproval: 4,
        maximalRejection: 3, 
        minimalVote: 7,
        members: members
    );
    
    // Step 1: Create and vote on proposal P1
    var proposalId = await CreateProposalAsync(organization, targetAction);
    await ApproveProposal(proposalId, memberA, memberB, memberC, memberD); // 4 approvals
    await RejectProposal(proposalId, memberE, memberF, memberG, memberH); // 4 rejections
    
    // Verify: Proposal is rejected (4 rejections > 3 threshold)
    var statusBefore = await GetProposalStatus(proposalId);
    Assert.False(statusBefore.ToBeReleased); // Should be rejected
    
    // Step 2: Remove dissenting members E and F
    var removalProposal = await CreateMemberRemovalProposal(organization, memberE, memberF);
    await ApproveAndReleaseProposal(removalProposal, memberA, memberB, memberC, memberD);
    
    // Step 3: Check proposal P1 status after member removal
    var statusAfter = await GetProposalStatus(proposalId);
    
    // BUG: Proposal that was rejected is now releasable
    // - Filtered rejections: 2 (only G,H remain) ≤ 3 ✓
    // - Filtered approvals: 4 ≥ 4 ✓  
    // - Unfiltered total: 8 ≥ 7 ✓
    Assert.True(statusAfter.ToBeReleased); // VULNERABILITY: Now releasable!
    
    // The rejected proposal can now be released
    await ReleaseProposal(proposalId);
    // Attack successful: Rejected proposal executed
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-100)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
```
