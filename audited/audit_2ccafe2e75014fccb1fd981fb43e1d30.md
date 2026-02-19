# Audit Report

## Title
Association Contract MinimalVoteThreshold Incorrectly Counts Votes from Removed Members

## Summary
The Association contract's `CheckEnoughVoteAndApprovals` method fails to filter votes by current organization membership when checking `MinimalVoteThreshold`, enabling proposals to pass with votes from removed members counting toward the participation threshold. This violates the fundamental governance guarantee that MinimalVoteThreshold represents minimum current member participation.

## Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals` method where the MinimalVoteThreshold check counts ALL votes without filtering by current organization membership. [1](#0-0) 

This contrasts sharply with the approval count check in the same function that correctly filters by current membership [2](#0-1) , and also differs from rejection [3](#0-2)  and abstention checks [4](#0-3)  that properly filter by membership.

**Root Cause:** When members vote via `Approve`, `Reject`, or `Abstain` methods, their addresses are added to proposal vote lists after membership verification [5](#0-4) . However, when members are removed via `RemoveMember`, only the organization membership list is updated [6](#0-5)  - their previous votes remain in active proposals.

This is proven to be a bug by comparing with the Parliament contract's correct implementation, which properly filters votes by current member list when checking vote thresholds. [7](#0-6) 

## Impact Explanation

**Governance Integrity Violation:** Proposals can be released with fewer participating current members than the MinimalVoteThreshold requires, undermining the fundamental governance guarantee that a minimum number of current organization members must participate in proposal decisions.

**Concrete Attack Scenario:**
- Organization has 5 members with MinimalVoteThreshold=5, MinimalApprovalThreshold=3
- Attacker-controlled majority adds 2 temporary members via proposal
- Temporary members cast votes (any type) on a malicious proposal  
- Organization removes temporary members via separate proposal
- Only 3 current members approve the malicious proposal
- Proposal passes: 3 current member approvals meet MinimalApprovalThreshold, and 5 total votes (including 2 from removed members) meet MinimalVoteThreshold
- Result: Proposal executes with 60% current member approval instead of requiring 100% participation

This enables minority control through coordinated membership manipulation, violating the security model where MinimalVoteThreshold enforces minimum participation from the current organization membership.

## Likelihood Explanation

**Reachable Entry Points:** All required methods (`AddMember`, `RemoveMember`, `Approve`, `Reject`, `Abstain`, `Release`) are public and accessible through standard proposal execution. [8](#0-7) [6](#0-5) 

**Feasible Preconditions:** Requires ability to pass proposals for adding/removing members, achievable if:
1. Organization has legitimate membership changes over time (non-malicious scenario triggering bug)
2. Attacker controls MinimalApprovalThreshold votes to manipulate membership (malicious scenario)

**Execution Practicality:** All steps use standard contract operations without requiring elevated privileges beyond normal proposal approval thresholds. The timing requirement (overlapping proposals) is easily achievable in practice.

**Likelihood Assessment:** MEDIUM - Requires coordination of multiple proposals but uses only standard contract functionality. More likely in organizations with frequent membership changes or where a faction seeks to game governance thresholds.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` method to filter total votes by current membership, consistent with all other threshold checks:

Change the MinimalVoteThreshold check to:
```csharp
var isVoteThresholdReached =
    proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
        .Count(organization.OrganizationMemberList.Contains) >=
    organization.ProposalReleaseThreshold.MinimalVoteThreshold;
```

This ensures only votes from current organization members count toward the MinimalVoteThreshold, matching the implementation pattern used in rejection checks, abstention checks, approval checks within the same method, and the Parliament contract's correct implementation.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task MinimalVoteThreshold_CountsRemovedMemberVotes_Bug()
{
    // Setup: Create organization with 3 members, MinimalVoteThreshold=3, MinimalApprovalThreshold=2
    var member1 = Accounts[0].Address;
    var member2 = Accounts[1].Address;
    var member3 = Accounts[2].Address;
    var tempMember = Accounts[3].Address;
    
    var orgAddress = await CreateOrganizationAsync(new[] { member1, member2, member3 }, 
        minimalVoteThreshold: 3, minimalApprovalThreshold: 2);
    
    // Step 1: Add temporary member via proposal
    var addMemberProposalId = await CreateAndApproveProposalAsync(orgAddress, 
        nameof(AddMember), tempMember, approvers: new[] { member1, member2 });
    
    // Step 2: Create target malicious proposal
    var targetProposalId = await CreateProposalAsync(orgAddress, "MaliciousAction");
    
    // Step 3: Temporary member votes on target proposal (any vote type works)
    await ApproveAsync(targetProposalId, tempMember);
    
    // Step 4: Remove temporary member via proposal  
    var removeProposalId = await CreateAndApproveProposalAsync(orgAddress,
        nameof(RemoveMember), tempMember, approvers: new[] { member1, member2 });
    
    // Step 5: Only 2 current members approve target proposal
    await ApproveAsync(targetProposalId, member1);
    await ApproveAsync(targetProposalId, member2);
    
    // BUG: Proposal can be released despite only 2 current members voting (not 3)
    // Total votes = 3 (tempMember + member1 + member2), but tempMember was removed
    var canRelease = await CheckProposalReadyToRelease(targetProposalId);
    
    // This should be false (only 2 current member votes, MinimalVoteThreshold=3)
    // But it returns true because removed member's vote still counts
    Assert.True(canRelease); // Demonstrates the bug
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

**File:** contract/AElf.Contracts.Association/Association.cs (L128-131)
```csharp
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Approvals.Add(Context.Sender);
        State.Proposals[input] = proposal;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L97-101)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
                .Count(parliamentMembers.Contains) * AbstractVoteTotal >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold * parliamentMembers.Count;
        return isVoteThresholdReached;
```
