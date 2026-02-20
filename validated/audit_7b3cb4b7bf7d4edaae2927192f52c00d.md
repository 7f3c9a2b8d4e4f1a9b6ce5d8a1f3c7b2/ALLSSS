# Audit Report

## Title
Inconsistent Membership Filtering in Vote Threshold Check Allows Governance Bypass

## Summary
The Association contract's `CheckEnoughVoteAndApprovals` function inconsistently applies membership filtering when validating proposal release thresholds. While approval, rejection, and abstention counts correctly filter by current organization membership, the total vote count includes votes from removed members. This allows proposals to meet the MinimalVoteThreshold requirement with artificially inflated participation from ex-members, undermining governance quorum enforcement.

## Finding Description
The vulnerability exists in the threshold validation logic that determines whether a proposal can be released. The Association contract enforces governance through the `ProposalReleaseThreshold` structure, which includes `MinimalVoteThreshold` to ensure adequate member participation.

**Inconsistent Membership Filtering:**

The `CheckEnoughVoteAndApprovals` function applies membership filtering inconsistently. The approval count correctly filters to include only current members: [1](#0-0) 

However, the total vote count does NOT filter by current membership, counting ALL votes including those from removed members: [2](#0-1) 

The same inconsistency exists with rejection and abstention checks, which correctly filter by current membership: [3](#0-2)  and [4](#0-3) 

**Root Cause:**

When members are removed via the `RemoveMember` function, they are deleted from the organization member list but their votes remain in existing proposals: [5](#0-4) 

The `RemoveMember` operation does not clear votes from active proposals. Combined with the unfiltered total vote count, this creates a state where:
- Approval/rejection/abstention thresholds correctly reflect only current member votes
- Total vote threshold incorrectly includes votes from ex-members
- Proposals can pass MinimalVoteThreshold with lower actual participation than intended

**Attack Scenario:**

Consider an organization with:
- MinimalVoteThreshold = 7 (requires 7 members to participate)
- MinimalApprovalThreshold = 5 (requires 5 approvals)
- 10 total members

Attack sequence:
1. Attacker creates proposal (requires proposer whitelist membership)
2. Obtains 5 approvals + 2 abstentions (7 total votes, meets threshold)
3. Executes another proposal to call `RemoveMember` for the 2 abstaining members
4. After removal: Only 8 current members remain
5. Threshold checks:
   - Approval count: 5 current members (meets MinimalApprovalThreshold = 5) ✓
   - Abstention count: 0 current members (removed members) ✓
   - **Total vote count: 7 votes (5 + 2 from ex-members, meets MinimalVoteThreshold = 7) ✓**
6. Proposal releases with only 5/8 (62.5%) current member participation instead of intended 7/8 (87.5%)

The `RemoveMember` function requires Context.Sender to be the organization address, which happens during proposal execution via `SendVirtualInlineBySystemContract`: [6](#0-5) 

## Impact Explanation
**HIGH Severity** - This vulnerability directly violates the core governance invariant that "organization thresholds must be correctly enforced."

**Governance Integrity Compromise:**
- Proposals can be released without meeting the intended minimum participation requirement from current active members
- The MinimalVoteThreshold becomes meaningless as it can be satisfied by votes from removed members
- Organizations relying on MinimalVoteThreshold for quorum enforcement are systematically undermined

**Affected Parties:**
- All Association-based organizations using MinimalVoteThreshold > MinimalApprovalThreshold (a common configuration to ensure broad participation)
- Critical governance decisions can be made with minority current member support
- The vulnerability affects the fundamental trust model of Association governance

**Quantified Impact:**
In the example scenario, an attacker achieves:
- 5/8 (62.5%) actual current member participation
- While appearing to meet 7/10 (70%) participation requirement
- This is a 7.5 percentage point participation deficit that completely bypasses the intended threshold

## Likelihood Explanation
**MEDIUM-HIGH Probability** - The vulnerability is present in every Association organization and exploitable through standard governance operations.

**Attacker Capabilities Required:**
- Proposer whitelist membership (normal governance role, not privileged system access)
- Ability to coordinate with some organization members for voting
- Does NOT require compromising any trusted roles or system contracts

**Attack Complexity: LOW**
- Uses only standard contract methods: `CreateProposal`, `Approve`, `Abstain`, `RemoveMember`, `Release`
- No complex timing requirements or state manipulation needed
- Member removal is a legitimate governance operation accessible through proposal execution

**Feasibility Conditions:**
1. Organization must use MinimalVoteThreshold > MinimalApprovalThreshold - This is a common configuration to ensure broad participation beyond just approvals
2. Ability to coordinate member voting then removal - Achievable through executing a proposal that calls `RemoveMember` (Context.Sender becomes organization address during proposal execution)

The `Release` method checks `IsReleaseThresholdReached`: [7](#0-6) , which calls the vulnerable `CheckEnoughVoteAndApprovals` function: [8](#0-7) 

**Detection Difficulty:**
- Member additions/removals are legitimate operations that occur regularly
- The exploit leaves no obvious traces beyond normal governance activity
- Observers would need to manually track member list changes and correlate with proposal votes to detect the bypass

## Recommendation
Modify the `CheckEnoughVoteAndApprovals` function to filter the total vote count by current membership, consistent with how approvals, rejections, and abstentions are filtered:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // Fix: Filter total votes by current membership
    var totalVotesFromCurrentMembers = 
        proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
        proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
        proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        totalVotesFromCurrentMembers >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

Alternatively, clear votes from removed members when `RemoveMember` is called, but this would be more complex as it requires iterating over all active proposals.

## Proof of Concept
The vulnerability can be demonstrated by:
1. Creating an Association organization with MinimalVoteThreshold=7, MinimalApprovalThreshold=5
2. Creating a proposal and obtaining 5 approvals + 2 abstentions
3. Executing another proposal that calls RemoveMember for the 2 abstaining members
4. Calling Release on the original proposal - it will pass threshold checks despite only 5/8 current members participating

The key code paths are:
- Release → IsReleaseThresholdReached → CheckEnoughVoteAndApprovals (inconsistent filtering)
- RemoveMember removes from organization but not from proposal votes
- Context.Sender becomes organization address during proposal execution, allowing RemoveMember calls

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L42-44)
```csharp
    {
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
