# Audit Report

## Title
Ghost Vote Counting Vulnerability: Removed Members' Votes Still Count Toward MinimalVoteThreshold

## Summary
The Association contract contains a critical inconsistency in vote counting logic. When checking if the MinimalVoteThreshold is reached, the contract counts all votes including those from removed members, but when checking abstention/rejection/approval thresholds, it only counts current members. This allows proposals to pass with insufficient participation from current organization members.

## Finding Description

The vulnerability exists in the threshold checking logic where vote counting is inconsistent across different validation checks.

**The Critical Inconsistency:**

When checking rejection thresholds, the contract filters to only count votes from current members: [1](#0-0) 

When checking abstention thresholds, the contract also filters to only count votes from current members: [2](#0-1) 

When checking approval counts, the contract filters to only count votes from current members: [3](#0-2) 

**However**, when checking if MinimalVoteThreshold is reached, the contract counts ALL votes without filtering by current membership: [4](#0-3) 

**Root Cause:**

The proposal stores votes as address lists in the ProposalInfo structure that are never cleaned when members are removed: [5](#0-4) 

When members are removed via the RemoveMember method, their past votes remain in existing proposals: [6](#0-5) 

The release process relies on these threshold checks through IsReleaseThresholdReached: [7](#0-6) 

**Why Existing Protections Fail:**

Members must be current members when voting (enforced by AssertIsAuthorizedOrganizationMember): [8](#0-7) 

However, there is no mechanism to invalidate or recount votes after member removal. The unfiltered count treats removed members' votes as valid participation toward the MinimalVoteThreshold.

## Impact Explanation

**Severity: HIGH**

This vulnerability breaks the fundamental governance invariant that thresholds represent current member participation.

**Concrete Attack Scenario:**
- Organization with 10 members  
- Thresholds: MinimalVoteThreshold=8, MinimalApprovalThreshold=6, MaximalAbstentionThreshold=1
- 3 members abstain on a proposal (addresses added to proposal.Abstentions)
- Organization removes these 3 members (7 current members remain)
- 6 current members approve (addresses added to proposal.Approvals)
- At release: abstention check counts 0 abstentions (filtered), approval check counts 6 approvals (filtered), but vote threshold check counts 9 total votes (unfiltered: 6 approvals + 3 ghost abstentions)
- Proposal passes despite only 6/7 current members (85.7%) voting, when threshold intended 8 participants

**Affected Parties:**
- All Association-governed organizations across the protocol
- Treasury releases and fund distributions
- Configuration changes and protocol upgrades
- Multi-signature operations requiring accurate participation tracking

The vulnerability enables unauthorized proposal execution through governance manipulation and makes the MinimalVoteThreshold security guarantee meaningless.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Triggering Requirements:**
- Control of organization majority to remove members (legitimate governance action)
- Ability to coordinate voting sequences  
- All steps use standard public methods with normal access control

**Attack Complexity:**
- Multiple coordinated transactions required
- Must time member removals between voting and release
- However, all operations are straightforward public contract methods

**Natural Occurrence Risk:**
This vulnerability can trigger even without malicious intent during normal organizational operations. When organizations naturally remove inactive members or rotate membership, existing proposals can inadvertently pass with insufficient current member participation, making this particularly dangerous.

**Detection Difficulty:**
Hard to detect as individual votes and member changes appear legitimate. The inconsistency only becomes visible when analyzing the threshold calculation logic across multiple checks.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` method to filter the total vote count by current membership, ensuring consistency with other threshold checks:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter total votes by current membership
    var currentMemberVoteCount = 
        proposal.Abstentions.Count(organization.OrganizationMemberList.Contains) +
        proposal.Approvals.Count(organization.OrganizationMemberList.Contains) +
        proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
    
    var isVoteThresholdReached =
        currentMemberVoteCount >= organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures all threshold calculations consistently count only votes from current organization members.

## Proof of Concept

The vulnerability is demonstrated through the code flow analysis:

**Test Setup:**
1. Create organization with 10 members, MinimalVoteThreshold=8, MinimalApprovalThreshold=6
2. Create proposal
3. Have 3 members call Abstain() - their addresses added to proposal.Abstentions
4. Organization calls RemoveMember() for those 3 members - they're removed from OrganizationMemberList
5. Have 6 remaining members call Approve() - their addresses added to proposal.Approvals
6. Call Release() - proposal incorrectly passes

**Expected:** Release should fail because only 6/7 current members voted (below MinimalVoteThreshold=8)

**Actual:** Release succeeds because vote count is 9 (6 approvals + 3 ghost abstentions from removed members)

The vulnerability is proven by the code at: [9](#0-8) 

This line uses `.Count()` without the filtering predicate `organization.OrganizationMemberList.Contains` that all other threshold checks properly use.

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L47-53)
```csharp
    private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
    {
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
        if (!isApprovalEnough)
            return false;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L55-58)
```csharp
        var isVoteThresholdReached =
            proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections).Count() >=
            organization.ProposalReleaseThreshold.MinimalVoteThreshold;
        return isVoteThresholdReached;
```

**File:** protobuf/association_contract.proto (L76-96)
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
```

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
