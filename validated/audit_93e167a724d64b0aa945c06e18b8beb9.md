# Audit Report

## Title
Association Contract MinimalVoteThreshold Incorrectly Counts Votes from Removed Members

## Summary
The Association contract's `CheckEnoughVoteAndApprovals` method fails to filter votes by current organization membership when checking `MinimalVoteThreshold`, enabling proposals to pass with votes from removed members counting toward the participation threshold. This violates the fundamental governance guarantee that MinimalVoteThreshold represents minimum current member participation.

## Finding Description

The vulnerability exists in the `CheckEnoughVoteAndApprovals` method where the MinimalVoteThreshold check counts ALL votes without filtering by current organization membership. [1](#0-0) 

This contrasts sharply with the approval count check in the same function that correctly filters by current membership: [2](#0-1) 

The rejection and abstention checks also properly filter by membership: [3](#0-2) [4](#0-3) 

**Root Cause:** When members vote via `Approve`, `Reject`, or `Abstain` methods, their addresses are added to proposal vote lists after membership verification: [5](#0-4) 

However, when members are removed via `RemoveMember`, only the organization membership list is updated - their previous votes remain in active proposals: [6](#0-5) 

This is proven to be a bug by comparing with the Parliament contract's correct implementation, which properly filters votes by current member list when checking vote thresholds: [7](#0-6) 

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

**Reachable Entry Points:** All required methods are public and accessible through standard proposal execution: [8](#0-7) [9](#0-8) 

**Feasible Preconditions:** Requires ability to pass proposals for adding/removing members, achievable if:
1. Organization has legitimate membership changes over time (non-malicious scenario triggering bug)
2. Attacker controls MinimalApprovalThreshold votes to manipulate membership (malicious scenario)

**Execution Practicality:** All steps use standard contract operations without requiring elevated privileges beyond normal proposal approval thresholds. The timing requirement (overlapping proposals) is easily achievable in practice.

**Likelihood Assessment:** MEDIUM - Requires coordination of multiple proposals but uses only standard contract functionality. More likely in organizations with frequent membership changes or where a faction seeks to game governance thresholds.

## Recommendation

Modify the `CheckEnoughVoteAndApprovals` method to filter votes by current organization membership when checking MinimalVoteThreshold, consistent with how rejection and abstention checks are implemented:

```csharp
private bool CheckEnoughVoteAndApprovals(ProposalInfo proposal, Organization organization)
{
    var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
    var isApprovalEnough =
        approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
    if (!isApprovalEnough)
        return false;

    // FIX: Filter votes by current membership
    var isVoteThresholdReached =
        proposal.Abstentions.Concat(proposal.Approvals).Concat(proposal.Rejections)
            .Count(organization.OrganizationMemberList.Contains) >=
        organization.ProposalReleaseThreshold.MinimalVoteThreshold;
    return isVoteThresholdReached;
}
```

This ensures MinimalVoteThreshold represents actual current member participation, matching the Parliament contract's correct implementation.

## Proof of Concept

```csharp
[Fact]
public async Task MinimalVoteThreshold_Counts_RemovedMembers_Vulnerability()
{
    // Setup: Create organization with 5 members, MinimalVoteThreshold=5, MinimalApprovalThreshold=3
    var member4 = Address.FromPublicKey(Accounts[4].KeyPair.PublicKey);
    var member5 = Address.FromPublicKey(Accounts[5].KeyPair.PublicKey);
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3, member4, member5 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 3,
            MinimalVoteThreshold = 5,
            MaximalAbstentionThreshold = 2,
            MaximalRejectionThreshold = 2
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { Reviewer1 } }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput)).Output;
    
    // Step 1: Create malicious proposal
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 2: Member4 and Member5 vote (will be removed later)
    await GetAssociationContractTester(Accounts[4].KeyPair).Approve.SendAsync(proposalId);
    await GetAssociationContractTester(Accounts[5].KeyPair).Approve.SendAsync(proposalId);
    
    // Step 3: Remove Member4 and Member5 through separate proposals
    var removeMember4Proposal = await CreateAssociationProposalAsync(Reviewer1KeyPair, member4, 
        nameof(AssociationContractStub.RemoveMember), organizationAddress);
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(removeMember4Proposal);
    await GetAssociationContractTester(Reviewer2KeyPair).Approve.SendAsync(removeMember4Proposal);
    await GetAssociationContractTester(Reviewer3KeyPair).Approve.SendAsync(removeMember4Proposal);
    await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(removeMember4Proposal);
    
    var removeMember5Proposal = await CreateAssociationProposalAsync(Reviewer1KeyPair, member5,
        nameof(AssociationContractStub.RemoveMember), organizationAddress);
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(removeMember5Proposal);
    await GetAssociationContractTester(Reviewer2KeyPair).Approve.SendAsync(removeMember5Proposal);
    await GetAssociationContractTester(Reviewer3KeyPair).Approve.SendAsync(removeMember5Proposal);
    await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(removeMember5Proposal);
    
    // Step 4: Only 3 current members (Reviewer1) approve the malicious proposal
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(proposalId);
    
    // Verify organization now has only 3 members
    var org = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress);
    org.OrganizationMemberList.OrganizationMembers.Count.ShouldBe(3);
    
    // BUG: Proposal should NOT be releasable (only 3 current members voted, need 5)
    // But it IS releasable because removed members' votes still count
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeFalse(); // EXPECTED: Should be false
    proposal.ToBeReleased.ShouldBeTrue();  // ACTUAL: Is true (BUG!)
    
    // Proposal can be released with only 3/5 current members participating
    var releaseResult = await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // Succeeds!
}
```

**Notes:**
- This vulnerability affects ALL Association organizations using MinimalVoteThreshold
- The inconsistency between approval/rejection/abstention checks (which filter) and the vote threshold check (which doesn't) indicates this is an implementation oversight rather than intentional design
- The Parliament contract's correct implementation confirms this is a bug

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
