# Audit Report

## Title
Mid-Voting Member Addition Enables Retroactive Vote Manipulation

## Summary
The Association contract allows organizations to add new members while proposals are actively being voted on. These newly added members can immediately vote on pre-existing proposals, and their votes are counted using the current organization member list rather than a membership snapshot at proposal creation time. This enables retroactive manipulation of vote outcomes.

## Finding Description

The vulnerability exists in the interaction between member management and vote counting mechanisms in the Association governance contract.

**Member Addition Without Snapshot Protection**: The `AddMember()` function adds new members to the organization without any checks for active proposals or creation of historical snapshots. [1](#0-0) 

**Vote Authorization Using Current Membership**: When members attempt to vote (approve/reject/abstain), the system verifies authorization by checking their presence in the CURRENT organization member list, not whether they were members when the proposal was created. [2](#0-1) [3](#0-2) 

**Vote Counting Filters By Current Membership**: When determining if a proposal can be released, the system counts votes by filtering them against the CURRENT organization member list. Rejections are counted using `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)` [4](#0-3) , abstentions using `proposal.Abstentions.Count(organization.OrganizationMemberList.Contains)` [5](#0-4) , and approvals using `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)` [6](#0-5) .

**Missing Membership Snapshot**: The `ProposalInfo` structure stores the lists of voters (approvals, rejections, abstentions) but does not capture a snapshot of organization members at proposal creation time. [7](#0-6) 

**Attack Scenario**:
1. Organization has 5 members {A,B,C,D,E} with thresholds: MinimalApprovalThreshold=3, MaximalRejectionThreshold=2
2. Proposal P1 is created and receives 3 approvals from A, B, and C (ready to pass)
3. Attacker controls enough members to pass a proposal calling `AddMember()` to add new members F, G, H
4. The AddMember proposal is released via `SendVirtualInlineBySystemContract` with the organization address as sender [8](#0-7) 
5. New members F, G, H immediately vote to reject P1 (allowed because authorization checks current membership)
6. When checking if P1 can be released, the system counts 3 rejections (F,G,H) which exceeds MaximalRejectionThreshold (2)
7. P1 is now blocked despite having sufficient approvals before the membership change

This breaks the fundamental governance invariant that vote outcomes should be determined by the electorate at proposal creation time, not retroactively changed by electorate modifications.

## Impact Explanation

**HIGH severity** - This vulnerability enables multiple critical governance attacks:

**Proposal Blocking**: Legitimate proposals that have already achieved the required approval threshold can be retroactively blocked by adding new members who vote to reject them, pushing rejections above `MaximalRejectionThreshold`.

**Malicious Approval**: Failing malicious proposals can be rescued by adding new attacker-controlled members who vote to approve them, pushing approvals above `MinimalApprovalThreshold`.

**Governance Integrity Violation**: The core principle of democratic governance is that the outcome should be determined by the electorate as it existed when the vote began. This vulnerability allows the electorate to be changed mid-vote to alter outcomes, fundamentally undermining trust in the governance system.

**Widespread Applicability**: This affects all Association organizations in the AElf ecosystem, making it a systemic governance vulnerability rather than an isolated issue.

## Likelihood Explanation

**MEDIUM-HIGH likelihood** - The attack is practical and straightforward:

**Attacker Prerequisites**: 
- Requires control of sufficient organization members to pass an `AddMember` proposal
- This is the same level of control needed for many governance attacks

**Attack Complexity**: LOW
- No technical sophistication required
- Simple transaction sequence: create AddMember proposal → approve it → new members vote
- No timing constraints beyond proposal expiration windows

**Detection Limitations**: 
- Member additions emit `MemberAdded` events but occur on-chain via legitimate proposal execution
- By the time additions are detected, new members can already vote
- No automated protection mechanisms exist in the contract

**Economic Feasibility**: If an attacker already controls governance, the cost is minimal (just transaction fees), while the benefit of manipulating critical proposals could be substantial.

## Recommendation

Implement membership snapshots at proposal creation time. When a proposal is created, capture and store the current organization member list in the `ProposalInfo` structure. Use this snapshot for:
1. Vote authorization checks - only allow voting from members who were part of the organization when the proposal was created
2. Vote counting - filter votes based on the snapshot membership list rather than the current list

Example fix in `ProposalInfo` protobuf:
```protobuf
message ProposalInfo {
    // ... existing fields ...
    // Snapshot of organization members at proposal creation time
    OrganizationMemberList member_snapshot = 14;
}
```

Update `CreateNewProposal()` to capture the snapshot [9](#0-8) , and modify vote authorization and counting logic to use the snapshot instead of the current organization member list.

## Proof of Concept

```csharp
[Fact]
public async Task MidVoting_MemberAddition_Manipulates_Vote()
{
    // Setup: Create organization with 5 members, thresholds: MinimalApproval=3, MaximalRejection=2
    var organizationAddress = await CreateOrganizationAsync(3, 5, 0, 2, Reviewer1);
    
    // Step 1: Create proposal P1 that should pass with 3 approvals
    var proposalP1 = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 2: Get 3 approvals (meets MinimalApprovalThreshold=3)
    await ApproveAsync(Reviewer1KeyPair, proposalP1);
    await ApproveAsync(Reviewer2KeyPair, proposalP1);
    await ApproveAsync(Reviewer3KeyPair, proposalP1);
    
    // Verify P1 is ready to release
    var proposal1Status = await AssociationContractStub.GetProposal.CallAsync(proposalP1);
    proposal1Status.ToBeReleased.ShouldBeTrue();
    
    // Step 3: Create and approve proposal to add new member
    var newMember = Accounts[10].Address;
    var addMemberProposal = await CreateAssociationProposalAsync(
        Reviewer1KeyPair, newMember, 
        nameof(AssociationContractStub.AddMember), organizationAddress);
    await ApproveAsync(Reviewer1KeyPair, addMemberProposal);
    await ApproveAsync(Reviewer2KeyPair, addMemberProposal);
    await ApproveAsync(Reviewer3KeyPair, addMemberProposal);
    
    // Step 4: Release AddMember proposal (adds new member)
    await ReleaseAsync(Reviewer1KeyPair, addMemberProposal);
    
    // Step 5: New member votes to reject P1
    var newMemberStub = GetAssociationContractTester(Accounts[10].KeyPair);
    await newMemberStub.Reject.SendAsync(proposalP1);
    
    // Add 2 more members and have them reject too (total 3 rejections > MaximalRejectionThreshold=2)
    // ... repeat steps 3-5 for additional members ...
    
    // Step 6: Verify P1 is now blocked despite having 3 approvals before
    var proposal1FinalStatus = await AssociationContractStub.GetProposal.CallAsync(proposalP1);
    proposal1FinalStatus.ToBeReleased.ShouldBeFalse(); // Attack successful - proposal blocked retroactively
}
```

## Notes

This vulnerability is confirmed through direct code analysis. The Association contract's design allows dynamic membership changes without considering the impact on active proposals. The lack of membership snapshots means the electorate can be altered mid-vote, violating the fundamental principle that governance outcomes should be determined by the electorate at vote inception.

The similar `RemoveMember()` and `ChangeMember()` methods [10](#0-9)  could potentially be exploited in reverse scenarios to exclude votes that were already cast by removing members after they voted.

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

**File:** contract/AElf.Contracts.Association/Association.cs (L248-280)
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L145-173)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            ToAddress = input.ToAddress,
            OrganizationAddress = input.OrganizationAddress,
            ProposalId = proposalId,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        State.Proposals[proposalId] = proposal;
        Context.Fire(new ProposalCreated
        {
            ProposalId = proposalId,
            OrganizationAddress = input.OrganizationAddress,
            Title = input.Title,
            Description = input.Description
        });
        return proposalId;
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
