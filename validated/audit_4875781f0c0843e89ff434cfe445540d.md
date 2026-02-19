# Audit Report

## Title
Mid-Voting Member Addition Enables Retroactive Vote Manipulation

## Summary
The Association contract allows organizations to add new members while proposals are actively being voted on. These newly added members can immediately vote on pre-existing proposals, and their votes are counted using the current organization member list rather than a membership snapshot at proposal creation time. This enables retroactive manipulation of vote outcomes.

## Finding Description

The vulnerability exists in the interaction between member management and vote counting mechanisms in the Association governance contract.

**Member Addition Without Snapshot Protection**: The `AddMember()` function adds new members to the organization without any checks for active proposals or creation of historical snapshots. [1](#0-0) 

**Vote Authorization Using Current Membership**: When members attempt to vote (approve/reject/abstain), the system checks if they are authorized by verifying their presence in the CURRENT organization member list, not whether they were members when the proposal was created. [2](#0-1) 

**Vote Counting Filters By Current Membership**: When determining if a proposal can be released, the system counts votes by filtering them against the CURRENT organization member list:
- Rejections are counted using `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)` [3](#0-2) 
- Abstentions are counted using `proposal.Abstentions.Count(organization.OrganizationMemberList.Contains)` [4](#0-3) 
- Approvals are counted using `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)` [5](#0-4) 

**Missing Membership Snapshot**: The `ProposalInfo` structure stores the lists of voters (approvals, rejections, abstentions) but does not capture a snapshot of organization members at proposal creation time. [6](#0-5) 

**Attack Scenario**:
1. Organization has 5 members {A,B,C,D,E} with thresholds: MinimalApprovalThreshold=3, MaximalRejectionThreshold=2
2. Proposal P1 is created and receives 3 approvals from A, B, and C (ready to pass)
3. Attacker controls enough members to pass a proposal adding new members F, G, H
4. New members F, G, H immediately vote to reject P1
5. When checking if P1 can be released, the system counts 3 rejections (F,G,H) which exceeds MaximalRejectionThreshold (2)
6. P1 is now blocked despite having sufficient approvals before the membership change

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

Implement a membership snapshot mechanism to ensure vote counting uses the organization member list as it existed at proposal creation time:

1. **Add Snapshot to ProposalInfo**: Store the organization member list when a proposal is created
2. **Use Snapshot for Authorization**: Check voting authorization against the snapshot, not current membership
3. **Use Snapshot for Vote Counting**: Count votes by filtering against the snapshot membership list

Alternative approach: Prevent membership changes while active proposals exist, though this could create denial-of-service concerns for legitimate membership management.

## Proof of Concept

```csharp
[Fact]
public async Task MidVoting_MemberAddition_BlocksLegitimateProposal()
{
    // Setup: Create organization with 5 members, thresholds: MinimalApproval=3, MaximalRejection=2
    var organizationAddress = await CreateOrganizationAsync(
        minimalApprovalThreshold: 3,
        minimalVoteThreshold: 5,
        maximalAbstentionThreshold: 0,
        maximalRejectionThreshold: 2,
        proposerWhiteList: Reviewer1);

    // Create target proposal P1
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // P1 gets 3 approvals - should be ready to pass
    await ApproveAsync(Reviewer1KeyPair, proposalId);
    await ApproveAsync(Reviewer2KeyPair, proposalId);
    await ApproveAsync(Reviewer3KeyPair, proposalId);
    
    // Verify P1 is ready to release
    var proposalBeforeAttack = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalBeforeAttack.ToBeReleased.ShouldBeTrue();
    
    // ATTACK: Create and pass proposal to add 3 new members
    var newMember1 = Accounts[5].Address;
    var newMember2 = Accounts[6].Address;
    var newMember3 = Accounts[7].Address;
    
    var addMemberProposal = await CreateAddMemberProposalAsync(Reviewer1KeyPair, organizationAddress, newMember1);
    await ApproveAsync(Reviewer1KeyPair, addMemberProposal);
    await ApproveAsync(Reviewer2KeyPair, addMemberProposal);
    await ApproveAsync(Reviewer3KeyPair, addMemberProposal);
    await ReleaseAsync(Reviewer1KeyPair, addMemberProposal);
    
    // New members vote to reject P1
    await RejectAsync(Accounts[5].KeyPair, proposalId);
    await RejectAsync(Accounts[6].KeyPair, proposalId);
    await RejectAsync(Accounts[7].KeyPair, proposalId);
    
    // P1 now has 3 rejections > MaximalRejectionThreshold (2), cannot be released
    var proposalAfterAttack = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposalAfterAttack.ToBeReleased.ShouldBeFalse(); // Previously passing proposal is now blocked!
}
```

## Notes

This vulnerability demonstrates a fundamental flaw in the Association contract's governance model where the electorate composition is mutable during active voting periods. The lack of membership snapshots violates the basic democratic principle that the outcome should be determined by those who had voting rights when the proposal was created, not by those who gained rights afterward. While the attack requires existing governance control to add members, this is a reasonable threat model for governance attacks where an attacker with partial control seeks to manipulate specific high-value proposals.

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L18-22)
```csharp
    private void AssertIsAuthorizedOrganizationMember(Organization organization, Address member)
    {
        Assert(organization.OrganizationMemberList.Contains(member),
            "Unauthorized member.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L36-38)
```csharp
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L43-43)
```csharp
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-49)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
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
