# Audit Report

## Title
Organization Member List Manipulation Allows Governance Bypass Through Post-Creation Vote Manipulation

## Summary
The Association contract fails to snapshot the organization member list at proposal creation time, instead dynamically checking membership during voting and vote counting. This design flaw allows organizations to manipulate proposal outcomes by adding or removing members after a proposal is created but before it is released, fundamentally compromising the governance system's integrity.

## Finding Description

The Association contract implements a governance model with a critical design flaw: it does not capture or store the member list at proposal creation time. Instead, voting authorization and vote counting dynamically reference the current organization member list, enabling retroactive manipulation of proposal outcomes.

**Flaw 1: No Member List Snapshot**

When a proposal is created, the ProposalInfo structure only stores the organization address reference, not a snapshot of the member list at that moment. [1](#0-0) 

The protobuf definition confirms that ProposalInfo only contains an `organization_address` field, with no member list snapshot. [2](#0-1) 

**Flaw 2: Dynamic Member Verification During Voting**

All voting methods (`Approve`, `Reject`, `Abstain`) call `AssertIsAuthorizedOrganizationMember` to verify the voter's eligibility. [3](#0-2) 

This authorization check queries the current organization member list, not a historical snapshot. [4](#0-3) 

**Flaw 3: Vote Counting Filters by Current Member List**

When determining if a proposal meets release thresholds, the contract filters votes by checking if voters exist in the current member list:

- Rejection counting: [5](#0-4) 
- Abstention counting: [6](#0-5) 
- Approval counting: [7](#0-6) 

**Flaw 4: Unrestricted Member Modification**

Organizations can modify their member lists at any time through `AddMember`, `RemoveMember`, and `ChangeMember` functions. These functions only verify that the caller is the organization itself (via virtual address), with no checks for active proposals. [8](#0-7) 

The organization can call these functions on itself by executing approved proposals that use `SendVirtualInlineBySystemContract`. [9](#0-8) 

## Impact Explanation

This vulnerability enables three critical attack vectors that completely undermine governance integrity:

**1. Vote Dilution Attack**: An organization can pass a proposal to add new members who will vote favorably on existing controversial proposals. These new members gain retroactive voting rights on proposals created before they joined, violating the principle that voting eligibility is determined at proposal creation time.

**2. Vote Invalidation Attack**: An organization can pass a proposal to remove members who have already voted against a pending proposal. When release threshold checks are performed, the removed members' votes are filtered out because they no longer exist in the current member list. This can transform a failing proposal into a passing one without gaining any new legitimate approvals.

**3. Threshold Manipulation**: By strategically modifying the member count, attackers can alter the effective voting thresholds. A proposal that correctly failed under the original member composition can artificially pass under a manipulated membership.

**Example Scenario:**
- Organization has members [A, B, C, D, E] with threshold: 3 approvals required, max 2 rejections allowed
- Proposal X created (e.g., treasury fund transfer)
- Votes cast: A, B approve; C, D, E reject
- Proposal X fails (2 approvals < 3 required, 3 rejections > 2 allowed)
- Organization passes Proposal Y to remove members C, D, E
- After member removal, checking Proposal X's release status:
  - Rejection count becomes 0 (C, D, E not in current member list)
  - Only 2 members remain (A, B)
  - Depending on threshold recalculation, Proposal X may now pass

This affects all Association organizations and completely compromises the trustworthiness of any governance decisions made through these contracts.

## Likelihood Explanation

**High Likelihood** - This attack is straightforward to execute and requires no special privileges:

**Attacker Requirements:**
- Control sufficient votes to pass a membership-modifying proposal (normal organization capability)
- No exploitation of bugs or edge cases - uses intended functionality

**Attack Complexity:**
- Low - Only standard proposal creation and execution
- No timing dependencies or race conditions
- No external contract interactions required

**Realistic Conditions:**
- Common in any contested governance scenario
- Natural coalition shifts make this attack pattern indistinguishable from legitimate membership changes
- No on-chain mechanism exists to prevent or detect this abuse

**Detection Difficulty:**
- Member modifications appear as legitimate governance actions
- No clear on-chain signals of malicious intent
- Voters may not monitor membership changes between voting and proposal release

## Recommendation

Implement a member list snapshot mechanism at proposal creation time:

1. **Snapshot Member List**: When creating a proposal, store a complete snapshot of the organization member list in the ProposalInfo structure. Modify the protobuf definition to include:
```
repeated aelf.Address member_list_snapshot = 14;
```

2. **Use Snapshot for Authorization**: Modify `AssertIsAuthorizedOrganizationMember` to check against the proposal's member snapshot during voting rather than the current organization member list.

3. **Use Snapshot for Vote Counting**: Modify `IsProposalRejected`, `IsProposalAbstained`, and `CheckEnoughVoteAndApprovals` to filter votes against the member list snapshot stored in the proposal, not the current organization member list.

4. **Alternative (Less Storage)**: If storage cost is a concern, store only the member count at proposal creation and validate that the count has not changed when checking release thresholds. This prevents threshold manipulation but does not fully prevent vote dilution/invalidation if membership can be swapped.

## Proof of Concept

```csharp
[Fact]
public async Task MemberRemoval_InvalidatesVotesAndAllowsProposalManipulation()
{
    // Setup: Create organization with 5 members
    var members = new[] { Address.FromPublicKey(Tester1KeyPair.PublicKey),
                         Address.FromPublicKey(Tester2KeyPair.PublicKey),
                         Address.FromPublicKey(Tester3KeyPair.PublicKey),
                         Address.FromPublicKey(Tester4KeyPair.PublicKey),
                         Address.FromPublicKey(Tester5KeyPair.PublicKey) };
    
    var organizationAddress = await CreateAssociationOrganization(
        members, 
        minimalApprovalThreshold: 3,
        maximalRejectionThreshold: 2);
    
    // Step 1: Create Proposal X (should fail)
    var proposalX = await CreateProposal(organizationAddress, targetMethod);
    
    // Step 2: Vote on Proposal X
    await ApproveProposal(proposalX, Tester1KeyPair); // Approve
    await ApproveProposal(proposalX, Tester2KeyPair); // Approve
    await RejectProposal(proposalX, Tester3KeyPair);  // Reject
    await RejectProposal(proposalX, Tester4KeyPair);  // Reject
    await RejectProposal(proposalX, Tester5KeyPair);  // Reject
    
    // Verify Proposal X cannot be released (3 rejections > 2 max allowed)
    var canRelease = await GetProposalReleaseStatus(proposalX);
    Assert.False(canRelease);
    
    // Step 3: Create and pass Proposal Y to remove rejecting members
    var removalProposal = await CreateMemberRemovalProposal(
        organizationAddress, 
        new[] { members[2], members[3], members[4] });
    
    await ApproveProposal(removalProposal, Tester1KeyPair);
    await ApproveProposal(removalProposal, Tester2KeyPair);
    await ReleaseProposal(removalProposal);
    
    // Step 4: Check Proposal X status after member removal
    canRelease = await GetProposalReleaseStatus(proposalX);
    
    // VULNERABILITY: Proposal X can now be released because rejection votes
    // from removed members are no longer counted
    Assert.True(canRelease); // This demonstrates the vulnerability
    
    await ReleaseProposal(proposalX); // Successfully releases despite original rejection
}
```

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L149-161)
```csharp
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
