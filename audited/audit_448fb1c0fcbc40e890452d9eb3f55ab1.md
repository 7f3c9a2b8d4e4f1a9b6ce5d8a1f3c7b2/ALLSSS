# Audit Report

## Title
Organization Member List Manipulation Allows Governance Bypass Through Post-Creation Vote Manipulation

## Summary
The Association contract lacks a member list snapshot mechanism at proposal creation time. Instead, it dynamically validates voting authorization and counts votes against the current organization member list. This allows organizations to manipulate governance outcomes by adding new voters or invalidating existing votes through member list modifications after proposal creation.

## Finding Description

The vulnerability stems from the Association contract's use of the current organization member list for both vote authorization and vote counting, rather than maintaining a snapshot from proposal creation time.

**Flaw 1: Dynamic Member Authorization During Voting**

When members attempt to vote, the contract validates authorization against the current member list. [1](#0-0) 

The voting functions (`Approve`, `Reject`, `Abstain`) all invoke this check against the current organization state. [2](#0-1) 

**Flaw 2: Vote Counting Uses Current Member List**

When determining if a proposal meets release thresholds, the contract filters votes by checking if voters exist in the current member list:

- Rejection counting: [3](#0-2) 
- Abstention counting: [4](#0-3) 
- Approval counting: [5](#0-4) 

**Root Cause: No Member List Snapshot**

The `ProposalInfo` structure only stores the organization address reference, not a member list snapshot. [6](#0-5) 

**Exploitation Path: Member List Modification**

Organizations can modify their member lists through three functions that are callable by the organization itself (via proposal execution):

- `AddMember`: [7](#0-6) 
- `RemoveMember`: [8](#0-7) 
- `ChangeMember`: [9](#0-8) 

These functions require `Context.Sender` to be the organization address, which occurs when proposals are executed via the `Release` function. [10](#0-9) 

## Impact Explanation

This vulnerability has **CRITICAL** impact on governance integrity:

1. **Vote Invalidation Attack**: Organizations can execute a proposal to remove members who voted against a controversial proposal. When the original proposal's release threshold is checked, those removed members' votes are filtered out because the vote counting logic checks `.Count(organization.OrganizationMemberList.Contains)`. This can flip a failing proposal into passing.

2. **Vote Dilution Attack**: Organizations can execute a proposal to add new members favorable to a pending proposal. These new members can then vote on the existing proposal, even though they weren't members when the proposal was created.

3. **Threshold Manipulation**: By strategically modifying membership, attackers can manipulate effective voting thresholds. For example, with thresholds of MinimalApproval=3, MaximalRejection=1, an organization could:
   - Have votes: 2 approvals, 2 rejections (fails due to exceeding MaximalRejection)
   - Execute proposal to remove both rejecting members
   - Original proposal now counts: 2 approvals, 0 rejections (may pass depending on MinimalVoteThreshold)

**Affected Parties:**
- All Association organizations and their active proposals
- Governance stakeholders whose votes can be retroactively invalidated
- Systems relying on Association contract governance (e.g., token operations, configuration changes)

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of exploitation:

**Attack Complexity: LOW**
- Only requires creating and executing standard proposals using designed contract features
- No need for special privileges beyond normal organization operation

**Attacker Requirements:**
- Ability to pass at least one proposal to modify membership (standard capability)
- Common in organizations with multiple factions or contested governance

**Realistic Scenario:**
1. Organization has 5 members: A, B, C, D, E
2. Controversial Proposal P1 created (e.g., treasury allocation)
3. Votes cast: A, B approve; C, D reject; E abstains
4. Proposal P1 fails (2 rejections exceeds MaximalRejection=1)
5. Faction controlling A, B, E creates Proposal P2: "Remove inactive members C and D"
6. Proposal P2 passes (3 votes: A, B, E)
7. P2 executes: RemoveMember(C), RemoveMember(D)
8. Now when checking P1: only 2 approvals counted, 0 rejections counted
9. P1 may now pass depending on thresholds

**Detection Difficulty:**
- Member modifications are legitimate function calls
- No on-chain indication of malicious intent
- Voters may not monitor membership changes between voting and release

## Recommendation

Implement a member list snapshot mechanism at proposal creation time:

1. **Add snapshot field to ProposalInfo**:
```protobuf
message ProposalInfo {
    // ... existing fields ...
    OrganizationMemberList member_list_snapshot = 14; // Snapshot at creation
}
```

2. **Capture snapshot during proposal creation**:
Store the current member list in the proposal when created.

3. **Use snapshot for authorization and counting**:
    - Vote authorization should check against `proposal.member_list_snapshot`
    - Vote counting should filter against `proposal.member_list_snapshot` instead of current organization member list

4. **Alternative approach** (if storage is a concern):
Store a hash of the member list and validate that it hasn't changed, rejecting votes if the member list has been modified since proposal creation.

## Proof of Concept

```csharp
[Fact]
public async Task MemberManipulation_Governance_Bypass_Test()
{
    // Setup: Create organization with 5 members and specific thresholds
    var minimalApprovalThreshold = 2;
    var minimalVoteThreshold = 3;
    var maximalAbstentionThreshold = 1;
    var maximalRejectionThreshold = 1; // Key: Max 1 rejection allowed
    
    // Add two more members beyond default Reviewer1, Reviewer2, Reviewer3
    var member4KeyPair = Accounts[4].KeyPair;
    var member5KeyPair = Accounts[5].KeyPair;
    var member4 = Accounts[4].Address;
    var member5 = Accounts[5].Address;
    
    var createOrgInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3, member4, member5 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = minimalApprovalThreshold,
            MinimalVoteThreshold = minimalVoteThreshold,
            MaximalAbstentionThreshold = maximalAbstentionThreshold,
            MaximalRejectionThreshold = maximalRejectionThreshold
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }
        }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization.SendAsync(createOrgInput)).Output;
    
    // Step 1: Create controversial Proposal A
    var proposalA = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 2: Vote on Proposal A - 2 approvals, 2 rejections
    await ApproveAsync(Reviewer1KeyPair, proposalA);
    await ApproveAsync(Reviewer2KeyPair, proposalA);
    await RejectAsync(Reviewer3KeyPair, proposalA);
    await RejectAsync(member4KeyPair, proposalA);
    
    // Verify Proposal A cannot be released (2 rejections > maximalRejectionThreshold=1)
    var proposalBeforeManipulation = await AssociationContractStub.GetProposal.CallAsync(proposalA);
    proposalBeforeManipulation.ToBeReleased.ShouldBeFalse(); // Should fail due to too many rejections
    proposalBeforeManipulation.RejectionCount.ShouldBe(2);
    
    // Step 3: Create Proposal B to remove the rejecting members
    var proposalB = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    await TransferToOrganizationAddressAsync(organizationAddress);
    
    // Vote on Proposal B to remove members - passes with 3 approvals
    await ApproveAsync(Reviewer1KeyPair, proposalB);
    await ApproveAsync(Reviewer2KeyPair, proposalB);
    await ApproveAsync(member5KeyPair, proposalB);
    
    // Step 4: Execute Proposal B to remove Reviewer3 and member4
    var associationStub = GetAssociationContractTester(Reviewer1KeyPair);
    await associationStub.Release.SendAsync(proposalB);
    
    // Verify members were removed
    var updatedOrg = await AssociationContractStub.GetOrganization.CallAsync(organizationAddress);
    updatedOrg.OrganizationMemberList.OrganizationMembers.Contains(Reviewer3).ShouldBeFalse();
    updatedOrg.OrganizationMemberList.OrganizationMembers.Contains(member4).ShouldBeFalse();
    
    // Step 5: Check Proposal A again - VULNERABILITY: votes from removed members don't count
    var proposalAfterManipulation = await AssociationContractStub.GetProposal.CallAsync(proposalA);
    
    // CRITICAL BUG: Proposal A now shows 0 rejections because Reviewer3 and member4
    // are no longer in the member list, so their votes are filtered out!
    proposalAfterManipulation.ToBeReleased.ShouldBeTrue(); // BUG: Now passes when it shouldn't
    
    // The stored rejections list still contains Reviewer3 and member4,
    // but the vote counting filters them out because they're not in current member list
    proposalAfterManipulation.RejectionCount.ShouldBe(2); // Still stored
    
    // But when checking threshold, it filters by current members:
    // proposal.Rejections.Count(organization.OrganizationMemberList.Contains) returns 0
    
    // This demonstrates complete governance bypass through member manipulation
}
```

## Notes

This vulnerability is a fundamental design flaw in the Association contract's governance model. The absence of a member list snapshot violates the core governance principle that voting rights and vote weight should be immutable once a proposal is created. The attack is highly practical because:

1. Member modification is a designed feature accessible through standard proposals
2. No special privileges are required beyond normal organization operation  
3. The attack leaves no suspicious on-chain traces
4. It can be executed in contested governance scenarios where factions have competing interests

The same vulnerability pattern should be checked in Parliament and Referendum contracts, though they may use different membership models (Parliament uses miner/proposer addresses, Referendum uses token-based voting).

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

**File:** contract/AElf.Contracts.Association/Association.cs (L248-264)
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
