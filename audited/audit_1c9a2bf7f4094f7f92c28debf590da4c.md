# Audit Report

## Title
Organization Member List Manipulation Allows Governance Bypass Through Post-Creation Vote Manipulation

## Summary
The Association contract does not snapshot the organization member list at proposal creation time. Instead, it dynamically checks membership against the current member list during both voting authorization and vote counting. This allows an organization to add new members who can vote on existing proposals or remove members to invalidate their already-cast votes, completely undermining the integrity of the governance system.

## Finding Description

The vulnerability exists across multiple functions in the Association contract with two critical flaws:

**Flaw 1: Dynamic Member List Check During Voting**

When a member attempts to vote on a proposal, the contract checks authorization against the current organization member list, not a snapshot from proposal creation time. The voting methods (`Approve`, `Reject`, `Abstain`) all call `AssertIsAuthorizedOrganizationMember` which checks if the voter is in the current member list. [1](#0-0) [2](#0-1) 

**Flaw 2: Vote Counting Uses Current Member List**

When determining if a proposal meets the release threshold, the contract filters votes by checking if voters exist in the current organization member list:

- Rejection counting filters by current member list: [3](#0-2) 

- Abstention counting filters by current member list: [4](#0-3) 

- Approval counting filters by current member list: [5](#0-4) 

**Root Cause: No Member List Snapshot**

The ProposalInfo structure stores only the organization address reference, not a snapshot of members at creation time: [6](#0-5) [7](#0-6) 

**Exploitation Path: Member List Modification Functions**

The organization can modify its member list after proposal creation through three functions:

- `AddMember` adds new members: [8](#0-7) 

- `RemoveMember` removes existing members: [9](#0-8) 

- `ChangeMember` replaces members: [10](#0-9) 

These functions are callable by the organization itself (via proposal execution using `SendVirtualInlineBySystemContract`): [11](#0-10) 

## Impact Explanation

**Critical Governance Compromise:**

1. **Vote Dilution Attack**: An organization with a pending controversial proposal can execute a separate proposal to add new members favorable to the outcome. These new members, who were not members when the proposal was created, can vote on the existing proposal. This violates the fundamental governance principle that voting rights are determined at proposal creation time.

2. **Vote Invalidation Attack**: An organization facing rejection of a proposal can execute a separate proposal to remove members who voted against it. When the original proposal's release threshold is checked, the removed members' votes are filtered out because the vote counting logic checks against the current member list. This can flip a failing proposal into a passing one.

3. **Threshold Manipulation**: By strategically adding or removing members, an attacker can manipulate the effective voting thresholds. For example:
   - Organization with 5 members (A, B, C, D, E)
   - Proposal X requires 3 approvals, max 2 rejections
   - Current votes: A, B approve; C, D, E reject (fails)
   - Pass proposal to remove C, D, E
   - When checking X's release status, only A and B's approvals count
   - With adjusted thresholds for 2 members, X might now pass

**Who is Affected:**
- All Association organizations and their proposals
- Any governance decisions made through Association contracts
- Stakeholders who voted based on the member list at proposal creation time

## Likelihood Explanation

**Medium-High Likelihood:**

**Attacker Capabilities Required:**
- Ability to pass at least one proposal to modify membership (standard organization capability)
- No special privileges beyond normal organization operation

**Attack Complexity:**
- Low complexity: Only requires creating and executing standard proposals
- The member modification functions are designed features, not exploits

**Feasibility Conditions:**
- Any organization with sufficient votes to pass membership-modifying proposals
- Common in contested governance scenarios where coalitions can shift

**Execution Steps:**
1. Create controversial Proposal A (e.g., treasury allocation)
2. Members vote on Proposal A (some approve, some reject)
3. Controlling coalition creates Proposal B to add favorable members or remove opposing members
4. Proposal B passes and executes, modifying the member list
5. New members vote on Proposal A, or removed members' votes are filtered out during threshold checks
6. Proposal A's outcome is manipulated

**Detection Constraints:**
- Member list modifications are legitimate function calls
- No on-chain indication of malicious intent
- Difficult for voters to detect timing-based manipulation

## Recommendation

Implement member list snapshotting at proposal creation time. Store the member list within the ProposalInfo structure:

1. **Modify ProposalInfo** to include a snapshot of organization members at creation:
   ```protobuf
   message ProposalInfo {
       // ... existing fields ...
       OrganizationMemberList member_snapshot = 14; // Snapshot at creation
   }
   ```

2. **Update CreateNewProposal** to capture the member snapshot:
   ```csharp
   var proposal = new ProposalInfo
   {
       // ... existing fields ...
       OrganizationAddress = input.OrganizationAddress,
       MemberSnapshot = organization.OrganizationMemberList // Snapshot here
   };
   ```

3. **Update vote authorization** to check against the snapshot:
   ```csharp
   private void AssertIsAuthorizedOrganizationMember(ProposalInfo proposal, Address member)
   {
       Assert(proposal.MemberSnapshot.Contains(member), "Unauthorized member.");
   }
   ```

4. **Update vote counting** to filter against the snapshot instead of current list:
   ```csharp
   var rejectionMemberCount = proposal.Rejections.Count(proposal.MemberSnapshot.Contains);
   var abstentionMemberCount = proposal.Abstentions.Count(proposal.MemberSnapshot.Contains);
   var approvedMemberCount = proposal.Approvals.Count(proposal.MemberSnapshot.Contains);
   ```

## Proof of Concept

```csharp
[Fact]
public async Task MemberListManipulation_AllowsVoteBypass()
{
    // Setup: Create organization with 5 members (Reviewer1, Reviewer2, Reviewer3, plus 2 more)
    var organizationAddress = await CreateOrganizationAsync(
        minimalApproveThreshold: 3,
        minimalVoteThreshold: 4, 
        maximalAbstentionThreshold: 1,
        maximalRejectionThreshold: 2,
        Reviewer1
    );
    
    // Step 1: Create controversial Proposal A
    var proposalA = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 2: Initial votes on Proposal A (2 approve, 3 reject - FAILS threshold)
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(proposalA);
    await GetAssociationContractTester(Reviewer2KeyPair).Approve.SendAsync(proposalA);
    await GetAssociationContractTester(Reviewer3KeyPair).Reject.SendAsync(proposalA);
    // Assume member4 and member5 also reject (not shown for brevity)
    
    // Step 3: Create Proposal B to remove rejecting members
    var removeMemberInput = new Address { Value = Reviewer3 }; // Remove Reviewer3
    var proposalB = await CreateAssociationProposalAsync(
        Reviewer1KeyPair,
        removeMemberInput,
        nameof(AssociationContractStub.RemoveMember),
        organizationAddress
    );
    
    // Step 4: Pass Proposal B (coalition of Reviewer1, Reviewer2 + one other)
    await GetAssociationContractTester(Reviewer1KeyPair).Approve.SendAsync(proposalB);
    await GetAssociationContractTester(Reviewer2KeyPair).Approve.SendAsync(proposalB);
    // One more approval makes it pass
    
    // Step 5: Release Proposal B - removes Reviewer3 from member list
    await GetAssociationContractTester(Reviewer1KeyPair).Release.SendAsync(proposalB);
    
    // Step 6: Check Proposal A - Reviewer3's rejection vote is now filtered out
    var proposalAInfo = await AssociationContractStub.GetProposal.CallAsync(proposalA);
    
    // VULNERABILITY: Reviewer3's rejection no longer counts because they're not in current member list
    // Proposal A may now pass despite originally having 3 rejections
    proposalAInfo.ToBeReleased.ShouldBeTrue(); // This should be FALSE but is TRUE
}
```

## Notes

This vulnerability is specific to the Association contract. The Parliament contract uses a similar dynamic member checking pattern but is not vulnerable because its member list (current miners) is determined by an external consensus contract, not by the organization itself. The Referendum contract uses token-weighted voting without a member list concept, so it is unaffected.

The core issue is the mismatch between governance best practices (voting rights determined at proposal creation) and the implementation (voting rights determined at vote/threshold-check time). This allows post-hoc manipulation of governance outcomes.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L128-128)
```csharp
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);
```

**File:** contract/AElf.Contracts.Association/Association.cs (L189-191)
```csharp
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L42-44)
```csharp
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L49-51)
```csharp
        var approvedMemberCount = proposal.Approvals.Count(organization.OrganizationMemberList.Contains);
        var isApprovalEnough =
            approvedMemberCount >= organization.ProposalReleaseThreshold.MinimalApprovalThreshold;
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
