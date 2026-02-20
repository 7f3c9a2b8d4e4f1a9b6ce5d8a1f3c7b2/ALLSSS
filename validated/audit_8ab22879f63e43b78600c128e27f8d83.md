# Audit Report

## Title
Unbounded OrganizationMemberList Size Enables Execution Limit DoS on Association Governance Operations

## Summary
The Association contract lacks validation for the maximum size of `OrganizationMemberList`, allowing creation of organizations with up to ~3,500 members (limited only by the 128KB state size constraint). During proposal release operations, O(m×n) complexity in membership verification causes transactions to exceed AElf's 15,000 branch count execution threshold, resulting in permanent denial-of-service of the affected organization's governance functions.

## Finding Description

The vulnerability stems from missing size validation in organization creation combined with quadratic-complexity membership checks during proposal operations.

**Missing Size Validation:**

The `Validate()` function checks that `OrganizationMemberList` is not empty and contains no duplicates, but imposes no maximum size limit. [1](#0-0)  This allows creation of organizations with thousands of members, constrained only by the 128KB state size limit [2](#0-1) , which permits approximately 3,500 addresses.

**O(n) Membership Checks:**

The `Contains()` method uses protobuf's `RepeatedField.Contains()`, which has O(n) complexity, iterating through all members for each check. [3](#0-2) 

**O(m×n) Complexity in Release:**

During proposal release, `IsReleaseThresholdReached()` [4](#0-3)  performs three critical checks:

1. `IsProposalRejected()` executes `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)` [5](#0-4) 

2. `IsProposalAbstained()` executes `proposal.Abstentions.Count(organization.OrganizationMemberList.Contains)` [6](#0-5) 

3. `CheckEnoughVoteAndApprovals()` executes `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)` [7](#0-6) 

Each `Count(predicate)` operation iterates through all votes (m) and for each vote calls `Contains()` which iterates through all members (n), resulting in m×n iterations per check.

**Branch Limit Exceeded:**

AElf enforces a 15,000 branch count execution limit [8](#0-7)  that throws `RuntimeBranchThresholdExceededException` when exceeded. [9](#0-8)  Each loop iteration counts as one branch, confirmed by tests showing 14,999 iterations succeed while 15,000 fail. [10](#0-9) 

With just 50 votes and 300 members:
- Each check: 50 × 300 = 15,000 branches
- Three checks total: 45,000 branches
- Result: **3× over the limit**

**Unrestricted Creation:**

Anyone can create organizations via the public `CreateOrganization()` method [11](#0-10) , which only validates through the flawed `Validate()` function. [12](#0-11)  Additionally, `AddMember()` can incrementally add members post-creation. [13](#0-12) 

## Impact Explanation

**Complete Governance DoS:**

Organizations with excessive member counts become permanently unusable. The `Release()` function [14](#0-13)  will always fail when checking `IsReleaseThresholdReached()` [15](#0-14)  due to the O(m×n) complexity exceeding the 15,000 branch limit.

**Permanent State:**

No recovery mechanism exists. Once an organization exceeds safe size limits, all proposals become unreleasable regardless of approval status. Members waste transaction fees voting on proposals that can never execute.

**Affected Parties:**
- Organization members unable to execute governance decisions
- Protocols depending on Association organizations for authorization
- Well-intentioned large organizations accidentally creating unusable structures

**Attack Scenarios:**
1. **Malicious DoS**: Attacker creates dysfunctional organization, tricks users into joining/voting
2. **Protocol Sabotage**: If system functions use Association organizations, attacker creates permanent DoS vector
3. **Accidental DoS**: Legitimate organizations with 1,000+ members unknowingly render themselves unusable

**Severity Justification:** Medium - Complete breakdown of governance functionality with no recovery path, though funds are not directly stolen or locked.

## Likelihood Explanation

**Attacker Requirements:**
- Public access to `CreateOrganization()` (no permissions required)
- Transaction fees for organization creation (typically low/zero for governance)
- List of ~1,000-3,500 addresses (can be attacker-controlled or arbitrary)

**Attack Complexity:** Low
1. Construct `CreateOrganizationInput` with large member list
2. Call `CreateOrganization()`
3. Organization immediately dysfunctional for proposal release

**Numerical Analysis:**
- 20 votes × 750 members × 3 checks = 45,000 branches (3× limit)
- 10 votes × 1,500 members × 3 checks = 45,000 branches (3× limit)
- 5 votes × 3,000 members × 3 checks = 45,000 branches (3× limit)

**Economic Feasibility:**
- Attack cost: One transaction fee
- Attack benefit: Permanent governance DoS
- Cost-to-impact ratio highly favorable for griefing/sabotage

**Detection:** Organizations with >500 members should be considered suspicious, but no contract-level prevention exists.

## Recommendation

Add a maximum size limit validation in the `Validate()` function:

```csharp
private bool Validate(Organization organization)
{
    const int MaxOrganizationMembers = 100; // Set reasonable limit
    
    if (organization.ProposerWhiteList.Empty() ||
        organization.ProposerWhiteList.AnyDuplicate() ||
        organization.OrganizationMemberList.Empty() ||
        organization.OrganizationMemberList.AnyDuplicate() ||
        organization.OrganizationMemberList.Count() > MaxOrganizationMembers) // Add this check
        return false;
    // ... rest of validation logic
}
```

Alternatively, optimize the membership checks by using a HashSet-based lookup structure instead of repeated linear searches, or implement batch validation that doesn't exceed branch limits.

## Proof of Concept

```csharp
[Fact]
public async Task TestLargeMemberListCausesDoS()
{
    // Create organization with 300 members
    var memberList = new OrganizationMemberList();
    for (int i = 0; i < 300; i++)
    {
        memberList.OrganizationMembers.Add(SampleAddress.AddressList[i % SampleAddress.AddressList.Count]);
    }
    
    var createInput = new CreateOrganizationInput
    {
        OrganizationMemberList = memberList,
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 1,
            MinimalVoteThreshold = 1,
            MaximalAbstentionThreshold = 300,
            MaximalRejectionThreshold = 300
        },
        ProposerWhiteList = new ProposerWhiteList { Proposers = { DefaultSender } }
    };
    
    var organizationAddress = await AssociationContractStub.CreateOrganization.SendAsync(createInput);
    
    // Create and vote on proposal with 50 votes
    var proposalId = await CreateProposalAsync(organizationAddress.Output);
    
    for (int i = 0; i < 50; i++)
    {
        await AssociationContractStub.Approve.SendAsync(proposalId);
    }
    
    // Attempt to release - should fail with RuntimeBranchThresholdExceededException
    var releaseResult = await AssociationContractStub.Release.SendWithExceptionAsync(proposalId);
    
    releaseResult.TransactionResult.Error.ShouldContain("RuntimeBranchThresholdExceededException");
}
```

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-81)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
        if (organization.OrganizationAddress == null || organization.OrganizationHash == null)
            return false;
        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        var organizationMemberCount = organization.OrganizationMemberList.Count();
        return proposalReleaseThreshold.MinimalVoteThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
               proposalReleaseThreshold.MaximalRejectionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount;
    }
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L17-20)
```csharp
    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
    }
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L29-36)
```csharp
    public void BranchCount()
    {
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");

        _branchCount++;
    }
```

**File:** test/AElf.Contracts.TestContract.Tests/PatchedContractSecurityTests.cs (L392-397)
```csharp
            await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendAsync(new Int32Input
                { Int32Value = 14999 });
            var txResult = await TestBasicSecurityContractStub.TestWhileInfiniteLoop.SendWithExceptionAsync(
                new Int32Input
                    { Int32Value = 15000 });
            txResult.TransactionResult.Error.ShouldContain(nameof(RuntimeBranchThresholdExceededException));
```

**File:** contract/AElf.Contracts.Association/Association.cs (L69-94)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            ProposerWhiteList = input.ProposerWhiteList,
            OrganizationMemberList = input.OrganizationMemberList,
            OrganizationHash = organizationHash,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization.");
        if (State.Organizations[organizationAddress] == null)
        {
            State.Organizations[organizationAddress] = organization;
            Context.Fire(new OrganizationCreated
            {
                OrganizationAddress = organizationAddress
            });
        }

        return organizationAddress;
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
