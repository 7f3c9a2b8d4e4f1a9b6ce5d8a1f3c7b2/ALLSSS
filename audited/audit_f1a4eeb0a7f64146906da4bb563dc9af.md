### Title
Unbounded OrganizationMemberList Size Enables Execution Limit DoS on Association Governance Operations

### Summary
The Association contract lacks validation for the maximum size of `OrganizationMemberList`, allowing creation of organizations with up to ~3,500 members (limited only by the 128KB state size constraint). During voting and proposal release operations, the O(n) `Contains()` checks and O(m*n) `Count(Contains)` operations cause transactions to exceed AElf's 15,000 branch count execution threshold, resulting in permanent DoS of the affected organization's governance functions.

### Finding Description

The vulnerability exists in the organization validation and voting operations across multiple functions:

**Missing Size Validation:**
The `Validate()` function in [1](#0-0)  checks that `OrganizationMemberList` is not empty and contains no duplicates, but imposes no maximum size limit. An attacker can create an organization with thousands of members (up to ~3,500 limited by the 128KB state size constraint defined in [2](#0-1) ).

**O(n) Complexity During Voting:**
When members vote, `AssertIsAuthorizedOrganizationMember()` at [3](#0-2)  calls `Contains()` which has O(n) complexity as implemented in [4](#0-3) . With 3,500 members, each vote requires iterating through all members.

**O(m*n) Complexity During Release:**
The critical failure occurs during proposal release. The `IsReleaseThresholdReached()` function calls `IsProposalRejected()` at [5](#0-4) , `IsProposalAbstained()` at [6](#0-5) , and `CheckEnoughVoteAndApprovals()` at [7](#0-6) . Each uses `Count(organization.OrganizationMemberList.Contains)` which iterates through all votes, and for each vote, iterates through all members - resulting in O(m*n) complexity where m = vote count and n = member count.

**Execution Limit Exceeded:**
AElf enforces a 15,000 branch count execution limit as documented in [8](#0-7)  and [9](#0-8) . With 100 votes and 3,500 members, the `Count(Contains)` operations require 350,000 checks, far exceeding the limit.

**Unrestricted Organization Creation:**
The `CreateOrganization()` function at [10](#0-9)  allows anyone to create organizations with arbitrary member lists, only checking validation at [11](#0-10)  which lacks size limits. Additionally, `AddMember()` at [12](#0-11)  can incrementally add members until the organization becomes unusable.

### Impact Explanation

**Governance DoS:**
Any organization with an excessively large member list becomes permanently unusable. The `Approve()`, `Reject()`, and `Abstain()` functions at [13](#0-12)  all call `AssertIsAuthorizedOrganizationMember()` which may fail for large organizations. Most critically, the `Release()` function at [14](#0-13)  will always fail when checking `IsReleaseThresholdReached()` due to the O(m*n) complexity.

**Affected Parties:**
- Organization members who cannot participate in governance
- Legitimate proposals that cannot be released even with sufficient approvals
- Any smart contracts or protocols that depend on the affected organization for authorization

**Attack Scenarios:**
1. **Accidental DoS:** Well-intentioned organizations with many members (e.g., 2,000+) accidentally create unusable governance structures
2. **Griefing Attack:** Malicious actors create dysfunctional organizations and trick users into participating, wasting their transaction fees and time
3. **Protocol Sabotage:** If critical system functions are gated by an Association organization, an attacker can create a DoS vector

**Severity:** Medium - While funds are not directly at risk, this represents a complete breakdown of governance functionality for affected organizations, with no recovery mechanism.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to create a transaction calling `CreateOrganization()` (publicly accessible)
- Sufficient funds to cover transaction fees for organization creation
- No special permissions or governance authority needed

**Attack Complexity:** Low
1. Prepare a list of ~3,500 addresses (can be attacker-controlled or arbitrary)
2. Call `CreateOrganization()` with this member list
3. Organization is created and immediately dysfunctional for voting/release operations

**Feasibility Conditions:**
- The 128KB state size limit naturally caps member count at ~3,500, but this is still sufficient to exceed the 15,000 branch limit
- Organization creation may have method fees, but these are typically low or zero for governance contracts
- No validation prevents this at contract level

**Economic Rationality:**
- Attack cost: One transaction fee for `CreateOrganization()`
- Attack benefit: Permanent DoS of that organization's governance
- For griefing or sabotage purposes, cost-to-impact ratio is favorable

**Detection:** Organizations with >1,000 members are suspicious and can be identified by querying organization state, but prevention at contract level does not exist.

### Recommendation

**Immediate Fix - Add Maximum Size Validation:**
Add a maximum member list size constant to [15](#0-14) :
```csharp
public const int MaxOrganizationMemberCount = 500;
```

Modify the `Validate()` function to enforce this limit:
```csharp
private bool Validate(Organization organization)
{
    var organizationMemberCount = organization.OrganizationMemberList.Count();
    
    if (organizationMemberCount > AssociationConstants.MaxOrganizationMemberCount)
        return false;
        
    // ... existing validation logic
}
```

**Long-term Fix - Optimize Data Structure:**
Consider using a more efficient membership verification mechanism:
- Store members in a `MappedState<Address, bool>` instead of repeated list
- This changes `Contains()` from O(n) to O(1)
- Update `AddMember()`, `RemoveMember()`, and `ChangeMember()` accordingly

**Additional Validation:**
Add size check in `AddMember()` at [12](#0-11)  before adding:
```csharp
Assert(organization.OrganizationMemberList.Count() < AssociationConstants.MaxOrganizationMemberCount, 
    "Organization member count exceeds maximum.");
```

**Test Cases:**
1. Verify organization creation fails when member list exceeds limit
2. Verify `AddMember()` fails when adding would exceed limit  
3. Verify organizations at the limit can still vote and release proposals within execution limits
4. Verify edge case of exactly maximum members functions correctly

### Proof of Concept

**Step 1 - Prepare Large Member List:**
```
memberList = [address_1, address_2, ..., address_3500]
// 3,500 addresses, each unique, just under 128KB state size limit
```

**Step 2 - Create Dysfunctional Organization:**
```
Call: AssociationContract.CreateOrganization({
    organization_member_list: memberList,
    proposal_release_threshold: {
        minimal_approval_threshold: 50,
        minimal_vote_threshold: 100,
        maximal_rejection_threshold: 1000,
        maximal_abstention_threshold: 1000
    },
    proposer_white_list: [proposer_address]
})

Expected: Organization created successfully
Result: Organization address returned
```

**Step 3 - Create Proposal:**
```
Call: AssociationContract.CreateProposal({
    organization_address: organization_from_step2,
    // ... other proposal parameters
})

Result: Proposal created successfully
```

**Step 4 - Members Vote (100 approvals):**
```
For i = 1 to 100:
    Call from memberList[i]: AssociationContract.Approve(proposal_id)
    
Expected: May succeed but with high gas costs (3,500 Contains checks per vote)
Result: Some votes may fail due to approaching execution limits
```

**Step 5 - Attempt Release (DoS Trigger):**
```
Call: AssociationContract.Release(proposal_id)

Expected: Proposal released if threshold met
Actual Result: TRANSACTION FAILS with "execution exceeded branch count threshold"

Reason: 
- IsReleaseThresholdReached() calls Count(Contains) three times
- 100 approvals * 3,500 members = 350,000 checks
- Far exceeds 15,000 branch limit
```

**Success Condition:** Transaction fails at Step 5, proving the organization's governance is permanently DoS'd despite having sufficient approvals.

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

**File:** docs-sphinx/architecture/smart-contract/restrictions/others.rst (L10-15)
```text
Execution observer
------------------

- AElf's contract patcher will patch method call count observer for your contract. This is used to prevent infinitely method call like recursion. The number of method called in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.

- AElf's contract patcher will patch method branch count observer for your contract. This is used to prevent infinitely loop case. The number of code control transfer in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.
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

**File:** contract/AElf.Contracts.Association/Association.cs (L123-181)
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

    public override Empty Reject(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Rejections.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Reject),
            OrganizationAddress = proposal.OrganizationAddress
        });
        return new Empty();
    }

    public override Empty Abstain(Hash input)
    {
        var proposal = GetValidProposal(input);
        AssertProposalNotYetVotedBySender(proposal, Context.Sender);
        var organization = GetOrganization(proposal.OrganizationAddress);
        AssertIsAuthorizedOrganizationMember(organization, Context.Sender);

        proposal.Abstentions.Add(Context.Sender);
        State.Proposals[input] = proposal;
        Context.Fire(new ReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = input,
            Time = Context.CurrentBlockTime,
            ReceiptType = nameof(Abstain),
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

**File:** contract/AElf.Contracts.Association/AssociationConstants.cs (L1-8)
```csharp
namespace AElf.Contracts.Association;

public static class AssociationConstants
{
    public const int MaxLengthForTitle = 255;
    public const int MaxLengthForDescription = 10200;
    public const int MaxLengthForProposalDescriptionUrl = 255;
}
```
