### Title
Unbounded List Sizes in Association Contract Enable Governance DoS via Computational Exhaustion

### Summary
The Association contract's extension methods and validation logic lack upper bound checks on `ProposerWhiteList` and `OrganizationMemberList` sizes, allowing attackers to create organizations with thousands of members. This causes O(n) and O(n*m) computational complexity in validation and vote counting operations, potentially exceeding AElf's execution limits and blocking critical governance operations.

### Finding Description

The vulnerability exists in multiple locations within the Association contract:

**Location 1: Duplicate checking with unbounded complexity** [1](#0-0) 

The `AnyDuplicate()` extension methods use `GroupBy().Any(g => g.Count() > 1)`, which has O(n) time and space complexity. This operation is called during organization validation without any size limits on the input lists.

**Location 2: Validation path without size bounds** [2](#0-1) 

The `Validate()` method calls `AnyDuplicate()` on both `ProposerWhiteList` and `OrganizationMemberList` (lines 64, 66) but performs no maximum size validation. The only constraint is that lists must not be empty.

**Location 3: Vote counting with O(n*m) complexity** [3](#0-2) 

The vote threshold checking logic performs nested iterations:
- `IsProposalRejected`: `proposal.Rejections.Count(organization.OrganizationMemberList.Contains)` 
- `IsProposalAbstained`: `proposal.Abstentions.Count(organization.OrganizationMemberList.Contains)`
- `CheckEnoughVoteAndApprovals`: `proposal.Approvals.Count(organization.OrganizationMemberList.Contains)`

Each `Contains()` call performs a linear search through the organization member list: [4](#0-3) 

For R rejections, A abstentions, AP approvals, and M organization members, the total complexity is O((R+A+AP) * M), which can reach millions of operations.

**Location 4: Public entry points without bounds** [5](#0-4) 

The `CreateOrganization` method accepts arbitrary-sized lists in the input and only validates against the 128KB state size limit. Within this limit, approximately 3,000-4,000 addresses can fit.

**Location 5: No size limit constants defined** [6](#0-5) 

Only title, description, and URL length limits exist. No maximum size constants are defined for member or proposer lists.

**Root Cause**: The contract relies solely on AElf's 128KB state size limit and 15,000 execution call/branch threshold without implementing application-level bounds on list sizes. This allows computationally expensive operations to be triggered with legitimate-sized state data.

### Impact Explanation

**Direct Governance Impact:**
An attacker can create an Association organization with maximum member counts (within the 128KB state limit, approximately 3,000-4,000 addresses). This causes:

1. **Organization management operations blocked**: Any call to `AddMember`, `RemoveMember`, `ChangeMember`, `ChangeOrganizationThreshold`, or `ChangeOrganizationProposerWhiteList` must validate the organization, triggering expensive `AnyDuplicate()` operations on the full member list. [7](#0-6) 

2. **Proposal release blocked**: The `Release` method calls `IsReleaseThresholdReached` which performs vote counting with O(n*m) complexity. For an organization with 3,000 members and a proposal with 1,500 votes, this results in approximately 4.5 million `Contains()` operations, likely exceeding execution limits. [8](#0-7) 

3. **Proposal status checks fail**: Even view methods like `GetProposal` call vote counting logic, preventing off-chain systems from determining proposal status. [9](#0-8) 

**Severity Justification**: Medium severity because:
- Affects governance operations critical to protocol management
- Can permanently freeze an organization's decision-making capability
- Does not directly steal funds but blocks treasury/configuration changes
- Requires attacker to create organization (low barrier) but only affects that specific organization
- Similar organizations created with reasonable sizes remain functional

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to submit transactions to create organizations (any user)
- Sufficient transaction fees for creating organization with large input data
- No special privileges or governance control needed

**Attack Complexity:**
1. Construct `CreateOrganizationInput` with 3,000-4,000 addresses in `OrganizationMemberList`
2. Call `CreateOrganization()` to establish the organization
3. Create proposals for that organization
4. Accumulate votes from members
5. Any attempt to release proposals or modify organization will hit computational limits

**Feasibility Conditions:**
- AElf's execution limits (15,000 calls/branches) apply to all contract execution
- Protobuf repeated fields support arbitrary list sizes up to state limit
- No application-level validation rejects large member lists
- The 128KB state limit allows thousands of addresses

**Execution Practicality:**
The attack is highly practical because:
- Creating organizations is permissionless
- Input data construction is straightforward
- Effects are immediate and deterministic
- No race conditions or timing dependencies
- Can be executed with standard transaction submission

**Economic Rationality:**
Cost is minimal (transaction fees for organization creation) while impact can block significant governance operations, especially for organizations managing valuable assets or critical protocol parameters.

### Recommendation

**1. Add maximum size constants:**
```
public const int MaxProposerWhiteListSize = 100;
public const int MaxOrganizationMemberListSize = 500;
```

**2. Implement size validation in the Validate method:**

Add checks before duplicate validation in `Association_Helper.cs`:
```csharp
private bool Validate(Organization organization)
{
    var proposerCount = organization.ProposerWhiteList.Count();
    var memberCount = organization.OrganizationMemberList.Count();
    
    if (proposerCount > AssociationConstants.MaxProposerWhiteListSize ||
        memberCount > AssociationConstants.MaxOrganizationMemberListSize)
        return false;
        
    // existing validation...
}
```

**3. Use more efficient duplicate detection:**
Replace `GroupBy().Any()` with a HashSet-based approach:
```csharp
public static bool AnyDuplicate(this ProposerWhiteList proposerWhiteList)
{
    var seen = new HashSet<Address>();
    return !proposerWhiteList.Proposers.All(seen.Add);
}
```

This reduces complexity from O(n) space + O(n) time to O(n) time with O(n) space but better constants.

**4. Consider vote counting optimization:**
Cache member set as HashSet in organization state for O(1) lookups instead of O(n) linear searches, or limit the number of votes that need checking.

**5. Add test cases:**
- Create organization with maximum allowed size
- Verify operations complete within execution limits
- Test with edge cases (max members, max votes)
- Ensure DoS protection doesn't break legitimate large organizations

### Proof of Concept

**Initial State:**
- AElf blockchain with Association contract deployed
- Attacker has sufficient transaction fees

**Attack Steps:**

1. **Create malicious organization:**
   - Construct `CreateOrganizationInput` with 3,500 addresses in `organization_member_list`
   - Set minimal thresholds: `minimal_approval_threshold = 1750`, `minimal_vote_threshold = 1750`
   - Add attacker-controlled addresses to `proposer_white_list`
   - Call `CreateOrganization(input)` → succeeds, returns organization address

2. **Create proposal:**
   - Call `CreateProposal` for the organization
   - Proposal created successfully

3. **Accumulate votes:**
   - Have 1,800 members call `Approve(proposalId)`
   - All approve transactions succeed

4. **Attempt release (DoS trigger):**
   - Call `Release(proposalId)`
   - Transaction attempts vote counting: 1,800 approvals × 3,500 members = 6.3 million `Contains()` operations
   - **Expected result**: Transaction completes and proposal executes
   - **Actual result**: Transaction fails due to exceeding execution call/branch threshold (15,000 limit)

5. **Governance blocked:**
   - Organization cannot release any proposals
   - Cannot modify organization settings (all require validation with `AnyDuplicate()`)
   - Governance for this organization is permanently frozen

**Success Condition:** Transaction failure in step 4 with execution limit exceeded error, confirming computational DoS blocks governance operations.

---

**Notes:**

- The vulnerability stems from the mismatch between AElf's execution limits (designed for typical operations) and the unbounded list sizes allowed by the contract logic
- While the 128KB state limit prevents infinite-sized lists, it still permits sizes large enough to cause computational exhaustion
- The issue affects all three governance contracts (Association, Parliament, Referendum) that use similar patterns, but this analysis focuses on Association as specified
- The problem is exacerbated by the O(n*m) vote counting complexity, which multiplies the cost across two unbounded dimensions (votes and members)

### Citations

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L19-27)
```csharp
    public static bool AnyDuplicate(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Proposers.GroupBy(p => p).Any(g => g.Count() > 1);
    }

    public static bool AnyDuplicate(this OrganizationMemberList organizationMemberList)
    {
        return organizationMemberList.OrganizationMembers.GroupBy(m => m).Any(g => g.Count() > 1);
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-58)
```csharp
    private bool IsProposalRejected(ProposalInfo proposal, Organization organization)
    {
        var rejectionMemberCount =
            proposal.Rejections.Count(organization.OrganizationMemberList.Contains);
        return rejectionMemberCount > organization.ProposalReleaseThreshold.MaximalRejectionThreshold;
    }

    private bool IsProposalAbstained(ProposalInfo proposal, Organization organization)
    {
        var abstentionMemberCount = proposal.Abstentions.Count(organization.OrganizationMemberList.Contains);
        return abstentionMemberCount > organization.ProposalReleaseThreshold.MaximalAbstentionThreshold;
    }

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

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L17-20)
```csharp
    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
    }
```

**File:** contract/AElf.Contracts.Association/Association.cs (L18-42)
```csharp
    public override ProposalOutput GetProposal(Hash proposalId)
    {
        var proposal = State.Proposals[proposalId];
        if (proposal == null) return new ProposalOutput();

        var organization = State.Organizations[proposal.OrganizationAddress];
        var readyToRelease = IsReleaseThresholdReached(proposal, organization);

        return new ProposalOutput
        {
            ProposalId = proposalId,
            ContractMethodName = proposal.ContractMethodName,
            ExpiredTime = proposal.ExpiredTime,
            OrganizationAddress = proposal.OrganizationAddress,
            Params = proposal.Params,
            Proposer = proposal.Proposer,
            ToAddress = proposal.ToAddress,
            ToBeReleased = readyToRelease,
            ApprovalCount = proposal.Approvals.Count,
            RejectionCount = proposal.Rejections.Count,
            AbstentionCount = proposal.Abstentions.Count,
            Title = proposal.Title,
            Description = proposal.Description
        };
    }
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

**File:** contract/AElf.Contracts.Association/Association.cs (L233-245)
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
