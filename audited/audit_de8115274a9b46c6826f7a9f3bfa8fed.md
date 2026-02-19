### Title
Association Organization DOS Attack via Unbounded Member List Size

### Summary
The Association contract lacks limits on organization member list size, allowing an attacker to create organizations with thousands of members (up to the 128KB state size limit). This causes O(n) and O(m×n) complexity in voting and proposal threshold checking operations, leading to execution observer limit violations or prohibitive resource costs that prevent legitimate governance operations.

### Finding Description

The vulnerability exists in the Association contract's handling of organization member lists. The `OrganizationMemberList` uses a protobuf `repeated` field with a linear search `Contains()` method: [1](#0-0) 

This O(n) operation is invoked in multiple critical paths without size constraints:

**Path 1: Voting Authorization Check** [2](#0-1) 

Called during every vote operation: [3](#0-2) 

**Path 2: Proposal Threshold Validation (O(m×n) complexity)** [4](#0-3) [5](#0-4) 

Each uses `Count(organization.OrganizationMemberList.Contains)` which iterates through all votes (m) and for each vote performs O(n) member lookup.

**Root Cause: Missing Size Limit**

The validation function checks for duplicates and non-empty lists, but imposes NO maximum size constraint: [6](#0-5) 

Organizations can be created by anyone with arbitrary member counts up to the state size limit: [7](#0-6) 

**Size Constraints**

The only limit is the 128KB state size constraint: [8](#0-7) 

With ~35 bytes per address (including protobuf overhead), this allows approximately 3,000-3,700 members per organization.

### Impact Explanation

**Execution Observer Limit Violations**

AElf enforces a 15,000 branch count limit per transaction: [9](#0-8) [10](#0-9) 

With 3,000 members:
- Single `Approve()` call performs 3,000 comparisons in `Contains()` → approaching branch limit
- `IsReleaseThresholdReached()` with just 10 votes performs 30,000 iterations (10 votes × 3,000 members) → exceeds branch limit
- Transaction fails with `RuntimeBranchThresholdExceededException`

**Operational DOS**

Once an attacker creates such an organization:
1. Legitimate members **cannot vote** - transactions exceed branch limits or consume excessive resources
2. **Cannot check proposal readiness** - `IsReleaseThresholdReached()` fails due to O(m×n) complexity
3. **Cannot modify membership** - `AddMember`/`RemoveMember` validation with `AnyDuplicate()` becomes prohibitive
4. **Complete governance paralysis** for that organization

**Affected Parties**
- All legitimate members of the attacked organization lose governance rights
- Proposals cannot be executed even if logically approved
- Organization becomes permanently unusable

### Likelihood Explanation

**Attack Feasibility: HIGH**

1. **Entry Point**: Public `CreateOrganization()` method accessible to any caller [11](#0-10) 

2. **Attack Cost**: One-time transaction to create organization with maximum members. While storing 3,000+ addresses incurs state write fees, this is a single upfront cost that permanently disables the organization.

3. **No Preconditions**: Attacker needs no special permissions or existing state

4. **Execution Simplicity**: Single transaction with large `OrganizationMemberList` in `CreateOrganizationInput`

5. **Detection Difficulty**: No validation prevents this during organization creation. The DOS only manifests when legitimate users attempt to interact with the organization.

**Economic Rationality**

The attacker pays once to create the organization, but all subsequent users pay excessive costs or fail entirely. This is a classic griefing attack with asymmetric cost structure favoring the attacker.

### Recommendation

**1. Add Maximum Member Count Validation**

Modify the `Validate(Organization)` function to enforce a maximum member count: [6](#0-5) 

Add a check:
```csharp
var organizationMemberCount = organization.OrganizationMemberList.Count();
if (organizationMemberCount > AssociationConstants.MaxOrganizationMembers)
    return false;
```

Define in `AssociationConstants.cs`: [12](#0-11) 

Suggested limit: 100-200 members to ensure O(n) operations remain within execution observer limits while supporting realistic governance scenarios.

**2. Consider HashSet Optimization**

For better performance, maintain a parallel HashSet in the partial class for O(1) lookups: [13](#0-12) 

**3. Add Integration Tests**

Create test cases that:
- Attempt to create organizations with excessive members
- Verify voting operations complete within execution limits
- Test threshold checking with maximum allowed members

### Proof of Concept

**Initial State**: Clean blockchain state

**Attack Steps**:

1. **Attacker creates malicious organization**:
   ```
   CreateOrganizationInput {
     OrganizationMemberList: [3000 unique addresses],
     ProposalReleaseThreshold: { MinimalApprovalThreshold: 2, MinimalVoteThreshold: 2, ... },
     ProposerWhiteList: [attacker_address]
   }
   → Organization created successfully (within 128KB limit)
   ```

2. **Attacker creates a proposal** (succeeds - no Contains() check)

3. **Legitimate member attempts to vote**:
   ```
   Approve(proposal_id)
   → Calls AssertIsAuthorizedOrganizationMember()
   → Performs Contains() over 3000 members
   → Transaction fails: RuntimeBranchThresholdExceededException
   OR
   → Transaction succeeds but costs prohibitive resource fees
   ```

4. **Attempt to check proposal status**:
   ```
   GetProposal(proposal_id)
   → Calls IsReleaseThresholdReached()
   → Performs Count(Contains) with O(m×n) complexity
   → With even 5 votes: 15,000 iterations exceeds branch limit
   → Transaction fails or times out
   ```

**Expected Result**: Voting and proposal operations succeed within normal resource limits

**Actual Result**: Complete governance DOS - members cannot vote, proposals cannot be checked or released, organization is permanently unusable

### Citations

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L5-21)
```csharp
public partial class OrganizationMemberList
{
    public int Count()
    {
        return organizationMembers_.Count;
    }

    public bool Empty()
    {
        return Count() == 0;
    }

    public bool Contains(Address address)
    {
        return organizationMembers_.Contains(address);
    }
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L34-45)
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```

**File:** docs-sphinx/architecture/smart-contract/restrictions/others.rst (L10-15)
```text
Execution observer
------------------

- AElf's contract patcher will patch method call count observer for your contract. This is used to prevent infinitely method call like recursion. The number of method called in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.

- AElf's contract patcher will patch method branch count observer for your contract. This is used to prevent infinitely loop case. The number of code control transfer in your contract will be counted during transaction execution. The observer will pause transaction execution if the number exceeds 15,000. The limit adjustment is governed by ``Parliament``.
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
