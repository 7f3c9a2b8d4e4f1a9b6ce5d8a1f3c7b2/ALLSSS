### Title
Null/Zero-Address Members Bypass Validation Enabling Governance DoS

### Summary
The `Validate(Organization)` function fails to validate that individual addresses in `OrganizationMemberList` are non-null and non-empty, only checking for duplicates via `AnyDuplicate()`. This allows creation of organizations with null or zero-address members that inflate the member count, enabling attackers to set threshold constraints that appear valid but are impossible to satisfy, permanently disabling the organization's governance functionality.

### Finding Description

The vulnerability exists in the `Validate(Organization)` method in `Association_Helper.cs`. [1](#0-0) 

At lines 65-66, the validation checks if `OrganizationMemberList` is empty or contains duplicates, but does NOT validate that individual addresses are non-null and non-empty. [2](#0-1) 

The `AnyDuplicate()` implementation uses `GroupBy(m => m).Any(g => g.Count() > 1)`, which only detects when multiple identical addresses exist. [3](#0-2) 

A single null or zero-address passes this check since there are no duplicates. The Address equality operator handles null comparisons, allowing null addresses to be grouped but not detected as invalid. [4](#0-3) 

This affects multiple entry points:
- `CreateOrganization` accepts input without validating individual member addresses [5](#0-4) 
- `AddMember` adds addresses without validation beyond the duplicate check [6](#0-5) 
- `ChangeMember` can replace valid members with invalid ones [7](#0-6) 

The member count used for threshold validation includes these invalid addresses. [8](#0-7) 

### Impact Explanation

**Permanent Governance DoS**: An attacker can create an organization with invalid members that makes it impossible to pass any proposal, permanently disabling governance functionality.

**Concrete Attack Scenario**:
- Attacker creates organization with 2 real members + 3 null/zero-address members (total count = 5)
- Sets `MinimalApprovalThreshold = 3` (requires 3 approvals to pass)
- Validation passes: 3 ≤ 5 ✓
- Reality: Only 2 real members can vote (null/zero-addresses cannot be transaction senders)
- Result: Impossible to obtain 3 approvals, no proposal can ever pass

**Who is Affected**:
- Organizations created with these invalid parameters become permanently non-functional
- All governance actions (proposal approval, configuration changes, fund releases) are blocked
- Any assets or permissions controlled by the organization become permanently frozen

**Severity Justification**: HIGH - This completely breaks the core governance functionality of Association contracts, with no recovery mechanism once an organization is created with these parameters.

### Likelihood Explanation

**Attacker Capabilities**: Any user can call `CreateOrganization` or (for existing organizations) the organization itself can call `AddMember` through a proposal.

**Attack Complexity**: Trivial - simply include `new Address()` or null in the member list when creating an organization.

**Feasibility Conditions**:
- No special permissions required for `CreateOrganization` [9](#0-8) 
- Input validation only checks `Empty()` and `AnyDuplicate()`, not address validity
- No existing tests verify null/zero-address rejection

**Detection Constraints**: The contract provides no way to detect or recover from this state once created. The organization appears valid but cannot function.

**Probability**: HIGH - The vulnerability is easily exploitable through normal contract interfaces with no barriers to exploitation.

### Recommendation

**Immediate Fix**: Add address validation to reject null and zero-addresses in member lists.

In `Association_Helper.cs`, add a validation method:
```csharp
private bool ContainsInvalidAddress(OrganizationMemberList memberList)
{
    return memberList.OrganizationMembers.Any(m => m == null || m.Value.IsNullOrEmpty());
}
```

Update the `Validate(Organization)` function to check for invalid addresses:
```csharp
if (organization.OrganizationMemberList.Empty() ||
    organization.OrganizationMemberList.AnyDuplicate() ||
    ContainsInvalidAddress(organization.OrganizationMemberList))
    return false;
```

Apply the same validation pattern used in the MultiToken contract. [10](#0-9) 

**Additional Validations**:
- Apply the same check to `ProposerWhiteList` validation
- Add explicit input validation in `AddMember`, `ChangeMember` before modifying the list
- Add regression tests verifying null/zero-addresses are rejected

**Test Cases**:
1. CreateOrganization with null member → should fail with "Invalid organization"
2. CreateOrganization with zero-address member → should fail  
3. AddMember with null address → should fail
4. ChangeMember replacing valid with null → should fail

### Proof of Concept

**Initial State**: None required - any user can execute

**Attack Steps**:

1. Prepare organization input with invalid members:
```csharp
var input = new CreateOrganizationInput
{
    OrganizationMemberList = new OrganizationMemberList
    {
        OrganizationMembers = { 
            RealMember1Address,
            RealMember2Address, 
            new Address(),  // zero-address
            null,           // null address (if protobuf allows)
            new Address()   // another zero-address
        }
    },
    ProposalReleaseThreshold = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 3,  // Impossible to reach with only 2 real members
        MinimalVoteThreshold = 3,
        MaximalRejectionThreshold = 1,
        MaximalAbstentionThreshold = 1
    },
    ProposerWhiteList = new ProposerWhiteList
    {
        Proposers = { RealMember1Address }
    }
};
```

2. Call `CreateOrganization(input)`

**Expected Result**: Transaction should fail with "Invalid organization" due to null/zero-address members

**Actual Result**: 
- Transaction succeeds
- Organization created with member count = 5
- Thresholds validate successfully (3 ≤ 5)
- No proposal can ever be approved (only 2 real members, need 3 approvals)
- Organization governance permanently disabled

**Success Condition**: The organization is created despite containing invalid members, and subsequent attempts to pass proposals fail due to insufficient voting members to meet the threshold.

### Citations

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

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L24-27)
```csharp
    public static bool AnyDuplicate(this OrganizationMemberList organizationMemberList)
    {
        return organizationMemberList.OrganizationMembers.GroupBy(m => m).Any(g => g.Count() > 1);
    }
```

**File:** src/AElf.Types/Types/Address.cs (L96-98)
```csharp
        public static bool operator ==(Address address1, Address address2)
        {
            return address1?.Equals(address2) ?? ReferenceEquals(address2, null);
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

**File:** contract/AElf.Contracts.Association/Association.cs (L233-238)
```csharp
    public override Empty AddMember(Address input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input);
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.Association/Association.cs (L248-255)
```csharp
    public override Empty ChangeMember(ChangeMemberInput input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        var removeResult = organization.OrganizationMemberList.OrganizationMembers.Remove(input.OldMember);
        Assert(removeResult, "Remove member failed.");
        organization.OrganizationMemberList.OrganizationMembers.Add(input.NewMember);
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```
