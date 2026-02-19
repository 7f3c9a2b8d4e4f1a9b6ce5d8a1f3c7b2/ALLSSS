### Title
Integer Overflow in Organization Threshold Validation Allows Bypass of Mathematical Feasibility Check

### Summary
The `Validate` function in `Association_Helper.cs` performs arithmetic addition of two `int64` threshold values without overflow protection, allowing the sum to wrap to negative values. This bypasses the validation check intended to ensure that `MaximalAbstentionThreshold + MinimalApprovalThreshold <= organizationMemberCount`, enabling creation of organizations with mathematically infeasible threshold configurations that violate governance invariants.

### Finding Description [1](#0-0) 

The validation logic adds `MaximalAbstentionThreshold` and `MinimalApprovalThreshold` (both `int64` fields defined in the protobuf schema) without overflow checks. [2](#0-1) 

In C#'s default unchecked arithmetic context, when two `int64` values sum beyond `long.MaxValue` (9,223,372,036,854,775,807), the result wraps to negative values. For example, if `MaximalAbstentionThreshold = long.MaxValue` and `MinimalApprovalThreshold = 1`, the sum becomes `long.MinValue` (-9,223,372,036,854,775,808), causing the comparison with `organizationMemberCount` (an `int` from `Count()`) to incorrectly evaluate as true. [3](#0-2) 

The same overflow vulnerability exists on lines 79-80 for the `MaximalRejectionThreshold + MinimalApprovalThreshold` check. This validation is invoked during organization creation, threshold changes, and member modifications. [4](#0-3) [5](#0-4) 

### Impact Explanation

The validation check ensures that the sum of required approvals and maximum allowed abstentions/rejections does not exceed the total member count, preventing impossible threshold configurations. Test cases confirm this intended behavior. [6](#0-5) 

Bypassing this validation allows creation of organizations where:
1. **Governance invariants are violated**: The critical invariant requiring valid "Organization thresholds" is broken
2. **Threshold mechanisms disabled**: Setting `MaximalAbstentionThreshold` to `long.MaxValue` effectively disables abstention blocking, since actual abstention counts (limited by member count) can never exceed this threshold
3. **Operational DoS potential**: Invalid threshold combinations where the sum genuinely exceeds member count create mathematically impossible release conditions, permanently blocking all proposals in that organization

While the impact is primarily confined to the attacker's own organization, it represents a concrete bypass of security validation logic designed to maintain governance integrity. The severity is Medium because it doesn't directly steal funds or affect other organizations, but it does enable manipulation of governance mechanisms and violation of protocol invariants.

### Likelihood Explanation

The vulnerability is highly exploitable:
- **Entry point**: `CreateOrganization` is publicly accessible without special authorization [7](#0-6) 

- **Attack complexity**: Trivial - simply provide threshold values that sum to overflow
- **Preconditions**: None - any user can create organizations with arbitrary threshold values
- **Detection**: Difficult to detect as the overflow occurs silently in unchecked arithmetic

The attack requires no special privileges, technical sophistication, or economic investment beyond standard transaction fees. An attacker can deliberately create dysfunctional organizations or modify existing ones (via governance proposals) to disable threshold protections.

### Recommendation

**Primary Fix**: Use checked arithmetic to detect overflow:

```csharp
// In Validate(Organization) function, replace lines 77-80 with:
try 
{
    var abstentionSum = checked(proposalReleaseThreshold.MaximalAbstentionThreshold + 
                                proposalReleaseThreshold.MinimalApprovalThreshold);
    var rejectionSum = checked(proposalReleaseThreshold.MaximalRejectionThreshold + 
                               proposalReleaseThreshold.MinimalApprovalThreshold);
    
    return /* ... other checks ... */ &&
           abstentionSum <= organizationMemberCount &&
           rejectionSum <= organizationMemberCount;
}
catch (OverflowException)
{
    return false;
}
```

**Additional Validation**: Add reasonable upper bounds for threshold values (e.g., threshold cannot exceed `int.MaxValue` since member count is limited to `int` range).

**Test Cases**: Add test cases that attempt organization creation with:
- `MaximalAbstentionThreshold = long.MaxValue` and `MinimalApprovalThreshold = 1`
- `MaximalRejectionThreshold = long.MaxValue` and `MinimalApprovalThreshold = 1`
- Expected result: validation failure with "Invalid organization" error

### Proof of Concept

**Step 1**: Create organization with overflow-inducing thresholds:
```
CreateOrganizationInput:
- OrganizationMemberList: [Address1, Address2, Address3] (3 members)
- MinimalApprovalThreshold: 1
- MinimalVoteThreshold: 3
- MaximalAbstentionThreshold: 9223372036854775807 (long.MaxValue)
- MaximalRejectionThreshold: 0
```

**Expected behavior**: Validation should fail because `long.MaxValue + 1 > 3`

**Actual behavior**: 
- Sum calculation: `9223372036854775807 + 1 = -9223372036854775808` (overflows to `long.MinValue`)
- Validation check: `-9223372036854775808 <= 3` evaluates to `true`
- Organization creation succeeds with invalid thresholds

**Success condition**: Organization is created with `MaximalAbstentionThreshold = long.MaxValue`, effectively disabling abstention blocking despite the validation check designed to prevent this configuration.

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L77-78)
```csharp
               proposalReleaseThreshold.MaximalAbstentionThreshold +
               proposalReleaseThreshold.MinimalApprovalThreshold <= organizationMemberCount &&
```

**File:** protobuf/acs3.proto (L128-137)
```text
message ProposalReleaseThreshold {
    // The value for the minimum approval threshold.
    int64 minimal_approval_threshold = 1;
    // The value for the maximal rejection threshold.
    int64 maximal_rejection_threshold = 2;
    // The value for the maximal abstention threshold.
    int64 maximal_abstention_threshold = 3;
    // The value for the minimal vote threshold.
    int64 minimal_vote_threshold = 4;
}
```

**File:** contract/AElf.Contracts.Association/OrganizationMemberList.cs (L7-10)
```csharp
    public int Count()
    {
        return organizationMembers_.Count;
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

**File:** contract/AElf.Contracts.Association/Association.cs (L207-208)
```csharp
        organization.ProposalReleaseThreshold = input;
        Assert(Validate(organization), "Invalid organization.");
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L248-262)
```csharp
        //invalid maximalAbstentionThreshold
        {
            var minimalApproveThreshold = 1;
            var minimalVoteThreshold = 3;
            var maximalAbstentionThreshold = 4;
            var maximalRejectionThreshold = 0;

            var createOrganizationInput = GenerateCreateOrganizationInput(minimalApproveThreshold,
                minimalVoteThreshold,
                maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);
            var transactionResult =
                await AssociationContractStub.CreateOrganization.SendWithExceptionAsync(createOrganizationInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            transactionResult.TransactionResult.Error.Contains("Invalid organization.").ShouldBeTrue();
        }
```
