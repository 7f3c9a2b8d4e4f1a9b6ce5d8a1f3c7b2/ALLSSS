### Title
Null Reference Exception in ProposerWhiteList Validation Causes DoS in Referendum Organization Management

### Summary
The `Empty()` extension method in `ProposerWhiteListExtensions.cs` fails to check if `proposerWhiteList` is null before accessing its properties. When users send `CreateOrganizationInput` or `ProposerWhiteList` protobuf messages without setting the `ProposerWhiteList` field, the field deserializes as null, causing a NullReferenceException crash in the `Validate()` method and blocking organization creation and whitelist updates.

### Finding Description
The vulnerability exists in the extension method chain used for ProposerWhiteList validation: [1](#0-0) 

The `Empty()` method calls `Count()` without null checking: [2](#0-1) 

When `proposerWhiteList` is null, line 10 throws a NullReferenceException attempting to access `proposerWhiteList.Proposers.Count`.

This vulnerable code path is invoked in two critical locations:

1. **CreateOrganization**: The method assigns `input.ProposerWhiteList` directly to the organization without null validation: [3](#0-2) 

2. **ChangeOrganizationProposerWhiteList**: The method assigns the input directly without null validation: [4](#0-3) 

Both methods call `Validate()` which checks `organization.ProposerWhiteList.Empty()`: [5](#0-4) 

In Protocol Buffers v3 with C# (Google.Protobuf), message fields are nullable reference types. When a protobuf message is deserialized without a specific field set, that field remains null rather than defaulting to an empty instance. This is confirmed by the codebase's extensive use of null checks for protobuf messages: [6](#0-5) 

### Impact Explanation
**Operational Impact - High Severity DoS**:
- **CreateOrganization DoS**: Any user can prevent organization creation in the Referendum contract by sending a `CreateOrganizationInput` protobuf message with the `ProposerWhiteList` field unset (null). This blocks all new referendum organizations from being created.
- **ChangeOrganizationProposerWhiteList DoS**: Organization administrators cannot update proposer whitelists if they accidentally send a null `ProposerWhiteList`, permanently blocking legitimate whitelist management.
- **Governance Disruption**: Since organizations are the foundation of the AElf governance system, preventing organization creation disrupts the entire referendum governance mechanism.

The same vulnerability pattern exists in the Association contract: [7](#0-6) [8](#0-7) 

This amplifies the impact across multiple governance contracts.

### Likelihood Explanation
**Likelihood: High**

- **Reachable Entry Point**: `CreateOrganization` and `ChangeOrganizationProposerWhiteList` are public methods callable by any user.
- **Zero Prerequisites**: No special permissions, tokens, or state setup required. Any account can trigger this vulnerability.
- **Trivial Execution**: Attacker simply needs to construct a protobuf message without setting the `ProposerWhiteList` field and send it in a transaction. Standard protobuf serialization libraries support creating messages with unset fields.
- **No Cost Barrier**: Only requires minimal gas fees for a failed transaction. Attacker can repeatedly exploit this with negligible cost.
- **Detection**: While failed transactions are visible on-chain, there's no way to distinguish malicious null inputs from accidental ones, making it impossible to block or rate-limit.

### Recommendation
Add explicit null checks before calling extension methods on `ProposerWhiteList`:

**In ProposerWhiteListExtensions.cs**, modify the `Empty()` method:
```csharp
public static bool Empty(this ProposerWhiteList proposerWhiteList)
{
    return proposerWhiteList == null || proposerWhiteList.Count() == 0;
}
```

**Alternatively, add validation at entry points** in `Referendum_Helper.cs`:
```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || 
        organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || 
        organization.ProposerWhiteList == null ||  // Add null check
        organization.ProposerWhiteList.Empty())
        return false;
    // ... rest of validation
}
```

**Apply the same fix to Association contract**: [9](#0-8) 

**Add regression tests** verifying that null `ProposerWhiteList` inputs are properly rejected with clear error messages instead of throwing exceptions.

### Proof of Concept
**Initial State**: Referendum contract deployed and initialized.

**Attack Steps**:
1. Attacker constructs a `CreateOrganizationInput` protobuf message:
   ```csharp
   var maliciousInput = new CreateOrganizationInput
   {
       TokenSymbol = "ELF",
       ProposalReleaseThreshold = new ProposalReleaseThreshold
       {
           MinimalApprovalThreshold = 1000,
           MinimalVoteThreshold = 1000,
           MaximalAbstentionThreshold = 5000,
           MaximalRejectionThreshold = 5000
       }
       // ProposerWhiteList intentionally NOT set (remains null)
   };
   ```

2. Attacker calls `ReferendumContract.CreateOrganization(maliciousInput)`

3. **Expected Result**: Method should return error message "Invalid organization data."

4. **Actual Result**: Transaction fails with unhandled `NullReferenceException` when `Validate()` attempts to call `organization.ProposerWhiteList.Empty()`, which calls `proposerWhiteList.Count()`, which accesses `null.Proposers.Count`.

5. **Success Condition**: Transaction status is `Failed` with exception trace showing NullReferenceException in `ProposerWhiteListExtensions.Count()`, confirming the DoS vulnerability.

The same attack works for `ChangeOrganizationProposerWhiteList` by passing a null `ProposerWhiteList` input.

### Citations

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L8-11)
```csharp
    public static int Count(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Proposers.Count;
    }
```

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L13-16)
```csharp
    public static bool Empty(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Count() == 0;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L19-28)
```csharp
        var organization = new Organization
        {
            ProposalReleaseThreshold = input.ProposalReleaseThreshold,
            OrganizationAddress = organizationAddress,
            TokenSymbol = input.TokenSymbol,
            OrganizationHash = organizationHash,
            ProposerWhiteList = input.ProposerWhiteList,
            CreationToken = input.CreationToken
        };
        Assert(Validate(organization), "Invalid organization data.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L139-144)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposerWhiteList = input;
        Assert(Validate(organization), "Invalid organization.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L90-93)
```csharp
    private bool Validate(Organization organization)
    {
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
```

**File:** test/AElf.Contracts.TestContract.BasicSecurity/BasicContract_View.cs (L130-134)
```csharp
    public override ProtobufMessage QueryMappedState(ProtobufInput input)
    {
        var message = State.MappedState[input.ProtobufValue.Int64Value];
        return message ?? new ProtobufMessage();
    }
```

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L9-16)
```csharp
    public static int Count(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Proposers.Count;
    }

    public static bool Empty(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Count() == 0;
```

**File:** contract/AElf.Contracts.Association/Association.cs (L74-83)
```csharp
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
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L61-67)
```csharp
    private bool Validate(Organization organization)
    {
        if (organization.ProposerWhiteList.Empty() ||
            organization.ProposerWhiteList.AnyDuplicate() ||
            organization.OrganizationMemberList.Empty() ||
            organization.OrganizationMemberList.AnyDuplicate())
            return false;
```
