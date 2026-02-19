### Title
ProposerWhiteList Validation Bypass Allows Creation of Permanently Bricked Referendum Organizations

### Summary
The Referendum contract's `Validate()` method only checks if the ProposerWhiteList contains at least one entry but fails to validate that individual addresses have valid (non-empty) value fields. An attacker can create a Referendum organization with addresses containing empty ByteString values, which passes validation but permanently prevents any legitimate user from creating proposals, resulting in a denial-of-service of the governance functionality for that organization.

### Finding Description

The vulnerability exists in the organization validation logic at [1](#0-0) 

The root cause is that the `Empty()` extension method only validates count: [2](#0-1) 

The Address protobuf message is defined as: [3](#0-2) 

In protobuf3, the `bytes value` field can be empty. While C# Address constructors enforce 32-byte length [4](#0-3) , protobuf deserialization bypasses these constructors, allowing Address messages with empty value fields.

The codebase has a proper validation pattern in the TokenContract: [5](#0-4) 

This uses the `IsNullOrEmpty()` extension: [6](#0-5) 

However, the Referendum contract does not apply this validation to ProposerWhiteList addresses.

**Execution Path:**
1. Attacker calls `CreateOrganization()` with ProposerWhiteList containing addresses with empty value fields [7](#0-6) 
2. Organization passes validation and is created
3. When any user attempts `CreateProposal()`, it calls `AssertIsAuthorizedProposer()` [8](#0-7) 
4. Authorization check fails because valid addresses never match empty addresses [9](#0-8) 
5. The `Contains()` method compares ByteString values which will never match [10](#0-9) 

### Impact Explanation

**Operational Impact - DoS of Governance:**
- Any Referendum organization created with invalid addresses is permanently bricked
- No legitimate user can ever create proposals for that organization
- The governance mechanism for that organization is completely non-functional
- While users lose only gas fees, the governance functionality is critical for protocol operations

**Scope:**
- Affects all Referendum organizations created with this attack
- Each bricked organization represents a permanent loss of governance capability
- Could be used to grief users who rely on Referendum-based governance

**Severity Justification:**
The impact is a complete denial-of-service of governance functionality for affected organizations, violating the critical invariant that "Organization thresholds, proposer whitelist checks" must function correctly.

### Likelihood Explanation

**Attacker Capabilities:**
- Any user can call `CreateOrganization()` - it's a public entry point
- Attacker needs to craft protobuf messages with Address objects containing empty value fields
- No special permissions or trusted role required

**Attack Complexity:**
- Medium complexity - requires understanding of protobuf message structure
- Attacker must manually construct CreateOrganizationInput with malformed addresses
- Transaction-level validation only checks if Address objects are null, not if their value fields are empty [11](#0-10) 

**Economic Rationality:**
- Attack cost is minimal (only transaction gas fees)
- No economic benefit to attacker, but enables griefing attacks
- Could be used to disrupt specific governance operations

**Detection:**
- Bricked organizations would be discovered when first proposal creation fails
- No proactive detection mechanism exists

### Recommendation

Add address value validation in the `Validate()` method for Referendum organizations:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    
    // Add validation for each address in whitelist
    foreach (var proposer in organization.ProposerWhiteList.Proposers)
    {
        if (proposer == null || proposer.Value.IsNullOrEmpty())
            return false;
    }
    
    Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
}
```

Apply the same validation in `ChangeOrganizationProposerWhiteList()` at [12](#0-11) 

Add regression test cases:
1. Test creating organization with Address objects having empty value fields (should fail)
2. Test changing whitelist to contain invalid addresses (should fail)
3. Test existing valid organizations continue to function

### Proof of Concept

**Initial State:**
- Attacker has a funded account for gas fees
- No special permissions required

**Attack Steps:**

1. Construct CreateOrganizationInput with invalid addresses:
```
CreateOrganizationInput input = new CreateOrganizationInput
{
    TokenSymbol = "ELF",
    ProposalReleaseThreshold = new ProposalReleaseThreshold
    {
        MinimalApprovalThreshold = 1000,
        MinimalVoteThreshold = 1000,
        MaximalAbstentionThreshold = 0,
        MaximalRejectionThreshold = 0
    },
    ProposerWhiteList = new ProposerWhiteList
    {
        Proposers = { new Address { Value = ByteString.Empty } }
    }
}
```

2. Call `CreateOrganization(input)` - succeeds and returns organization address

3. Legitimate user attempts to create proposal:
```
CreateProposalInput proposalInput = new CreateProposalInput
{
    OrganizationAddress = organizationAddress,
    ContractMethodName = "SomeMethod",
    ToAddress = someAddress,
    Params = someParams,
    ExpiredTime = futureTime
}
```

4. Call `CreateProposal(proposalInput)` - fails with "Unauthorized to propose."

**Expected vs Actual Result:**
- Expected: CreateOrganization should fail validation when addresses have empty value fields
- Actual: Organization is created successfully but is permanently unusable for proposals

**Success Condition:**
Organization exists in state storage but `CreateProposal()` always fails for any legitimate proposer address, confirming the DoS condition.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L90-102)
```csharp
    private bool Validate(Organization organization)
    {
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
            return false;
        Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");

        var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
        return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
               proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
               proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
               proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L13-16)
```csharp
    public static bool Empty(this ProposerWhiteList proposerWhiteList)
    {
        return proposerWhiteList.Count() == 0;
    }
```

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L18-21)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
    }
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```

**File:** src/AElf.Types/Types/Address.cs (L12-18)
```csharp
        private Address(byte[] bytes)
        {
            if (bytes.Length != AElfConstants.AddressHashLength)
                throw new ArgumentException("Invalid bytes.", nameof(bytes));

            Value = ByteString.CopyFrom(bytes);
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** src/AElf.Types/Extensions/ByteStringExtensions.cs (L34-37)
```csharp
        public static bool IsNullOrEmpty(this ByteString byteString)
        {
            return byteString == null || byteString.IsEmpty;
        }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L12-40)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        var organizationHash = organizationHashAddressPair.OrganizationHash;
        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;
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

        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;

        State.Organizations[organizationAddress] = organization;
        Context.Fire(new OrganizationCreated
        {
            OrganizationAddress = organizationAddress
        });

        return organizationAddress;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-59)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L139-152)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var organization = State.Organizations[Context.Sender];
        Assert(organization != null, "Organization not found.");
        organization.ProposerWhiteList = input;
        Assert(Validate(organization), "Invalid organization.");
        State.Organizations[Context.Sender] = organization;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
    }
```

**File:** src/AElf.Types/Types/Transaction.cs (L19-31)
```csharp
        public bool VerifyFields()
        {
            if (To == null || From == null)
                return false;

            if (RefBlockNumber < 0)
                return false;

            if (string.IsNullOrEmpty(MethodName))
                return false;

            return true;
        }
```
