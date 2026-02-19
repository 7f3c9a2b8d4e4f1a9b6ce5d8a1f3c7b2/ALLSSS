# Audit Report

## Title
Referendum Organizations Can Be Permanently Bricked With Invalid Proposer Addresses

## Summary
The Referendum contract's organization validation fails to verify that addresses in the ProposerWhiteList contain valid (non-empty) ByteString values. An attacker can create organizations with whitelists containing only addresses with empty ByteString values, which pass validation but are permanently unusable since no valid proposer can create proposals and the whitelist cannot be modified without executing a proposal.

## Finding Description

The vulnerability exists in the organization validation logic during creation. When `CreateOrganization` is called, it validates the organization using the `Validate()` method [1](#0-0) , which checks whether the ProposerWhiteList is empty but never validates individual address validity [2](#0-1) .

The `Empty()` extension method only checks if the count is zero [3](#0-2) . This allows an attacker to add Address objects with `Value = ByteString.Empty` (protobuf3 default) to satisfy the non-empty requirement.

The ProposerWhiteList is defined as a repeated Address field with no inherent validation [4](#0-3) , and Address itself is just a bytes wrapper [5](#0-4) .

When users attempt to create proposals, authorization is enforced via `AssertIsAuthorizedProposer` [6](#0-5) , which checks if the proposer exists in the whitelist using `Contains()` [7](#0-6) . This check uses protobuf equality comparison [8](#0-7) , where addresses with valid ByteString values will never equal addresses with empty ByteString values.

The recovery mechanism is blocked because `ChangeOrganizationProposerWhiteList` requires `Context.Sender` to be the organization address itself [9](#0-8) , which can only occur through virtual inline calls during proposal execution. Since no proposals can be created, the whitelist cannot be updated, permanently bricking the organization.

Notably, other contracts in the codebase implement proper address validation. The MultiToken contract validates addresses with `AssertValidInputAddress` that checks for null and empty values [10](#0-9) , but the Referendum contract lacks this validation for whitelist addresses.

## Impact Explanation

**Operational Impact - Permanent DoS:**
- Any user can create permanently unusable Referendum organizations at minimal gas cost
- Organization addresses are deterministic based on input parameters [11](#0-10) , allowing attackers to pre-occupy addresses that legitimate users intend to create
- Once created, organizations cannot be deleted or recovered [12](#0-11) 
- State bloat from accumulation of unusable organizations

**Governance Impact:**
- Complete DoS of Referendum governance functionality for affected organizations
- No admin override or recovery mechanism exists
- Violates the fundamental governance invariant that organizations with non-empty whitelists must allow authorized proposers to create proposals

The severity is **HIGH** because it enables permanent, unrecoverable DoS of critical governance infrastructure with minimal attack cost and no privileged access required.

## Likelihood Explanation

**Entry Point:** The `CreateOrganization` method is publicly accessible [13](#0-12) .

**Attack Feasibility:**
- In protobuf3 C#, creating an Address with empty ByteString is trivial: `new Address()` defaults to `Value = ByteString.Empty`
- The attacker constructs a `CreateOrganizationInput` with valid parameters except the ProposerWhiteList contains only invalid addresses
- Single transaction execution with standard gas cost
- No special permissions required

**Economic Rationality:**
- Attack cost: Only transaction gas fees (same as normal organization creation)
- Impact: Permanent bricking of organization functionality
- High impact-to-cost ratio makes this economically viable for griefing attacks

The likelihood is **HIGH** due to public accessibility, trivial execution, and minimal cost.

## Recommendation

Add validation to ensure all addresses in the ProposerWhiteList contain valid (non-empty) ByteString values. Implement similar validation to what exists in the MultiToken contract:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    
    // Add validation for individual addresses in whitelist
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

## Proof of Concept

```csharp
[Fact]
public async Task CreateBrickedOrganization_WithInvalidProposerAddresses_Test()
{
    // Create organization with invalid address (empty ByteString) in whitelist
    var invalidAddress = new Address(); // Value defaults to ByteString.Empty in protobuf3
    
    var createOrganizationInput = new CreateOrganizationInput
    {
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 5000,
            MinimalVoteThreshold = 5000,
            MaximalAbstentionThreshold = 10000,
            MaximalRejectionThreshold = 10000
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { invalidAddress } // Contains only invalid address
        },
        TokenSymbol = "ELF"
    };
    
    // Organization creation succeeds because validation only checks count > 0
    var result = await ReferendumContractStub.CreateOrganization.SendAsync(createOrganizationInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var organizationAddress = result.Output;
    
    // Verify organization exists
    var organization = await ReferendumContractStub.GetOrganization.CallAsync(organizationAddress);
    organization.OrganizationAddress.ShouldBe(organizationAddress);
    organization.ProposerWhiteList.Proposers.Count.ShouldBe(1);
    
    // Try to create proposal with valid user address - this will FAIL
    var validProposer = DefaultSender;
    var proposalInput = new CreateProposalInput
    {
        OrganizationAddress = organizationAddress,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContract.Create),
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(1),
        Params = new CreateInput
        {
            Symbol = "TEST",
            TokenName = "Test Token",
            TotalSupply = 1000000,
            Decimals = 8,
            Issuer = organizationAddress,
            IsBurnable = true
        }.ToByteString(),
        Title = "Test Proposal",
        Description = "Test Description"
    };
    
    // Proposal creation fails because valid address doesn't match invalid address in whitelist
    var proposalResult = await ReferendumContractStub.CreateProposal.SendWithExceptionAsync(proposalInput);
    proposalResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    proposalResult.TransactionResult.Error.ShouldContain("Unauthorized to propose");
    
    // Try to change whitelist - this will also FAIL
    var newWhitelist = new ProposerWhiteList
    {
        Proposers = { validProposer }
    };
    
    var changeResult = await ReferendumContractStub.ChangeOrganizationProposerWhiteList.SendWithExceptionAsync(newWhitelist);
    changeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    changeResult.TransactionResult.Error.ShouldContain("Organization not found");
    
    // Organization is permanently bricked - no recovery possible
}
```

## Notes

This vulnerability affects only the Referendum contract. Similar validation gaps should be checked in the Association and Parliament contracts. The fix should be applied consistently across all governance contracts that use ProposerWhiteList validation.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L12-12)
```csharp
    public override Address CreateOrganization(CreateOrganizationInput input)
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L17-18)
```csharp
        if (State.Organizations[organizationAddress] != null)
            return organizationAddress;
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L28-28)
```csharp
        Assert(Validate(organization), "Invalid organization data.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L55-55)
```csharp
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L141-141)
```csharp
        var organization = State.Organizations[Context.Sender];
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L92-94)
```csharp
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
            return false;
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L204-204)
```csharp
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L207-218)
```csharp
    private OrganizationHashAddressPair CalculateOrganizationHashAddressPair(
        CreateOrganizationInput createOrganizationInput)
    {
        var organizationHash = HashHelper.ComputeFrom(createOrganizationInput);
        var organizationAddress = Context.ConvertVirtualAddressToContractAddressWithContractHashName(
            CalculateVirtualHash(organizationHash, createOrganizationInput.CreationToken));

        return new OrganizationHashAddressPair
        {
            OrganizationAddress = organizationAddress,
            OrganizationHash = organizationHash
        };
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

**File:** protobuf/acs3.proto (L139-142)
```text
message ProposerWhiteList{
    // The address of the proposers
    repeated aelf.Address proposers = 1;
}
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```
