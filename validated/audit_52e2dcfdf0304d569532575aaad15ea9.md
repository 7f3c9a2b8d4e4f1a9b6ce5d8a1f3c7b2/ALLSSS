# Audit Report

## Title
Proposer Whitelist Validation Bypass Allows Organization DoS via Empty Addresses

## Summary
The Referendum contract's whitelist validation only checks the count of addresses without validating their content. This allows an attacker to set a proposer whitelist containing empty addresses (instantiated via `new Address()`), which passes validation but permanently breaks proposal authorization, causing irreversible denial-of-service of the organization's governance capabilities.

## Finding Description

The vulnerability exists in the proposer whitelist validation mechanism. The `Empty()` extension method only verifies count without checking if addresses have valid `Value` fields. [1](#0-0) 

The `Validate()` function relies on this flawed check when validating organization state: [2](#0-1) 

When `ChangeOrganizationProposerWhiteList` is called through a governance proposal, it updates the whitelist and validates using `Validate(organization)`, but validation only ensures count > 0, not content validity: [3](#0-2) 

Unlike other contracts that properly validate addresses by checking both null and empty `Value` fields, the Referendum whitelist validation lacks this critical check: [4](#0-3) [5](#0-4) 

**Attack Execution Path:**

1. Authorized proposer creates proposal calling `ChangeOrganizationProposerWhiteList` with `ProposerWhiteList { Proposers = { new Address() } }`
2. Proposal gets approved through token-weighted voting
3. Proposer releases the proposal, executing the whitelist change
4. Validation passes because count > 0
5. Organization state is updated with the invalid whitelist
6. All subsequent `CreateProposal` calls fail at authorization check: [6](#0-5) 

The `Contains()` method uses protobuf Address equality, comparing `Value` fields. An empty Address (with `Value = ByteString.Empty`) never equals any valid address: [7](#0-6) 

The Address protobuf definition confirms addresses can be instantiated empty via parameterless constructor: [8](#0-7) 

Production code demonstrates empty Address usage, confirming this is possible: [9](#0-8) 

## Impact Explanation

**HIGH Severity** - This causes permanent, irreversible denial-of-service of critical governance functionality:

- **Operational Impact**: The organization becomes completely unable to create new proposals. All `CreateProposal` calls fail with "Unauthorized to propose" because no valid address matches empty addresses in the whitelist.

- **Governance Impact**: The organization is effectively bricked. It cannot execute any governance actions requiring new proposals, including attempts to fix the whitelist itself. Core governance capability is permanently lost.

- **Affected Parties**: All members of the affected Referendum organization lose their governance rights and cannot participate in decision-making.

Test suite evidence shows empty whitelists (count=0) should be rejected, confirming invalid whitelists are unintended: [10](#0-9) 

The prevalence of proper address validation patterns elsewhere confirms this is an unintended security gap.

## Likelihood Explanation

**MEDIUM Likelihood** - The attack is feasible but requires specific conditions:

**Attacker Capabilities Required:**
- Must be an authorized proposer in the target Referendum organization
- Must convince token holders to approve the malicious proposal through token-weighted voting

**Attack Complexity:**
- LOW technical complexity: Simply create a proposal with `new Address()` in the whitelist
- Protobuf supports default instantiation of empty Address objects
- The attack could be disguised or result from compromised proposer account

**Feasibility Assessment:**
- Realistic in governance attack scenarios with insider access
- Requires governance participation (token-weighted voting), but achievable
- Once executed, damage is permanent and irreversible

This represents a credible threat in scenarios involving malicious insiders with proposer privileges, compromised proposer accounts, or social engineering to get voters to approve seemingly legitimate proposals.

## Recommendation

Add address content validation to the `Empty()` method or in the `Validate()` function. Check that each address in the whitelist has a non-empty `Value` field:

```csharp
// In ProposerWhiteListExtensions.cs
public static bool Empty(this ProposerWhiteList proposerWhiteList)
{
    return proposerWhiteList.Count() == 0 || 
           proposerWhiteList.Proposers.Any(p => p == null || p.Value.IsNullOrEmpty());
}
```

Or in `Referendum_Helper.cs`:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || 
        organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || 
        organization.ProposerWhiteList.Empty() ||
        organization.ProposerWhiteList.Proposers.Any(p => p == null || p.Value.IsNullOrEmpty()))
        return false;
    // ... rest of validation
}
```

## Proof of Concept

```csharp
[Fact]
public async Task ProposerWhitelist_EmptyAddress_Causes_DoS()
{
    // Create organization with valid whitelist
    var organizationAddress = await CreateOrganizationAsync(5000, 5000, 10000, 10000, 
        new[] { DefaultSender });
    
    // Create proposal to change whitelist to empty Address
    var emptyAddressWhitelist = new ProposerWhiteList
    {
        Proposers = { new Address() } // Empty address with no Value
    };
    
    var proposalId = await CreateReferendumProposalAsync(DefaultSenderKeyPair, 
        emptyAddressWhitelist,
        nameof(ReferendumContractStub.ChangeOrganizationProposerWhiteList), 
        organizationAddress,
        ReferendumContractAddress);
    
    // Approve and release the proposal
    await ApproveAllowanceAsync(Accounts[3].KeyPair, 5000, proposalId);
    await ApproveAsync(Accounts[3].KeyPair, proposalId);
    var releaseResult = await ReferendumContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify whitelist was updated (validation passed despite empty address)
    var org = await ReferendumContractStub.GetOrganization.CallAsync(organizationAddress);
    org.ProposerWhiteList.Proposers.Count.ShouldBe(1);
    
    // Try to create new proposal - should fail permanently
    var createInput = new CreateProposalInput
    {
        ContractMethodName = "Test",
        ToAddress = ReferendumContractAddress,
        Params = ByteString.Empty,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        OrganizationAddress = organizationAddress
    };
    
    var result = await ReferendumContractStub.CreateProposal.SendWithExceptionAsync(createInput);
    result.TransactionResult.Error.ShouldContain("Unauthorized to propose");
    
    // Organization is now permanently unable to create proposals
}
```

### Citations

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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L90-94)
```csharp
    private bool Validate(Organization organization)
    {
        if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
            organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
            return false;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L397-399)
```csharp
        Assert(contractOperation.Deployer != null && !contractOperation.Deployer.Value.IsNullOrEmpty(),
            "Invalid input deploying address.");
        Assert(contractOperation.Salt != null && !contractOperation.Salt.Value.IsNullOrEmpty(), "Invalid input salt.");
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```

**File:** test/AElf.Contracts.TestContract.MockParliament/Contract.cs (L8-11)
```csharp
    public override Address GetDefaultOrganizationAddress(Empty input)
    {
        return State.DefaultOrganizationAddress.Value ?? new Address();
    }
```

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L1140-1143)
```csharp
            validInput.ProposerWhiteList.Proposers.Clear();
            var ret = await ReferendumContractStub.CreateOrganization.SendWithExceptionAsync(validInput);
            ret.TransactionResult.Error.ShouldContain("Invalid organization data");
        }
```
