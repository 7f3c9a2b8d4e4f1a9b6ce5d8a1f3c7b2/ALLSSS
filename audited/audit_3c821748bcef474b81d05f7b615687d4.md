### Title
Proposer Whitelist Validation Bypass Allows Organization DoS via Empty Addresses

### Summary
The `Empty()` function in `ProposerWhiteListExtensions.cs` only validates the count of addresses in the whitelist, not whether those addresses contain valid data. This allows an attacker to set a proposer whitelist containing only empty addresses (e.g., `new Address()` with no byte value), which passes the `Validate()` invariant check but permanently breaks proposal authorization, resulting in a denial-of-service condition where no new proposals can be created for the organization.

### Finding Description

**Root Cause:**
The `Empty()` extension method only checks if the proposer count is zero [1](#0-0) , without validating whether the addresses themselves contain valid byte values.

The `Validate()` function in the Referendum contract checks if the whitelist is empty using this `Empty()` method [2](#0-1) , but does not verify that addresses in the list have non-empty `Value` fields.

**Why Protections Fail:**
When `ChangeOrganizationProposerWhiteList` is called, it updates the organization's whitelist and validates using `Validate(organization)` [3](#0-2) . However, this validation only ensures the list is not empty by count, not by content validity.

Unlike other contracts in the codebase that properly validate addresses using the pattern `Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.")` [4](#0-3) , the Referendum whitelist validation does not check address validity.

**Execution Path:**
1. Attacker creates proposal calling `ChangeOrganizationProposerWhiteList` with `ProposerWhiteList { Proposers = { new Address() } }`
2. Proposal gets approved and released
3. Whitelist update passes validation (count > 0, so `Empty()` returns false)
4. State is updated with invalid whitelist
5. Subsequent `CreateProposal` calls fail at `AssertIsAuthorizedProposer` [5](#0-4)  because no valid address can match the empty addresses in the whitelist via `Contains()` [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
- **Operational Impact**: Organization becomes permanently unable to create new proposals, as all `CreateProposal` calls will fail authorization checks
- **Governance Impact**: Organization is effectively bricked - cannot execute any governance actions that require new proposals, including attempts to fix the whitelist itself
- **Who Is Affected**: All members of the affected Referendum organization lose governance capabilities

**Severity Justification:**
HIGH severity due to permanent and irreversible DoS of critical governance functionality. The test suite confirms that empty whitelists should be rejected [7](#0-6) , and other contracts properly reject empty addresses [8](#0-7) , indicating this is an unintended security gap.

### Likelihood Explanation

**Attacker Capabilities:**
- Attacker must be an authorized proposer in the target organization
- Attacker must convince voters to approve the malicious proposal (in Referendum, this requires token-weighted voting approval)

**Attack Complexity:**
- LOW complexity: Create single proposal with empty address in whitelist
- Addresses in protobuf are classes (reference types) that can be instantiated empty [9](#0-8) 
- Protobuf serialization allows empty messages to be transmitted

**Feasibility:**
- MEDIUM feasibility: Requires insider access (authorized proposer) but realistic in governance attack scenarios
- Attack could be disguised within a complex proposal or executed by compromised proposer
- Once executed, damage is permanent and cannot be undone through normal governance channels

**Probability:**
MEDIUM - Requires governance participation but achievable by malicious or compromised insiders

### Recommendation

**Code-Level Mitigation:**
1. Enhance the `Empty()` function to validate address contents:
```csharp
public static bool Empty(this ProposerWhiteList proposerWhiteList)
{
    return proposerWhiteList.Count() == 0 || 
           proposerWhiteList.Proposers.Any(p => p == null || p.Value.IsNullOrEmpty());
}
```

2. Alternatively, add explicit validation in `Validate()` method to check each address:
```csharp
if (organization.ProposerWhiteList.Empty() || 
    organization.ProposerWhiteList.Proposers.Any(p => p == null || p.Value.IsNullOrEmpty()))
    return false;
```

**Invariant Checks:**
- Whitelist must contain only non-null addresses with non-empty byte values
- Consider adding check for duplicate addresses (as Association contract does)

**Test Cases:**
Add regression test attempting to set whitelist with:
- Empty `Address()` instances
- Null addresses
- Mix of valid and invalid addresses
All should be rejected with "Invalid organization" error

### Proof of Concept

**Initial State:**
- Referendum organization exists with valid proposer whitelist
- Attacker is an authorized proposer with token balance for voting

**Attack Steps:**
1. Create proposal targeting organization's `ChangeOrganizationProposerWhiteList` method
2. Set input to `new ProposerWhiteList { Proposers = { new Address() } }`
3. Approve and release proposal (attacker + accomplices provide token-weighted approval)
4. Proposal executes successfully - validation passes because `Proposers.Count == 1`
5. Attempt to create new proposal with any valid proposer address
6. `CreateProposal` fails at authorization check because `Contains(validAddress)` returns false

**Expected Result:** Step 4 should fail with "Invalid organization" error

**Actual Result:** Attack succeeds, organization permanently disabled from creating proposals

**Success Condition:** Organization can no longer execute `CreateProposal` for any valid address, confirming permanent DoS state

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

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L774-788)
```csharp
        // invalid proposal whitelist
        {
            var organizationAddress = await CreateOrganizationAsync();
            var newProposalWhitelist = new ProposerWhiteList();
            var changeProposerWhitelistProposalId = await CreateReferendumProposalAsync(DefaultSenderKeyPair,
                newProposalWhitelist,
                nameof(ReferendumContractStub.ChangeOrganizationProposerWhiteList), organizationAddress,
                ReferendumContractAddress);
            var keyPair = Accounts[3].KeyPair;
            await ApproveAllowanceAsync(keyPair, 5000, changeProposerWhitelistProposalId);
            await ApproveAsync(keyPair, changeProposerWhitelistProposalId);
            var ret = await ReferendumContractStub.Release.SendWithExceptionAsync(
                changeProposerWhitelistProposalId);
            ret.TransactionResult.Error.ShouldContain("Invalid organization");
        }
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L1526-1531)
```csharp
        resetRet = await creator.ResetManager.SendWithExceptionAsync(new ResetManagerInput
        {
            NewManager = new Address(),
            SchemeId = schemeId
        });
        resetRet.TransactionResult.Error.ShouldContain("Invalid new sponsor.");
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```
