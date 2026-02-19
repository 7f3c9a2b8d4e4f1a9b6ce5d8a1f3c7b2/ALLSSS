### Title
Organization Self-Proposal Vulnerability via Proposer Whitelist Bypass

### Summary
The Referendum contract allows an organization's address to be included in its own proposer whitelist, enabling the organization to create proposals to itself without requiring individual proposers. This bypasses the intended governance separation between proposal creation (proposers) and approval (voters), allowing self-perpetuating governance control.

### Finding Description

The vulnerability exists in the Referendum contract's proposer authorization logic and organization creation validation:

**Root Cause 1 - Missing Self-Inclusion Validation:**
The `Contains()` method simply checks if an address exists in the proposer whitelist without any special handling for the organization address itself. [1](#0-0) 

The organization validation logic checks if the proposer whitelist is not empty, but does not prevent the organization address from being included in its own whitelist. [2](#0-1) 

**Root Cause 2 - Deterministic Address Calculation:**
The organization address is deterministically calculated from the creation input via a public view method, allowing attackers to pre-calculate the address before creation and include it in the `ProposerWhiteList`. [3](#0-2) [4](#0-3) 

**Root Cause 3 - Context.Sender in Virtual Inline Calls:**
When a proposal is released, it executes via `SendVirtualInlineBySystemContract` with the organization's virtual address, causing `Context.Sender` in the called method to be the organization address. [5](#0-4) 

As documented, when inline transactions execute, the `Context.Sender` becomes the calling contract's address, not the original transaction sender. [6](#0-5) 

**Exploitation Path:**
The `CreateProposal` method only validates that `Context.Sender` is in the organization's proposer whitelist via `AssertIsAuthorizedProposer`. [7](#0-6) [8](#0-7) 

If the organization address is in its own whitelist and a proposal calls `CreateProposal`, the check passes because `Context.Sender` equals the organization address (from the virtual inline call), which is in the whitelist.

### Impact Explanation

**Governance Separation Bypass:**
- The fundamental governance model separates proposers (who initiate changes) from approvers (who vote on changes)
- This separation ensures accountability and prevents unilateral action
- By allowing self-proposal, an organization can continuously create new proposals to itself without individual proposer accountability

**Self-Perpetuating Control:**
- Once created with itself in the whitelist, the organization can:
  - Create proposals to modify its own configuration
  - Change voting thresholds via `ChangeOrganizationThreshold`
  - Modify the proposer whitelist via `ChangeOrganizationProposerWhiteList`
  - Execute arbitrary contract calls on behalf of the organization

**Loss of Accountability:**
- No individual proposer is responsible for proposals created this way
- The `Proposer` field in proposals would be the organization address itself, obscuring who actually initiated the governance action

**Affected Parties:**
- All users who participate in or rely on the governance organization
- Token holders who lock tokens to vote on proposals
- Contracts that depend on the organization's governance decisions

**Severity Justification: HIGH**
This breaks a fundamental governance invariant (proposer/approver separation) and allows organizations to bypass intended authorization controls, potentially enabling unauthorized configuration changes and arbitrary contract execution.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Only standard user permissions (no privileged roles needed)
- Ability to call public contract methods
- Knowledge of the organization address calculation mechanism

**Attack Complexity: LOW**
1. Call `CalculateOrganizationAddress` with desired creation parameters
2. Include the calculated address in the `ProposerWhiteList` field
3. Call `CreateOrganization` with those parameters
4. Create and approve a proposal that calls `CreateProposal` on the same contract
5. Release the proposal, triggering the self-proposal mechanism

**Feasibility Conditions:**
- All required methods are public and accessible
- No special state setup required
- Attack works on a freshly deployed contract
- The address calculation is deterministic and reliable

**Economic Rationality:**
- Minimal cost (only transaction fees for organization creation)
- No tokens need to be locked or at risk during setup
- The attack provides persistent control advantage

**Detection/Prevention:**
- No runtime detection mechanism exists
- The vulnerability is in the design, not a race condition or timing issue
- Once an organization is created this way, the condition persists indefinitely

**Probability: HIGH**
The attack is straightforward, uses only public APIs, requires no special timing or conditions, and provides significant governance control advantages.

### Recommendation

**Immediate Fix - Add Self-Inclusion Validation:**
Modify the `Validate` method in `Referendum_Helper.cs` to check that the organization address is not in its own proposer whitelist:

```csharp
private bool Validate(Organization organization)
{
    if (string.IsNullOrEmpty(organization.TokenSymbol) || organization.OrganizationAddress == null ||
        organization.OrganizationHash == null || organization.ProposerWhiteList.Empty())
        return false;
    
    // NEW CHECK: Prevent organization from being in its own proposer whitelist
    Assert(!organization.ProposerWhiteList.Contains(organization.OrganizationAddress),
        "Organization cannot be in its own proposer whitelist.");
    
    Assert(!string.IsNullOrEmpty(GetTokenInfo(organization.TokenSymbol).Symbol), "Token not exists.");
    
    var proposalReleaseThreshold = organization.ProposalReleaseThreshold;
    return proposalReleaseThreshold.MinimalApprovalThreshold <= proposalReleaseThreshold.MinimalVoteThreshold &&
           proposalReleaseThreshold.MinimalApprovalThreshold > 0 &&
           proposalReleaseThreshold.MaximalAbstentionThreshold >= 0 &&
           proposalReleaseThreshold.MaximalRejectionThreshold >= 0;
}
```

**Apply Same Fix to Association and Parliament Contracts:**
Both contracts have identical vulnerability patterns and require the same validation.

**Test Cases to Add:**
1. Test that `CreateOrganization` fails when organization address is in `ProposerWhiteList`
2. Test that `ChangeOrganizationProposerWhiteList` fails when attempting to add organization address
3. Verify that legitimate proposer whitelist configurations still work correctly
4. Add regression tests for the self-proposal attack scenario

### Proof of Concept

**Step 1 - Calculate Organization Address:**
```
Input: CreateOrganizationInput {
    TokenSymbol: "ELF",
    ProposalReleaseThreshold: { MinimalApprovalThreshold: 1, ... },
    ProposerWhiteList: { Proposers: [] },  // Empty initially
    CreationToken: null
}

Call: CalculateOrganizationAddress(Input)
Result: organizationAddr = 0x123... (deterministic address)
```

**Step 2 - Create Organization with Self in Whitelist:**
```
Input: CreateOrganizationInput {
    TokenSymbol: "ELF",
    ProposalReleaseThreshold: { MinimalApprovalThreshold: 1000, MinimalVoteThreshold: 1000, ... },
    ProposerWhiteList: { Proposers: [organizationAddr] },  // Organization address included
    CreationToken: null
}

Call: CreateOrganization(Input)
Result: Organization created at organizationAddr with itself in proposer whitelist
```

**Step 3 - Create Proposal that Calls CreateProposal:**
```
Input: CreateProposalInput {
    OrganizationAddress: organizationAddr,
    ToAddress: ReferendumContractAddress,
    ContractMethodName: "CreateProposal",
    Params: (serialized CreateProposalInput for some arbitrary action),
    ExpiredTime: CurrentTime + 7 days
}

Call: CreateProposal(Input) from any whitelisted address
Result: proposalId1 created
```

**Step 4 - Approve and Release:**
```
- Sufficient voters approve proposalId1 (lock tokens and call Approve)
- Threshold is reached
- Call: Release(proposalId1) from proposer

Expected: Proposal fails to execute CreateProposal
Actual: Proposal successfully creates proposalId2 with Context.Sender = organizationAddr
        This succeeds because organizationAddr is in its own proposer whitelist
```

**Success Condition:**
The organization has successfully created a proposal (proposalId2) without any individual proposer, demonstrating the governance separation bypass.

### Citations

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L18-21)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
    }
```

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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L207-219)
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L163-177)
```csharp
    public override Empty Release(Hash input)
    {
        var proposal = GetValidProposal(input);
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
        var organization = State.Organizations[proposal.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposal.ToAddress,
            proposal.ContractMethodName, proposal.Params);

        Context.Fire(new ProposalReleased { ProposalId = input });
        State.Proposals.Remove(input);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L211-216)
```csharp
    public override Address CalculateOrganizationAddress(CreateOrganizationInput input)
    {
        var organizationHashAddressPair = CalculateOrganizationHashAddressPair(input);
        var organizationAddress = organizationHashAddressPair.OrganizationAddress;
        return organizationAddress;
    }
```

**File:** docs-sphinx/getting-started/smart-contract-development/developing-smart-contracts/tx-execution-context.md (L34-46)
```markdown
## Origin, Sender and Self

- **Origin**: the address of the sender (signer) of the transaction being executed. Its type is an AElf address. It corresponds to the **From** field of the transaction. This value never changes, even for nested inline calls. This means that when you access this property in your contract, it's value will be the entity that created the transaction (user or smart contract through an inline call) 
- **Self**: the address of the contract currently being executed. This changes for every transaction and inline transaction.
- **Sender**: the address sending the transaction. If the transaction execution does not produce any inline transactions, this will always be the same. But if one contract calls another with an inline transaction, the sender will be the contract that is calling.

To use these values, you can access them through the **Context** property.

```protobuf
Context.Origin
Context.Sender
Context.Self
```
```
