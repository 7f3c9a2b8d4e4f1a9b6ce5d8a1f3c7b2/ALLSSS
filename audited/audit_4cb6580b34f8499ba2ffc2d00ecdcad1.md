### Title
Removed Proposers Can Still Release Pre-Existing Proposals Bypassing Whitelist Authorization

### Summary
When an organization removes a proposer from the whitelist using `ChangeOrganizationProposerWhiteList()`, that proposer retains the ability to release proposals they created before removal. The `Release()` function only verifies that the caller matches the original proposer address but does not re-validate whitelist membership, allowing removed proposers to execute unauthorized governance actions.

### Finding Description

**Exact Code Locations:**

The vulnerability exists in the `Release()` method which only performs a proposer identity check: [1](#0-0) 

The whitelist can be modified by authorized callers via: [2](#0-1) 

**Root Cause:**

The authorization model is inconsistent across the proposal lifecycle. During proposal creation, the system enforces whitelist membership: [3](#0-2) 

However, during proposal release, the system only checks proposer identity without re-validating whitelist membership: [4](#0-3) 

**Why Protections Fail:**

The `Release()` method performs two checks: proposer identity and approval threshold. Neither check validates current whitelist membership. The proposer address is stored immutably in the proposal at creation time, and subsequent whitelist changes do not affect this stored value. [5](#0-4) 

**Execution Path:**
1. Proposer A (in whitelist) creates proposal → passes `AssertIsAuthorizedProposer` check
2. Proposal gains sufficient approvals from organization members
3. Organization removes Proposer A from whitelist via `ChangeOrganizationProposerWhiteList`
4. Proposer A calls `Release()` → passes identity check at line 186, bypasses whitelist re-validation
5. Proposal executes via virtual inline call

### Impact Explanation

**Concrete Harm:**
Organizations remove proposers from whitelists for security reasons (compromise, loss of trust, role changes). This vulnerability means such security measures are ineffective against already-created proposals. A removed proposer can execute governance actions including:
- Transfer organization funds
- Modify organization parameters
- Execute arbitrary contract calls with organization authority

**Protocol Damage:**
Organizations cannot fully revoke privileges from untrusted proposers. This breaks the fundamental security invariant that whitelist changes should immediately affect authorization for all governance actions.

**Affected Parties:**
- Association organizations that depend on whitelist-based access control
- Organization members whose voting power is used to approve proposals that may execute after the proposer is deemed untrustworthy
- Any contracts or addresses targeted by such proposals

**Severity Justification:**
This is a **Medium severity** authorization bypass because:
- It requires the proposer to have legitimately created the proposal (not arbitrary exploitation)
- The proposal still requires member approval (threshold must be met)
- However, it completely bypasses post-removal authorization controls
- Organizations have no mechanism to prevent execution once a proposer is removed

The same vulnerability pattern exists in Parliament and Referendum contracts: [6](#0-5) [7](#0-6) 

### Likelihood Explanation

**Attacker Capabilities:**
The "attacker" is a previously-authorized proposer who has been removed from the whitelist. They need:
- To have created proposals before removal (normal legitimate activity)
- Those proposals to have reached approval threshold (requires genuine member support)
- Ability to call the public `Release()` method

**Attack Complexity:**
Very low. The attack is simply calling `Release()` on an existing proposal after being removed from the whitelist. No special techniques or privilege escalation required.

**Feasibility Conditions:**
Highly feasible. Organizations commonly:
- Rotate proposer roles
- Remove compromised or untrusted members
- Adjust whitelists based on changing governance needs

The test suite validates that removed proposers cannot create NEW proposals but does not test whether they can release EXISTING ones: [8](#0-7) 

**Detection/Operational Constraints:**
- Organizations cannot detect this until the removed proposer actually releases a proposal
- No on-chain mechanism exists to prevent release once whitelist is changed
- Events are emitted but provide no prevention capability

**Probability:**
Likely to occur in production environments where:
- Organizations actively manage proposer permissions
- Proposers are removed due to security concerns
- Pending approved proposals exist at time of removal

### Recommendation

**Code-Level Mitigation:**

Add a whitelist validation check in the `Release()` method immediately after the proposer identity check:

```solidity
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // ADD THIS CHECK:
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(organization.ProposerWhiteList.Contains(proposalInfo.Proposer), 
        "Proposer no longer authorized.");
    
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    // ... rest of implementation
}
```

**Invariant Checks to Add:**
1. Proposer must be in whitelist at both creation time AND release time
2. Document whether whitelist changes should retroactively affect pending proposals
3. Consider adding a mechanism to invalidate proposals when proposer is removed (if desired behavior)

**Test Cases to Prevent Regression:**
1. Test: Create proposal → get removed from whitelist → attempt release → should fail
2. Test: Create proposal → get removed and re-added → release should succeed
3. Test: Multiple proposals from same proposer, remove proposer, verify none can be released
4. Test: Proposal approval after proposer removal should not enable release

Apply the same fix to Parliament and Referendum contracts which exhibit identical vulnerability patterns.

### Proof of Concept

**Required Initial State:**
- Association organization exists with Reviewer1 in proposer whitelist
- Organization has sufficient members to meet approval thresholds

**Transaction Steps:**

1. **Setup:** Create organization with Reviewer1 as proposer
   ```
   CreateOrganization({
     ProposerWhiteList: [Reviewer1],
     OrganizationMemberList: [Member1, Member2, Member3],
     MinimalApprovalThreshold: 2
   })
   ```

2. **Create Proposal:** Reviewer1 creates proposal to transfer funds
   ```
   CreateProposal({
     OrganizationAddress: orgAddress,
     ToAddress: TokenContract,
     ContractMethodName: "Transfer",
     Params: {To: Reviewer1, Amount: 1000}
   })
   // Returns: proposalId
   ```

3. **Approve Proposal:** Members approve the proposal
   ```
   Member1.Approve(proposalId)
   Member2.Approve(proposalId)
   // Approval threshold reached
   ```

4. **Remove Proposer:** Organization removes Reviewer1 from whitelist
   ```
   CreateProposal({
     ContractMethodName: "ChangeOrganizationProposerWhiteList",
     Params: {Proposers: [Reviewer2]}  // Reviewer1 removed
   })
   // Approve and Release this whitelist change proposal
   ```

5. **Verify Removal:** Reviewer1 can no longer create new proposals
   ```
   Reviewer1.CreateProposal(...) 
   // Expected: Fails with "Unauthorized to propose."
   // Actual: Fails correctly ✓
   ```

6. **Exploit:** Reviewer1 releases the old proposal despite being removed
   ```
   Reviewer1.Release(proposalId)
   // Expected: Should fail with authorization error
   // Actual: SUCCEEDS and transfers 1000 tokens ✗
   ```

**Success Condition:**
The exploit succeeds when step 6 executes the proposal despite Reviewer1 no longer being in the whitelist. The transaction status is `Mined` and the `ProposalReleased` event is emitted, with the transfer executing successfully via the organization's virtual address.

### Citations

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

**File:** contract/AElf.Contracts.Association/Association.cs (L218-231)
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L145-173)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            ToAddress = input.ToAddress,
            OrganizationAddress = input.OrganizationAddress,
            ProposalId = proposalId,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        State.Proposals[proposalId] = proposal;
        Context.Fire(new ProposalCreated
        {
            ProposalId = proposalId,
            OrganizationAddress = input.OrganizationAddress,
            Title = input.Title,
            Description = input.Description
        });
        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L135-135)
```csharp
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L166-166)
```csharp
        Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L790-839)
```csharp
    public async Task Change_OrganizationProposalWhitelist_Test()
    {
        var minimalApproveThreshold = 1;
        var minimalVoteThreshold = 1;
        var maximalAbstentionThreshold = 1;
        var maximalRejectionThreshold = 1;
        var organizationAddress = await CreateOrganizationAsync(minimalApproveThreshold, minimalVoteThreshold,
            maximalAbstentionThreshold, maximalRejectionThreshold, Reviewer1);

        var proposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer2 }
        };

        var associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
        var changeProposalId = await CreateAssociationProposalAsync(Reviewer1KeyPair, proposerWhiteList,
            nameof(associationContractStub.ChangeOrganizationProposerWhiteList), organizationAddress);
        await ApproveAsync(Reviewer1KeyPair, changeProposalId);
        var releaseResult = await associationContractStub.Release.SendAsync(changeProposalId);
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        await TransferToOrganizationAddressAsync(organizationAddress);
        var transferInput = new TransferInput
        {
            Symbol = "ELF",
            Amount = 100,
            To = Reviewer1,
            Memo = "Transfer"
        };
        associationContractStub = GetAssociationContractTester(Reviewer1KeyPair);
        var createProposalInput = new CreateProposalInput
        {
            ContractMethodName = nameof(TokenContractStub.Approve),
            ToAddress = TokenContractAddress,
            Params = transferInput.ToByteString(),
            ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(2),
            OrganizationAddress = organizationAddress
        };
        var result = await associationContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        result.TransactionResult.Error.ShouldContain("Unauthorized to propose.");

        //Verify association proposal
        var verifyResult = await associationContractStub.ValidateProposerInWhiteList.CallAsync(
            new ValidateProposerInWhiteListInput
            {
                OrganizationAddress = organizationAddress,
                Proposer = Reviewer2
            });
        verifyResult.Value.ShouldBeTrue();
    }
```
