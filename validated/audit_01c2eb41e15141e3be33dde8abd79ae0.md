# Audit Report

## Title
Proposer Whitelist Bypass - Removed Proposers Can Execute Approved Proposals

## Summary
The `Release` method in Association, Parliament, and Referendum governance contracts fails to re-validate whether the caller is still in the organization's proposer whitelist. This allows proposers who have been removed from the whitelist via `ChangeOrganizationProposerWhiteList` to retain execution authority for previously approved proposals, creating a critical authorization bypass vulnerability.

## Finding Description

The vulnerability exists across all three governance contracts due to insufficient authorization validation in the `Release` method.

**Proposal Creation - Whitelist Validated:**

When a proposal is created, the system properly validates the proposer's whitelist membership: [1](#0-0) 

This validation checks the proposer against the current whitelist: [2](#0-1) 

The same pattern exists in Parliament and Referendum: [3](#0-2) [4](#0-3) 

**Whitelist Updates Allowed:**

Organizations can update their proposer whitelist at any time through `ChangeOrganizationProposerWhiteList`: [5](#0-4) [6](#0-5) [7](#0-6) 

**Proposal Release - No Whitelist Re-Check:**

When releasing an approved proposal, the `Release` method only verifies the original proposer identity without re-validating current whitelist membership: [8](#0-7) 

The critical flaw is at line 186: `Assert(Context.Sender == proposalInfo.Proposer, "No permission.");` verifies that the caller is the original proposer, but never re-validates whether this proposer is still in the current `organization.ProposerWhiteList`.

The same authorization gap exists in Parliament and Referendum: [9](#0-8) [10](#0-9) 

The proposer address stored in the proposal at creation time becomes immutable: [11](#0-10) 

Once a proposer creates a proposal and gets it approved, they retain release authority indefinitely (until expiration), even after being explicitly removed from the whitelist. The `Contains` extension method used during proposal creation is never re-evaluated at release time: [12](#0-11) 

## Impact Explanation

**HIGH Severity** - This vulnerability represents a fundamental authorization bypass with severe consequences:

1. **Authorization Invariant Violation:** The proposer whitelist is a core security control mechanism. The expected invariant is: "Only addresses currently in the proposer whitelist can interact with governance proposals." This is completely violated for the Release operation.

2. **No Effective Revocation:** When organizations remove a proposer from the whitelist (due to compromise, discovered malicious intent, or changed trust model), they reasonably expect this revokes all governance authority. However, removed proposers retain full execution rights for any approved proposals.

3. **Arbitrary Contract Execution:** The `Release` method executes `Context.SendVirtualInlineBySystemContract` on behalf of the organization's virtual address, which can invoke any contract method including:
   - Token transfers from organization treasury
   - Contract upgrades and deployments
   - Permission and configuration changes
   - Cross-chain operations
   - Other privileged governance actions

4. **Real Attack Scenarios:**
   - **Compromised Account:** Organization detects proposer account compromise and removes them from whitelist, but attacker can still execute approved proposals
   - **Malicious Proposer Discovery:** Proposer's malicious intent discovered after approval (through parameter obfuscation), but whitelist removal doesn't prevent execution
   - **Changed Trust Model:** Organization needs to reduce proposer set for security, but cannot revoke release rights for existing approved proposals

5. **No Mitigation Available:** The only defense is waiting for proposal expiration and using `ClearProposal`: [13](#0-12) 

This requires organizations to wait the entire proposal lifetime (typically days) while the removed proposer can execute at will.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is highly feasible to exploit:

1. **Low Attacker Capabilities:** Attacker must only:
   - Initially be in proposer whitelist (normal operational state)
   - Create a proposal that gets approved (standard governance flow)
   - No special technical exploits, economic resources, or timing attacks required

2. **Low Attack Complexity:** The exploit is straightforward:
   - Step 1: Create proposal while whitelisted (passes `AssertIsAuthorizedProposer`)
   - Step 2: Wait for organization member approval (normal operation)
   - Step 3: After being removed from whitelist via `ChangeOrganizationProposerWhiteList`, call `Release`
   - Step 4: Release succeeds because it only checks `Context.Sender == proposalInfo.Proposer`

3. **Realistic Triggering Conditions:**
   - Account compromise is a realistic operational risk requiring immediate whitelist removal
   - Discovering proposer malicious intent post-approval is common in governance
   - Organizations regularly need to update their trust model and proposer set
   - Extended attack window (approval to expiration, typically days)

4. **No Effective Detection/Prevention:**
   - Transactions are on-chain and visible, but prevention is impossible once proposal is approved
   - Organizations have no mechanism to revoke release authority
   - `ClearProposal` only works after expiration, leaving a long vulnerable window

## Recommendation

Add whitelist re-validation in the `Release` method for all three governance contracts. For Association contract:

```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // ADD THIS: Re-validate proposer is still in whitelist
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(organization.ProposerWhiteList.Contains(Context.Sender), 
        "Proposer no longer in whitelist.");
    
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposalInfo.ToAddress, proposalInfo.ContractMethodName, proposalInfo.Params);

    Context.Fire(new ProposalReleased
    {
        ProposalId = input,
        OrganizationAddress = proposalInfo.OrganizationAddress
    });
    State.Proposals.Remove(input);

    return new Empty();
}
```

Apply the same fix to Parliament and Referendum contracts, adapting for their specific whitelist validation logic (Parliament has additional checks for `ProposerAuthorityRequired` and `ParliamentMemberProposingAllowed`).

## Proof of Concept

```csharp
[Fact]
public async Task RemovedProposer_Can_Still_Release_Approved_Proposal()
{
    // Setup: Create organization with Reviewer1 in proposer whitelist
    var organizationAddress = await CreateOrganizationAsync(
        minimalApproveThreshold: 1,
        minimalVoteThreshold: 1,
        maximalAbstentionThreshold: 1,
        maximalRejectionThreshold: 1,
        proposer: Reviewer1);

    // Step 1: Reviewer1 creates a proposal (whitelist check passes)
    var proposalId = await CreateProposalAsync(Reviewer1KeyPair, organizationAddress);
    
    // Step 2: Get proposal approved by organization member
    var reviewer1Stub = GetAssociationContractTester(Reviewer1KeyPair);
    await reviewer1Stub.Approve.SendAsync(proposalId);

    // Step 3: Organization removes Reviewer1 from whitelist
    var newWhiteList = new ProposerWhiteList { Proposers = { Reviewer2 } }; // Reviewer1 removed
    var changeProposalId = await CreateAssociationProposalAsync(
        Reviewer1KeyPair, 
        newWhiteList,
        nameof(reviewer1Stub.ChangeOrganizationProposerWhiteList), 
        organizationAddress);
    await reviewer1Stub.Approve.SendAsync(changeProposalId);
    await reviewer1Stub.Release.SendAsync(changeProposalId);

    // Verify Reviewer1 is no longer in whitelist
    var verifyResult = await reviewer1Stub.ValidateProposerInWhiteList.CallAsync(
        new ValidateProposerInWhiteListInput
        {
            OrganizationAddress = organizationAddress,
            Proposer = Reviewer1
        });
    verifyResult.Value.ShouldBeFalse(); // Reviewer1 removed from whitelist

    // Step 4: VULNERABILITY - Reviewer1 can still release the approved proposal!
    var releaseResult = await reviewer1Stub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // SUCCESS!
    
    // This should have failed with "Unauthorized" but succeeds due to missing whitelist re-check
}
```

## Notes

This vulnerability affects all three governance contracts identically (Association, Parliament, Referendum). The root cause is that the `Release` method validates the proposer's identity but not their current authorization status. This creates a time-of-check-to-time-of-use (TOCTOU) vulnerability where the whitelist state at proposal creation differs from the state at proposal release, but only the former is validated.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L107-111)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
```

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

**File:** contract/AElf.Contracts.Association/Association.cs (L282-289)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L22-34)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        // It is a valid proposer if
        // authority check is disable,
        // or sender is in proposer white list,
        // or sender is one of miners when member proposing allowed.
        Assert(
            !organization.ProposerAuthorityRequired || ValidateAddressInWhiteList(proposer) ||
            (organization.ParliamentMemberProposingAllowed && ValidateParliamentMemberAuthority(proposer)),
            "Unauthorized to propose.");
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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L132-145)
```csharp
    public override Empty Release(Hash proposalId)
    {
        var proposalInfo = GetValidProposal(proposalId);
        Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
        var organization = State.Organizations[proposalInfo.OrganizationAddress];
        Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
        Context.SendVirtualInlineBySystemContract(
            CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
            proposalInfo.ContractMethodName, proposalInfo.Params);
        Context.Fire(new ProposalReleased { ProposalId = proposalId });
        State.Proposals.Remove(proposalId);

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L162-177)
```csharp
    public override Empty ChangeOrganizationProposerWhiteList(ProposerWhiteList input)
    {
        var defaultOrganizationAddress = State.DefaultOrganizationAddress.Value;
        Assert(defaultOrganizationAddress == Context.Sender, "No permission.");
        var organization = State.Organizations[defaultOrganizationAddress];
        Assert(
            input.Proposers.Count > 0 || !organization.ProposerAuthorityRequired ||
            organization.ParliamentMemberProposingAllowed, "White list can't be empty.");
        State.ProposerWhiteList.Value = input;
        Context.Fire(new OrganizationWhiteListChanged
        {
            OrganizationAddress = Context.Sender,
            ProposerWhiteList = input
        });
        return new Empty();
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

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L29-32)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
    }
```
