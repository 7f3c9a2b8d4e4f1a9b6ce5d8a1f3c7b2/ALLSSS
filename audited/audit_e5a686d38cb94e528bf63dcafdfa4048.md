# Audit Report

## Title
Proposer Whitelist Bypass - Removed Proposers Can Execute Approved Proposals

## Summary
The `Release` method in Association, Parliament, and Referendum governance contracts validates only that the caller is the original proposer without re-checking current whitelist membership. This allows proposers removed from the whitelist via `ChangeOrganizationProposerWhiteList` to retain execution authority for previously approved proposals, completely bypassing the whitelist authorization mechanism.

## Finding Description

The vulnerability exists in the authorization logic across all three governance contracts (Association, Parliament, Referendum).

When a proposal is created, the system properly validates that the proposer is in the whitelist [1](#0-0) . This validation occurs through the helper method [2](#0-1)  which checks whitelist membership using the `Contains` extension method [3](#0-2) .

However, when releasing an approved proposal, the authorization check is critically insufficient [4](#0-3) . The `Release` method only verifies `Context.Sender == proposalInfo.Proposer` (line 186) without re-validating whether the proposer is still in the current whitelist.

Meanwhile, organizations can update their proposer whitelist at any time [5](#0-4) , which updates the organization's `ProposerWhiteList` field (line 222). This creates a critical authorization gap: once a proposer creates and gets approval for a proposal, they retain the ability to execute it even after being explicitly removed from the whitelist.

The same vulnerability pattern exists in Parliament [6](#0-5)  and Referendum [7](#0-6)  contracts with identical insufficient authorization checks at release time.

## Impact Explanation

**Authorization Bypass Severity:** Organizations use the proposer whitelist as a critical security control to manage who can interact with their governance. Removing a proposer from the whitelist via `ChangeOrganizationProposerWhiteList` is an explicit revocation of trust and authority. However, this control is completely ineffective for existing proposals - removed proposers retain full execution rights.

**Real-World Harm Scenarios:**

1. **Compromised Account:** When a legitimate proposer's account is compromised, the organization immediately removes them from the whitelist. However, the attacker can still execute any approved proposals, potentially draining funds or changing critical configurations.

2. **Malicious Proposer Discovery:** If a proposer's malicious intent is discovered after their proposal was approved (through social engineering, parameter obfuscation, or deceptive proposal descriptions), removing them from the whitelist does not prevent execution.

3. **Changed Circumstances:** A previously-approved proposal becomes harmful due to changed market/protocol conditions. The organization removes the proposer to prevent execution, but cannot actually stop it.

**Concrete Damage:** Approved proposals can execute arbitrary contract methods on behalf of the organization through `Context.SendVirtualInlineBySystemContract` (lines 189-191 in Association, 138-140 in Parliament, 169-171 in Referendum), including fund transfers, contract upgrades, permission changes, and other privileged operations. Organizations have no mechanism to revoke release rights for approved but not-yet-expired proposals except waiting for expiration and using `ClearProposal`.

**Impact Assessment: HIGH** - This violates the fundamental authorization invariant that whitelist membership controls proposal authority throughout the entire proposal lifecycle, not just at creation time.

## Likelihood Explanation

**Attacker Capabilities Required:**
- Must initially be in the proposer whitelist (normal operational state for legitimate proposers)
- Must create a proposal that gets approved by organization members (normal operation)
- No special technical exploits or economic resources required beyond normal participation

**Attack Complexity: LOW** - The exploit path is straightforward:
1. Create proposal while whitelisted (validated by `AssertIsAuthorizedProposer`)
2. Wait for member approval through normal voting process
3. After being removed from whitelist via `ChangeOrganizationProposerWhiteList`, call `Release` method
4. The method executes successfully because it only checks `Context.Sender == proposalInfo.Proposer`

**Feasibility:** Extremely feasible - this follows the normal proposal flow with one realistic additional step (whitelist removal). The attack window extends from approval until expiration (typically days to weeks), providing ample opportunity. No race conditions or precise timing attacks are needed.

**Operational Realism:** The scenarios triggering this vulnerability (account compromise, discovered malicious intent, changed circumstances requiring authority revocation) are realistic operational events that organizations must regularly handle. The inability to revoke release authority represents a critical gap in the governance security model.

**Likelihood Assessment: HIGH** - The combination of low attack complexity, realistic preconditions, and common triggering scenarios makes this vulnerability highly likely to be exploited.

## Recommendation

Add whitelist re-validation in the `Release` method before allowing proposal execution. For all three contracts (Association, Parliament, Referendum), modify the `Release` method to call `AssertIsAuthorizedProposer` before executing the proposal:

```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // ADD THIS LINE: Re-validate proposer is still authorized
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, Context.Sender);
    
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposalInfo.ToAddress,
        proposalInfo.ContractMethodName, 
        proposalInfo.Params);
    // ... rest of method
}
```

This ensures that proposers must maintain whitelist membership throughout the entire proposal lifecycle, from creation through execution, which is the expected security invariant.

## Proof of Concept

```csharp
[Fact]
public async Task ProposerWhitelistBypass_RemovedProposerCanStillReleaseApprovedProposal()
{
    // 1. Setup: Create organization with Reviewer1 in proposer whitelist
    var createOrganizationInput = new CreateOrganizationInput
    {
        OrganizationMemberList = new OrganizationMemberList
        {
            OrganizationMembers = { Reviewer1, Reviewer2, Reviewer3 }
        },
        ProposalReleaseThreshold = new ProposalReleaseThreshold
        {
            MinimalApprovalThreshold = 2,
            MinimalVoteThreshold = 2,
            MaximalAbstentionThreshold = 1,
            MaximalRejectionThreshold = 1
        },
        ProposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Reviewer1 }  // Reviewer1 is initially whitelisted
        }
    };
    
    var organizationAddress = (await AssociationContractStub.CreateOrganization.SendAsync(createOrganizationInput)).Output;
    
    // 2. Reviewer1 creates a proposal while whitelisted
    var proposalId = (await AssociationContractStubReviewer1.CreateProposal.SendAsync(new CreateProposalInput
    {
        OrganizationAddress = organizationAddress,
        ToAddress = TokenContractAddress,
        ContractMethodName = nameof(TokenContractContainer.TokenContractStub.Transfer),
        Params = new TransferInput { To = Reviewer1, Symbol = "ELF", Amount = 1000 }.ToByteString(),
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    })).Output;
    
    // 3. Get approval from organization members (2 approvals needed)
    await AssociationContractStubReviewer1.Approve.SendAsync(proposalId);
    await AssociationContractStubReviewer2.Approve.SendAsync(proposalId);
    
    // 4. Organization removes Reviewer1 from whitelist (e.g., due to compromise/malicious behavior)
    var organizationStub = GetAssociationContractTester(organizationAddress);
    await organizationStub.ChangeOrganizationProposerWhiteList.SendAsync(new ProposerWhiteList
    {
        Proposers = { }  // Empty whitelist - Reviewer1 removed
    });
    
    // 5. Verify Reviewer1 is no longer in whitelist
    var validationResult = await AssociationContractStub.ValidateProposerInWhiteList.CallAsync(
        new ValidateProposerInWhiteListInput
        {
            OrganizationAddress = organizationAddress,
            Proposer = Reviewer1
        });
    validationResult.Value.ShouldBeFalse();  // Reviewer1 is NOT in whitelist
    
    // 6. VULNERABILITY: Despite being removed from whitelist, Reviewer1 can still release the proposal
    var releaseResult = await AssociationContractStubReviewer1.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);  // Succeeds!
    
    // The proposal executed successfully even though the proposer was removed from the whitelist,
    // completely bypassing the whitelist authorization mechanism.
}
```

This test demonstrates that a proposer removed from the whitelist can still execute approved proposals, proving the authorization bypass vulnerability.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L107-112)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
    }
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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Association/Association_Extensions.cs (L29-32)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
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
