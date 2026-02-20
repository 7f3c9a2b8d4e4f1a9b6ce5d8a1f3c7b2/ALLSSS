# Audit Report

## Title
Proposer Whitelist Bypass - Removed Proposers Can Execute Approved Proposals

## Summary
The `Release` method in Association, Parliament, and Referendum governance contracts validates only that the caller is the original proposer without re-checking current whitelist membership. This allows proposers removed from the whitelist via `ChangeOrganizationProposerWhiteList` to retain execution authority for previously approved proposals, completely bypassing the whitelist authorization mechanism.

## Finding Description

The vulnerability exists in the authorization logic across all three governance contracts due to incomplete access control checks at the proposal release stage.

When a proposal is created, the system properly validates that the proposer is in the whitelist. [1](#0-0)  This validation occurs through the authorization helper method. [2](#0-1)  The whitelist membership check uses the `Contains` extension method. [3](#0-2) 

However, when releasing an approved proposal, the authorization check is critically insufficient. [4](#0-3)  The `Release` method only verifies that the sender matches the original proposer without re-validating current whitelist membership.

Organizations can update their proposer whitelist at any time. [5](#0-4)  This creates a critical authorization gap: once a proposer creates and gets approval for a proposal, they retain execution ability even after being explicitly removed from the whitelist.

The same vulnerability pattern exists in Parliament [6](#0-5)  and Referendum [7](#0-6)  contracts with identical insufficient authorization checks at release time.

This violates the security invariant that whitelist membership should control proposal authority throughout the entire proposal lifecycle, not just at creation time. The authorization model assumes that removing a proposer from the whitelist revokes all their governance privileges, but this assumption is false for already-approved proposals.

## Impact Explanation

**Authorization Bypass Severity:** Organizations use the proposer whitelist as a critical security control to manage who can execute governance actions. Removing a proposer from the whitelist via `ChangeOrganizationProposerWhiteList` is an explicit revocation of trust and authority. However, this control is completely ineffective for existing approved proposals.

**Concrete Damage:** Approved proposals execute arbitrary contract methods on behalf of organizations through virtual inline calls. [8](#0-7)  This can include fund transfers, contract upgrades, permission changes, and other privileged operations.

**Real-World Harm Scenarios:**

1. **Compromised Account:** When a proposer's account is compromised, the organization immediately removes them from the whitelist. However, the attacker retains ability to execute any previously-approved proposals, potentially draining funds or changing critical configurations.

2. **Malicious Proposer Discovery:** If a proposer's malicious intent is discovered after their proposal was approved (through social engineering, parameter obfuscation, or deceptive proposal descriptions), removing them from the whitelist does not prevent execution.

3. **Changed Circumstances:** A previously-approved proposal becomes harmful due to changed market/protocol conditions. The organization removes the proposer to prevent execution, but removal has no effect.

Organizations have no mechanism to revoke release rights for approved but not-yet-expired proposals except waiting for expiration. [9](#0-8) 

**Impact Assessment: HIGH** - This violates fundamental authorization guarantees and enables removed proposers to execute arbitrary privileged operations on behalf of organizations.

## Likelihood Explanation

**Attack Complexity: LOW** - The exploit path is straightforward and follows normal governance operations:

1. Create proposal while whitelisted (validated by `AssertIsAuthorizedProposer`) [1](#0-0) 
2. Wait for member approval through normal voting process
3. After being removed from whitelist via `ChangeOrganizationProposerWhiteList`, call `Release` method
4. The method executes successfully because it only checks sender equals original proposer

**Feasibility:** Extremely feasible - this follows the normal proposal flow with one realistic additional step (whitelist removal). The attack window extends from approval until expiration (typically days to weeks), providing ample opportunity. No race conditions, precise timing attacks, or special technical exploits are needed beyond normal participation.

**Operational Realism:** The scenarios triggering this vulnerability (account compromise, discovered malicious intent, changed circumstances requiring authority revocation) are realistic operational events that organizations must regularly handle. The inability to revoke release authority represents a critical gap in the governance security model.

**Attacker Capabilities Required:**
- Must initially be in the proposer whitelist (normal operational state for legitimate proposers)
- Must create a proposal that gets approved by organization members (normal operation)
- No special economic resources or privileges required beyond normal participation

**Likelihood Assessment: HIGH** - The combination of low attack complexity, realistic preconditions, common triggering scenarios, and straightforward execution path makes this vulnerability highly likely to be exploited in production environments.

## Recommendation

Add whitelist membership validation to the `Release` method in all three governance contracts:

**For Association Contract:**
```csharp
public override Empty Release(Hash input)
{
    var proposalInfo = GetValidProposal(input);
    Assert(Context.Sender == proposalInfo.Proposer, "No permission.");
    
    // Add this check to re-validate whitelist membership
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, Context.Sender);
    
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposalInfo.ToAddress,
        proposalInfo.ContractMethodName, 
        proposalInfo.Params);

    Context.Fire(new ProposalReleased
    {
        ProposalId = input,
        OrganizationAddress = proposalInfo.OrganizationAddress
    });
    State.Proposals.Remove(input);

    return new Empty();
}
```

Apply the same fix to Parliament and Referendum contracts by calling their respective `AssertIsAuthorizedProposer` methods before executing the proposal.

This ensures that whitelist membership is enforced at both proposal creation AND release time, maintaining the security invariant throughout the entire proposal lifecycle.

## Proof of Concept

```csharp
// This test demonstrates the vulnerability
[Fact]
public async Task ProposerWhitelistBypass_RemovedProposerCanStillRelease()
{
    // Setup: Create organization with proposer A in whitelist
    var proposerA = Accounts[0].Address;
    var organizationAddress = await CreateOrganizationWithProposer(proposerA);
    
    // Step 1: Proposer A creates proposal (succeeds - A is in whitelist)
    var proposalId = await CreateProposalAsProposer(proposerA, organizationAddress);
    
    // Step 2: Get proposal approved by organization members
    await ApproveProposalByMembers(proposalId);
    
    // Step 3: Organization removes proposer A from whitelist
    await RemoveProposerFromWhitelist(organizationAddress, proposerA);
    
    // Step 4: Proposer A attempts to release proposal
    // EXPECTED: Should fail - proposer no longer in whitelist
    // ACTUAL: Succeeds - authorization bypass
    var result = await ReleaseProposalAsProposer(proposerA, proposalId);
    
    // Vulnerability confirmed: Release succeeded despite proposer removal
    Assert.True(result.Success); // This should be False but is True
}
```

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
