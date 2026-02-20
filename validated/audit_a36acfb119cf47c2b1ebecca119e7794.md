# Audit Report

## Title
Removed Proposers Can Still Release Approved Proposals Due to Missing Whitelist Validation in Release Function

## Summary
The Referendum, Association, and Parliament governance contracts enforce proposer whitelist validation during proposal creation but fail to re-validate whitelist membership during proposal release. This allows proposers who have been removed from the whitelist to execute their previously approved proposals, bypassing the organization's intent to revoke governance privileges.

## Finding Description

This is a Time-of-Check-Time-of-Use (TOCTOU) vulnerability that exists across all three AElf governance contracts. The authorization model is inconsistent throughout the proposal lifecycle.

**Referendum Contract:**

The `CreateProposal` method enforces whitelist validation by calling `AssertIsAuthorizedProposer`: [1](#0-0) 

The whitelist check verifies membership: [2](#0-1) 

The `Contains` extension validates whitelist membership: [3](#0-2) 

However, the `Release` function only verifies that the caller matches the original proposer address, without re-checking current whitelist status: [4](#0-3) 

Organizations can modify whitelists at any time: [5](#0-4) 

**Association Contract:**

The same vulnerability exists. Whitelist is checked during proposal creation: [6](#0-5) 

Whitelist validation in helper: [7](#0-6) 

Release function missing whitelist re-validation: [8](#0-7) 

Whitelist can be modified: [9](#0-8) 

**Parliament Contract:**

Parliament also has this vulnerability. Whitelist/permission checked during creation: [10](#0-9) 

Whitelist validation in helper: [11](#0-10) 

Release function missing whitelist re-validation: [12](#0-11) 

**Attack Scenario:**
1. Proposer Alice is initially in the whitelist (legitimate access)
2. Alice creates proposal via `CreateProposal` (passes whitelist check)
3. Organization members approve the proposal (reaches approval threshold)
4. Organization removes Alice from whitelist via `ChangeOrganizationProposerWhiteList` after detecting suspicious behavior
5. Alice calls `Release` with her approved proposal
6. Release succeeds because it only checks `Context.Sender.Equals(proposal.Proposer)`, not current whitelist membership
7. Arbitrary contract method executes with organization authority via `SendVirtualInlineBySystemContract`

## Impact Explanation

**High Impact - Authorization Bypass:**

1. **Trust Revocation Ineffective**: When an organization removes a proposer from the whitelist, they explicitly signal loss of trust. However, the removed proposer retains execution rights for all previously approved proposals, defeating the purpose of whitelist removal.

2. **Unauthorized Operations with Organization Authority**: The released proposal executes via `SendVirtualInlineBySystemContract` using the organization's virtual address, meaning removed proposers can:
   - Transfer tokens from organization-controlled addresses
   - Execute contract upgrades and configuration changes
   - Release treasury funds
   - Modify authority structures
   - Perform any privileged operation the organization can execute

3. **Malicious Insider Attack Window**: A sophisticated attacker can:
   - Create multiple benign-looking proposals while authorized
   - Wait for approval through normal governance processes
   - Get removed from whitelist after detection of malicious intent
   - Execute all approved proposals post-removal with full organization authority

4. **No Direct Mitigation Available**: Organizations cannot directly revoke release permissions. The only options are:
   - Wait for proposal expiration (time-limited and may be too late)
   - Call `ClearProposal` after expiration (reactive, not preventive)
   - Continuously monitor removed proposers (impractical)

This violates the fundamental security invariant that authorization checks must be enforced consistently throughout the entire governance lifecycle, not just at proposal creation.

## Likelihood Explanation

**Medium-to-High Likelihood:**

1. **Public Entry Points**: Both `CreateProposal` and `Release` are public methods accessible to any address. The authorization for `Release` only checks address equality, not current permissions.

2. **Realistic Preconditions**:
   - Attacker needs initial whitelist access (legitimate starting point for any proposer)
   - Must create proposals while authorized (normal governance operation)
   - Proposals must be approved (standard governance flow)
   - Removal from whitelist occurs (realistic scenario when trust is lost)

3. **Low Attack Cost**: Only requires standard transaction fees to call `Release`.

4. **High Attack Value**: Successful exploitation allows execution of privileged operations with full organization authority.

5. **Natural Exploitation Window**: The time gap between proposal approval and potential whitelist removal creates a realistic exploitation opportunity, especially in high-activity organizations with multiple concurrent proposals.

6. **No Warning System**: There is no mechanism to alert organizations that removed proposers still have executable approved proposals.

The likelihood is elevated because proposal approval is a normal governance operation, and organizations removing malicious proposers from whitelists is a realistic defensive action that should revoke all privileges.

## Recommendation

Add whitelist re-validation in the `Release` method for all three governance contracts. The fix should verify that the proposer is still in the current whitelist at the time of release.

**For Referendum Contract:**
```csharp
public override Empty Release(Hash input)
{
    var proposal = GetValidProposal(input);
    Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
    
    // Add whitelist re-validation
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(organization.ProposerWhiteList.Contains(proposal.Proposer), 
           "Proposer no longer in whitelist.");
    
    Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposal.ToAddress, proposal.ContractMethodName, proposal.Params);

    Context.Fire(new ProposalReleased { ProposalId = input });
    State.Proposals.Remove(input);
    return new Empty();
}
```

**For Association Contract:**
Apply the same pattern by adding `Assert(organization.ProposerWhiteList.Contains(proposalInfo.Proposer), "Proposer no longer in whitelist.");` after loading the organization in the `Release` method.

**For Parliament Contract:**
Re-validate the proposer's authorization using the existing `AssertIsAuthorizedProposer` helper method in the `Release` function.

This ensures that authorization is consistently enforced throughout the entire proposal lifecycle, maintaining the security invariant that only currently-authorized proposers can execute proposals.

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Create organization with proposer whitelist containing Alice
2. Alice creates a proposal (passes whitelist check)
3. Organization members approve the proposal
4. Organization removes Alice from whitelist via `ChangeOrganizationProposerWhiteList`
5. Alice successfully calls `Release` (should fail but doesn't)
6. Proposal executes with organization authority despite Alice being removed

This can be tested by adding a test case to the existing governance contract test suites that:
- Creates an organization with a proposer whitelist
- Creates and approves a proposal from a whitelisted proposer
- Removes that proposer from the whitelist
- Verifies that the removed proposer can still call `Release` successfully
- Confirms that the proposal executes with organization authority

The expected behavior should be that `Release` fails with "Proposer no longer in whitelist" or equivalent error, but currently it succeeds, confirming the authorization bypass vulnerability.

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-58)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** contract/AElf.Contracts.Referendum/ProposerWhiteListExtensions.cs (L18-21)
```csharp
    public static bool Contains(this ProposerWhiteList proposerWhiteList, Address address)
    {
        return proposerWhiteList.Proposers.Contains(address);
    }
```

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

**File:** contract/AElf.Contracts.Parliament/Parliament.cs (L61-66)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);
        return proposalId;
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
