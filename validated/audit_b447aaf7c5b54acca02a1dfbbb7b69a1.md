# Audit Report

## Title
Time-of-Check-Time-of-Use Vulnerability: Removed Proposers Can Still Release Approved Proposals

## Summary
The Referendum, Parliament, and Association governance contracts validate proposer whitelist membership only at proposal creation time, but not at release time. This allows proposers who have been removed from the ProposerWhiteList to still release their previously created and approved proposals, enabling unauthorized proposal execution and bypassing governance controls.

## Finding Description

The vulnerability exists across all three ACS3 governance contracts (Referendum, Parliament, Association) and stems from inconsistent authorization checks between proposal creation and release.

**At Proposal Creation (Time-of-Check):**
All three contracts verify whitelist membership via `AssertIsAuthorizedProposer()`. For Referendum, this check validates that the proposer exists in the organization's ProposerWhiteList: [1](#0-0) [2](#0-1) 

Parliament has similar validation: [3](#0-2) [4](#0-3) 

Association follows the same pattern: [5](#0-4) [6](#0-5) 

**Whitelist Modification Capability:**
Organizations can update their ProposerWhiteList at any time, removing previously authorized proposers: [7](#0-6) [8](#0-7) [9](#0-8) 

**At Proposal Release (Time-of-Use):**
The `Release()` function only verifies that the caller is the original proposer, without re-checking current whitelist membership. For Referendum: [10](#0-9) 

Parliament's Release: [11](#0-10) 

Association's Release: [12](#0-11) 

**Attack Sequence:**
1. Proposer is initially in ProposerWhiteList (legitimate state)
2. Proposer creates proposal via `CreateProposal()` - passes whitelist validation
3. Proposal receives sufficient approval votes from organization members
4. Organization removes proposer from ProposerWhiteList via `ChangeOrganizationProposerWhiteList()`
5. Removed proposer calls `Release()` on the approved proposal
6. Release succeeds because only proposer identity is checked, not current whitelist status
7. Proposal executes with organization's virtual address authority

This breaks the security guarantee that whitelist removal should revoke all proposal-related privileges for that address.

## Impact Explanation

**Unauthorized Governance Execution:**
A proposer removed from the whitelist retains the ability to execute previously created proposals, even after the organization has explicitly revoked their authorization. This enables:

- **Fund Transfers**: Proposals can transfer tokens from organization-controlled virtual addresses
- **Configuration Changes**: Proposals can modify critical contract parameters or governance thresholds
- **Arbitrary Contract Calls**: Proposals can execute any contract method with organization authority

**Governance Security Violation:**
Organizations lose the ability to effectively revoke proposal release rights from problematic proposers. Common scenarios include:
- Responding to compromised proposer accounts
- Removing malicious or rogue members
- Policy updates that restrict proposer authority
- Emergency response to detected threats

**Privilege Persistence:**
The vulnerability creates a persistent privilege problem where removed proposers maintain execution capabilities for all their approved proposals until those proposals expire or are manually cleared.

**Severity Justification (Medium):**
While proposals still require threshold approval from voters (limiting arbitrary execution), the vulnerability enables unauthorized execution after explicit privilege revocation. The impact scales with organization authority and the number of approved proposals at the time of removal.

## Likelihood Explanation

**Attack Prerequisites:**
1. Attacker must initially be a legitimate whitelisted proposer (achievable through normal governance)
2. Create one or more proposals while authorized (standard governance workflow)
3. Wait for proposals to receive sufficient approval votes (requires voter participation)
4. After whitelist removal, call `Release()` on approved proposals (single transaction)

**Attack Complexity: Low**
- Single function call to `Release(proposalId)`
- No special privileges beyond initially being whitelisted
- No complex state manipulation required
- Works identically across all three governance contracts

**Realistic Scenarios:**
Organizations routinely update ProposerWhiteLists to:
- Remove compromised or suspicious accounts
- Revoke access from departed members
- Respond to detected malicious behavior
- Update governance policies and authority structures

**Detection Difficulty:**
The vulnerability is difficult to detect because:
- Removed proposers retain valid `proposal.Proposer` status in storage
- No on-chain indication that proposer is no longer whitelisted
- Standard monitoring would not flag the Release transaction as anomalous

**Economic Rationality:**
- Cost: Only transaction gas fees for `Release()`
- Benefit: Execute proposals with full organization authority after removal
- Rational for attackers to create multiple proposals before expected removal

**Probability: Medium-High**
Whitelist changes are common governance operations, making this scenario likely in production environments.

## Recommendation

Add a whitelist re-validation check in the `Release()` function to ensure the proposer is still authorized at release time.

For Referendum contract:
```csharp
public override Empty Release(Hash input)
{
    var proposal = GetValidProposal(input);
    Assert(Context.Sender.Equals(proposal.Proposer), "No permission.");
    
    // Add re-validation of whitelist membership
    AssertIsAuthorizedProposer(proposal.OrganizationAddress, proposal.Proposer);
    
    var organization = State.Organizations[proposal.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposal, organization), "Not approved.");
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), 
        proposal.ToAddress,
        proposal.ContractMethodName, 
        proposal.Params);

    Context.Fire(new ProposalReleased { ProposalId = input });
    State.Proposals.Remove(input);

    return new Empty();
}
```

Apply the same fix to Parliament and Association contracts by adding `AssertIsAuthorizedProposer(proposal.OrganizationAddress, proposal.Proposer)` after the initial proposer identity check.

This ensures that proposer authorization is validated at both proposal creation and release time, eliminating the TOCTOU vulnerability.

## Proof of Concept

```csharp
[Fact]
public async Task TOCTOU_RemovedProposerCanStillRelease_Test()
{
    // Setup: Create organization with proposer in whitelist
    var proposer = Accounts[0].KeyPair;
    var organizationAddress = await CreateOrganizationAsync(
        minimalApproveThreshold: 5000, 
        minimalVoteThreshold: 5000,
        maximalAbstentionThreshold: 10000, 
        maximalRejectionThreshold: 10000,
        proposers: new[] { Address.FromPublicKey(proposer.PublicKey) }
    );

    // Step 1: Proposer creates proposal while whitelisted
    var proposalInput = new CreateProposalInput
    {
        ContractMethodName = "TestMethod",
        ToAddress = TokenContractAddress,
        Params = ByteString.Empty,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        OrganizationAddress = organizationAddress
    };
    
    var proposalId = await ReferendumContractStub.CreateProposal.CallAsync(proposalInput);

    // Step 2: Proposal gets approved
    await ApproveAllowanceAsync(Accounts[3].KeyPair, 5000, proposalId);
    await ApproveAsync(Accounts[3].KeyPair, proposalId);

    // Step 3: Organization removes proposer from whitelist
    var newWhiteList = new ProposerWhiteList
    {
        Proposers = { Accounts[1].Address } // Different address, proposer removed
    };
    
    var changeWhitelistProposal = await CreateReferendumProposalAsync(
        proposer,
        newWhiteList,
        nameof(ReferendumContractStub.ChangeOrganizationProposerWhiteList),
        organizationAddress,
        ReferendumContractAddress
    );
    
    await ApproveAllowanceAsync(Accounts[3].KeyPair, 5000, changeWhitelistProposal);
    await ApproveAsync(Accounts[3].KeyPair, changeWhitelistProposal);
    await ReferendumContractStub.Release.SendAsync(changeWhitelistProposal);

    // Verify proposer is no longer in whitelist
    var validateResult = await ReferendumContractStub.ValidateProposerInWhiteList.CallAsync(
        new ValidateProposerInWhiteListInput
        {
            OrganizationAddress = organizationAddress,
            Proposer = Address.FromPublicKey(proposer.PublicKey)
        }
    );
    validateResult.Value.ShouldBeFalse(); // Proposer removed from whitelist

    // Step 4: VULNERABILITY - Removed proposer can still release their approved proposal
    var releaseResult = await ReferendumContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    // This should fail but succeeds - unauthorized execution after whitelist removal
}
```

## Notes

This vulnerability affects all organizations using AElf's governance contracts (Referendum, Parliament, Association). While proposals still require approval thresholds to be met, the inability to revoke release privileges through whitelist removal creates a significant governance security gap. Organizations should be aware that removing a proposer from the whitelist does not prevent them from releasing previously created and approved proposals.

### Citations

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
