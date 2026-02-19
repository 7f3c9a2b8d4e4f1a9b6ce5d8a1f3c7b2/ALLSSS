# Audit Report

## Title
Pending Proposals from Removed Proposers Can Still Be Executed After Whitelist Changes

## Summary
The governance contracts (Parliament, Association, and Referendum) validate proposer authorization only at proposal creation time, not at release time. This allows proposers who are removed from the whitelist to still execute their previously created proposals, undermining the whitelist security control mechanism.

## Finding Description

The vulnerability exists in the proposal lifecycle across all three governance contracts. When a proposal is created, the system validates that the proposer is authorized via the `AssertIsAuthorizedProposer` function [1](#0-0) [2](#0-1) . This check confirms the proposer is either in the whitelist or is a parliament member (when allowed).

However, when releasing a proposal, the `Release` function only verifies that the caller is the original proposer, without re-validating their current authorization status [3](#0-2) . The critical check at line 135 only confirms `Context.Sender.Equals(proposalInfo.Proposer)` without calling `AssertIsAuthorizedProposer` or checking the current whitelist.

The `ChangeOrganizationProposerWhiteList` function can remove addresses from the whitelist without considering their pending proposals [4](#0-3) .

**Attack Scenario:**
1. Authorized proposer creates a malicious proposal
2. Malicious behavior is detected, proposer is removed from whitelist via `ChangeOrganizationProposerWhiteList`
3. The proposal continues to collect votes from organization members
4. Removed proposer successfully calls `Release()` once approval threshold is reached
5. Proposal executes despite proposer no longer being authorized

**Same pattern exists in other governance contracts:**
- Association: [5](#0-4)  (creation with auth check), [6](#0-5)  (release without re-check)
- Referendum: [7](#0-6)  (creation with auth check), [8](#0-7)  (release without re-check)

## Impact Explanation

This is a **HIGH severity** governance security bypass that affects all three governance contract types:

1. **Security Control Circumvention**: When a proposer is removed from the whitelist (typically due to malicious behavior, key compromise, or loss of trust), the intent is to revoke their governance powers. However, they retain the ability to execute any proposals created while authorized.

2. **Concrete Harm**: Depending on proposal content, this could lead to:
   - Unauthorized system configuration changes
   - Unauthorized fund transfers or movements
   - Unauthorized contract upgrades or deployments
   - Unauthorized parameter modifications

3. **Scope**: Affects Parliament contract (including the default organization managing system governance), Association contract (multi-sig governance), and Referendum contract (token-weighted voting).

4. **Trust Model Break**: The whitelist mechanism is a critical security boundary. Its compromise defeats the purpose of governance access control.

## Likelihood Explanation

**HIGH likelihood** due to:

1. **Low Attack Complexity**: Straightforward sequence requiring no special blockchain manipulation:
   - Create proposal while authorized
   - Get removed from whitelist (or trigger removal)
   - Wait for proposal to reach approval threshold
   - Call `Release()`

2. **Realistic Attacker Profile**: 
   - Insider threat (initially authorized proposer)
   - Compromised authorized address
   - No special permissions needed beyond normal proposal rights

3. **Economic Rationality**: Zero cost to maintain a pending proposal - attacker simply waits for votes to accumulate.

4. **Detection Gap**: Existing tests confirm removed proposers cannot create NEW proposals [9](#0-8) , but do not test whether they can release OLD proposals.

5. **Time Window**: Proposals can have long expiration periods, giving attackers ample time to execute after removal.

## Recommendation

Add authorization re-validation in the `Release` function for all three governance contracts. Before executing the proposal, verify that the proposer is still authorized:

**For Parliament Contract:**
```csharp
public override Empty Release(Hash proposalId)
{
    var proposalInfo = GetValidProposal(proposalId);
    Assert(Context.Sender.Equals(proposalInfo.Proposer), "No permission.");
    
    // Add re-validation of proposer authorization
    AssertIsAuthorizedProposer(proposalInfo.OrganizationAddress, proposalInfo.Proposer);
    
    var organization = State.Organizations[proposalInfo.OrganizationAddress];
    Assert(IsReleaseThresholdReached(proposalInfo, organization), "Not approved.");
    // ... rest of execution
}
```

Apply the same fix pattern to Association and Referendum contracts by adding the authorization check before proposal execution.

**Alternative approach**: When removing a proposer from the whitelist, provide a mechanism to automatically clear or invalidate their pending proposals.

## Proof of Concept

```csharp
[Fact]
public async Task RemovedProposer_Can_Still_Release_Pending_Proposal_Test()
{
    // 1. Create organization with initial proposer in whitelist
    var proposerKeyPair = CryptoHelper.GenerateKeyPair();
    var proposerAddress = Address.FromPublicKey(proposerKeyPair.PublicKey);
    
    var organizationAddress = await CreateOrganizationAsync(
        proposerWhiteList: new[] { proposerAddress }
    );
    
    // 2. Proposer creates a proposal while authorized
    var proposerStub = GetParliamentContractTester(proposerKeyPair);
    var proposalInput = CreateProposalInput(transferInput, organizationAddress);
    var proposalId = await proposerStub.CreateProposal.CallAsync(proposalInput);
    
    // 3. Remove proposer from whitelist
    var newWhiteList = new ProposerWhiteList { Proposers = { } }; // Empty whitelist
    var changeWhitelistProposal = await CreateParliamentProposalAsync(
        newWhiteList, 
        organizationAddress,
        nameof(ParliamentContractStub.ChangeOrganizationProposerWhiteList)
    );
    await ParliamentMemberApprove(changeWhitelistProposal);
    await ReleaseProposalAsync(changeWhitelistProposal);
    
    // 4. Verify proposer cannot create NEW proposals
    var result = await proposerStub.CreateProposal.SendWithExceptionAsync(proposalInput);
    result.TransactionResult.Error.ShouldContain("Unauthorized to propose");
    
    // 5. Original proposal gets approved by parliament members
    await ParliamentMemberApprove(proposalId);
    
    // 6. VULNERABILITY: Removed proposer can still release the old proposal
    var releaseResult = await proposerStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Proposal executes despite proposer being removed from whitelist
}
```

### Citations

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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-58)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
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

**File:** test/AElf.Contracts.Referendum.Tests/ReferendumContractTest.cs (L844-848)
```csharp
        ReferendumContractStub = GetReferendumContractTester(DefaultSenderKeyPair);
        var result = await ReferendumContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        result.TransactionResult.Error.ShouldContain("Unauthorized to propose.");
    }
```
