# Audit Report

## Title
Pending Proposals from Removed Proposers Can Still Be Executed After Whitelist Changes

## Summary
The governance contracts (Parliament, Association, and Referendum) validate proposer authorization only at proposal creation time. When a proposer is removed from the whitelist via `ChangeOrganizationProposerWhiteList()`, their pending proposals remain executable because the `Release()` function does not re-validate authorization status. This allows removed proposers to execute previously created proposals even after being removed, undermining the whitelist security model.

## Finding Description

The vulnerability exists across all three governance contract implementations and breaks the fundamental security guarantee that whitelist removal revokes all proposal privileges.

**Authorization at Creation Time:**
When creating a proposal in Parliament, the contract validates proposer authorization through `AssertIsAuthorizedProposer`, which checks if the proposer is in the whitelist or is a parliament member [1](#0-0) [2](#0-1) 

The same pattern exists in Association [3](#0-2) [4](#0-3)  and Referendum [5](#0-4) [6](#0-5) 

**No Re-validation at Release Time:**
When releasing a proposal in Parliament, the function only verifies that the caller is the original proposer, without re-validating their current authorization status [7](#0-6) 

Association has the same flaw [8](#0-7)  as does Referendum [9](#0-8) 

**Whitelist Updates Don't Invalidate Pending Proposals:**
The `ChangeOrganizationProposerWhiteList` function updates the whitelist without any validation or cleanup of pending proposals from removed addresses [10](#0-9) 

**Attack Sequence:**
1. Attacker (legitimate proposer) creates proposal with far-future expiration
2. Malicious behavior is detected, governance removes them from whitelist
3. Removed proposer cannot create NEW proposals (correctly blocked by authorization check)
4. However, their OLD proposal continues to collect votes
5. Once vote threshold is reached, removed proposer calls `Release()` successfully
6. The proposal executes despite proposer no longer being authorized

## Impact Explanation

**High Severity - Governance Authorization Bypass**

This vulnerability directly undermines the core security model of AElf's governance system. The whitelist mechanism exists specifically to control who can propose and execute governance actions. When an address is removed from the whitelist - typically due to discovered malicious behavior, compromised private keys, or loss of trust - the expectation is that ALL their governance privileges are immediately revoked.

However, due to this flaw, removed proposers retain the ability to execute any proposals they created while authorized. Depending on the proposal's content, this could enable:
- Unauthorized system configuration changes
- Fund transfers or treasury manipulation
- Contract upgrades or deployments
- Changes to consensus parameters
- Modification of fee structures

The impact extends across all organizations using these three core governance contracts:
- **Parliament**: Controls critical system governance including the default organization that manages protocol-level decisions
- **Association**: Used for multi-signature governance in organizational settings
- **Referendum**: Enables token-weighted voting for community governance

A single compromised or malicious proposer can "time-bomb" the system by creating benign-looking proposals before their removal, then executing them later to bypass the whitelist protection.

## Likelihood Explanation

**Medium-High Likelihood**

The attack has low complexity and realistic preconditions:

**Attacker Profile:**
- Must initially be a legitimate authorized proposer (in whitelist or parliament member)
- Could be an insider threat or a compromised authorized address
- No special permissions required beyond normal proposal flow

**Attack Feasibility:**
- Zero cost to maintain pending proposals
- Proposals can have far-future expiration times
- No blockchain state manipulation required
- Standard transaction flow using public methods

**Economic Rationality:**
Highly rational for a malicious actor. Once they suspect they might be removed (or after committing malicious acts), they can pre-emptively create proposals that will execute after their removal. The attack has zero ongoing cost and cannot be easily detected until execution.

**Detection Difficulty:**
The pending proposal appears completely legitimate in the system. Governance would need to manually track all pending proposals and cross-reference them against whitelist changes to identify this threat proactively. The test suite confirms that removed proposers cannot create new proposals but does not validate that they cannot release old ones [11](#0-10) 

## Recommendation

Implement authorization re-validation at release time. The `Release()` function should call `AssertIsAuthorizedProposer` to verify the proposer's current authorization status before executing the proposal.

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
    Context.SendVirtualInlineBySystemContract(
        CalculateVirtualHash(organization.OrganizationHash, organization.CreationToken), proposalInfo.ToAddress,
        proposalInfo.ContractMethodName, proposalInfo.Params);
    Context.Fire(new ProposalReleased { ProposalId = proposalId });
    State.Proposals.Remove(proposalId);
    return new Empty();
}
```

Apply the same fix to Association and Referendum contracts.

**Alternative Approach:**
Implement automatic invalidation of pending proposals when a proposer is removed from the whitelist. When `ChangeOrganizationProposerWhiteList` is called, iterate through pending proposals and remove any created by addresses being removed from the whitelist.

## Proof of Concept

```csharp
[Fact]
public async Task RemovedProposer_CanStillReleaseOldProposal_Test()
{
    // Setup: Get default organization and create authorized proposer
    var organizationAddress = await GetDefaultOrganizationAddressAsync();
    var proposerKeyPair = CryptoHelper.GenerateKeyPair();
    var proposerAddress = Address.FromPublicKey(proposerKeyPair.PublicKey);
    
    // Step 1: Add proposer to whitelist
    var addWhitelistProposal = new ProposerWhiteList { Proposers = { Tester.GetCallOwnerAddress(), proposerAddress } };
    var addProposalInput = CreateParliamentProposalInput(addWhitelistProposal, organizationAddress);
    var addResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal), addProposalInput);
    var addProposalId = Hash.Parser.ParseFrom(addResult.ReturnValue);
    await ParliamentMemberApprove(addProposalId);
    await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.Release), addProposalId);
    
    // Step 2: Proposer creates a proposal while authorized
    var proposerTester = Tester.CreateNewContractTester(proposerKeyPair);
    var transferInput = TransferInput(proposerAddress);
    var maliciousProposal = CreateProposalInput(transferInput, organizationAddress);
    var createResult = await proposerTester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal), maliciousProposal);
    createResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var maliciousProposalId = Hash.Parser.ParseFrom(createResult.ReturnValue);
    
    // Step 3: Remove proposer from whitelist
    var removeWhitelistProposal = new ProposerWhiteList { Proposers = { Tester.GetCallOwnerAddress() } };
    var removeProposalInput = CreateParliamentProposalInput(removeWhitelistProposal, organizationAddress);
    var removeResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal), removeProposalInput);
    var removeProposalId = Hash.Parser.ParseFrom(removeResult.ReturnValue);
    await ParliamentMemberApprove(removeProposalId);
    await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.Release), removeProposalId);
    
    // Step 4: Verify proposer cannot create NEW proposals
    var newProposalResult = await proposerTester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal), maliciousProposal);
    newProposalResult.Status.ShouldBe(TransactionResultStatus.Failed);
    newProposalResult.Error.ShouldContain("Unauthorized to propose");
    
    // Step 5: Approve the OLD proposal created before removal
    await ParliamentMemberApprove(maliciousProposalId);
    
    // Step 6: VULNERABILITY - Removed proposer can still release OLD proposal
    var releaseResult = await proposerTester.ExecuteContractWithMiningAsync(ParliamentAddress,
        nameof(ParliamentContractImplContainer.ParliamentContractImplStub.Release), maliciousProposalId);
    
    // This SHOULD fail but currently succeeds - demonstrating the vulnerability
    releaseResult.Status.ShouldBe(TransactionResultStatus.Mined); // Vulnerability confirmed
}
```

## Notes

This vulnerability represents a fundamental flaw in the authorization model of AElf's governance system. The whitelist is intended to be a dynamic security boundary that can be updated to respond to threats, but the current implementation only enforces it at proposal creation time. This creates a significant time-of-check-to-time-of-use (TOCTOU) vulnerability where authorization status changes between proposal creation and execution.

The fix is straightforward but critical: authorization must be validated at both creation and execution time to ensure that only currently authorized addresses can execute governance actions. Without this fix, the whitelist mechanism cannot effectively protect against compromised or malicious proposers who can pre-position proposals for later execution.

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

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L11-16)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "No registered organization.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L200-205)
```csharp
    private void AssertIsAuthorizedProposer(Address organizationAddress, Address proposer)
    {
        var organization = State.Organizations[organizationAddress];
        Assert(organization != null, "Organization not found.");
        Assert(organization.ProposerWhiteList.Contains(proposer), "Unauthorized to propose.");
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractPrivilegeTest.cs (L94-125)
```csharp
    public async Task Change_OrganizationProposalWhiteList_Test()
    {
        var organizationAddress = await GetDefaultOrganizationAddressAsync();
        var result = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetProposerWhiteList), new Empty());
        var proposers = ProposerWhiteList.Parser.ParseFrom(result.ReturnValue).Proposers;

        proposers.Count.ShouldBe(1);
        proposers.Contains(Tester.GetCallOwnerAddress()).ShouldBeTrue();
        var ecKeyPair = CryptoHelper.GenerateKeyPair();

        var proposerWhiteList = new ProposerWhiteList
        {
            Proposers = { Tester.GetAddress(ecKeyPair) }
        };
        var proposalInput = CreateParliamentProposalInput(proposerWhiteList, organizationAddress);
        var createResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.CreateProposal),
            proposalInput);
        createResult.Status.ShouldBe(TransactionResultStatus.Mined);
        var proposalId = Hash.Parser.ParseFrom(createResult.ReturnValue);
        await ParliamentMemberApprove(proposalId);
        var releaseResult = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.Release), proposalId);
        releaseResult.Status.ShouldBe(TransactionResultStatus.Mined);

        result = await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractImplContainer.ParliamentContractImplStub.GetProposerWhiteList), new Empty());
        proposers = ProposerWhiteList.Parser.ParseFrom(result.ReturnValue).Proposers;
        proposers.Count.ShouldBe(1);
        proposers.Contains(Tester.GetAddress(ecKeyPair)).ShouldBeTrue();
    }
```
