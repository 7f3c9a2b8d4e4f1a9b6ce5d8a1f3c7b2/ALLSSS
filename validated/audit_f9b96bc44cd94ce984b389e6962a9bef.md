# Audit Report

## Title
Proposal-Request Mismatch in ReleaseSideChainCreation Allows Unauthorized Token Creation

## Summary
The `ReleaseSideChainCreation()` function retrieves the side chain creation request from `Context.Sender`'s storage but releases a proposal specified by `input.ProposalId` without validating these are correlated. This allows an attacker with a pending request to release any approved proposal, creating a token for the attacker while consuming the victim's governance-approved proposal.

## Finding Description

The vulnerability exists in `ReleaseSideChainCreation()` where token creation and proposal release operate on disconnected data sources without validation. [1](#0-0) 

The function retrieves the creation request keyed by `Context.Sender`, then creates a token using this retrieved request (including the attacker's token parameters: symbol, supply, decimals, with the attacker as issuer and owner). It then releases `input.ProposalId` which may belong to a completely different user. **There is no validation that `input.ProposalId` was created by or corresponds to `Context.Sender`'s stored request.** [2](#0-1) 

When a proposal is created via `ProposeNewSideChain()`, the proposal params include both the creation request and the proposer address. [3](#0-2) 

When the proposal is released by the governance contract, it calls `CreateSideChain()` with the proposer from the proposal params, retrieving the request state keyed by `input.Proposer` (the victim's address from the proposal), not `Context.Sender`. [4](#0-3) 

The token is created with the `creator` as both Issuer and Owner, using token parameters from the creation request.

**Attack Flow:**
1. User A calls `RequestSideChainCreation` with request (token symbol "AAA", supply 1000)
2. User B calls `RequestSideChainCreation` with request (token symbol "BBB", supply 2000)
3. Parliament approves User A's proposal
4. User B calls `ReleaseSideChainCreation(User_A_ProposalId)`
5. Token "BBB" is created with User B as issuer/owner
6. User A's proposal is consumed for side chain creation
7. User A's token is never created despite governance approval [5](#0-4) 

The Parliament contract's `Release` method checks that the caller equals the proposal's proposer. However, this check verifies `Context.Sender` (the CrossChain contract when called via SendInline) equals `proposalInfo.Proposer`. [6](#0-5) 

Since proposals created via `CreateProposalBySystemContract` store `Context.Sender` (the CrossChain contract) as the proposer, any call from the CrossChain contract can release any CrossChain-created proposal, bypassing user-level authorization.

## Impact Explanation

**Direct Economic Impact**: The attacker obtains a token on the main chain with their chosen parameters (symbol, supply, decimals) with themselves as issuer and owner. They can issue these tokens to themselves or others, gaining economic value without governance approval.

**Governance Integrity Impact**: The victim's approved proposal is consumed but their token is not created. The governance process is circumvented - a proposal that was reviewed and approved for User A's token creation is instead used to create User B's token.

**Protocol Invariant Violation**: The system's guarantee that "an approved proposal creates the token specified in that proposal" is broken. Token creation and side chain creation operate on different users' requests, violating the expected atomicity between proposal approval and execution.

**Affected Parties**:
- Victim: Approved proposal consumed without receiving token creation benefit
- Attacker: Receives unauthorized token creation without governance approval
- Protocol: Governance integrity compromised, enabling arbitrary token creation

## Likelihood Explanation

**Attacker Capabilities Required**:
- Submit side chain creation request via `RequestSideChainCreation()` (public method, no special privileges)
- Observe victim's approved proposal ID (publicly visible on-chain via events/state queries)
- Call `ReleaseSideChainCreation()` with victim's proposal ID (public method)

**Attack Complexity**: Low - single transaction exploit with no complex setup. Proposal IDs are observable from blockchain events and state queries.

**Preconditions**:
- Multiple users have pending side chain creation requests (common in production environments where multiple entities want to create side chains)
- At least one proposal is approved by Parliament (happens regularly as part of normal governance operations)
- No authorization check prevents calling `ReleaseSideChainCreation()` with arbitrary proposal IDs

**Economic Rationality**: Tokens created as side chain tokens have inherent value through issuer privileges (ability to issue/mint), owner privileges, and potential secondary market value. The attack cost is only gas fees, while the benefit is obtaining governance-approved token creation rights without undergoing governance approval.

**Probability**: High - the vulnerability is trivially exploitable whenever the preconditions exist, which represents the normal operating state of the protocol.

## Recommendation

Add validation in `ReleaseSideChainCreation()` to ensure that the provided `input.ProposalId` corresponds to `Context.Sender`'s stored request:

1. Store the proposal ID when creating the request in `RequestSideChainCreation()`
2. Validate that `input.ProposalId` matches the stored proposal ID for `Context.Sender`

Alternatively, remove the decoupling by having the proposal release mechanism itself call the token creation with the proposer from the proposal params, ensuring atomicity between proposal approval and execution.

## Proof of Concept

```csharp
[Fact]
public async Task Exploit_ProposalRequestMismatch_UnauthorizedTokenCreation()
{
    // Setup
    await InitializeCrossChainContractAsync();
    
    // User A creates request and proposal
    var userAStub = GetCrossChainContractStub(UserAKeyPair);
    await ApproveBalanceAsync(100, UserAKeyPair);
    var requestA = CreateSideChainCreationRequest(1, 100, "AAA", 1000);
    await userAStub.RequestSideChainCreation.SendAsync(requestA);
    var proposalA = await GetProposalIdForUser(UserAAddress);
    await ApproveWithMinersAsync(proposalA);
    
    // User B creates request (different parameters)
    var userBStub = GetCrossChainContractStub(UserBKeyPair);
    await ApproveBalanceAsync(100, UserBKeyPair);
    var requestB = CreateSideChainCreationRequest(1, 100, "BBB", 2000);
    await userBStub.RequestSideChainCreation.SendAsync(requestB);
    
    // User B releases User A's proposal
    var result = await userBStub.ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = proposalA });
    
    // Verify: Token BBB created with User B as issuer/owner
    var tokenBBB = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "BBB" });
    tokenBBB.Issuer.ShouldBe(UserBAddress);
    tokenBBB.Owner.ShouldBe(UserBAddress);
    
    // Verify: Token AAA was NOT created
    var tokenAAA = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "AAA" });
    tokenAAA.Symbol.ShouldBeEmpty(); // Token doesn't exist
    
    // Verify: User A's proposal consumed
    var proposalState = await ParliamentContractStub.GetProposal.CallAsync(proposalA);
    proposalState.ProposalId.ShouldBeNull(); // Proposal removed after release
}
```

## Notes

The vulnerability stems from a fundamental architectural flaw where user-initiated actions (token creation from Context.Sender's request) are decoupled from governance-approved actions (proposal release with arbitrary proposal ID). The Parliament contract's authorization model checks contract-level permissions but not user-level ownership, allowing any user with a pending request to hijack any approved proposal. This breaks the core governance guarantee that approved proposals execute the approved actions for the approved beneficiaries.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L98-114)
```csharp
    public override Empty ReleaseSideChainCreation(ReleaseSideChainCreationInput input)
    {
        var sideChainCreationRequest = State.ProposedSideChainCreationRequestState[Context.Sender];
        Assert(sideChainCreationRequest != null, "Release side chain creation failed.");
        if (!TryClearExpiredSideChainCreationRequestProposal(input.ProposalId, Context.Sender))
        {
            var serialNumber = State.SideChainSerialNumber.Value.Add(1);
            var chainId = GetChainId(serialNumber);
            CreateSideChainToken(sideChainCreationRequest.SideChainCreationRequest, chainId,
                sideChainCreationRequest.Proposer);
            Context.SendInline(State.SideChainLifetimeController.Value.ContractAddress,
                nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release),
                input.ProposalId);
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L121-133)
```csharp
    public override Int32Value CreateSideChain(CreateSideChainInput input)
    {
        // side chain creation should be triggered by organization address.
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var proposedSideChainCreationRequestState = State.ProposedSideChainCreationRequestState[input.Proposer];
        State.ProposedSideChainCreationRequestState.Remove(input.Proposer);
        var sideChainCreationRequest = input.SideChainCreationRequest;
        Assert(
            proposedSideChainCreationRequestState != null &&
            proposedSideChainCreationRequestState.SideChainCreationRequest.Equals(sideChainCreationRequest),
            "Side chain creation failed without proposed data.");
        AssertValidSideChainCreationRequest(sideChainCreationRequest, input.Proposer);
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L176-195)
```csharp
    private void CreateSideChainToken(SideChainCreationRequest sideChainCreationRequest, int chainId,
        Address creator)
    {
        if (!IsPrimaryTokenNeeded(sideChainCreationRequest))
            return;

        // new token needed only for exclusive side chain
        SetContractStateRequired(State.TokenContract, SmartContractConstants.TokenContractSystemName);
        State.TokenContract.Create.Send(new CreateInput
        {
            TokenName = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenName,
            Decimals = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenDecimals,
            IsBurnable = true,
            Issuer = creator,
            IssueChainId = chainId,
            Symbol = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenSymbol,
            TotalSupply = sideChainCreationRequest.SideChainTokenCreationRequest.SideChainTokenTotalSupply,
            Owner = creator
        });
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L360-388)
```csharp
    private SideChainCreationRequestState ProposeNewSideChain(SideChainCreationRequest request, Address proposer)
    {
        var sideChainLifeTimeController = GetSideChainLifetimeController();
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput =
                new CreateProposalInput
                {
                    ContractMethodName = nameof(CreateSideChain),
                    ToAddress = Context.Self,
                    ExpiredTime =
                        Context.CurrentBlockTime.AddSeconds(SideChainCreationProposalExpirationTimePeriod),
                    Params = new CreateSideChainInput { SideChainCreationRequest = request, Proposer = proposer }
                        .ToByteString(),
                    OrganizationAddress = sideChainLifeTimeController.OwnerAddress
                },
            OriginProposer = Context.Sender
        };
        Context.SendInline(sideChainLifeTimeController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);
        var sideChainCreationRequest = new SideChainCreationRequestState
        {
            SideChainCreationRequest = request,
            ExpiredTime = proposalCreationInput.ProposalInput.ExpiredTime,
            Proposer = proposer
        };
        return sideChainCreationRequest;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L225-253)
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
