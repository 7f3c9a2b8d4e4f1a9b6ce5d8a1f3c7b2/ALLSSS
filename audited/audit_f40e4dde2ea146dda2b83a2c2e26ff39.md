### Title
Proposer Override in CreateProposalBySystemContract Breaks Governance Model and Creates Incorrect Audit Trail

### Summary
When system contracts create proposals via `CreateProposalBySystemContract`, the `OriginProposer` parameter is validated for authorization but then completely discarded. The proposal's proposer field is set to `Context.Sender` (the system contract) instead of the actual `OriginProposer`, preventing the original user from releasing their proposal and creating misleading governance records. This issue affects all three governance contracts (Association, Parliament, and Referendum).

### Finding Description

In the `CreateProposalBySystemContract` function, the code validates that `input.OriginProposer` is an authorized proposer: [1](#0-0) 

The authorization check at line 118 validates `input.OriginProposer` against the organization's proposer whitelist. However, when `CreateNewProposal` is subsequently called, the proposer field is hardcoded to `Context.Sender`: [2](#0-1) 

At line 157, `Proposer = Context.Sender` is set, where `Context.Sender` is the system contract (not the `OriginProposer`). This creates a fundamental mismatch: authorization is checked against the actual user, but the stored proposer is the system contract.

The `CreateProposalBySystemContractInput` proto definition explicitly includes `origin_proposer` as "The actor that trigger the call": [3](#0-2) 

When proposals are released, the `Release` function enforces that only the stored proposer can release: [4](#0-3) 

The permission check at line 186 requires `Context.Sender == proposalInfo.Proposer`, meaning only the system contract can release proposals created via `CreateProposalBySystemContract`, not the original user.

This same issue exists in Parliament and Referendum contracts: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Governance Model Violation:**
- Users who pass authorization checks cannot release their own proposals directly
- Only the system contract can call `Release`, forcing a mandatory wrapper function architecture
- This breaks the standard governance model where proposers control their proposals

**Incorrect Audit Trail:**
- All proposals show the system contract as proposer in `GetProposal` responses, not the actual user
- Governance transparency is compromised as the real initiator is hidden
- External observers cannot identify who actually proposed changes

**Loss of User Control:**
- Original proposers lose direct control over proposal lifecycle
- Users must rely on system contract wrapper functions (e.g., `ReleaseApprovedContract` in Genesis contract) to release proposals
- If a system contract lacks proper wrapper functions, proposals become unreleasable by their creators

**System-Wide Impact:**
This affects critical governance flows including:
- Contract deployment proposals (Genesis contract)
- Cross-chain indexing proposals (CrossChain contract)
- All governance actions routed through system contracts

The proposer field is exposed in the public API and used for permission checks, making this a core governance integrity issue affecting all three governance contract types (Association, Parliament, Referendum).

### Likelihood Explanation

**Certainty: 100%**
This issue occurs every time `CreateProposalBySystemContract` is invoked across all three governance contracts.

**Real-World Usage:**
The function is actively used in production code:
- Genesis contract for contract deployment/update proposals [7](#0-6) 

- CrossChain contract for indexing proposals [8](#0-7) 

**Mitigation Exists But Issue Remains:**
System contracts implement wrapper functions to work around this issue (e.g., `ReleaseApprovedContract` validates the original proposer in its own state before calling Release). However, this doesn't eliminate the problem:
- Proposals still show incorrect proposer in all queries
- Users cannot release proposals directly through the governance contract
- The architecture is forced into a specific pattern not documented in ACS3

### Recommendation

**Code-Level Fix:**
Modify `CreateNewProposal` to accept an optional proposer parameter. Update all three governance contracts (Association, Parliament, Referendum):

```csharp
private Hash CreateNewProposal(CreateProposalInput input, Address proposer = null)
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
        Proposer = proposer ?? Context.Sender,  // Use provided proposer or fall back to Context.Sender
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

Then update `CreateProposalBySystemContract` to pass the origin proposer:
```csharp
public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
{
    Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
        "Not authorized to propose.");
    AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);
    var proposalId = CreateNewProposal(input.ProposalInput, input.OriginProposer);
    return proposalId;
}
```

**Additional Safeguards:**
1. Add explicit test cases verifying that proposals created via `CreateProposalBySystemContract` show the correct `OriginProposer` in `GetProposal` responses
2. Add test cases where `OriginProposer` attempts to release proposals directly
3. Update documentation to clarify the intended behavior and proposer semantics

### Proof of Concept

**Initial State:**
- User A is whitelisted as proposer in an Association organization
- A system contract exists that can call `CreateProposalBySystemContract`

**Exploit Steps:**

1. User A calls system contract function that invokes `CreateProposalBySystemContract`:
   - Input: `OriginProposer = User A`, `ProposalInput = {valid proposal data}`
   - Authorization check passes (User A is whitelisted)
   - Proposal is created with `Proposer = System Contract` (not User A)

2. Organization members vote and approve the proposal

3. User A attempts to release the proposal by calling `Release(proposalId)` on Association contract:
   - **Expected:** User A can release their own proposal
   - **Actual:** Transaction fails with "No permission" because `Context.Sender (User A) != proposalInfo.Proposer (System Contract)`

4. Anyone calls `GetProposal(proposalId)`:
   - **Expected:** Returns `Proposer = User A`
   - **Actual:** Returns `Proposer = System Contract`

**Success Condition:**
The vulnerability is confirmed when:
- User A passes authorization but cannot release their proposal
- Proposal records show System Contract as proposer instead of User A
- Only the System Contract can successfully call `Release`

This demonstrates that the `OriginProposer` parameter is validated but then completely ignored, breaking the governance model and creating incorrect audit records.

### Citations

**File:** contract/AElf.Contracts.Association/Association.cs (L114-121)
```csharp
    public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
    {
        Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
            "Not authorized to propose.");
        AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);
        var proposalId = CreateNewProposal(input.ProposalInput);
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

**File:** protobuf/acs3.proto (L151-156)
```text
message CreateProposalBySystemContractInput {
    // The parameters of creating proposal.
    acs3.CreateProposalInput proposal_input =1;
    // The actor that trigger the call.
    aelf.Address origin_proposer = 2;
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

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L159-187)
```csharp
    private Hash CreateNewProposal(CreateProposalInput input)
    {
        CheckCreateProposalInput(input);
        var proposalId = GenerateProposalId(input);
        Assert(State.Proposals[proposalId] == null, "Proposal already exists.");
        var proposal = new ProposalInfo
        {
            ContractMethodName = input.ContractMethodName,
            ToAddress = input.ToAddress,
            ExpiredTime = input.ExpiredTime,
            Params = input.Params,
            OrganizationAddress = input.OrganizationAddress,
            Proposer = Context.Sender,
            ProposalDescriptionUrl = input.ProposalDescriptionUrl,
            Title = input.Title,
            Description = input.Description
        };
        Assert(Validate(proposal), "Invalid proposal.");
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L143-165)
```csharp
        var proposalCreationInput = new CreateProposalBySystemContractInput
        {
            ProposalInput = new CreateProposalInput
            {
                ToAddress = Context.Self,
                ContractMethodName =
                    nameof(BasicContractZeroImplContainer.BasicContractZeroImplBase.ProposeContractCodeCheck),
                Params = new ContractCodeCheckInput
                {
                    ContractInput = input.ToByteString(),
                    CodeCheckReleaseMethod = nameof(DeploySmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = input.Category,
                    IsSystemContract = false
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput.ToByteString());
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
