### Title
Incorrect Proposer Assignment in CreateProposalBySystemContract Causes Loss of User Control Over Proposals

### Summary
When proposals are created via `CreateProposalBySystemContract`, the `Proposer` field is incorrectly set to the system contract address (`Context.Sender`) instead of the actual user (`OriginProposer`). This prevents users from directly releasing their own proposals and creates a mandatory dependency on system contracts implementing release proxy logic, potentially causing proposals to become permanently stuck if the proxy logic is missing or faulty.

### Finding Description
The vulnerability exists in all three governance contracts (Association, Parliament, and Referendum) in their `CreateNewProposal` helper functions: [1](#0-0) [2](#0-1) [3](#0-2) 

When `CreateProposalBySystemContract` is called by system contracts (Genesis, CrossChain), the flow is: [4](#0-3) 

The authorization check correctly validates the `OriginProposer` (the actual user), but `CreateNewProposal` uses `Context.Sender` (the system contract) for the `Proposer` field. This is evident from Genesis contract usage: [5](#0-4) 

The `Release` method in all governance contracts enforces that only the recorded proposer can release: [6](#0-5) [7](#0-6) [8](#0-7) 

Since the proposer is recorded as the system contract address, users cannot directly call `Release` on proposals they initiated.

### Impact Explanation
**Governance Impact:**
1. **Loss of User Autonomy**: Users who create proposals via system contracts (contract deployment/updates, cross-chain operations) cannot directly release them after approval. They are forced to use system contract proxy methods.

2. **Wrong Metadata**: All proposals show the system contract as proposer instead of the actual user, breaking transparency and audit trails. This affects blockchain explorers, events, and any off-chain systems reading proposal data.

3. **Dependency Risk**: Users are completely dependent on system contracts implementing correct release proxy logic. Genesis contract has `ReleaseApprovedContract` and `ReleaseCodeCheckedContract`, but if any system contract using `CreateProposalBySystemContract` lacks proper release logic, those proposals become permanently stuck after approval.

4. **Violation of Design Intent**: The existence and validation of the `OriginProposer` parameter proves the system intends to track the real proposer, but this intent is not honored in the stored proposal data.

This affects all contract deployment/update proposals (via Genesis) and cross-chain indexing proposals (via CrossChain contract).

### Likelihood Explanation
**Guaranteed to Occur:**
- Every proposal created through `CreateProposalBySystemContract` is affected
- Genesis contract uses this for all contract deployments and updates
- CrossChain contract uses this for all cross-chain indexing proposals

**Real-World Usage:** [9](#0-8) [10](#0-9) 

The vulnerability occurs in normal protocol operations, not just edge cases. While current system contracts (Genesis, CrossChain) have implemented workaround release proxies, this creates fragile coupling and the issue will manifest if:
- New system contracts use `CreateProposalBySystemContract` without implementing release proxies
- System contract release logic has bugs or access control issues
- Users attempt to interact directly with governance contracts (reasonable expectation)

### Recommendation
**Immediate Fix:**
Modify `CreateNewProposal` to accept an optional proposer parameter. When called from `CreateProposalBySystemContract`, pass the `OriginProposer` instead of using `Context.Sender`:

```csharp
// In Association.cs (and Parliament.cs, Referendum.cs)
public override Hash CreateProposalBySystemContract(CreateProposalBySystemContractInput input)
{
    Assert(Context.GetSystemContractNameToAddressMapping().Values.Contains(Context.Sender),
        "Not authorized to propose.");
    AssertIsAuthorizedProposer(input.ProposalInput.OrganizationAddress, input.OriginProposer);
    var proposalId = CreateNewProposal(input.ProposalInput, input.OriginProposer); // Pass OriginProposer
    return proposalId;
}

// In Association_Helper.cs (and Parliament_Helper.cs, Referendum_Helper.cs)
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
        Proposer = proposer ?? Context.Sender, // Use provided proposer or fall back to Context.Sender
        ProposalDescriptionUrl = input.ProposalDescriptionUrl,
        Title = input.Title,
        Description = input.Description
    };
    // ... rest of function
}
```

**Test Cases:**
Add tests verifying that proposals created via `CreateProposalBySystemContract` record the `OriginProposer` (not the system contract) in the `Proposer` field, and that the original user can successfully call `Release` after approval.

### Proof of Concept
**Initial State:**
- User address: `UserA`
- Genesis contract address: `GenesisContract`
- Parliament organization with default members including `UserA` as authorized proposer

**Attack/Exploit Sequence:**

1. `UserA` calls `GenesisContract.ProposeUpdateContract(contractUpdateInput)`
   - Genesis sets `OriginProposer = UserA` (Context.Sender at this point)
   
2. `GenesisContract` calls `ParliamentContract.CreateProposalBySystemContract({OriginProposer: UserA})`
   - Parliament validates `OriginProposer` is authorized ✓
   - `CreateNewProposal` is called
   - `Context.Sender = GenesisContract` (changed due to SendInline)
   - **Bug**: Proposal stored with `Proposer = GenesisContract` instead of `UserA`

3. Parliament members approve the proposal ✓

4. **Expected**: `UserA` can call `ParliamentContract.Release(proposalId)` since they created the proposal
   **Actual**: Transaction fails with "No permission" because `Proposer = GenesisContract ≠ UserA`

5. **Workaround Required**: `UserA` must call `GenesisContract.ReleaseApprovedContract(input)` which then calls `ParliamentContract.Release` with `Context.Sender = GenesisContract = stored Proposer` ✓

**Success Condition for Exploit:**
The proposal metadata shows `Proposer = GenesisContract` instead of `UserA`, and `UserA` cannot directly release their own proposal, demonstrating loss of user control and incorrect metadata recording.

### Citations

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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L150-173)
```csharp
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

        Context.Fire(new ContractProposed
        {
            ProposedContractInputHash = proposedContractInputHash
        });

        return proposedContractInputHash;
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L202-224)
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
                    CodeCheckReleaseMethod = nameof(UpdateSmartContract),
                    ProposedContractInputHash = proposedContractInputHash,
                    Category = info.Category,
                    IsSystemContract = info.IsSystemContract
                }.ToByteString(),
                OrganizationAddress = State.ContractDeploymentController.Value.OwnerAddress,
                ExpiredTime = Context.CurrentBlockTime.AddSeconds(expirationTimePeriod)
            },
            OriginProposer = Context.Sender
        };
        Context.SendInline(State.ContractDeploymentController.Value.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                .CreateProposalBySystemContract), proposalCreationInput);
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
