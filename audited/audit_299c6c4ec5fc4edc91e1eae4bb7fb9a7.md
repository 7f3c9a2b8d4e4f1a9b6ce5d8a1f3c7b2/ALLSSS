### Title
ChangeMethodFeeController Orphans Pending Parliament Proposals for Method Fee Changes

### Summary
The `ChangeMethodFeeController` function in the Referendum contract can migrate the method fee controller from Parliament's default organization to a custom organization without checking for pending Parliament proposals that target `SetMethodFee`. These approved proposals become orphaned and fail upon execution because the authorization check compares `Context.Sender` (Parliament organization address) against the newly changed controller, causing legitimate governance actions to be permanently blocked.

### Finding Description

The Referendum contract implements ACS1 and initializes its `MethodFeeController` to Parliament's default organization [1](#0-0) . The `ChangeMethodFeeController` function only validates that the sender is authorized and the new organization exists, but performs no check for pending proposals [2](#0-1) .

When a Parliament proposal is released to call `SetMethodFee`, the execution uses a virtual address derived from the organization's hash [3](#0-2) . This virtual address becomes the `Context.Sender` in the inline call. The organization address is calculated using the same virtual hash [4](#0-3) , meaning `Context.Sender` equals the Parliament organization address.

However, `SetMethodFee` enforces: `Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.")` [5](#0-4) . If the controller was changed before the proposal's release, `State.MethodFeeController.Value.OwnerAddress` points to the new custom organization, not Parliament, causing the authorization check to fail and the proposal execution to revert.

### Impact Explanation

Approved Parliament proposals targeting `SetMethodFee` on the Referendum contract become permanently unexecutable after a controller migration, resulting in:

1. **Governance Disruption**: Legitimate method fee adjustments approved by miners cannot be implemented despite meeting all voting thresholds
2. **Wasted Governance Resources**: Proposers expend transaction fees and coordination effort on proposals that ultimately fail
3. **Operational Delays**: Critical fee updates must be re-proposed under the new controller, causing governance delays
4. **Potential Malicious Use**: An attacker with sufficient influence could strategically change the controller to block unwanted fee adjustments that are close to approval

The impact is limited to governance overhead rather than direct fund loss, but represents a violation of governance invariants where approved proposals should be executable. This justifies Medium severity as it disrupts protocol operations without direct financial theft.

### Likelihood Explanation

The exploit requires:
1. A Parliament proposal for `SetMethodFee` on Referendum contract (created via standard governance process)
2. The proposal reaching approval threshold (miners vote to approve)
3. A separate Parliament proposal for `ChangeMethodFeeController` being released before the first proposal
4. The first proposal being released after the controller change

All preconditions are realistic:
- **Entry Point**: `ChangeMethodFeeController` is a public governance method reachable through Parliament proposals [2](#0-1) 
- **Execution Practicality**: Parliament proposal workflows are standard operations confirmed by tests [6](#0-5) 
- **Economic Rationality**: Creating two proposals costs minimal gas; the attacker doesn't need special privileges beyond standard proposal rights
- **Timing Window**: Proposals can remain pending for extended periods between approval and release, creating a natural window for this issue

The likelihood is elevated because controller changes are expected during protocol evolution, and there's no warning or coordination mechanism to prevent collisions with pending proposals.

### Recommendation

Add a check in `ChangeMethodFeeController` to verify no pending proposals exist that would be orphaned by the controller change:

1. **Before Controller Migration**: Query the current controller's contract (Parliament) for pending proposals targeting `SetMethodFee` on the Referendum contract using `GetNotVotedPendingProposals` or a similar method
2. **Assertion**: Revert if pending proposals are found with a clear error message: "Cannot change controller while pending method fee proposals exist"
3. **Alternative Approach**: Store a grace period after controller changes during which the old controller can still execute pending proposals
4. **Documentation**: Add clear warnings that changing the controller orphans pending proposals, requiring operators to check proposal queues before migrations

**Code-level fix example** (add to `ChangeMethodFeeController`):
```csharp
// Before line 28 (State.MethodFeeController.Value = input;)
// Add validation that no pending SetMethodFee proposals exist for current controller
Assert(NoPendingMethodFeeProposals(), "Cannot change controller with pending method fee proposals");
```

**Test cases to add**:
- Create Parliament proposal for `SetMethodFee` → Approve → Change controller → Attempt to release original proposal → Verify it fails
- Verify the recommended fix prevents controller changes when pending proposals exist

### Proof of Concept

**Initial State**:
- Referendum contract deployed
- `MethodFeeController` = Parliament default organization (address `PARL_ORG`)

**Step 1**: Create Parliament Proposal P1
- Target: `ReferendumContract.SetMethodFee`
- Parameters: New method fees for `CreateProposal`
- Organization: Parliament default (`PARL_ORG`)
- Proposal approved by miners, reaches release threshold

**Step 2**: Create Parliament Proposal P2
- Target: `ReferendumContract.ChangeMethodFeeController`
- Parameters: `AuthorityInfo { OwnerAddress = CUSTOM_ORG, ContractAddress = CustomContract }`
- Organization: Parliament default (`PARL_ORG`)
- Proposal approved and **released immediately**

**Step 3**: Verify Controller Changed
- Call `ReferendumContract.GetMethodFeeController()`
- **Expected**: Returns `CUSTOM_ORG`
- **Actual**: Returns `CUSTOM_ORG` ✓

**Step 4**: Release Proposal P1
- Call `ParliamentContract.Release(P1)`
- Parliament executes virtual inline call to `ReferendumContract.SetMethodFee`
- `Context.Sender` = `PARL_ORG` (Parliament organization address)
- Authorization check: `Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress)`
- `State.MethodFeeController.Value.OwnerAddress` = `CUSTOM_ORG`
- **Expected**: Transaction succeeds (P1 was approved)
- **Actual**: Transaction fails with "Unauthorized to set method fee."

**Success Condition**: Proposal P1 fails to execute despite being properly approved, demonstrating the orphaning of pending proposals when the controller is changed.

### Citations

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L15-15)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L21-30)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Referendum/ReferendumContract_ACS1_TransactionFeeProvider.cs (L49-63)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L293-305)
```csharp
    private OrganizationHashAddressPair CalculateOrganizationHashAddressPair(
        CreateOrganizationInput createOrganizationInput)
    {
        var organizationHash = HashHelper.ComputeFrom(createOrganizationInput);
        var organizationAddress =
            Context.ConvertVirtualAddressToContractAddressWithContractHashName(
                CalculateVirtualHash(organizationHash, createOrganizationInput.CreationToken));
        return new OrganizationHashAddressPair
        {
            OrganizationAddress = organizationAddress,
            OrganizationHash = organizationHash
        };
    }
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L948-985)
```csharp
    public async Task ChangeMethodFeeController_Test()
    {
        // await InitializeParliamentContracts();
        var parliamentContractStub = GetParliamentContractTester(InitialMinersKeyPairs[0]);
        var createOrganizationResult =
            await parliamentContractStub.CreateOrganization.SendAsync(
                new CreateOrganizationInput
                {
                    ProposalReleaseThreshold = new ProposalReleaseThreshold
                    {
                        MinimalApprovalThreshold = 1000,
                        MinimalVoteThreshold = 1000
                    }
                });
        var organizationAddress = Address.Parser.ParseFrom(createOrganizationResult.TransactionResult.ReturnValue);

        var methodFeeController = await parliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
        var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        methodFeeController.OwnerAddress.ShouldBe(defaultOrganization);

        const string proposalCreationMethodName = nameof(parliamentContractStub.ChangeMethodFeeController);
        var proposalId = await CreateFeeProposalAsync(ParliamentContractAddress,
            methodFeeController.OwnerAddress, proposalCreationMethodName, new AuthorityInfo
            {
                OwnerAddress = organizationAddress,
                ContractAddress = ParliamentContractAddress
            });
        await ApproveAsync(InitialMinersKeyPairs[0], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[1], proposalId);
        await ApproveAsync(InitialMinersKeyPairs[2], proposalId);

        var releaseResult = await parliamentContractStub.Release.SendAsync(proposalId);
        releaseResult.TransactionResult.Error.ShouldBeNullOrEmpty();
        releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

        var newMethodFeeController = await parliamentContractStub.GetMethodFeeController.CallAsync(new Empty());
        newMethodFeeController.OwnerAddress.ShouldBe(organizationAddress);
    }
```
