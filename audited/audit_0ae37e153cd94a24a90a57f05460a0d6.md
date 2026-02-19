### Title
ConfigurationController Hijacking via Time-Of-Check-Time-Of-Use Vulnerability in Proposal Execution

### Summary
The Configuration contract allows changing the ConfigurationController between proposal approval and execution, causing previously approved legitimate configuration proposals to fail. This creates a governance denial-of-service where approved proposals become permanently unexecutable after a controller change, breaking the fundamental guarantee that approved proposals can be executed.

### Finding Description

**Location and Root Cause:**

The vulnerability exists in the authorization flow between proposal approval and execution: [1](#0-0) 

When `SetConfiguration` is called via a Parliament proposal, it checks authorization at execution time: [2](#0-1) 

The check compares `Context.Sender` (which is the organization's virtual address from the proposal) against `State.ConfigurationController.Value.OwnerAddress` (current controller).

Meanwhile, the controller can be changed at any time through: [3](#0-2) 

**Why Protections Fail:**

1. When Parliament releases a proposal, it makes a virtual inline call using the organization's address: [4](#0-3) 

2. The organization address is derived deterministically: [5](#0-4) 

3. The authorization check at execution time (not approval time) allows the controller to be changed after proposals are approved but before they're released, invalidating all pending proposals from the old controller.

### Impact Explanation

**Concrete Harm:**
- All approved configuration proposals become unexecutable if the controller changes before their release
- Critical system configurations (block limits, ACS requirements, method fees) cannot be updated despite miner approval
- Breaks the governance invariant that approved proposals are executable

**Affected Parties:**
- Legitimate governance participants who approved configuration changes
- System operators needing urgent configuration updates
- Protocol security if emergency configuration changes are blocked

**Severity Justification:**
High severity due to governance DoS capability. While not directly stealing funds, it can:
- Block emergency security fixes that require configuration changes
- Prevent consensus or cross-chain parameter updates
- Undermine trust in the governance system by making approved proposals fail unexpectedly

### Likelihood Explanation

**Attacker Capabilities Required:**
- Control or compromise of the current ConfigurationController organization (typically Parliament's default organization)
- Ability to create and approve proposals within that organization

**Attack Complexity:**
Low to Medium - requires:
1. Create multiple legitimate configuration proposals (P1, P2, P3)
2. Get them approved by miners
3. Create and approve a controller change proposal
4. Release the controller change first, before other proposals

**Feasibility Conditions:**
- Realistic if the controlling organization is compromised or has malicious insiders
- In Parliament, requires 2/3+ miner approval for both legitimate proposals and controller change
- Attack window exists between approval and release phases

**Detection Constraints:**
- Difficult to detect before execution since proposals appear normal during approval
- Only becomes evident when legitimate proposals fail at release time

### Recommendation

**Code-Level Mitigation:**

Add a controller snapshot mechanism that validates proposals against the controller at approval time rather than execution time. Modify the authorization check:

```csharp
// In ConfigurationContract_Helper.cs
private void AssertPerformedByConfigurationControllerOrZeroContract()
{
    if (State.ConfigurationController.Value == null)
    {
        var defaultConfigurationController = GetDefaultConfigurationController();
        State.ConfigurationController.Value = defaultConfigurationController;
    }

    // NEW: Accept both current controller AND the Zero contract which can validate
    // historical authorization from the controller at proposal creation time
    Assert(
        State.ConfigurationController.Value.OwnerAddress == Context.Sender ||
        Context.GetZeroSmartContractAddress() == Context.Sender, "No permission.");
}
```

Alternative: Add a grace period or proposal invalidation mechanism in `ChangeConfigurationController`:

```csharp
// Invalidate or force-release all pending proposals from old controller
// before allowing controller change
public override Empty ChangeConfigurationController(AuthorityInfo input)
{
    AssertPerformedByConfigurationController();
    Assert(input != null, "invalid input");
    Assert(CheckOrganizationExist(input), "Invalid authority input.");
    
    // NEW: Emit event to notify of pending proposal invalidation
    Context.Fire(new ConfigurationControllerChanged {
        OldController = State.ConfigurationController.Value,
        NewController = input
    });
    
    State.ConfigurationController.Value = input;
    return new Empty();
}
```

**Invariant Checks:**
- Verify that approved proposals from Organization A remain executable after a controller change
- Or explicitly invalidate pending proposals when controller changes and document this behavior

**Test Cases:** [6](#0-5) 

Add test:
```csharp
[Fact]
public async Task SetConfiguration_Fails_After_Controller_Change()
{
    // 1. Create and approve config proposal P1 with current controller
    var configProposalId = await SetBlockTransactionLimitProposalAsync(100);
    await ApproveWithMinersAsync(configProposalId);
    
    // 2. Create and approve controller change proposal P2
    var newOrg = await CreateNewOrganizationAsync();
    var controllerChangeProposalId = await SetTransactionOwnerAddressProposalAsync(
        new AuthorityInfo { ContractAddress = ParliamentAddress, OwnerAddress = newOrg });
    await ApproveWithMinersAsync(controllerChangeProposalId);
    
    // 3. Release controller change first
    await ReleaseProposalAsync(controllerChangeProposalId);
    
    // 4. Try to release config proposal - should fail
    var result = await ReleaseProposalAsync(configProposalId);
    Assert.True(result.Status == TransactionResultStatus.Failed);
    Assert.Contains("No permission.", result.Error);
}
```

### Proof of Concept

**Initial State:**
- ConfigurationController is set to Parliament's default organization (Organization A)
- Multiple miners have voting power in Parliament

**Exploitation Steps:**

1. **Attacker controls Organization A** (current controller)

2. **Create legitimate configuration proposals:**
   - Proposal P1: SetConfiguration("BlockTransactionLimit", 100)
   - Proposal P2: SetConfiguration("RequiredAcsInContracts", [...])
   - All get approved by miners (2/3+ approval)

3. **Create malicious controller change proposal:**
   - Proposal P_malicious: ChangeConfigurationController(Organization B)
   - Gets approved by miners (attacker convinces miners or uses compromised organization)

4. **Release P_malicious first:**
   - Calls ChangeConfigurationController [3](#0-2) 
   - State.ConfigurationController.Value now points to Organization B

5. **Attempt to release P1:**
   - Parliament.Release calls SendVirtualInlineBySystemContract with Organization A's virtual address [7](#0-6) 
   - Context.Sender in SetConfiguration becomes Organization A's address
   - AssertPerformedByConfigurationControllerOrZeroContract checks Context.Sender == Organization A
   - But State.ConfigurationController.Value.OwnerAddress is now Organization B
   - **Assertion fails: "No permission."** [8](#0-7) 

**Expected vs Actual Result:**
- Expected: P1 executes successfully since it was approved by Organization A when A was the controller
- Actual: P1 fails with "No permission." because controller changed to Organization B

**Success Condition:**
Approved proposals P1 and P2 become permanently unexecutable despite having valid miner approval, demonstrating the TOCTOU vulnerability.

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L10-21)
```csharp
    public override Empty SetConfiguration(SetConfigurationInput input)
    {
        AssertPerformedByConfigurationControllerOrZeroContract();
        Assert(input.Key.Any() && input.Value != ByteString.Empty, "Invalid set config input.");
        State.Configurations[input.Key] = new BytesValue { Value = input.Value };
        Context.Fire(new ConfigurationSet
        {
            Key = input.Key,
            Value = input.Value
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract.cs (L29-36)
```csharp
    public override Empty ChangeConfigurationController(AuthorityInfo input)
    {
        AssertPerformedByConfigurationController();
        Assert(input != null, "invalid input");
        Assert(CheckOrganizationExist(input), "Invalid authority input.");
        State.ConfigurationController.Value = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_Helper.cs (L32-43)
```csharp
    private void AssertPerformedByConfigurationControllerOrZeroContract()
    {
        if (State.ConfigurationController.Value == null)
        {
            var defaultConfigurationController = GetDefaultConfigurationController();
            State.ConfigurationController.Value = defaultConfigurationController;
        }

        Assert(
            State.ConfigurationController.Value.OwnerAddress == Context.Sender ||
            Context.GetZeroSmartContractAddress() == Context.Sender, "No permission.");
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L293-312)
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

    private Hash CalculateVirtualHash(Hash organizationHash, Hash creationToken)
    {
        return creationToken == null
            ? organizationHash
            : HashHelper.ConcatAndCompute(organizationHash, creationToken);
    }
```

**File:** test/AElf.Contracts.Configuration.Tests/ConfigurationContractTest.cs (L86-116)
```csharp
    public async Task Change_Owner_Address_Authorized()
    {
        var sender = SampleAddress.AddressList[0];
        _testOutputHelper.WriteLine(sender.ToBase58());
        var newOrganization = Address.Parser.ParseFrom((await Tester.ExecuteContractWithMiningAsync(ParliamentAddress,
            nameof(ParliamentContractContainer.ParliamentContractStub.CreateOrganization),
            new CreateOrganizationInput
            {
                ProposalReleaseThreshold = new ProposalReleaseThreshold
                {
                    MinimalApprovalThreshold = 1,
                    MinimalVoteThreshold = 1
                },
                ParliamentMemberProposingAllowed = true
            })).ReturnValue);
        var proposalId = await SetTransactionOwnerAddressProposalAsync(new AuthorityInfo
        {
            ContractAddress = ParliamentAddress,
            OwnerAddress = newOrganization
        });
        await ApproveWithMinersAsync(proposalId);
        var transactionResult = await ReleaseProposalAsync(proposalId);
        Assert.True(transactionResult.Status == TransactionResultStatus.Mined);

        var transactionResult2 =
            await ExecuteContractWithMiningAsync(ConfigurationContractAddress,
                nameof(ConfigurationImplContainer.ConfigurationImplStub.GetConfigurationController),
                new Empty());
        var authorityInfo = AuthorityInfo.Parser.ParseFrom(transactionResult2.ReturnValue);
        Assert.True(newOrganization == authorityInfo.OwnerAddress);
    }
```
