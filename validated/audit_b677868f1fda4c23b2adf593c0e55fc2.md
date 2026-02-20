# Audit Report

## Title
Insufficient Address Validation in Governance Contracts Enables Griefing Attack via Unexecutable Proposals

## Summary
The Association, Parliament, and Referendum governance contracts only validate that `ToAddress` is not null, failing to check if the internal `Value` byte array is empty or valid. This allows whitelisted proposers to create proposals with non-null but invalid addresses that pass validation during both creation and release, but fail during inline transaction execution. The failure causes the Release transaction to revert, leaving approved proposals permanently stuck in state until expiry.

## Finding Description

All three governance contracts implement insufficient address validation that only checks for null object references rather than validating the internal byte array content.

**Association Contract Validation:**
The `Validate(ProposalInfo proposal)` method only checks if the ToAddress object is null, not whether its internal Value is empty: [1](#0-0) 

**Parliament Contract Validation:**
Parliament uses the same insufficient null-only check: [2](#0-1) 

**Referendum Contract Validation:**
Referendum also only validates null references: [3](#0-2) 

**Proper Validation Pattern:**
The codebase contains the correct validation pattern in TokenContract that checks both the object reference AND the internal Value: [4](#0-3) 

**Address Protobuf Definition:**
The Address protobuf type allows construction with empty Value: [5](#0-4) 

**Attack Flow:**

1. A whitelisted proposer creates a proposal with `new Address() { Value = ByteString.Empty }` during CreateProposal [6](#0-5) 

2. Validation passes because it only checks `!= null`, not `Value.IsNullOrEmpty()`

3. Organization members vote and approve the proposal normally

4. When Release is called, validation passes again and SendVirtualInlineBySystemContract creates an inline transaction: [7](#0-6) 

5. During inline transaction execution, GetExecutiveAsync attempts to get the executive for the invalid address and throws SmartContractFindRegistrationException: [8](#0-7) 

6. The inline trace is marked unsuccessful, which causes execution to break: [9](#0-8) 

7. Failed traces only have pre/post plugin state changes applied, not the main transaction's state changes: [10](#0-9) 

8. The `State.Proposals.Remove(input)` at the end of Release never persists, leaving the proposal in an approved but permanently unexecutable state until it expires.

This behavior is confirmed by existing test cases that demonstrate failed inline transactions prevent state changes from persisting: [11](#0-10) 

## Impact Explanation

**Governance Denial of Service**: Organizations lose the ability to execute approved proposals, disrupting critical governance operations. Members waste significant time and effort reviewing, voting on, and attempting to execute proposals that can never succeed.

**Resource Waste**: Approved proposals remain stuck in contract state consuming storage until their expiration time (potentially days or weeks later), preventing efficient governance operations.

**Repeated Griefing**: Any whitelisted proposer can create multiple such proposals simultaneously, overwhelming the organization with unexecutable proposals and forcing them to wait for each to expire naturally.

**Trust Erosion**: Repeated failures to execute approved proposals damage member confidence in the governance system, potentially causing members to disengage from governance activities.

The severity is **Medium** because while it does not directly steal funds or compromise token supplies, it significantly disrupts critical governance infrastructure that controls protocol upgrades, treasury management, and other essential operations.

## Likelihood Explanation

**Attacker Requirements**: The attacker must be in the organization's proposer whitelist. While this is a barrier, it is realistic in multi-organization ecosystems where various parties participate in governance (DAOs, protocol partners, delegates, etc.).

**Attack Complexity**: The attack is trivial to execute—simply instantiate an Address with `Value = ByteString.Empty` when creating a proposal. No complex state manipulation, precise timing, or special conditions are required.

**Detection Difficulty**: The issue is difficult to detect before Release execution because the validation consistently passes at both creation and release time. Organization members have no way to identify such proposals before voting.

**Economic Feasibility**: The attack costs only standard transaction fees, making sustained griefing campaigns economically viable.

**Reproducibility**: The attack works consistently under normal operational conditions with no special preconditions needed.

The likelihood is **Medium** due to the low technical barrier and the realistic attacker profile of a malicious whitelisted proposer.

## Recommendation

Implement comprehensive address validation in all three governance contracts by checking both null reference and empty Value:

```csharp
private bool Validate(ProposalInfo proposal)
{
    // Check ToAddress is not null AND has valid Value
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsNullOrEmpty())
        return false;
    
    if (string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

Apply this pattern consistently in:
- `Association_Helper.cs` line 85
- `Parliament_Helper.cs` line 159
- `Referendum_Helper.cs` line 106

## Proof of Concept

```csharp
[Fact]
public async Task GriefingAttack_InvalidAddress_ProposalStuck()
{
    // Setup: Create organization and add malicious proposer to whitelist
    var organization = await CreateOrganization();
    var maliciousProposer = Accounts[1].Address;
    
    // Attacker creates proposal with invalid address (empty Value)
    var invalidAddress = new Address { Value = ByteString.Empty };
    var proposalId = await AssociationContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = invalidAddress,  // Invalid: null object but empty Value
        ContractMethodName = "Transfer",
        Params = new TransferInput().ToByteString(),
        OrganizationAddress = organization,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // Members approve proposal normally
    await ApproveProposal(proposalId.Output, organization);
    
    // Attempt to release - should fail due to invalid address
    var releaseResult = await AssociationContractStub.Release.SendAsync(proposalId.Output);
    
    // Verify: Transaction failed
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    
    // Verify: Proposal still exists (not removed from state)
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId.Output);
    proposal.ProposalId.ShouldBe(proposalId.Output);
    
    // Verify: Proposal is approved but stuck until expiry
    proposal.ToBeReleased.ShouldBeTrue();
}
```

### Citations

**File:** contract/AElf.Contracts.Association/Association_Helper.cs (L83-90)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        if (proposal.ToAddress == null || string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
            !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
            return false;

        return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
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

**File:** contract/AElf.Contracts.Parliament/Parliament_Helper.cs (L157-166)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = CheckProposalNotExpired(proposal);
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L104-113)
```csharp
    private bool Validate(ProposalInfo proposal)
    {
        var validDestinationAddress = proposal.ToAddress != null;
        var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
        var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
        var hasOrganizationAddress = proposal.OrganizationAddress != null;
        var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
        return validDestinationAddress && validDestinationMethodName && validExpiredTime &&
               hasOrganizationAddress && validDescriptionUrl;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L94-97)
```csharp
    private void AssertValidInputAddress(Address input)
    {
        Assert(input != null && !input.Value.IsNullOrEmpty(), "Invalid input address.");
    }
```

**File:** protobuf/aelf/core.proto (L135-138)
```text
message Address
{
    bytes value = 1;
}
```

**File:** contract/AElf.Contracts.Association/Association.cs (L183-200)
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
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L105-126)
```csharp
    private static bool TryUpdateStateCache(TransactionTrace trace, TieredStateCache groupStateCache)
    {
        if (trace == null)
            return false;

        if (!trace.IsSuccessful())
        {
            var transactionExecutingStateSets = new List<TransactionExecutingStateSet>();

            AddToTransactionStateSets(transactionExecutingStateSets, trace.PreTraces);
            AddToTransactionStateSets(transactionExecutingStateSets, trace.PostTraces);

            groupStateCache.Update(transactionExecutingStateSets);
            trace.SurfaceUpError();
        }
        else
        {
            groupStateCache.Update(trace.GetStateSets());
        }

        return true;
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L150-161)
```csharp
        try
        {
            executive = await _smartContractExecutiveService.GetExecutiveAsync(
                internalChainContext,
                singleTxExecutingDto.Transaction.To);
        }
        catch (SmartContractFindRegistrationException)
        {
            txContext.Trace.ExecutionStatus = ExecutionStatus.ContractError;
            txContext.Trace.Error += "Invalid contract address.\n";
            return trace;
        }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L236-243)
```csharp
            var inlineTrace = await ExecuteOneAsync(singleTxExecutingDto, cancellationToken);

            if (inlineTrace == null)
                break;
            trace.InlineTraces.Add(inlineTrace);
            if (!inlineTrace.IsSuccessful())
                // Already failed, no need to execute remaining inline transactions
                break;
```

**File:** test/AElf.Parallel.Tests/DeleteDataFromStateDbTest.cs (L2128-2134)
```csharp
        transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);

        value = await GetValueAsync(accountAddress, key, block.GetHash(), block.Height);
        CheckValueNotExisted(value);

        var blockStateSet = await _blockStateSetManger.GetBlockStateSetAsync(block.GetHash());
        blockStateSet.Changes.Count.ShouldBe(0);
```
