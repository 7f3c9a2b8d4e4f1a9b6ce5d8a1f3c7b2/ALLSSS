# Audit Report

## Title
Insufficient Address Validation in Governance Contracts Enables Griefing Attack via Unexecutable Proposals

## Summary
The Association, Parliament, and Referendum governance contracts use incomplete address validation that only checks for null object references without verifying the internal byte array value. This allows whitelisted proposers to create proposals with empty addresses that pass validation but fail during execution, causing approved proposals to remain stuck in storage until expiry.

## Finding Description

The three governance contracts implement a weaker validation pattern than other parts of the codebase:

**Association Contract** validates proposals by checking only if the Address object is null: [1](#0-0) 

**Parliament Contract** uses the same insufficient pattern: [2](#0-1) 

**Referendum Contract** follows the same weak validation: [3](#0-2) 

In contrast, the proper validation pattern used in TokenContract checks both the object reference AND the internal Value property: [4](#0-3) 

The genesis contract also uses this stronger validation for deployment operations: [5](#0-4) 

When a proposal with an empty address reaches the Release stage, the inline transaction is created without immediate validation: [6](#0-5) 

The `SendVirtualInlineBySystemContract` method adds the transaction to a list for later execution: [7](#0-6) 

During inline transaction execution, failures cause the parent transaction to fail and skip remaining inline transactions: [8](#0-7) 

An invalid address triggers a SmartContractFindRegistrationException during contract lookup: [9](#0-8) 

In protobuf, an Address message can be instantiated with an empty Value property (ByteString.Empty), which passes the `!= null` check but represents an invalid contract address. When execution attempts to look up this address, it fails, causing the entire transaction to revert. Critically, the proposal removal operation that occurs after the inline transaction creation is also reverted, leaving the proposal stuck in storage until its expiration time.

## Impact Explanation

This vulnerability enables a governance denial-of-service attack with the following impacts:

1. **Wasted Resources**: Organization members invest time reviewing, voting on, and approving proposals that can never execute
2. **Governance Disruption**: Critical governance actions are blocked despite proper approval
3. **Storage Bloat**: Unexecutable proposals occupy storage until expiry
4. **Trust Damage**: Repeated execution failures erode confidence in the governance system
5. **Systematic Exploitation**: Malicious proposers can create multiple such proposals

While proposals can eventually be cleared after expiry using ClearProposal: [10](#0-9) 

The temporary governance disruption and wasted effort constitute significant operational impact. The severity is Medium because while it doesn't cause direct fund loss, it seriously disrupts critical governance operations.

## Likelihood Explanation

The attack is highly feasible:

1. **Attacker Profile**: Any whitelisted proposer can execute this attack. In multi-organization ecosystems, whitelist membership is realistic and achievable
2. **Technical Simplicity**: Creating a protobuf Address message with empty Value is trivial
3. **Minimal Preconditions**: Only requires proposer whitelist access
4. **Detection Difficulty**: The malicious proposal appears valid until Release execution
5. **Low Cost**: Only requires standard transaction fees

Tests confirm that null addresses are caught by validation: [11](#0-10) 

However, an Address object with empty Value (non-null but invalid) would bypass these checks. The likelihood is Medium due to the realistic attacker profile and minimal execution complexity.

## Recommendation

Update the proposal validation methods in all three governance contracts to use the comprehensive address validation pattern:

```csharp
private bool Validate(ProposalInfo proposal)
{
    // Use the same validation as TokenContract_Helper
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsNullOrEmpty() || 
        string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

Apply this fix to:
- `Association_Helper.cs` Validate method
- `Parliament_Helper.cs` Validate method  
- `Referendum_Helper.cs` Validate method

## Proof of Concept

```csharp
[Fact]
public async Task CreateProposal_WithEmptyAddressValue_ShouldFail()
{
    // Setup: Create organization with whitelisted proposer
    var organizationAddress = await CreateOrganizationAsync();
    
    // Attack: Create proposal with Address object that has empty Value
    var emptyAddress = new Address(); // Value is ByteString.Empty by default
    var createProposalInput = new CreateProposalInput
    {
        ToAddress = emptyAddress, // Non-null but invalid
        ContractMethodName = "TestMethod",
        Params = ByteString.Empty,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
        OrganizationAddress = organizationAddress
    };
    
    // This should fail but currently passes validation
    var result = await AssociationContractStub.CreateProposal.SendAsync(createProposalInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var proposalId = result.Output;
    
    // Approve and try to release
    await ApproveProposalAsync(proposalId);
    
    // Release will fail, but proposal won't be removed from storage
    var releaseResult = await AssociationContractStub.Release.SendWithExceptionAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    
    // Verify proposal still exists in storage
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ProposalId.ShouldNotBeNull();
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero_Helper.cs (L395-402)
```csharp
    private void ValidateContractOperation(ContractOperation contractOperation, int currentVersion, Hash codeHash)
    {
        Assert(contractOperation.Deployer != null && !contractOperation.Deployer.Value.IsNullOrEmpty(),
            "Invalid input deploying address.");
        Assert(contractOperation.Salt != null && !contractOperation.Salt.Value.IsNullOrEmpty(), "Invalid input salt.");
        Assert(contractOperation.CodeHash != null && !contractOperation.CodeHash.Value.IsNullOrEmpty(),
            "Invalid input code hash.");
        Assert(!contractOperation.Signature.IsNullOrEmpty(), "Invalid input signature.");
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

**File:** contract/AElf.Contracts.Association/Association.cs (L282-289)
```csharp
    public override Empty ClearProposal(Hash input)
    {
        // anyone can clear proposal if it is expired
        var proposal = State.Proposals[input];
        Assert(proposal != null && Context.CurrentBlockTime >= proposal.ExpiredTime, "Proposal clear failed");
        State.Proposals.Remove(input);
        return new Empty();
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L266-276)
```csharp
    public void SendVirtualInlineBySystemContract(Hash fromVirtualAddress, Address toAddress, string methodName,
        ByteString args)
    {
        TransactionContext.Trace.InlineTransactions.Add(new Transaction
        {
            From = ConvertVirtualAddressToContractAddressWithContractHashName(fromVirtualAddress, Self),
            To = toAddress,
            MethodName = methodName,
            Params = args
        });
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L216-247)
```csharp
    private async Task ExecuteInlineTransactions(int depth, Timestamp currentBlockTime,
        ITransactionContext txContext, TieredStateCache internalStateCache,
        IChainContext internalChainContext,
        Hash originTransactionId,
        CancellationToken cancellationToken)
    {
        var trace = txContext.Trace;
        internalStateCache.Update(txContext.Trace.GetStateSets());
        foreach (var inlineTx in txContext.Trace.InlineTransactions)
        {
            var singleTxExecutingDto = new SingleTransactionExecutingDto
            {
                Depth = depth + 1,
                ChainContext = internalChainContext,
                Transaction = inlineTx,
                CurrentBlockTime = currentBlockTime,
                Origin = txContext.Origin,
                OriginTransactionId = originTransactionId
            };

            var inlineTrace = await ExecuteOneAsync(singleTxExecutingDto, cancellationToken);

            if (inlineTrace == null)
                break;
            trace.InlineTraces.Add(inlineTrace);
            if (!inlineTrace.IsSuccessful())
                // Already failed, no need to execute remaining inline transactions
                break;

            internalStateCache.Update(inlineTrace.GetStateSets());
        }
    }
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractExecutiveService.cs (L180-198)
```csharp
    {
        var transaction = new Transaction
        {
            From = _defaultContractZeroCodeProvider.ContractZeroAddress,
            To = _defaultContractZeroCodeProvider.ContractZeroAddress,
            MethodName = "GetSmartContractRegistrationByAddress",
            Params = address.ToByteString()
        };

        var txContext = _transactionContextFactory.Create(transaction, chainContext);

        await executiveZero.ApplyAsync(txContext);
        var returnBytes = txContext.Trace?.ReturnValue;
        if (returnBytes != null && returnBytes != ByteString.Empty)
            return SmartContractRegistration.Parser.ParseFrom(returnBytes);

        throw new SmartContractFindRegistrationException(
            $"failed to find registration from zero contract {txContext.Trace.Error}");
    }
```

**File:** test/AElf.Contracts.Association.Tests/AssociationContractTests.cs (L356-365)
```csharp
        //ToAddress is null
        {
            createProposalInput.ContractMethodName = "Test";
            createProposalInput.ToAddress = null;

            var transactionResult =
                await associationContractStub.CreateProposal.SendWithExceptionAsync(createProposalInput);
            transactionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
            transactionResult.TransactionResult.Error.Contains("Invalid proposal.").ShouldBeTrue();
        }
```
