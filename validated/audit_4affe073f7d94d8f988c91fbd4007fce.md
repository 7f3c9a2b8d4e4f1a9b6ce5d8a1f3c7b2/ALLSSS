# Audit Report

## Title
Missing Contract Address Validation in Governance Proposal Creation Allows Governance DoS

## Summary
The Referendum, Parliament, and Association governance contracts fail to validate that proposal target addresses correspond to deployed smart contracts. This allows proposals targeting non-existent addresses to pass validation, get approved by voters, but permanently fail during release execution, causing governance denial-of-service and locking voter tokens until proposal expiration.

## Finding Description

All three governance contracts contain insufficient validation in their proposal creation logic. The `Validate(ProposalInfo)` method only checks if the target address is non-null, without verifying that it corresponds to a deployed contract: [1](#0-0) [2](#0-1) [3](#0-2) 

When an approved proposal with an invalid target address is released, the system attempts to execute an inline transaction to the non-existent contract: [4](#0-3) 

During execution, when attempting to get an executive for the target address, if the contract doesn't exist, a `SmartContractFindRegistrationException` is caught and the inline transaction fails: [5](#0-4) 

The critical issue is that when any inline transaction fails, the parent transaction's `IsSuccessful()` check returns false: [6](#0-5) 

When a transaction fails due to inline transaction failure, only pre/post plugin state changes are committed, not the main transaction's state changes including the proposal removal: [7](#0-6) 

This behavior is confirmed by test cases showing that when inline transactions fail, the parent transaction's state changes are not committed: [8](#0-7) 

For Referendum, voters must lock tokens when voting, which remain locked until the proposal expires: [9](#0-8) [10](#0-9) 

## Impact Explanation

**Governance Disruption**: Approved proposals cannot execute their intended governance actions, completely breaking the governance process for critical protocol updates or parameter changes. The proposal remains in an approved state but cannot be released.

**Resource Waste**: For Referendum contracts, voter tokens are locked in the proposal virtual address and cannot be reclaimed until the proposal expires. This represents a significant loss of capital efficiency for governance participants.

**Denial of Service**: The proposer can repeatedly attempt to release the proposal, each time consuming gas and failing. The proposal cannot be successfully executed until it naturally expires, during which time the governance system's capacity is effectively reduced.

**System-Wide Impact**: This affects all three governance contract types (Referendum, Parliament, Association), potentially impacting the entire governance layer of the AElf ecosystem. A single malicious or erroneous proposal can waste substantial governance resources and time.

## Likelihood Explanation

**Reachable Entry Point**: The `CreateProposal` method is publicly accessible to whitelisted proposers across all three governance contracts: [11](#0-10) 

**Realistic Preconditions**: 
- Proposer must be in the organization's proposer whitelist, which is a normal governance setup requirement, not a privileged position
- Proposers are expected to create proposals as part of standard governance operations
- No validation prevents submitting invalid addresses at creation time

**Execution Practicality**:
- **Accidental**: Simple human error such as copying the wrong address, typographical errors, or using an address that appears valid but points to an undeployed contract
- **Intentional**: Malicious whitelisted proposer can deliberately create proposals with invalid addresses to disrupt governance and lock voter funds
- The AElf address format validation ensures syntactically valid addresses, but contract existence is never checked

**Attack Complexity**: Low - requires only creating a proposal with a non-existent but validly-formatted address, which can happen accidentally or through minimal malicious effort.

## Recommendation

Add contract existence validation in the `Validate(ProposalInfo)` method by querying the Genesis contract's `GetContractInfo` method. The Genesis contract already provides this functionality: [12](#0-11) 

**Recommended Fix** for all three governance contracts (example for Referendum):

```csharp
private bool Validate(ProposalInfo proposal)
{
    var validDestinationAddress = proposal.ToAddress != null;
    if (!validDestinationAddress)
        return false;
        
    // Add contract existence validation
    if (State.GenesisContract.Value == null)
    {
        State.GenesisContract.Value = 
            Context.GetContractAddressByName(SmartContractConstants.GenesisBasicContractSystemName);
    }
    
    var contractInfo = State.GenesisContract.GetContractInfo.Call(proposal.ToAddress);
    var contractExists = contractInfo != null && contractInfo.ContractAddress != null;
    if (!contractExists)
        return false;
    
    var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
    var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    var hasOrganizationAddress = proposal.OrganizationAddress != null;
    var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
    return validDestinationMethodName && validExpiredTime &&
           hasOrganizationAddress && validDescriptionUrl;
}
```

This fix should be applied to:
- `contract/AElf.Contracts.Referendum/Referendum_Helper.cs`
- `contract/AElf.Contracts.Parliament/Parliament_Helper.cs`
- `contract/AElf.Contracts.Association/Association_Helper.cs`

## Proof of Concept

```csharp
[Fact]
public async Task CreateProposal_WithNonExistentContractAddress_ShouldFailRelease()
{
    // Setup organization
    var organizationAddress = await CreateReferendumOrganization();
    
    // Create proposal with non-existent contract address (validly formatted but not deployed)
    var nonExistentAddress = SampleAddress.AddressList[99]; // Valid address format, but no contract deployed
    var proposalId = await CreateProposalAsync(organizationAddress, nonExistentAddress, 
        "SomeMethod", new Empty());
    
    // Proposal creation succeeds (only checks ToAddress != null)
    proposalId.ShouldNotBeNull();
    
    // Vote and approve the proposal
    await ApproveProposal(proposalId, sufficientTokenAmount);
    
    // Verify proposal is approved
    var proposal = await ReferendumContractStub.GetProposal.CallAsync(proposalId);
    proposal.ToBeReleased.ShouldBeTrue();
    
    // Attempt to release - should fail because contract doesn't exist
    var releaseResult = await ReferendumContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    releaseResult.TransactionResult.Error.ShouldContain("Invalid contract address");
    
    // Verify proposal still exists (state changes reverted)
    var proposalAfterRelease = await ReferendumContractStub.GetProposal.CallAsync(proposalId);
    proposalAfterRelease.ProposalId.ShouldBe(proposalId);
    
    // Verify tokens are still locked (cannot reclaim before expiration)
    var reclaimResult = await ReferendumContractStub.ReclaimVoteToken.SendWithExceptionAsync(proposalId);
    reclaimResult.TransactionResult.Error.ShouldContain("Unable to reclaim at this time");
}
```

### Citations

**File:** contract/AElf.Contracts.Referendum/Referendum_Helper.cs (L39-72)
```csharp
    private ReferendumReceiptCreated LockToken(string symbol, long amount, Hash proposalId, Address lockedAddress,
        Address organizationAddress)
    {
        Assert(State.LockedTokenAmount[lockedAddress][proposalId] == null, "Already locked.");

        var lockId = Context.GenerateId(Context.Self,
            HashHelper.ConcatAndCompute(proposalId, HashHelper.ComputeFrom(lockedAddress)));
        RequireTokenContractStateSet();
        Context.SendVirtualInline(proposalId, State.TokenContract.Value,
            nameof(TokenContractContainer.TokenContractReferenceState.TransferFrom), new TransferFromInput
            {
                From = Context.Sender,
                To = GetProposalVirtualAddress(proposalId),
                Symbol = symbol,
                Amount = amount,
                Memo = "Referendum."
            });
        State.LockedTokenAmount[Context.Sender][proposalId] = new Receipt
        {
            Amount = amount,
            LockId = lockId,
            TokenSymbol = symbol
        };

        return new ReferendumReceiptCreated
        {
            Address = Context.Sender,
            ProposalId = proposalId,
            Amount = amount,
            Symbol = symbol,
            Time = Context.CurrentBlockTime,
            OrganizationAddress = organizationAddress
        };
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

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L53-59)
```csharp
    public override Hash CreateProposal(CreateProposalInput input)
    {
        AssertIsAuthorizedProposer(input.OrganizationAddress, Context.Sender);
        var proposalId = CreateNewProposal(input);

        return proposalId;
    }
```

**File:** contract/AElf.Contracts.Referendum/Referendum.cs (L115-122)
```csharp
    public override Empty ReclaimVoteToken(Hash input)
    {
        var proposal = State.Proposals[input];
        Assert(proposal == null ||
               Context.CurrentBlockTime >= proposal.ExpiredTime, "Unable to reclaim at this time.");
        UnlockToken(input, Context.Sender);
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

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L149-161)
```csharp
        IExecutive executive;
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

**File:** src/AElf.Kernel.Core/Extensions/TransactionTraceExtensions.cs (L8-19)
```csharp
    public static bool IsSuccessful(this TransactionTrace txTrace)
    {
        if (txTrace.ExecutionStatus != ExecutionStatus.Executed) return false;

        if (txTrace.PreTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.InlineTraces.Any(trace => !trace.IsSuccessful())) return false;

        if (txTrace.PostTraces.Any(trace => !trace.IsSuccessful())) return false;

        return true;
    }
```

**File:** test/AElf.Parallel.Tests/DeleteDataFromStateDbTest.cs (L2127-2135)
```csharp
        var transactionResult = await GetTransactionResultAsync(transaction.GetHash(), block.Header);
        transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);

        value = await GetValueAsync(accountAddress, key, block.GetHash(), block.Height);
        CheckValueNotExisted(value);

        var blockStateSet = await _blockStateSetManger.GetBlockStateSetAsync(block.GetHash());
        blockStateSet.Changes.Count.ShouldBe(0);
        blockStateSet.Deletes.Count.ShouldBe(0);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L46-49)
```csharp
    public override SmartContractRegistration GetSmartContractRegistrationByAddress(Address input)
    {
        var info = State.ContractInfos[input];
        if (info == null) return null;
```
