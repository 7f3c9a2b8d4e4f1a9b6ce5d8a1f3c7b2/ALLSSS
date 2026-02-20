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

When a transaction fails due to inline transaction failure, the state changes are cleared before commitment: [7](#0-6) 

And only pre/post plugin state changes are committed, not the main transaction's state changes including the proposal removal: [8](#0-7) 

This behavior is confirmed by test cases showing that when inline transactions fail, the parent transaction's state changes are not committed: [9](#0-8) 

For Referendum, voters must lock tokens when voting, which remain locked until the proposal expires: [10](#0-9) [11](#0-10) 

## Impact Explanation

**Governance Disruption**: Approved proposals cannot execute their intended governance actions, completely breaking the governance process for critical protocol updates or parameter changes. The proposal remains in an approved state but cannot be released because the `State.Proposals.Remove(input)` state change is cleared when the inline transaction fails.

**Resource Waste**: For Referendum contracts, voter tokens are locked in the proposal virtual address via `LockToken` and cannot be reclaimed until the proposal expires, as `ReclaimVoteToken` requires `proposal == null || Context.CurrentBlockTime >= proposal.ExpiredTime`. This represents a significant loss of capital efficiency for governance participants.

**Denial of Service**: The proposer can repeatedly attempt to release the proposal, each time consuming gas and failing. The proposal cannot be successfully executed until it naturally expires, during which time the governance system's capacity is effectively reduced.

**System-Wide Impact**: This affects all three governance contract types (Referendum, Parliament, Association), potentially impacting the entire governance layer of the AElf ecosystem. A single malicious or erroneous proposal can waste substantial governance resources and time.

## Likelihood Explanation

**Reachable Entry Point**: The `CreateProposal` method is publicly accessible to whitelisted proposers across all three governance contracts: [12](#0-11) 

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

Add contract existence validation in the `Validate(ProposalInfo)` method for all three governance contracts. The validation should check that the `ToAddress` corresponds to a deployed smart contract before allowing proposal creation.

Example fix for Referendum (similar changes needed for Parliament and Association):

```csharp
private bool Validate(ProposalInfo proposal)
{
    var validDestinationAddress = proposal.ToAddress != null;
    var validDestinationMethodName = !string.IsNullOrWhiteSpace(proposal.ContractMethodName);
    var validExpiredTime = proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
    var hasOrganizationAddress = proposal.OrganizationAddress != null;
    var validDescriptionUrl = ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl);
    
    // Add contract existence check
    var contractExists = false;
    if (validDestinationAddress)
    {
        try
        {
            var contractInfo = Context.GetContractInfo(proposal.ToAddress);
            contractExists = contractInfo != null;
        }
        catch
        {
            contractExists = false;
        }
    }
    
    return validDestinationAddress && contractExists && validDestinationMethodName && 
           validExpiredTime && hasOrganizationAddress && validDescriptionUrl;
}
```

Alternatively, add a check in the `Release` method before calling `SendVirtualInlineBySystemContract` to verify contract existence and revert early if the contract doesn't exist, allowing the proposal to be removed from state properly.

## Proof of Concept

This vulnerability can be demonstrated by:
1. Creating a governance organization in any of the three governance contracts
2. Creating a proposal with a validly-formatted but non-existent contract address
3. Getting the proposal approved by voters/members
4. Attempting to release the proposal
5. Observing that the release transaction fails due to "Invalid contract address" error
6. Verifying that the proposal remains in state (not removed)
7. For Referendum: verifying that voter tokens remain locked and cannot be reclaimed until proposal expiration

The test would call `CreateProposal` with a non-existent address, approve it through the voting process, call `Release`, and verify the transaction fails while the proposal remains in storage.

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

**File:** src/AElf.Runtime.CSharp/Executive.cs (L209-213)
```csharp
        if (!CurrentTransactionContext.Trace.IsSuccessful())
        {
            changes.Writes.Clear();
            changes.Deletes.Clear();
        }
```

**File:** test/AElf.Parallel.Tests/DeleteDataFromStateDbTest.cs (L2085-2093)
```csharp
        var transactionResult = await GetTransactionResultAsync(transaction.GetHash(), block.Header);
        transactionResult.Status.ShouldBe(TransactionResultStatus.Failed);

        value = await GetValueAsync(accountAddress, key, block.GetHash(), block.Height);
        CheckValueNotExisted(value);

        var blockStateSet = await _blockStateSetManger.GetBlockStateSetAsync(block.GetHash());
        blockStateSet.Changes.Count.ShouldBe(0);
        blockStateSet.Deletes.Count.ShouldBe(0);
```
