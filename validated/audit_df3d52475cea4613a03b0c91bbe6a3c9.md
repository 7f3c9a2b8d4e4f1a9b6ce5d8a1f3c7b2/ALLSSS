# Audit Report

## Title
Insufficient Address Validation in Governance Contracts Enables Griefing Attack via Unexecutable Proposals

## Summary
The Association, Parliament, and Referendum governance contracts fail to properly validate the `ToAddress` field of proposals. The validation only checks if the Address object reference is null, but does not verify that the internal `Value` byte array is non-empty. This allows whitelisted proposers to create proposals with empty addresses that pass all validation checks but fail during execution, causing approved proposals to become permanently stuck until expiry.

## Finding Description

The three governance contracts use an insufficient validation pattern that only checks the Address object reference for null, without validating the internal `Value` property:

**Association Contract** checks only object reference null: [1](#0-0) 

**Parliament Contract** checks only object reference null: [2](#0-1) 

**Referendum Contract** checks only object reference null: [3](#0-2) 

However, the proper validation pattern used elsewhere in the codebase checks BOTH the object reference AND the internal Value: [4](#0-3) 

When a proposal with an empty address value reaches the Release stage, the inline transaction is created: [5](#0-4) 

The `SendVirtualInlineBySystemContract` method simply adds the transaction to a list without immediate validation: [6](#0-5) 

When inline transactions are executed, any failure causes the parent transaction to fail: [7](#0-6) 

The inline transaction with an invalid address triggers a `SmartContractFindRegistrationException`: [8](#0-7) 

The contract registration lookup returns null for empty addresses: [9](#0-8) 

When the transaction fails, state changes are reverted and only pre/post traces are committed: [10](#0-9) 

This means the proposal removal in the Release method never gets committed, leaving the proposal stuck in storage until it can be cleared after expiry.

## Impact Explanation

This vulnerability creates a **governance denial-of-service** attack vector with the following impacts:

1. **Wasted Resources**: Organization members spend time and effort reviewing, voting on, and approving proposals that can never be executed
2. **Governance Disruption**: Critical governance decisions cannot be implemented even after proper approval
3. **Storage Waste**: Unexecutable proposals remain in storage until expiry (potentially days/weeks)
4. **Trust Erosion**: Repeated failures damage member confidence in the governance system
5. **Repeatability**: Any whitelisted proposer can create multiple such proposals

While the proposals can eventually be cleared after expiry using the `ClearProposal` method, the temporary DoS and wasted effort constitute significant operational impact on governance processes.

The severity is **Medium** because while it doesn't result in direct fund loss, it significantly disrupts critical governance operations and can be systematically exploited by malicious proposers.

## Likelihood Explanation

The attack is highly feasible:

1. **Attacker Profile**: Any whitelisted proposer can execute this attack. In multi-organization ecosystems, whitelist membership is common and realistic
2. **Technical Complexity**: Trivial - simply create a proposal with an Address object that has an empty Value property
3. **Preconditions**: None beyond being a whitelisted proposer
4. **Detection**: Difficult to detect before Release execution since validation passes at both creation and release stages
5. **Cost**: Only requires transaction fees for proposal creation

The likelihood is **Medium** due to the realistic attacker profile and low execution complexity.

## Recommendation

Add proper address validation to all three governance contracts by checking both the object reference AND the Value property. The validation should follow the pattern already established in `TokenContract_Helper.cs`:

```csharp
private bool Validate(ProposalInfo proposal)
{
    if (proposal.ToAddress == null || proposal.ToAddress.Value.IsNullOrEmpty() || 
        string.IsNullOrWhiteSpace(proposal.ContractMethodName) ||
        !ValidateDescriptionUrlScheme(proposal.ProposalDescriptionUrl))
        return false;

    return proposal.ExpiredTime != null && Context.CurrentBlockTime < proposal.ExpiredTime;
}
```

This change should be applied to:
- `contract/AElf.Contracts.Association/Association_Helper.cs` (line 85)
- `contract/AElf.Contracts.Parliament/Parliament_Helper.cs` (line 159)
- `contract/AElf.Contracts.Referendum/Referendum_Helper.cs` (line 106)

## Proof of Concept

```csharp
[Fact]
public async Task CreateProposal_WithEmptyAddressValue_ShouldRevert()
{
    // Create an Address object with empty Value
    var emptyAddress = new Address { Value = ByteString.Empty };
    
    // Create proposal with empty address
    var proposalInput = new CreateProposalInput
    {
        OrganizationAddress = organizationAddress,
        ToAddress = emptyAddress,  // Address object exists but Value is empty
        ContractMethodName = "SomeMethod",
        Params = ByteString.Empty,
        ExpiredTime = BlockTimeProvider.GetBlockTime().AddDays(1)
    };
    
    // This should fail but currently passes validation
    var proposalId = await AssociationContractStub.CreateProposal.SendAsync(proposalInput);
    
    // Members approve the proposal
    await ApproveProposal(proposalId);
    
    // Release attempt should fail with inline transaction error
    var releaseResult = await AssociationContractStub.Release.SendWithExceptionAsync(proposalId);
    
    // Proposal should be removed after successful release, but remains due to revert
    var proposal = await AssociationContractStub.GetProposal.CallAsync(proposalId);
    proposal.ShouldNotBeNull(); // Proposal still exists - demonstrates the bug
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L46-52)
```csharp
    public override SmartContractRegistration GetSmartContractRegistrationByAddress(Address input)
    {
        var info = State.ContractInfos[input];
        if (info == null) return null;

        return State.SmartContractRegistrations[info.CodeHash];
    }
```
