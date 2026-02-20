# Audit Report

## Title
Self-Referential Method Fee Setting Enables Governance Lockout

## Summary
The `SetMethodFee` function in the Genesis contract lacks validation to prevent setting transaction fees on itself, allowing governance to configure a fee that must be paid to modify any method fees. If set excessively high and the Parliament organization's virtual address lacks sufficient funds, governance becomes permanently locked out of all method fee management system-wide.

## Finding Description

The `SetMethodFee` method stores fee configurations without validating whether `input.MethodName` references itself. The method only validates token symbols and amounts (non-negative), then directly stores the fee configuration. [1](#0-0) 

When Parliament releases a proposal, the transaction originates from the organization's virtual address via `SendVirtualInlineBySystemContract`, which uses a calculated virtual hash to execute the transaction. [2](#0-1) 

Before any transaction executes, the pre-execution plugin generates a `ChargeTransactionFees` transaction that constructs the charging input with the method name and contract address. [3](#0-2) 

The fee charging implementation sets `fromAddress = Context.Sender` (the organization's virtual address when released via Parliament) and attempts to retrieve and charge the configured method fee. [4](#0-3) 

The `GetMethodFee` method returns the stored fee from `State.TransactionFees[input.Value]` without any special exemption for `SetMethodFee` or organization addresses. [5](#0-4) 

If fee charging fails due to insufficient balance, the `IsStopExecuting` method returns true, which causes the execution service to prevent the main transaction from executing. [6](#0-5) [7](#0-6) 

Both `SetMethodFee` and `ChangeMethodFeeController` require authorization from the same `State.MethodFeeController.Value.OwnerAddress` (typically Parliament's default organization), providing no alternative recovery path. [8](#0-7) 

Test evidence confirms organizations must pre-fund their virtual addresses before releasing proposals, as the transaction execution originates from the organization's virtual address which must have sufficient balance to pay fees. [9](#0-8) 

## Impact Explanation

Once a prohibitively high fee is configured for `SetMethodFee`, all future method fee modifications require paying that fee from Parliament's virtual address. Since `SetMethodFee` is the only mechanism to modify method fees (including reducing its own fee), and `ChangeMethodFeeController` requires identical authorization, governance lockout occurs if the organization cannot afford the fee.

This affects system-wide fee management capability across all contracts. The validation logic only checks that amounts are non-negative and tokens are valid - there is no upper bound validation on fee amounts. If the fee exceeds economically feasible amounts (e.g., exceeding total ELF supply or Parliament's available balance), recovery becomes impossible, resulting in permanent loss of fee governance.

## Likelihood Explanation

While this requires Parliament governance approval (2/3 miner consensus), it represents a realistic threat through:

1. **Human error**: Accidental misconfiguration during routine fee updates (e.g., incorrect decimal places: intending 100 ELF but setting 100000000 ELF due to the 8-decimal precision used in token amounts)
2. **Lack of validation**: No upper bound checks or warnings during proposal creation/approval
3. **Approval blindness**: Multiple miners could approve routine-looking fee adjustment proposals without detailed value verification, especially if the proposal appears to be a standard fee update

The attack requires only one successful governance proposal with `input.MethodName = "SetMethodFee"` and an excessive fee value. The precondition (governance approval) is routine as Parliament regularly votes on fee adjustments during normal operations.

## Recommendation

Add validation in `SetMethodFee` to prevent self-referential fee setting or implement an upper bound check on fee amounts:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);

    RequiredMethodFeeControllerSet();

    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    
    // Prevent self-referential fee setting
    Assert(input.MethodName != nameof(SetMethodFee), "Cannot set fee on SetMethodFee itself.");
    
    // Optional: Add reasonable upper bound validation
    foreach (var methodFee in input.Fees)
    {
        Assert(methodFee.BasicFee <= MaxReasonableFee, "Fee amount exceeds maximum allowed.");
    }
    
    State.TransactionFees[input.MethodName] = input;

    return new Empty();
}
```

Alternatively, implement exemption logic in the fee charging mechanism for system-critical governance operations or organization virtual addresses when executing governance-approved proposals.

## Proof of Concept

```csharp
[Fact]
public async Task SetMethodFee_SelfReferential_Causes_Governance_Lockout()
{
    // Setup: Get default Parliament organization
    var defaultOrganization = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Step 1: Create proposal to set high fee on SetMethodFee itself
    var excessiveFee = 1000000000000000; // Impossibly high amount
    var proposalId = await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = BasicContractZeroAddress,
        ContractMethodName = nameof(BasicContractZero.SetMethodFee),
        Params = new MethodFees
        {
            MethodName = nameof(BasicContractZero.SetMethodFee),
            Fees = { new MethodFee { Symbol = "ELF", BasicFee = excessiveFee } }
        }.ToByteString(),
        OrganizationAddress = defaultOrganization,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // Step 2: Approve and release proposal (with sufficient organization balance for this transaction)
    await TransferToOrganizationAddressAsync(defaultOrganization, excessiveFee);
    await ApproveWithMinersAsync(proposalId.Output);
    await ParliamentContractStub.Release.SendAsync(proposalId.Output);
    
    // Step 3: Verify fee is set
    var feeSet = await BasicContractZeroStub.GetMethodFee.CallAsync(new StringValue 
        { Value = nameof(BasicContractZero.SetMethodFee) });
    feeSet.Fees.First().BasicFee.ShouldBe(excessiveFee);
    
    // Step 4: Attempt to create another proposal to reduce the fee
    var reduceFeeProposal = await ParliamentContractStub.CreateProposal.SendAsync(new CreateProposalInput
    {
        ToAddress = BasicContractZeroAddress,
        ContractMethodName = nameof(BasicContractZero.SetMethodFee),
        Params = new MethodFees
        {
            MethodName = nameof(BasicContractZero.SetMethodFee),
            Fees = { new MethodFee { Symbol = "ELF", BasicFee = 100 } }
        }.ToByteString(),
        OrganizationAddress = defaultOrganization,
        ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1)
    });
    
    // Step 5: Approve but cannot release - organization cannot afford the excessive fee
    await ApproveWithMinersAsync(reduceFeeProposal.Output);
    
    // This will fail because ChargeTransactionFees cannot charge the excessive fee from organization
    var releaseResult = await ParliamentContractStub.Release.SendWithExceptionAsync(reduceFeeProposal.Output);
    
    // Assert: Governance is locked out - cannot modify any method fees
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    releaseResult.TransactionResult.Error.ShouldContain("Transaction fee not enough");
}
```

## Notes

This vulnerability exploits the lack of input validation combined with the uniform fee charging mechanism. The critical insight is that `SetMethodFee` can configure a fee on itself without any safeguards, creating a circular dependency where modifying the fee requires paying the fee first. Since organization virtual addresses must pay fees like regular addresses and have finite balances, an excessively high self-referential fee creates an unrecoverable governance deadlock.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L9-19)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);

        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L34-47)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var fees = State.TransactionFees[input.Value];
        if (fees == null && input.Value == nameof(ReleaseApprovedUserSmartContract))
        {
            fees = new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
        }

        return fees;
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

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L91-96)
```csharp
            var chargeTransactionFeesInput = new ChargeTransactionFeesInput
            {
                MethodName = transactionContext.Transaction.MethodName,
                ContractAddress = transactionContext.Transaction.To,
                TransactionSizeFee = txCost
            };
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee/MethodFeeChargedPreExecutionPluginBase.cs (L123-129)
```csharp
    public bool IsStopExecuting(ByteString txReturnValue, out string preExecutionInformation)
    {
        var chargeTransactionFeesOutput = new ChargeTransactionFeesOutput();
        chargeTransactionFeesOutput.MergeFrom(txReturnValue);
        preExecutionInformation = chargeTransactionFeesOutput.ChargingInformation;
        return !chargeTransactionFeesOutput.Success;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L24-52)
```csharp
    public override ChargeTransactionFeesOutput ChargeTransactionFees(ChargeTransactionFeesInput input)
    {
        Context.LogDebug(() => "ChargeTransactionFees Start");
        AssertPermissionAndInput(input);
        // Primary token not created yet.
        if (State.ChainPrimaryTokenSymbol.Value == null)
        {
            return new ChargeTransactionFeesOutput { Success = true };
        }

        // Record tx fee bill during current charging process.
        var bill = new TransactionFeeBill();
        var allowanceBill = new TransactionFreeFeeAllowanceBill();
        var fromAddress = Context.Sender;
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L288-293)
```csharp
                if (!plugin.IsStopExecuting(preTrace.ReturnValue, out var error)) continue;

                // If pre-tx fails, still commit the changes, but return false to notice outside to stop the execution.
                preTrace.Error = error;
                preTrace.ExecutionStatus = ExecutionStatus.Executed;
                return false;
```

**File:** test/AElf.Contracts.Parliament.Tests/ParliamentContractTest.cs (L1582-1591)
```csharp
    private async Task TransferToOrganizationAddressAsync(Address to)
    {
        await TokenContractStub.Transfer.SendAsync(new TransferInput
        {
            Symbol = "ELF",
            Amount = 200,
            To = to,
            Memo = "transfer organization address"
        });
    }
```
