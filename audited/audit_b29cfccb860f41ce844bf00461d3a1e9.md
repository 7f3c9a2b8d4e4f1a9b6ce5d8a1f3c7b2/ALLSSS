### Title
Inconsistent Fee Exemption Pattern for ReleaseApprovedUserSmartContract Allows Size Fee Charging on System Transactions

### Summary
The Genesis contract's `GetMethodFee()` implementation uses a conditional pattern that differs from other system contracts, checking stored configuration before applying the special case for `ReleaseApprovedUserSmartContract`. If governance sets method fees for this system method with `IsSizeFeeFree=false` (or omitted), miners will be charged size fees for their own system-generated transactions, contradicting the intended behavior and creating operational friction in the user contract deployment flow.

### Finding Description

The Genesis contract implements a special case for `ReleaseApprovedUserSmartContract` that only applies when no fees are configured: [1](#0-0) 

This pattern differs fundamentally from how other system contracts handle their system-generated methods. The AEDPoS contract checks method name FIRST: [2](#0-1) 

The CrossChain contract follows the same pattern: [3](#0-2) 

The Parliament contract also checks method name first: [4](#0-3) 

And the MultiToken contract hardcodes system methods unconditionally: [5](#0-4) 

`ReleaseApprovedUserSmartContract` is invoked via system transaction generator by miners: [6](#0-5) 

The method itself requires miner authority: [7](#0-6) 

When fees are charged, the system queries `GetMethodFee()` and respects the `IsSizeFeeFree` flag: [8](#0-7) 

Governance can set method fees via Parliament-controlled `SetMethodFee`: [9](#0-8) 

### Impact Explanation

**Direct Fund Impact**: When governance sets fees for `ReleaseApprovedUserSmartContract` without explicitly setting `IsSizeFeeFree=true`, miners executing these system transactions will be charged size fees. This represents unexpected fund loss for miners who are simply performing their protocol duties.

**Operational Impact**: If fees are set too high, miners may become reluctant to generate `ReleaseApprovedUserSmartContract` transactions, disrupting the user contract deployment and update flow. This affects the entire user contract lifecycle on the chain.

**Affected Parties**: All miners generating code check release transactions, and indirectly all users attempting to deploy or update contracts.

**Severity Justification**: Medium severity due to the operational disruption and inconsistency with established patterns across all other system contracts, though it requires governance action to manifest.

### Likelihood Explanation

**Reachable Entry Point**: Parliament-controlled `SetMethodFee` is the standard mechanism for configuring method fees, accessible through normal governance proposals.

**Feasible Preconditions**: Parliament members propose and approve a method fee configuration for `ReleaseApprovedUserSmartContract`. If they omit `IsSizeFeeFree` (defaults to false) or explicitly set it to false, the vulnerability manifests.

**Execution Practicality**: This is a realistic scenario that could occur through:
- Unintentional misconfiguration when setting fees systematically across methods
- Lack of awareness that this particular method requires special handling
- Assumption that the hardcoded special case always applies (as it does in other contracts)

**Detection Constraints**: The issue would only become apparent when miners notice unexpected fee deductions on their accounts after generating code check release transactions.

**Probability**: Medium - while requiring governance action, the inconsistent pattern increases the risk of misconfiguration during routine fee administration.

### Recommendation

Modify `GetMethodFee()` to check the method name FIRST, making it consistent with all other system contracts:

```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    if (input.Value == nameof(ReleaseApprovedUserSmartContract))
        return new MethodFees
        {
            MethodName = input.Value,
            IsSizeFeeFree = true
        };
    
    return State.TransactionFees[input.Value];
}
```

This ensures `ReleaseApprovedUserSmartContract` is always size-fee-free, regardless of any stored configuration, matching the pattern used in:
- AEDPoS contract for consensus methods
- CrossChain contract for cross-chain indexing methods  
- Parliament contract for batch approval methods
- MultiToken contract for fee charging methods

**Test Cases**: Add integration tests verifying that `ReleaseApprovedUserSmartContract` remains size-fee-free even after governance explicitly sets fees with `IsSizeFeeFree=false`.

### Proof of Concept

**Initial State**: 
- Genesis contract deployed with default configuration
- `ReleaseApprovedUserSmartContract` has no configured fees (null in State.TransactionFees)
- Miner has sufficient balance for transaction fees

**Step 1**: Query current fee configuration
```
GetMethodFee("ReleaseApprovedUserSmartContract")
Result: Returns IsSizeFeeFree=true (special case applies)
```

**Step 2**: Parliament sets fees via proposal and approval
```
SetMethodFee({
    MethodName: "ReleaseApprovedUserSmartContract",
    Fees: [{ Symbol: "ELF", BasicFee: 1000000 }],
    IsSizeFeeFree: false  // or omitted, defaults to false
})
```

**Step 3**: Query fee configuration again
```
GetMethodFee("ReleaseApprovedUserSmartContract")
Result: Returns configured fees with IsSizeFeeFree=false
```

**Step 4**: Miner executes ReleaseApprovedUserSmartContract via system transaction generator

**Expected Result**: No size fees charged (system transaction should be size-fee-free)

**Actual Result**: Size fees ARE charged because GetMethodFee returned IsSizeFeeFree=false, and ChargeTransactionFees respects this flag

**Success Condition**: The mismatch is confirmed when miner's balance shows deductions for both base fee AND size fee, despite this being a system-generated transaction that should only incur base fees.

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L38-52)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (new List<string>
            {
                nameof(InitialAElfConsensusContract), nameof(FirstRound), nameof(UpdateValue),
                nameof(UpdateTinyBlockInformation), nameof(NextRound), nameof(NextTerm)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };

        return State.TransactionFees[input.Value];
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_ACS1_TransactionFeeProvider.cs (L37-49)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (new List<string>
            {
                nameof(ProposeCrossChainIndexing), nameof(ReleaseCrossChainIndexingProposal)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
        return State.TransactionFees[input.Value];
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L34-44)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(ApproveMultiProposals))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };

        return State.TransactionFees[input.Value];
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L37-52)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (new List<string>
            {
                nameof(ClaimTransactionFees), nameof(DonateResourceToken), nameof(ChargeTransactionFees),
                nameof(CheckThreshold), nameof(CheckResourceToken), nameof(ChargeResourceToken),
                nameof(CrossChainReceiveToken)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
        var fees = State.TransactionFees[input.Value];
        return fees;
    }
```

**File:** src/AElf.Kernel.CodeCheck/Application/CodeCheckProposalReleaseTransactionGenerator.cs (L60-72)
```csharp
        var releaseContractTransactions = releaseRequired.Select(proposal => new Transaction
        {
            From = from,
            MethodName = nameof(ACS0Container.ACS0Stub.ReleaseApprovedUserSmartContract),
            To = zeroContractAddress,
            RefBlockNumber = preBlockHeight,
            RefBlockPrefix = BlockHelper.GetRefBlockPrefix(preBlockHash),
            Params = new ReleaseContractInput
            {
                ProposalId = proposal.ProposalId,
                ProposedContractInputHash = proposal.ProposedContractInputHash
            }.ToByteString()
        }).ToList();
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZero.cs (L476-493)
```csharp
    public override Empty ReleaseApprovedUserSmartContract(ReleaseContractInput input)
    {
        var contractProposingInput = State.ContractProposingInputMap[input.ProposedContractInputHash];

        Assert(
            contractProposingInput != null &&
            contractProposingInput.Status == ContractProposingInputStatus.CodeCheckProposed &&
            contractProposingInput.Proposer == Context.Self, "Invalid contract proposing status.");

        AssertCurrentMiner();

        contractProposingInput.Status = ContractProposingInputStatus.CodeChecked;
        State.ContractProposingInputMap[input.ProposedContractInputHash] = contractProposingInput;
        var codeCheckController = State.CodeCheckController.Value;
        Context.SendInline(codeCheckController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release), input.ProposalId);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L24-53)
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
    }
```
