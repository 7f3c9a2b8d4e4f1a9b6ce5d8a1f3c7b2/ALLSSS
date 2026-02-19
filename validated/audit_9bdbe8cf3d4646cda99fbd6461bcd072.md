# Audit Report

## Title
Governance Fee Control Bypass for Cross-Chain Indexing Methods Due to Hardcoded GetMethodFee Override

## Summary
The CrossChain contract's `GetMethodFee` method contains hardcoded logic that always returns `IsSizeFeeFree=true` for `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal`, completely bypassing any fees stored via `SetMethodFee`. This creates a governance control failure where Parliament can set fees through the standard ACS1 interface, but those fees are silently ignored during transaction execution.

## Finding Description

The vulnerability exists in the CrossChain contract's ACS1 fee provider implementation due to a state inconsistency between fee storage and fee retrieval:

**Fee Storage Path:**
The `SetMethodFee` function accepts any method name without validation and stores the fee configuration in `State.TransactionFees[input.MethodName]`. [1](#0-0) 

This allows governance (Parliament by default) to successfully store fees for `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal` without any indication that these fees will be ignored.

**Fee Retrieval Path:**
However, `GetMethodFee` contains hardcoded logic that completely bypasses stored state for these specific methods. [2](#0-1) 

For `ProposeCrossChainIndexing` and `ReleaseCrossChainIndexingProposal`, it returns a new `MethodFees` object with `IsSizeFeeFree=true` and an empty `Fees` list, completely ignoring the stored state at `State.TransactionFees[input.Value]`.

**Actual Fee Collection:**
The TokenContract's `ChargeTransactionFees` method calls the target contract's `GetMethodFee` to retrieve the fee configuration that determines what fees to charge. [3](#0-2) 

The `isSizeFeeFree` flag from `GetMethodFee` determines whether size fees are charged, and the `fee` dictionary from `methodFees.Fees` determines base fees. Since the hardcoded return has `IsSizeFeeFree=true` and empty fees, no fees are collected regardless of what governance stored via `SetMethodFee`.

**Root Cause:**
The hardcoded override in `GetMethodFee` takes absolute precedence over stored state, creating an unbreakable bypass of governance fee control. There is no validation in `SetMethodFee` to prevent setting fees for these methods, nor any warning mechanism to inform governance that such fees will be ignored.

## Impact Explanation

**Governance Integrity Violation:**
Parliament (the default MethodFeeController) completely loses control over fee configuration for two critical cross-chain methods. [4](#0-3) 

When governance passes a proposal to set fees for these methods, the fees are stored but silently ignored during execution.

**Economic and Operational Impact:**
1. **Spam Prevention Failure**: If governance determines that fee-free cross-chain indexing could enable abuse, they cannot enforce fees to mitigate this risk
2. **Economic Policy Bypass**: Any economic incentive structure requiring fees on cross-chain indexing cannot be implemented
3. **Dead State Storage**: `State.TransactionFees` accumulates misleading configuration data
4. **ACS1 Standard Violation**: The ACS1 interface creates an expectation that `SetMethodFee` controls fees for all methods, but this hidden exception violates that contract

**Affected Parties:**
- **Governance/Parliament**: Loses control over critical infrastructure fee configuration
- **Miners**: Can execute cross-chain indexing fee-free regardless of governance policy [5](#0-4) 
- **Protocol Economics**: Cannot implement fee-based controls for cross-chain operations

While both methods are restricted to current miners only [6](#0-5) , governance should still retain ultimate authority over fee configuration per the ACS1 standard.

## Likelihood Explanation

**Trigger Condition:**
Parliament calls `SetMethodFee` with `MethodName = "ProposeCrossChainIndexing"` or `"ReleaseCrossChainIndexingProposal"` through normal governance processes.

**Reproducibility:**
- **Probability**: 100% - every attempt to set fees for these methods results in silent failure
- **Prerequisites**: None beyond normal governance operations
- **Detection**: Extremely difficult - fees appear set successfully in state but are never enforced

**Feasibility:**
This is not an attacker exploit but a governance dysfunction that triggers automatically whenever governance legitimately attempts to set fees for these methods. The hardcoded logic cannot be overridden or bypassed.

## Recommendation

**Option 1 - Remove Hardcoded Override:**
Modify `GetMethodFee` to respect stored state for all methods, removing the hardcoded exception. If these methods should be fee-free by default, set this through governance rather than hardcoding.

**Option 2 - Add Validation:**
Add validation in `SetMethodFee` to reject or warn when attempting to set fees for methods with hardcoded overrides:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    var hardcodedMethods = new List<string> { 
        nameof(ProposeCrossChainIndexing), 
        nameof(ReleaseCrossChainIndexingProposal) 
    };
    Assert(!hardcodedMethods.Contains(input.MethodName), 
        "Cannot set fees for methods with hardcoded fee configuration.");
    
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Option 3 - Governance-Controlled Override Flag:**
Store the fee-free status in state and allow governance to modify it, rather than hardcoding it.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Deploy CrossChain contract with Parliament as MethodFeeController
2. Call `SetMethodFee` via Parliament proposal to set fees for `ProposeCrossChainIndexing` (e.g., 1 ELF base fee, size fees enabled)
3. Verify fees are stored in `State.TransactionFees["ProposeCrossChainIndexing"]`
4. Call `GetMethodFee("ProposeCrossChainIndexing")` and observe it returns `IsSizeFeeFree=true` with empty fees list
5. Execute `ProposeCrossChainIndexing` as a miner and verify no fees are charged
6. Demonstrate that the stored fees in state are completely ignored

This proves that governance loses control over fee configuration for these critical methods despite the ACS1 standard promising such control.

**Notes:**
- This vulnerability represents a design flaw rather than a traditional exploit
- The severity stems from violating governance expectations and the ACS1 standard contract
- While the affected methods are miner-only (reducing attack surface), governance should retain ultimate authority over all protocol fees
- The silent failure aspect is particularly problematic as it provides no feedback to governance that their fee settings are ineffective

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_ACS1_TransactionFeeProvider.cs (L12-22)
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_ACS1_TransactionFeeProvider.cs (L61-73)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        SetContractStateRequired(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-52)
```csharp
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-302)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
    }

    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```
