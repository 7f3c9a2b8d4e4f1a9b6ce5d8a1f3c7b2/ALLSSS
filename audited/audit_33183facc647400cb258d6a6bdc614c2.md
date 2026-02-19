# Audit Report

## Title
NFT Contract ACS1 Implementation Completely Non-Functional - Governance Cannot Adjust Method Fees

## Summary
The NFT contract's `SetMethodFee()` and `ChangeMethodFeeController()` methods are stub implementations that return empty responses without performing any state modifications. This prevents Parliament governance from adjusting transaction fees for NFT operations, creating a permanent 100 ELF fee for the Create method that cannot be modified through governance.

## Finding Description

The NFT contract implements the ACS1 (Transaction Fee Standard) interface but provides only non-functional stub implementations. The `SetMethodFee` method accepts input but immediately returns an empty response without validation, authorization checks, or state storage. [1](#0-0) 

Similarly, `ChangeMethodFeeController` performs no operations. [2](#0-1) 

The `GetMethodFee` method returns a hardcoded value of 100 ELF (100,000,000,000 smallest units) for the "Create" method, with no retrieval from contract state. [3](#0-2) 

The root cause is the complete absence of state storage properties. The NFT contract state definition lacks both `TransactionFees` and `MethodFeeController` properties that are required for ACS1 implementation. [4](#0-3) 

In contrast, properly implemented system contracts like Association include authorization checks, token validation, and state persistence in `SetMethodFee`. [5](#0-4) 

These contracts also retrieve fees from state rather than hardcoded values. [6](#0-5) 

The Association contract state properly defines the required storage properties. [7](#0-6) 

Parliament contract follows the same proper implementation pattern with authorization and state storage. [8](#0-7) 

Parliament state also includes the required properties. [9](#0-8) 

When fees are charged, the Token contract calls `GetMethodFee` on the target contract via cross-contract call to retrieve fee configuration. [10](#0-9) 

## Impact Explanation

**Governance Authority Violation:** Parliament governance cannot exercise method-fee provider authority over the NFT contract, breaking the uniform governance model that applies to all other AElf system contracts. This violates a fundamental protocol invariant.

**Economic Rigidity:** The Create method fee is permanently fixed at 100 ELF. If ELF appreciates significantly in market value (e.g., 10x-100x), this fee becomes prohibitively expensive with no governance mechanism to adjust it. This could effectively DoS NFT protocol creation during price spikes.

**Silent State Divergence:** When `SetMethodFee` is called (whether directly or through Parliament governance proposals), the transaction executes successfully but produces zero effect on contract behavior. External observers see successful transactions but the contract's actual fee structure never changes, creating false governance signals.

**Protocol Evolution Blocked:** Standard economic adjustments that should be handled through governance (fee reductions for ecosystem growth, zero-fee promotional periods, differentiated pricing for NFT types) cannot be implemented without deploying a new contract version.

## Likelihood Explanation

**Certainty of Occurrence:** This is not a probabilistic vulnerability - it occurs with 100% certainty on every interaction. The governance denial is already active in production; the hardcoded fee is already in effect.

**No Prerequisites:** Any address can observe this by calling `SetMethodFee` (no authorization exists) or by examining the contract code. Governance proposals that appear to succeed have zero actual effect.

**Market-Driven Impact:** As ELF price fluctuates in external markets, the economic consequences manifest automatically. The protocol has no adaptive mechanism to respond to market conditions.

**Immediate Detectability:** The issue is visible through simple code review comparing the NFT contract's ACS1 implementation against any other system contract.

## Recommendation

Implement proper ACS1 support in the NFT contract:

1. Add required state properties to `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

2. Implement `SetMethodFee` with authorization and state persistence following the pattern from Association/Parliament contracts:
   - Validate token symbols and amounts
   - Initialize method fee controller with Parliament default organization
   - Check caller is authorized (Context.Sender == MethodFeeController.OwnerAddress)
   - Store fees in state: `State.TransactionFees[input.MethodName] = input`

3. Implement `ChangeMethodFeeController` with authority validation and state updates

4. Modify `GetMethodFee` to retrieve from state: `return State.TransactionFees[input.Value]`

5. Add initialization logic to set default Parliament organization as method fee controller during contract deployment

## Proof of Concept

```csharp
[Fact]
public async Task NFT_SetMethodFee_DoesNotPersist()
{
    // Setup: Get Parliament default organization
    var defaultOrg = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Verify initial hardcoded fee is 100 ELF
    var initialFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    initialFee.Fees[0].BasicFee.ShouldBe(100_00000000); // 100 ELF hardcoded
    
    // Attempt to change fee to 50 ELF through SetMethodFee
    await NFTContractStub.SetMethodFee.SendAsync(new MethodFees
    {
        MethodName = "Create",
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
    });
    
    // Verify fee remains unchanged - proving governance failure
    var afterFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    afterFee.Fees[0].BasicFee.ShouldBe(100_00000000); // Still 100 ELF, not 50 ELF
    
    // Demonstrates: SetMethodFee executed successfully but had zero effect
}
```

## Notes

This vulnerability represents a fundamental governance failure rather than a funds-at-risk issue. The security impact stems from:

1. **Inconsistency with protocol standards:** All other system contracts properly implement ACS1 with state persistence
2. **Governance model violation:** Parliament authority over method fees is a core protocol invariant that is broken for NFT contract
3. **Economic inflexibility:** The fixed fee prevents protocol adaptation to market conditions without contract upgrades

The issue does not allow fund theft or supply manipulation, but it does prevent legitimate governance operations and creates economic rigidity that could suppress protocol usage during unfavorable market conditions.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L8-11)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L13-16)
```csharp
    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L20-37)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        if (input.Value == nameof(Create))
            return new MethodFees
            {
                MethodName = input.Value,
                Fees =
                {
                    new MethodFee
                    {
                        Symbol = Context.Variables.NativeSymbol,
                        BasicFee = 100_00000000
                    }
                }
            };

        return new MethodFees();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L1-46)
```csharp
﻿using AElf.Sdk.CSharp.State;
using AElf.Types;

namespace AElf.Contracts.NFT;

public partial class NFTContractState : ContractState
{
    public Int64State NftProtocolNumberFlag { get; set; }
    public Int32State CurrentSymbolNumberLength { get; set; }
    public MappedState<long, bool> IsCreatedMap { get; set; }

    /// <summary>
    ///     Symbol -> Addresses have permission to mint this token
    /// </summary>
    public MappedState<string, MinterList> MinterListMap { get; set; }

    public MappedState<Hash, NFTInfo> NftInfoMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Balance
    /// </summary>
    public MappedState<Hash, Address, long> BalanceMap { get; set; }

    public MappedState<string, NFTProtocolInfo> NftProtocolMap { get; set; }

    /// <summary>
    ///     Token Hash -> Owner Address -> Spender Address -> Approved Amount
    ///     Need to record approved by whom.
    /// </summary>
    public MappedState<Hash, Address, Address, long> AllowanceMap { get; set; }

    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }

    public MappedState<string, string> NFTTypeShortNameMap { get; set; }
    public MappedState<string, string> NFTTypeFullNameMap { get; set; }

    public SingletonState<Address> ParliamentDefaultAddress { get; set; }

    public SingletonState<NFTTypes> NFTTypes { get; set; }

    /// <summary>
    ///     Symbol (Protocol) -> Owner Address -> Operator Address List
    /// </summary>
    public MappedState<string, Address, AddressList> OperatorMap { get; set; }
}
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L10-19)
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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L34-37)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        return State.TransactionFees[input.Value];
    }
```

**File:** contract/AElf.Contracts.Association/AssociationState.cs (L11-12)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-18)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
```

**File:** contract/AElf.Contracts.Parliament/ParliamentState.cs (L23-26)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }

    public SingletonState<ProposerWhiteList> ProposerWhiteList { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-39)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
```
