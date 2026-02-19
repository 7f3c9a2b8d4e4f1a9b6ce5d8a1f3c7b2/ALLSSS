# Audit Report

## Title
NFT Contract Fee Governance Desynchronization - SetMethodFee Silently Ignores Updates While GetMethodFee Returns Hardcoded Values

## Summary
The NFT contract implements the ACS1 Transaction Fee Standard interface with non-functional stub methods. `SetMethodFee()` accepts governance fee updates but doesn't persist changes to state, while `GetMethodFee()` returns a hardcoded 100 ELF fee instead of reading from state. This creates a governance desynchronization where Parliament believes fee updates succeed, but the runtime continues charging the original hardcoded fee indefinitely.

## Finding Description

The NFT contract's ACS1 implementation lacks the state persistence layer required for fee governance. [1](#0-0) 

The `SetMethodFee()` method is a no-op stub that returns `Empty` without persisting any state changes, lacking both authorization checks and state writes.

The `GetMethodFee()` method returns a hardcoded 100 ELF (100_00000000 base units) fee for the "Create" method, ignoring any fee configurations that might have been intended. [2](#0-1) 

The NFT contract state completely lacks the `TransactionFees` mapped state variable and `MethodFeeController` state variable that all other system contracts use to persist fee configurations. [3](#0-2) 

By contrast, the standard ACS1 implementation pattern in other system contracts (MultiToken, Parliament, Treasury) properly persists fees to state. [4](#0-3) 

The MultiToken contract reads fees from state. [5](#0-4) 

And includes the required state variable. [6](#0-5) 

The AElf runtime's fee charging mechanism calls `GetMethodFee()` on the target contract to determine transaction fees before execution. [7](#0-6) 

The NFT contract has a public `Create` method that would be subject to these fees. [8](#0-7) 

## Impact Explanation

**Governance Integrity Violation**: Parliament loses the ability to adjust NFT contract fees through standard governance mechanisms. Fee update proposals will execute successfully (returning `Empty`), creating a false confirmation that governance decisions have been implemented. Governance has no visibility that their decisions are being silently ignored, undermining the fundamental principle that governance should control protocol economics.

**Economic Inflexibility**: The Create method fee is permanently locked at 100 ELF regardless of economic conditions. If ELF token price increases significantly, the fixed 100 ELF fee becomes prohibitively expensive, potentially blocking NFT protocol adoption. Conversely, governance cannot increase fees for protocol revenue optimization. The protocol cannot adapt to changing market conditions or strategic needs.

**Protocol Consistency Breach**: All other AElf system contracts (MultiToken, Parliament, Treasury, Election, etc.) properly implement ACS1 with state persistence and governance control. The NFT contract breaks this standard pattern, creating operational inconsistency and governance uncertainty across the protocol.

**Affected Parties**:
- **Governance (Parliament)**: Loses fee control capability and receives false success signals
- **NFT creators**: Pay fixed fees regardless of economic conditions
- **Protocol operators**: Cannot optimize fee structure for protocol growth or revenue

## Likelihood Explanation

**Certainty**: GUARANTEED - This is a structural design flaw present in 100% of fee update attempts, not a race condition or edge case.

**Entry Point**: The `SetMethodFee` method is part of the public ACS1 interface that governance uses to update fees across all system contracts. It is a legitimate, expected governance action.

**Feasibility**: Parliament would naturally attempt to update NFT fees through standard governance proposals as they do for all other contracts. The transaction succeeds without error, providing false confirmation. Detection requires either reading the contract source code or observing over time that fees never change despite governance actions taken.

**Execution Path**:
1. Parliament creates a proposal to call `NFT.SetMethodFee` with new fee configuration
2. Proposal receives miner approval and is released  
3. `SetMethodFee` executes, returning `Empty` (success signal)
4. Governance records the action as successful
5. Subsequent `Create` transactions continue charging the hardcoded 100 ELF
6. Eventually governance discovers fees are unchanged, potentially months later

**No Attack Required**: This is not an active exploit by a malicious actor but a passive governance failure that occurs through normal, legitimate protocol operations.

## Recommendation

Implement proper ACS1 state persistence in the NFT contract:

1. Add state variables to `NFTContractState.cs`:
   - `internal MappedState<string, MethodFees> TransactionFees { get; set; }`
   - `public SingletonState<AuthorityInfo> MethodFeeController { get; set; }`

2. Implement `SetMethodFee` with authorization and persistence:
   - Check authorization against `MethodFeeController`
   - Validate fee token symbols
   - Persist to state: `State.TransactionFees[input.MethodName] = input;`

3. Implement `GetMethodFee` to read from state:
   - Return `State.TransactionFees[input.Value]` instead of hardcoded values
   - Keep size-fee-free flag for Create method if desired

4. Implement `ChangeMethodFeeController` and `GetMethodFeeController` properly

5. Initialize `MethodFeeController` to Parliament default organization during contract initialization

Follow the implementation pattern from MultiToken, Parliament, or Treasury contracts as reference.

## Proof of Concept

This vulnerability is inherent in the contract design and doesn't require a complex test. A simple verification:

```csharp
// Governance calls SetMethodFee with new fee (e.g., 50 ELF)
var newFees = new MethodFees 
{
    MethodName = "Create",
    Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
};
nftContract.SetMethodFee(newFees); // Returns Empty (success)

// Query the fee
var retrievedFees = nftContract.GetMethodFee(new StringValue { Value = "Create" });

// VULNERABILITY: retrievedFees.Fees[0].BasicFee will still be 100_00000000
// Not the 50_00000000 that was just set
Assert(retrievedFees.Fees[0].BasicFee == 100_00000000); // Always true - fees never change
```

The contract state inspection confirms no `TransactionFees` variable exists to store the updated values, and `GetMethodFee` always returns the hardcoded 100 ELF value regardless of any `SetMethodFee` calls.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L8-11)
```csharp
    public override Empty SetMethodFee(MethodFees input)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-22)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
        return new Empty();
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

**File:** contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs (L10-10)
```csharp
    internal MappedState<string, MethodFees> TransactionFees { get; set; }
```

**File:** docs-sphinx/reference/acs/acs1.rst (L109-143)
```text
   public override BoolValue ChargeTransactionFees(ChargeTransactionFeesInput input)
   {
       // ...
       // Record tx fee bill during current charging process.
       var bill = new TransactionFeeBill();
       var fromAddress = Context.Sender;
       var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
           new StringValue {Value = input.MethodName});
       var successToChargeBaseFee = true;
       if (methodFees != null && methodFees.Fees.Any())
       {
           successToChargeBaseFee = ChargeBaseFee(GetBaseFeeDictionary(methodFees), ref bill);
       }
       var successToChargeSizeFee = true;
       if (!IsMethodFeeSetToZero(methodFees))
       {
           // Then also do not charge size fee.
           successToChargeSizeFee = ChargeSizeFee(input, ref bill);
       }
       // Update balances.
       foreach (var tokenToAmount in bill.FeesMap)
       {
           ModifyBalance(fromAddress, tokenToAmount.Key, -tokenToAmount.Value);
           Context.Fire(new TransactionFeeCharged
           {
               Symbol = tokenToAmount.Key,
               Amount = tokenToAmount.Value
           });
           if (tokenToAmount.Value == 0)
           {
               //Context.LogDebug(() => $"Maybe incorrect charged tx fee of {tokenToAmount.Key}: it's 0.");
           }
       }
       return new BoolValue {Value = successToChargeBaseFee && successToChargeSizeFee};
   }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-17)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
```
