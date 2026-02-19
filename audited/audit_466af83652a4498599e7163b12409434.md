### Title
NFT Contract Fee Governance Desynchronization - SetMethodFee Silently Ignores Updates While GetMethodFee Returns Hardcoded Values

### Summary
The NFT contract's ACS1 implementation is incomplete: `SetMethodFee()` accepts fee update calls but doesn't persist changes to state, while `GetMethodFee()` returns hardcoded values instead of reading from state. This causes governance desynchronization where Parliament believes fees are updated, but the runtime continues charging the original hardcoded 100 ELF fee for the Create method indefinitely.

### Finding Description

The NFT contract implements the ACS1 (Transaction Fee Standard) interface but with non-functional stub methods: [1](#0-0) 

The `SetMethodFee()` method returns successfully without persisting any state changes. [2](#0-1) 

The `GetMethodFee()` method returns a hardcoded 100 ELF fee for the "Create" method, ignoring any fee configurations. [3](#0-2) 

The contract state lacks the `TransactionFees` mapped state variable that all other system contracts use to persist fee configurations.

The standard implementation pattern shows proper state persistence: [4](#0-3) [5](#0-4) [6](#0-5) 

The runtime fee charging mechanism calls `GetMethodFee()` to determine fees: [7](#0-6) 

**Root Cause**: The NFT contract's ACS1 implementation is incomplete - it provides the interface methods but lacks the state persistence layer and logic to store/retrieve fee configurations.

### Impact Explanation

**Governance Integrity Violation**: 
- Parliament cannot adjust NFT contract fees through standard governance mechanisms
- Fee update proposals will appear to succeed but have no effect
- Governance has no visibility that their decisions are being ignored

**Economic Inflexibility**:
- The Create method fee is permanently fixed at 100 ELF (1,000,000,000 base units)
- Cannot reduce fees if ELF price increases significantly
- Cannot increase fees for protocol revenue optimization
- Cannot disable fees if needed for protocol growth

**Protocol Consistency Breach**:
- All other system contracts support fee governance via ACS1
- NFT contract breaks this standard pattern
- Creates operational confusion and governance uncertainty

**Affected Parties**:
- Governance (Parliament) - loses fee control capability
- NFT creators - pay fixed fee regardless of economic conditions
- Protocol - cannot optimize fee structure for NFT protocol adoption

### Likelihood Explanation

**Certainty**: GUARANTEED - This is a design flaw that manifests in 100% of fee update attempts.

**Entry Point**: The `SetMethodFee` method is part of the public ACS1 interface that governance uses to update fees across all system contracts.

**Feasibility**: 
- Governance would naturally attempt to update NFT fees via Parliament proposals
- The transaction succeeds (returns Empty), giving false confirmation
- No error or revert indicates the problem
- Detection requires reading contract code or observing that fees never change despite governance actions

**Execution Path**:
1. Parliament creates proposal to call NFT.SetMethodFee with new fee structure
2. Proposal gets miner approval and is released
3. SetMethodFee executes successfully, returning Empty
4. Governance believes fee update succeeded
5. Subsequent Create transactions still charge hardcoded 100 ELF
6. Governance discovers fees unchanged, potentially months later

**No Attack Required**: This is not an active exploit but a passive governance failure that occurs through normal protocol operation.

### Recommendation

**Immediate Fix** - Add complete ACS1 implementation to NFT contract:

1. **Add State Variable** to `NFTContractState.cs`:
```csharp
internal MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

2. **Implement SetMethodFee** with state persistence:
```csharp
public override Empty SetMethodFee(MethodFees input)
{
    foreach (var symbolToAmount in input.Fees) 
        AssertValidToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);
    
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to set method fee.");
    
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

3. **Update GetMethodFee** to read from state:
```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    // Return stored fees if configured
    var fees = State.TransactionFees[input.Value];
    if (fees != null) return fees;
    
    // Fallback to default for Create method
    if (input.Value == nameof(Create))
        return new MethodFees
        {
            MethodName = input.Value,
            Fees = { new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 100_00000000 } }
        };
    
    return new MethodFees();
}
```

4. **Initialize MethodFeeController** with Parliament governance:
```csharp
private void RequiredMethodFeeControllerSet()
{
    if (State.MethodFeeController.Value != null) return;
    
    if (State.ParliamentContract.Value == null)
        State.ParliamentContract.Value = 
            Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);
    
    State.MethodFeeController.Value = new AuthorityInfo
    {
        OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
        ContractAddress = State.ParliamentContract.Value
    };
}
```

5. **Implement ChangeMethodFeeController**:
```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to change method fee controller.");
    Assert(CheckOrganizationExist(input), "Invalid authority input.");
    
    State.MethodFeeController.Value = input;
    return new Empty();
}
```

**Test Coverage**: Add ACS1 implementation tests similar to other system contracts covering authorization, fee updates, and controller changes.

### Proof of Concept

**Initial State**:
- NFT contract deployed with hardcoded 100 ELF fee for Create method
- Parliament is the default governance authority

**Step 1**: Parliament creates proposal to reduce Create fee to 10 ELF
```
Proposal: NFTContract.SetMethodFee({
    MethodName: "Create",
    Fees: [{ Symbol: "ELF", BasicFee: 10_00000000 }]
})
```

**Step 2**: Miners approve and release proposal
- Transaction succeeds, returns Empty
- Governance records: "NFT Create fee updated to 10 ELF"

**Step 3**: User attempts to create NFT protocol
```
NFTContract.Create({...})
```

**Expected Result**: User is charged 10 ELF transaction fee

**Actual Result**: User is still charged 100 ELF transaction fee

**Verification**:
```
NFTContract.GetMethodFee("Create") 
// Returns: { MethodName: "Create", Fees: [{ Symbol: "ELF", BasicFee: 100_00000000 }] }
// Hardcoded value, ignoring governance update
```

**Success Condition**: Governance desynchronization confirmed - SetMethodFee accepted input but GetMethodFee returns original hardcoded value, proving fee governance is non-functional.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-39)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
```
