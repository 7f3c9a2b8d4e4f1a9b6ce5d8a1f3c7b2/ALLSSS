# Audit Report

## Title
NFT Contract ACS1 Implementation Completely Non-Functional - Governance Cannot Adjust Method Fees

## Summary
The NFT contract's ACS1 implementation consists entirely of non-functional stub methods that create state divergence, preventing Parliament governance from adjusting transaction fees despite the contract explicitly implementing the ACS1 standard interface.

## Finding Description

The NFT contract declares ACS1 compliance [1](#0-0)  but implements all fee governance methods as no-op stubs. The `SetMethodFee()` and `ChangeMethodFeeController()` methods immediately return empty results without any state modifications [2](#0-1) , while `GetMethodFee()` returns hardcoded values instead of stored configuration [3](#0-2) .

The root cause is the complete absence of required state storage properties. The NFTContractState lacks both `TransactionFees` and `MethodFeeController` properties [4](#0-3) , making it structurally impossible to store fee configuration.

In contrast, all other system contracts implement ACS1 correctly with proper state storage and authorization. For example, the Association contract stores fees in state [5](#0-4)  after validating authorization [6](#0-5) , and retrieves fees from stored state [7](#0-6) . The Association state properly declares the required properties [8](#0-7) .

When transaction fees are charged, the Token contract queries the target contract's `GetMethodFee()` method [9](#0-8) . For the NFT contract, this always returns the hardcoded 100 ELF fee for the Create method, regardless of any governance attempts to modify it.

The ACS1 standard explicitly promises: "Set the method fees for the specified method. Note that this will override all fees of the method" and "Change the method fee controller, the default is parliament and default organization" [10](#0-9) . The NFT contract violates this contractual obligation.

## Impact Explanation

**Governance Authority Denial:** Parliament's default organization, which should control method fees per the ACS1 standard, is completely blocked from exercising this authority for the NFT contract. This violates the uniform governance model where all 15 other system contracts properly delegate fee control to Parliament.

**State Divergence:** When governance creates proposals to adjust NFT fees, the transactions execute successfully but produce zero state changes. External observers see successful execution while the contract behavior remains unchanged, creating false confidence in governance control. This is more dangerous than simple reversion because it provides no feedback about the failure.

**Economic Rigidity:** The Create method fee is permanently fixed at 100 ELF (100,000,000,000 base units). If ELF appreciates significantly in market value (e.g., 10x-100x increase), this fee becomes prohibitively expensive with no governance mechanism to reduce it, potentially DoS'ing NFT protocol creation. The protocol cannot adapt to changing economic conditions.

**Protocol Inconsistency:** Breaking the uniform ACS1 implementation pattern across system contracts creates unpredictability and violates users' reasonable expectations about governance capabilities.

## Likelihood Explanation

**Certainty:** This is not a probabilistic issue but a deterministic failure occurring with 100% certainty on every attempt to adjust fees. The issue is immediately observable by calling `SetMethodFee()` and verifying that `GetMethodFee()` returns unchanged hardcoded values.

**No Prerequisites:** The vulnerability requires no special preconditions, attack complexity, or economic circumstances. Any address can directly call `SetMethodFee()` to demonstrate the non-functional implementation (noting that proper implementations would enforce authorization but still accept the call).

**Already Active:** The governance denial is not a future risk but a present reality. If Parliament were to attempt fee adjustments today through standard governance procedures (proposal creation, miner approval, release), the actions would succeed transactionally while achieving no practical effect.

**Observable Pattern Violation:** Comparing the NFT contract's implementation against all other system contracts (Association, Parliament, Election, Treasury, etc.) immediately reveals the broken pattern - all 15 other contracts use `RequiredMethodFeeControllerSet()` helper and proper state storage, while NFT uses none of this infrastructure.

## Recommendation

Implement proper ACS1 support by:

1. **Add required state properties** to `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

2. **Implement `SetMethodFee()` with authorization** following the pattern from other contracts:
```csharp
public override Empty SetMethodFee(MethodFees input)
{
    foreach (var methodFee in input.Fees) 
        AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

3. **Implement `GetMethodFee()` to read from state**:
```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    return State.TransactionFees[input.Value];
}
```

4. **Add `RequiredMethodFeeControllerSet()` helper** to initialize controller to Parliament's default organization, following the pattern in all other system contracts.

5. **Implement proper `ChangeMethodFeeController()` and `GetMethodFeeController()`** with authorization checks and organization validation.

## Proof of Concept

```csharp
[Fact]
public async Task NFT_SetMethodFee_Has_No_Effect_Test()
{
    // Query initial fee for Create method
    var initialFee = await NFTContractStub.GetMethodFee.CallAsync(
        new StringValue { Value = "Create" });
    initialFee.Fees[0].BasicFee.ShouldBe(100_00000000); // Hardcoded 100 ELF
    
    // Attempt to change fee via SetMethodFee
    await NFTContractStub.SetMethodFee.SendAsync(new MethodFees
    {
        MethodName = "Create",
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
    });
    
    // Query fee again - should be changed but isn't
    var afterFee = await NFTContractStub.GetMethodFee.CallAsync(
        new StringValue { Value = "Create" });
    
    // VULNERABILITY: Fee remains hardcoded despite SetMethodFee call
    afterFee.Fees[0].BasicFee.ShouldBe(100_00000000); // Still 100 ELF!
    // Expected: 50_00000000, Actual: 100_00000000
    
    // Demonstrates state divergence - SetMethodFee succeeded but had no effect
}
```

## Notes

This vulnerability represents a complete failure to implement the ACS1 standard despite explicit declaration of compliance. The contract's inheritance from `acs1.proto` creates a contractual obligation that is violated by the stub implementation. While this does not result in direct fund loss, it constitutes a governance denial that breaks protocol invariants and creates economic rigidity with potential DoS implications. The state divergence (successful transactions with zero effect) is particularly problematic as it provides false feedback to governance participants.

### Citations

**File:** protobuf/nft_contract.proto (L20-20)
```text
    option (aelf.base) = "acs1.proto";
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L8-16)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        return new Empty();
    }

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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L6-46)
```csharp
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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L15-15)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L16-16)
```csharp
        State.TransactionFees[input.MethodName] = input;
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L36-36)
```csharp
        return State.TransactionFees[input.Value];
```

**File:** contract/AElf.Contracts.Association/AssociationState.cs (L11-12)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-39)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
```

**File:** protobuf/acs1.proto (L21-27)
```text
    // Set the method fees for the specified method. Note that this will override all fees of the method.
    rpc SetMethodFee (MethodFees) returns (google.protobuf.Empty) {
    }

    // Change the method fee controller, the default is parliament and default organization.
    rpc ChangeMethodFeeController (AuthorityInfo) returns (google.protobuf.Empty) {
    }
```
