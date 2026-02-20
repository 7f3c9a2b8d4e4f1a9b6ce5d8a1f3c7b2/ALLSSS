# Audit Report

## Title
NFT Contract Governance Fee Changes Silently Ignored Due to Missing State Management

## Summary
The NFT contract inherits from ACS1 transaction fee standard but fails to implement the required state storage for fee configurations and controller authority. The `SetMethodFee()` and `ChangeMethodFeeController()` methods are non-functional stubs that discard input without state mutations, while `GetMethodFee()` returns hard-coded fees (100 ELF for Create method). This creates a silent failure where governance fee adjustment proposals execute successfully but have zero effect on actual fee enforcement.

## Finding Description

The NFT contract explicitly inherits from ACS1 via its protobuf definition [1](#0-0) , establishing an expectation of full fee governance support.

**Missing State Variables:**

The `NFTContractState` class completely lacks the state mappings required for ACS1 compliance [2](#0-1) . In contrast, proper ACS1 implementations define both `TransactionFees` and `MethodFeeController` state variables [3](#0-2) .

**Non-Functional SetMethodFee:**

The NFT contract's `SetMethodFee()` method immediately returns empty without any state mutation [4](#0-3) . Compare this to proper implementations that validate tokens, check authorization, and persist fees to state [5](#0-4) .

**Hard-Coded Fee Enforcement:**

The `GetMethodFee()` method returns a hard-coded fee of 100 ELF (100_00000000 in smallest units) for the Create method instead of retrieving stored values [6](#0-5) . Proper implementations retrieve fees from state storage [7](#0-6) .

**Fee Enforcement Path:**

During transaction execution, the fee charging system queries the target contract's `GetMethodFee()` to determine what to charge users [8](#0-7) . The hard-coded return values become the actual enforced fees regardless of governance settings.

**Non-Functional Controller Management:**

Similarly, `ChangeMethodFeeController()` discards controller updates without storing [9](#0-8) , and `GetMethodFeeController()` returns an empty authority structure [10](#0-9) , contrasting with proper implementations that manage controller state [11](#0-10) .

**Target Method Affected:**

The Create method, which establishes new NFT protocols on the mainchain, is the primary method affected by this fixed fee [12](#0-11) .

## Impact Explanation

**Governance Dysfunction:**
When governance creates proposals to adjust NFT contract fees through standard procedures, the proposals execute successfully but produce no effect. The silent failure mode provides no indication to governance participants that their decisions are being ignored, creating institutional distrust and operational confusion.

**Economic Harm and Availability Risk:**
Users are locked into paying a fixed 100 ELF fee for the Create method that cannot adapt to market conditions. If ELF token appreciates significantly, this fee becomes economically prohibitive (potentially thousands of dollars at realistic token prices), effectively creating a denial-of-service condition for NFT protocol creation functionality. No mechanism exists to adjust fees except a full contract upgrade.

**Interface Contract Violation:**
The contract inherits from ACS1, creating an explicit expectation of fee governance support, but the implementation is non-functional. This violates the principle of interface transparency - external systems and governance participants have no indication that fee changes are impossible without examining the contract's internal implementation.

## Likelihood Explanation

**High Likelihood - Normal Operations:**
Fee adjustments are routine governance activities across all AElf system contracts. The NFT contract appearing to support the ACS1 interface makes governance attempts inevitable as market conditions evolve. This is not an attack scenario but a design flaw affecting normal operations.

**Zero Complexity:**
Any governance actor following standard procedures to adjust fees will encounter this issue. The execution path is straightforward: create proposal → approve → release → call SetMethodFee → observe no effect. The transaction succeeds with no error, no event indicating failure, and no state change that can be queried.

**Economic Inevitability:**
Token price volatility makes fee adjustments economically necessary over the contract's lifetime. Market forces guarantee this issue will manifest as fees become either too expensive (limiting usage) or require adjustment for other economic reasons.

## Recommendation

Add the required state variables to `NFTContractState`:

```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

Implement proper state storage in `SetMethodFee()` following the pattern used by other ACS1 contracts - validate input, check authorization against controller, and persist to state. Similarly, implement `ChangeMethodFeeController()` to store the new controller, and update `GetMethodFee()` and `GetMethodFeeController()` to retrieve values from state rather than returning hard-coded or empty values.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task NFTContract_SetMethodFee_HasNoEffect()
{
    // 1. Query initial fee for Create method
    var initialFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    initialFee.Fees[0].BasicFee.ShouldBe(100_00000000); // 100 ELF hard-coded
    
    // 2. Attempt to change fee via governance
    var newFee = new MethodFees
    {
        MethodName = "Create",
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
    };
    await NFTContractStub.SetMethodFee.SendAsync(newFee);
    
    // 3. Query fee again - it should be changed but isn't
    var updatedFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    updatedFee.Fees[0].BasicFee.ShouldBe(100_00000000); // Still 100 ELF, change ignored
    // Expected: 50 ELF
    // Actual: 100 ELF (governance change had no effect)
}
```

## Notes

This vulnerability affects the core governance principle that system contract parameters should be adjustable through standard governance procedures. The silent failure is particularly problematic because it provides no feedback mechanism - transactions succeed, no errors are thrown, and no events indicate the configuration change was ignored. This can lead to prolonged confusion where governance believes fees have been adjusted when they haven't, or worse, economic lock-in where the Create functionality becomes prohibitively expensive with no recourse except a full contract upgrade.

### Citations

**File:** protobuf/nft_contract.proto (L20-20)
```text
    option (aelf.base) = "acs1.proto";
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

**File:** contract/AElf.Contracts.Parliament/ParliamentState.cs (L23-26)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }

    public SingletonState<ProposerWhiteList> ProposerWhiteList { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L39-42)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        return new AuthorityInfo();
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-19)
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

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L21-30)
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

**File:** docs-sphinx/reference/acs/acs1.rst (L115-116)
```text
       var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
           new StringValue {Value = input.MethodName});
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-24)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
        var tokenExternalInfo = GetTokenExternalInfo(input);
        var creator = input.Creator ?? Context.Sender;
        var tokenCreateInput = new MultiToken.CreateInput
        {
```
