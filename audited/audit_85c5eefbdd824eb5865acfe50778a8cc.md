### Title
NFT Contract Method Fee Governance Completely Absent - Hardcoded Fees Cannot Be Adjusted

### Summary
The NFT contract implements ACS1 (Transaction Fee Standard) with stub methods only, lacking the required state variables (`State.MethodFeeController` and `State.TransactionFees`) and returning empty results from `GetMethodFeeController()`. This means the hardcoded 100 ELF fee for the `Create` method is permanently immutable and ungovernable, violating the ACS1 standard which mandates Parliament-based governance control over method fees.

### Finding Description

The NFT contract's ACS1 implementation in `NFTContract_ACS1.cs` contains only stub methods that return empty values without performing any actual governance operations: [1](#0-0) [2](#0-1) 

The contract state file completely lacks the required state variables for ACS1 governance: [3](#0-2) 

In contrast, all other system contracts properly implement ACS1 with the required state variables: [4](#0-3) 

And implement proper authorization checks in their ACS1 methods: [5](#0-4) [6](#0-5) 

The ACS1 standard explicitly defines that the method fee controller should default to Parliament: [7](#0-6) 

The NFT contract has hardcoded the Create method fee at 100 ELF (100_00000000 with 8 decimals) with no mechanism to adjust it: [8](#0-7) 

**Root Cause**: The NFT contract was deployed with incomplete ACS1 implementation - the interface methods exist but are non-functional stubs. The required `State.MethodFeeController` and `State.TransactionFees` state variables were never defined, and no initialization logic sets up governance control.

**Why Protections Fail**: There are no protections. The `SetMethodFee` and `ChangeMethodFeeController` methods immediately return empty without any validation, state changes, or authorization checks.

### Impact Explanation

**Operational Impact - DoS Risk**: The 100 ELF fee for creating NFT protocols is permanently hardcoded. If ELF token price increases significantly (e.g., from $0.50 to $50), the $50 fee becomes $5,000, effectively creating a Denial-of-Service condition where creating NFT protocols becomes economically infeasible for most users. This cannot be adjusted through any means.

**Governance Impact - Violation of ACS1 Standard**: The contract violates the ACS1 standard expectation that method fees are governable through Parliament (requiring 2/3 miner approval). Users and miners have no mechanism to adjust fees to match changing economic conditions, removing a fundamental governance control that exists in all other system contracts.

**Trust Impact - Inconsistent Design**: The NFT contract uses Parliament governance for other administrative functions (`AddNFTType`, `RemoveNFTType`): [9](#0-8) 

But inexplicably lacks it for method fee governance, creating an inconsistent and incomplete governance model.

**Who Is Affected**: All users attempting to create NFT protocols via the `Create` method are affected by the immutable fee structure. The broader AElf ecosystem is affected by having a system contract that doesn't conform to standards.

### Likelihood Explanation

**Certainty: 100%** - This is not a probabilistic vulnerability but a confirmed design deficiency present in the deployed code. The stub implementations and missing state variables are demonstrable facts.

**Preconditions**: None required - the issue affects all calls to `Create` and all attempts to govern method fees.

**Attack Complexity**: N/A - This is not an active attack but rather a permanent limitation. However, the economic impact becomes severe under certain market conditions (ELF price changes) which are beyond any user's control.

**Detection**: The issue is trivially detectable by examining the contract code or attempting to call `GetMethodFeeController()` which returns an empty `AuthorityInfo`.

**No Initialization**: The contract's initialization provider explicitly returns an empty list of initialization methods: [10](#0-9) 

This confirms no setup of the method fee controller occurs during deployment.

### Recommendation

**1. Add Required State Variables** to `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**2. Implement `RequiredMethodFeeControllerSet()` Helper**:
Follow the standard pattern used in all other contracts to initialize the controller to Parliament's default organization on first access.

**3. Replace Stub Implementations** in `NFTContract_ACS1.cs` with proper implementations following the pattern from `AssociationContract_ACS1_TransactionFeeProvider.cs`:
- `SetMethodFee`: Validate sender is controller's OwnerAddress, validate token symbols, update State.TransactionFees
- `ChangeMethodFeeController`: Validate sender is current controller, verify new organization exists, update State.MethodFeeController
- `GetMethodFeeController`: Call RequiredMethodFeeControllerSet() then return State.MethodFeeController.Value
- `GetMethodFee`: Return State.TransactionFees[methodName] (keep the hardcoded fee as default only)

**4. Add Invariant Checks**:
- Assert MethodFeeController is set before allowing fee modifications
- Assert sender authorization in SetMethodFee and ChangeMethodFeeController
- Validate fee token symbols are burnable and available for method fees

**5. Add Test Cases**:
- Test ChangeMethodFeeController through Parliament proposal
- Test SetMethodFee with and without authorization
- Test GetMethodFeeController returns Parliament default initially
- Test fee changes take effect after governance approval

**6. Consider Migration Path**: Since the contract is already deployed, coordinate with the AElf team on whether a contract upgrade is needed or if the fixed-fee model is intentional despite ACS1 compliance issues.

### Proof of Concept

**Initial State**: NFT contract is deployed with stub ACS1 implementation.

**Step 1 - Verify No Controller Exists**:
```
Call: NFTContract.GetMethodFeeController()
Expected (ACS1 Standard): Returns AuthorityInfo with Parliament default organization
Actual Result: Returns empty AuthorityInfo { OwnerAddress = null, ContractAddress = null }
Success Condition: Confirms no governance controller is configured
```

**Step 2 - Verify Fee Cannot Be Changed**:
```
Call: NFTContract.SetMethodFee(new MethodFees { 
    MethodName = "Create", 
    Fees = { new MethodFee { Symbol = "ELF", BasicFee = 1 } } 
})
Expected (ACS1 Standard): Should check authorization and update fees
Actual Result: Returns Empty without any state change, no authorization check
Success Condition: Fee remains 100 ELF, proving immutability
```

**Step 3 - Verify Controller Cannot Be Changed**:
```
Call: NFTContract.ChangeMethodFeeController(new AuthorityInfo { 
    OwnerAddress = parliamentAddress, 
    ContractAddress = parliamentContract 
})
Expected (ACS1 Standard): Should verify sender authorization and update controller
Actual Result: Returns Empty without any state change, no authorization check
Success Condition: GetMethodFeeController() still returns empty, proving ungovernable
```

**Step 4 - Demonstrate Economic DoS Scenario**:
```
Scenario: ELF price increases from $0.50 to $50 (100x)
Current Fee: 100 ELF = $50
After Price Increase: 100 ELF = $5,000
Impact: Creating an NFT protocol costs $5,000, economically infeasible for most users
Mitigation Available: None - fee is hardcoded and ungovernable
Success Condition: Demonstrates operational DoS risk from inflexible fee structure
```

### Citations

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

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L20-36)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L39-42)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        return new AuthorityInfo();
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

**File:** contract/AElf.Contracts.Association/AssociationState.cs (L11-12)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L10-29)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }

    public override Empty ChangeMethodFeeController(AuthorityInfo input)
    {
        RequiredMethodFeeControllerSet();
        AssertSenderAddressWith(State.MethodFeeController.Value.OwnerAddress);
        var organizationExist = CheckOrganizationExist(input);
        Assert(organizationExist, "Invalid authority input.");

        State.MethodFeeController.Value = input;
        return new Empty();
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L39-43)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        RequiredMethodFeeControllerSet();
        return State.MethodFeeController.Value;
    }
```

**File:** protobuf/acs1.proto (L25-27)
```text
    // Change the method fee controller, the default is parliament and default organization.
    rpc ChangeMethodFeeController (AuthorityInfo) returns (google.protobuf.Empty) {
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L131-150)
```csharp
    public override Empty AddNFTType(AddNFTTypeInput input)
    {
        AssertSenderIsParliamentDefaultAddress();
        InitialNFTTypeNameMap();
        var fullName = input.FullName;
        Assert(input.ShortName.Length == 2, "Incorrect short name.");
        Assert(State.NFTTypeFullNameMap[input.ShortName] == null, $"Short name {input.ShortName} already exists.");
        Assert(State.NFTTypeShortNameMap[fullName] == null, $"Full name {fullName} already exists.");
        State.NFTTypeFullNameMap[input.ShortName] = fullName;
        State.NFTTypeShortNameMap[fullName] = input.ShortName;
        var nftTypes = State.NFTTypes.Value;
        nftTypes.Value.Add(input.ShortName, fullName);
        State.NFTTypes.Value = nftTypes;
        Context.Fire(new NFTTypeAdded
        {
            ShortName = input.ShortName,
            FullName = input.FullName
        });
        return new Empty();
    }
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractInitializationProvider.cs (L13-16)
```csharp
    public List<ContractInitializationMethodCall> GetInitializeMethodList(byte[] contractCode)
    {
        return new List<ContractInitializationMethodCall>();
    }
```
