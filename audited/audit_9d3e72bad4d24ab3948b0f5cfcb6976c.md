### Title
NFT Contract ACS1 Implementation Contains Non-Functional Stubs Breaking Fee Governance

### Summary
The NFT contract declares ACS1 as a base contract but implements only stub methods that perform no operations, missing all required state variables and authorization logic. This completely disables method fee governance for the NFT contract, violating the ACS1 standard and creating an inconsistency with all other AElf system contracts. The hardcoded 100 ELF fee for the Create method cannot be adjusted through governance mechanisms.

### Finding Description

The NFT contract's ACS1 implementation consists of non-functional stub methods: [1](#0-0) [2](#0-1) 

The protobuf specification explicitly declares ACS1 as a base contract requirement: [3](#0-2) 

However, the contract state lacks the required ACS1 state variables (`MethodFeeController` and `TransactionFees`) that all other system contracts define: [4](#0-3) 

Compare this to the proper implementation pattern used by all other system contracts: [5](#0-4) [6](#0-5) 

The proper implementation includes:
- Token validation via `AssertValidToken`
- Authorization checks via `RequiredMethodFeeControllerSet` and sender verification
- Organization existence validation via `CheckOrganizationExist`
- State persistence in `State.TransactionFees` and `State.MethodFeeController`

The NFT contract has NONE of these protections or functionality. There are no tests covering these methods, and no documentation or comments indicating this is intentional for a beta phase.

### Impact Explanation

**Governance Breakdown:**
- The NFT contract's method fees cannot be managed through Parliament, Association, or Referendum governance
- The hardcoded 100 ELF fee for the Create method cannot be adjusted for market conditions or economic policy changes
- No authority can be established to control NFT contract fees

**Standard Violation:**
- The contract violates the ACS1 standard it explicitly declares as base, breaking protocol consistency
- All 15+ other AElf system contracts properly implement ACS1 with full governance support
- This creates a governance gap where the NFT contract cannot participate in system-wide fee policies

**Economic Rigidity:**
- Protocol creators must always pay exactly 100 ELF regardless of token price fluctuations
- No mechanism exists to waive, reduce, or adjust fees for special circumstances
- Fee revenue from NFT contract operations cannot be properly tracked or distributed through governance

### Likelihood Explanation

**Certainty: 100%**
This is not a probabilistic vulnerability but a definitive implementation gap:
- The stub methods are publicly accessible and always execute (doing nothing)
- Any governance proposal attempting to set NFT contract fees will appear to succeed but have zero effect
- The hardcoded fee behavior is permanent and unchangeable through standard governance channels

**Detection:**
- Observable through direct contract inspection
- Verifiable by attempting governance fee changes (they will fail silently)
- Evident from missing test coverage for ACS1 methods

**No Evidence of Intentional Design:**
- No TODO, FIXME, or beta-phase comments in code
- No documentation explaining temporary limitation
- No tests indicating planned future implementation
- Contradicts declared ACS1 base requirement in protobuf

### Recommendation

**1. Add Required State Variables to NFTContractState.cs:**
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**2. Implement SetMethodFee with proper authorization:**
- Validate token symbols and amounts using MultiToken contract
- Initialize method fee controller to Parliament default organization
- Check sender matches controller's OwnerAddress
- Store fees in State.TransactionFees[input.MethodName]

**3. Implement ChangeMethodFeeController with validation:**
- Verify current controller is set
- Validate sender authorization
- Verify new organization exists via ValidateOrganizationExist
- Update State.MethodFeeController.Value

**4. Update GetMethodFee to read from state:**
- Return State.TransactionFees[input.Value] instead of hardcoded values
- Maintain special handling for Create method as default if not set

**5. Update GetMethodFeeController properly:**
- Call RequiredMethodFeeControllerSet() to initialize if needed
- Return State.MethodFeeController.Value with valid authority

**6. Add comprehensive test coverage:**
- Test successful fee setting via Parliament proposal
- Test unauthorized attempts properly fail
- Test controller changes with valid/invalid organizations
- Test fee retrieval after updates [7](#0-6) 

### Proof of Concept

**Step 1: Verify stub behavior**
Call `NFTContract.SetMethodFee` with any input → Returns Empty, no state change

**Step 2: Verify missing controller**
Call `NFTContract.GetMethodFeeController` → Returns empty AuthorityInfo (no owner, no contract address)

**Step 3: Verify hardcoded fees**
Call `NFTContract.GetMethodFee("Create")` → Always returns 100 ELF, regardless of any previous SetMethodFee calls

**Step 4: Attempt governance fee change**
1. Create Parliament proposal to change Create method fee to 50 ELF
2. Approve and execute proposal through SetMethodFee
3. Query GetMethodFee("Create") → Still returns 100 ELF (unchanged)

**Expected Result:** Governance should control NFT contract fees
**Actual Result:** All governance attempts fail silently, fees remain hardcoded

**Conclusion:** These are accidental omissions that must be completed. The evidence shows no intentional design for beta phase, but rather an incomplete implementation that violates the contract's declared ACS1 base requirement and breaks fee governance for the NFT contract.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L39-42)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        return new AuthorityInfo();
    }
```

**File:** protobuf/nft_contract.proto (L18-21)
```text
service NFTContract {
    option (aelf.csharp_state) = "AElf.Contracts.NFT.NFTContractState";
    option (aelf.base) = "acs1.proto";

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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L10-86)
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
    }

    #region Views

    public override MethodFees GetMethodFee(StringValue input)
    {
        return State.TransactionFees[input.Value];
    }

    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        RequiredMethodFeeControllerSet();
        return State.MethodFeeController.Value;
    }

    #endregion

    #region private methods

    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }

    private void AssertSenderAddressWith(Address address)
    {
        Assert(Context.Sender == address, "Unauthorized behavior.");
    }

    private bool CheckOrganizationExist(AuthorityInfo authorityInfo)
    {
        return Context.Call<BoolValue>(authorityInfo.ContractAddress,
            nameof(ValidateOrganizationExist), authorityInfo.OwnerAddress).Value;
    }

    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }

```
