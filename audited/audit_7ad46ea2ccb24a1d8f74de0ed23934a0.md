### Title
NFT Contract Lacks Parliament Governance Integration for Method Fee Management

### Summary
The NFT contract declares ACS1 (Transaction Fee Standard) inheritance but fails to implement Parliament governance integration for method fee management. The `GetMethodFeeController()` method returns an empty `AuthorityInfo` object instead of the Parliament default organization, and `SetMethodFee`/`ChangeMethodFeeController` are non-functional stub implementations. This breaks the governance invariant that Parliament controls method fees across all system contracts and makes the hardcoded 100 ELF Create fee immutable except through contract upgrades.

### Finding Description

The NFT contract declares ACS1 inheritance in its protobuf definition [1](#0-0)  but provides only stub implementations of the ACS1 governance methods.

**Root Cause:**

The `GetMethodFeeController()` method returns an empty `AuthorityInfo` object [2](#0-1)  with no controller address or owner address set. This contrasts sharply with other system contracts like MultiToken [3](#0-2)  Configuration [4](#0-3)  and Profit [5](#0-4)  which all properly initialize the method fee controller by calling `State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())`.

The `SetMethodFee()` and `ChangeMethodFeeController()` methods are non-functional stubs that return empty results without performing any operations [6](#0-5) 

The `GetMethodFee()` method returns hardcoded fees without checking stored state [7](#0-6)  Unlike other contracts such as Profit [8](#0-7)  and Vote [9](#0-8)  which check `State.TransactionFees[methodName]` first before falling back to defaults, the NFT contract completely bypasses any stored fee configuration.

**Why Existing Protections Fail:**

The NFT contract demonstrates it knows how to integrate with Parliament for other operations - the `AssertSenderIsParliamentDefaultAddress()` helper method properly calls Parliament's `GetDefaultOrganizationAddress` [10](#0-9)  for `AddNFTType` and `RemoveNFTType` governance. However, this integration pattern was not applied to the ACS1 methods, leaving no authorization checks on method fee changes.

### Impact Explanation

**Governance Authority Violation:**
The NFT contract violates the critical invariant that "method-fee provider authority" must be under governance control. Parliament's default organization, which requires 2/3 miner approval for changes, cannot adjust the NFT Create method's 100 ELF fee.

**Operational Inflexibility:**
If market conditions cause significant ELF price appreciation (e.g., 10x-100x), the 100 ELF fee becomes prohibitively expensive for NFT creation, effectively DoSing the protocol. Conversely, if ELF depreciates significantly, the fee becomes too low to prevent spam. Without governance control, these issues cannot be addressed without a full contract upgrade requiring consensus from all nodes.

**Standard Violation:**
The NFT contract declares ACS1 compliance but fails to implement the standard's governance requirements, creating inconsistency across the system contract ecosystem where all other contracts (MultiToken, Parliament, Configuration, Profit, Vote, Election, etc.) properly integrate with Parliament for fee management.

**Who Is Affected:**
- NFT protocol creators face fixed 100 ELF cost regardless of market conditions
- Parliament loses governance authority over a system contract it should control
- The broader AElf ecosystem loses fee flexibility for NFT operations

### Likelihood Explanation

**Permanent Condition:**
This is not a transient vulnerability requiring specific preconditions - it is a permanent design flaw in the deployed NFT contract code that affects all users at all times.

**Verification:**
Any user can verify this by calling `GetMethodFeeController()` and observing it returns an empty `AuthorityInfo`. Parliament members can confirm they cannot submit proposals to change NFT method fees because no valid controller is registered.

**Market Condition Changes:**
Cryptocurrency market volatility makes significant price changes highly probable. Historical data shows major tokens (including native blockchain tokens) experiencing 10x-100x price swings over months to years. The inability to adjust fees in response is operationally certain to cause issues.

**No Attack Required:**
This is a governance gap, not an exploit requiring attacker action. The impact manifests naturally through market forces and the inability of legitimate governance to respond.

### Recommendation

**Immediate Fix:**
Implement proper ACS1 governance integration in the NFT contract:

1. Add a `RequiredMethodFeeControllerSet()` private method following the standard pattern used in other system contracts:
```csharp
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
```

2. Update `GetMethodFeeController()` to call `RequiredMethodFeeControllerSet()` and return the controller.

3. Implement `SetMethodFee()` to store fees in `State.TransactionFees[methodName]` with proper authorization checks.

4. Implement `ChangeMethodFeeController()` with authorization checks and organization validation.

5. Update `GetMethodFee()` to check `State.TransactionFees[methodName]` first before returning hardcoded defaults.

6. Add `State.MethodFeeController` to the contract state definition [11](#0-10) 

**Test Cases:**
Add comprehensive ACS1 tests similar to those in MultiToken [12](#0-11)  covering:
- Getting method fee controller returns Parliament default organization
- Setting method fees requires Parliament authorization
- Unauthorized fee changes are rejected
- Changed fees are properly retrieved by GetMethodFee

### Proof of Concept

**Initial State:**
- NFT contract deployed on chain
- Parliament contract operational with default organization

**Verification Steps:**

1. **Call GetMethodFeeController:**
```csharp
var controller = await NFTContractStub.GetMethodFeeController.CallAsync(new Empty());
// Expected: controller.OwnerAddress = Parliament default org
// Actual: controller.OwnerAddress = null (empty Address)
// Actual: controller.ContractAddress = null (empty Address)
```

2. **Attempt to change method fee via Parliament proposal:**
```csharp
// Create Parliament proposal to change NFT Create fee to 50 ELF
var proposalId = await ParliamentStub.CreateProposal.SendAsync(new CreateProposalInput
{
    ToAddress = NFTContractAddress,
    ContractMethodName = nameof(NFTContract.SetMethodFee),
    Params = new MethodFees
    {
        MethodName = nameof(NFTContract.Create),
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
    }.ToByteString(),
    OrganizationAddress = defaultParliamentOrg
});

// Get 2/3 miner approvals and release
// ... approval logic ...

// Expected: Fee changed to 50 ELF
// Actual: SetMethodFee does nothing, fee remains 100 ELF hardcoded
```

3. **Verify fee unchanged:**
```csharp
var methodFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
// Actual: Still returns 100_00000000 (hardcoded value)
// State.TransactionFees["Create"] is never checked or used
```

**Success Condition:**
The NFT contract fails to integrate with Parliament governance - fees cannot be changed through legitimate governance channels, violating the ACS1 standard and the "Authorization & Governance" critical invariant.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_ACS1.cs (L39-42)
```csharp
    public override AuthorityInfo GetMethodFeeController(Empty input)
    {
        return new AuthorityInfo();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L91-109)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo();

        // Parliament Auth Contract maybe not deployed.
        if (State.ParliamentContract.Value != null)
        {
            defaultAuthority.OwnerAddress =
                State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());
            defaultAuthority.ContractAddress = State.ParliamentContract.Value;
        }

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L51-65)
```csharp
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
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L35-59)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var methodFees = State.TransactionFees[input.Value];
        if (methodFees != null) return methodFees;

        switch (input.Value)
        {
            case nameof(CreateScheme):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
            default:
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                    }
                };
        }
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L71-83)
```csharp
    private void RequiredMethodFeeControllerSet()
    {
        if (State.MethodFeeController.Value != null) return;
        ValidateContractState(State.ParliamentContract, SmartContractConstants.ParliamentContractSystemName);

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MethodFeeController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract_ACS1_TransactionFeeProvider.cs (L35-59)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
        var tokenAmounts = State.TransactionFees[input.Value];
        if (tokenAmounts != null) return tokenAmounts;

        switch (input.Value)
        {
            case nameof(Register):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
            default:
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 1_00000000 }
                    }
                };
        }
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L171-182)
```csharp
    private void AssertSenderIsParliamentDefaultAddress()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        if (State.ParliamentDefaultAddress.Value == null)
            State.ParliamentDefaultAddress.Value =
                State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty());

        Assert(Context.Sender == State.ParliamentDefaultAddress.Value, "No permission.");
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

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/ACS1_ImplementTest.cs (L1-10)
```csharp
using System.Linq;
using System.Threading.Tasks;
using AElf.Contracts.Parliament;
using AElf.CSharp.Core.Extension;
using AElf.Kernel;
using AElf.Standards.ACS1;
using AElf.Standards.ACS3;
using AElf.Types;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
```
