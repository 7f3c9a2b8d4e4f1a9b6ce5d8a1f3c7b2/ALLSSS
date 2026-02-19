### Title
NFT Contract Method Fee Permanently Fixed at 100 ELF Due to Non-Functional SetMethodFee Implementation

### Summary
The NFT contract's ACS1 implementation has a hardcoded 100 ELF fee for the Create method that cannot be modified through governance. The `SetMethodFee()` function does not persist any changes to state, and `GetMethodFee()` returns a hardcoded value instead of reading from storage, making the fee permanently fixed and ungovernable.

### Finding Description

The NFT contract violates the ACS1 Transaction Fee Standard through a critically flawed implementation:

**Root Cause - Non-Functional SetMethodFee:**
The `SetMethodFee()` method is a no-op that immediately returns empty without storing the input anywhere. [1](#0-0) 

**Root Cause - Hardcoded GetMethodFee:**
The `GetMethodFee()` method returns a hardcoded fee of 100_00000000 (100 ELF with 8 decimals) for the Create method without reading from any state storage. [2](#0-1) 

**Missing State Variables:**
The NFTContractState.cs file completely lacks the required `TransactionFees` and `MethodFeeController` state variables that would store fee configurations. [3](#0-2) 

**Standard Implementation Comparison:**
Other AElf contracts correctly implement ACS1 by storing fees in `State.TransactionFees[input.MethodName]` during `SetMethodFee()`. [4](#0-3) 

And retrieve them from state storage in `GetMethodFee()`. [5](#0-4) 

These contracts define the necessary state variables to persist fee configurations. [6](#0-5) 

**Execution Path:**
When a user calls the Create method, the fee charging mechanism invokes `GetMethodFee` on the NFT contract to determine the fee amount. [7](#0-6) 

The returned hardcoded value is what actually gets charged, bypassing any governance-set fees.

### Impact Explanation

**Governance Bypass (High):**
- The fee for NFT creation is permanently locked at 100 ELF and cannot be adjusted through the standard governance process
- Parliament proposals to change fees via `SetMethodFee()` will appear to succeed but have zero effect
- This violates a critical ACS1 invariant that method fees must be governable by the authorized fee controller

**Economic Inflexibility (High):**
- If ELF token value increases significantly, the 100 ELF fee becomes prohibitively expensive for NFT creation
- If ELF token value decreases, the fee may become too low to prevent spam
- The protocol cannot adapt fees to changing market conditions or governance decisions

**User Impact:**
- All users attempting to create NFTs are forced to pay exactly 100 ELF regardless of economic conditions
- No fee reductions can be implemented even if governance votes for them
- Users cannot benefit from potential fee optimizations

**Protocol Integrity:**
- The contract violates the ACS1 standard that all other system contracts follow
- Creates inconsistency in governance control across the protocol
- Breaks the trust model where Parliament (2/3 of block producers) should control system parameters

### Likelihood Explanation

**Certainty: Very High**
- The vulnerability is present in production code and affects every invocation of the Create method
- No special preconditions required - the flaw is structural

**Reachability:**
- `GetMethodFee()` is called automatically by the fee charging mechanism before every Create transaction
- The hardcoded return value is guaranteed to be used

**Exploitability:**
- Not an exploit per se, but a systemic failure affecting all users
- The dysfunction is continuous and unavoidable
- Governance attempting to adjust fees will discover their changes have no effect

**Detection:**
- Governance votes to change fees will execute without error but silently fail
- Only observable by comparing proposed fees vs. actually charged fees
- The `ChangeMethodFeeController()` and `GetMethodFeeController()` methods also return empty, providing no visibility into the broken state

### Recommendation

**1. Add Required State Variables:**
Modify `NFTContractState.cs` to include:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**2. Implement SetMethodFee Correctly:**
Follow the standard pattern from other contracts:
- Validate input tokens
- Check authorization via `RequiredMethodFeeControllerSet()`
- Verify sender is the controller's owner
- Store fees: `State.TransactionFees[input.MethodName] = input;`

**3. Implement GetMethodFee Correctly:**
Replace hardcoded logic with state retrieval:
- Read from `State.TransactionFees[input.Value]`
- Return stored value or empty MethodFees if not set

**4. Implement ChangeMethodFeeController:**
Follow standard pattern to allow governance to change the fee controller

**5. Implement GetMethodFeeController:**
Return `State.MethodFeeController.Value` after ensuring it's initialized

**6. Add Invariant Tests:**
- Test that fees set via `SetMethodFee()` are correctly returned by `GetMethodFee()`
- Test that only authorized controller can change fees
- Test fee charging with various configured fee amounts
- Test migration path for existing deployments

### Proof of Concept

**Initial State:**
- NFT contract is deployed with the current implementation
- Parliament default organization wants to reduce Create fee to 50 ELF to encourage adoption

**Step 1: Governance Proposal**
- Parliament creates and approves a proposal to call `NFTContract.SetMethodFee()` with 50 ELF for Create method
- Proposal executes successfully (no error thrown)

**Step 2: Query Fee Configuration**
- Call `NFTContract.GetMethodFee("Create")`
- **Expected Result:** Returns 50 ELF (the newly set fee)
- **Actual Result:** Returns 100 ELF (hardcoded value) [8](#0-7) 

**Step 3: Create NFT Transaction**
- User attempts to create an NFT
- Fee charging mechanism calls `GetMethodFee("Create")` 
- **Expected Result:** User charged 50 ELF
- **Actual Result:** User charged 100 ELF (governance change ignored)

**Success Condition for Exploit:**
The vulnerability is confirmed when the fee charged (100 ELF) does not match the governance-approved fee (50 ELF), demonstrating that `SetMethodFee()` changes have zero effect on actual fee collection.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-39)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
```
