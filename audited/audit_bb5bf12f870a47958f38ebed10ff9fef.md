# Audit Report

## Title
NFT Contract Governance Bypass - Method Fee Management Silently Non-Functional

## Summary
The NFT contract declares ACS1 interface implementation but provides empty implementations of `SetMethodFee()` and `ChangeMethodFeeController()` governance methods. Parliament proposals to adjust NFT fees will execute successfully without errors but produce zero state changes, permanently hardcoding the Create method fee at 100 ELF and completely bypassing governance control.

## Finding Description

The NFT contract explicitly declares ACS1 implementation through its protobuf service definition [1](#0-0) , which exposes all four ACS1 governance methods to external callers.

However, the governance setter methods are implemented as no-ops. The `SetMethodFee()` method simply returns an empty object without performing any state modifications [2](#0-1) . Similarly, `ChangeMethodFeeController()` returns empty without updating controller authority [3](#0-2) .

The contract state file completely lacks the infrastructure required for fee governance [4](#0-3) . Specifically missing are:
- `MappedState<string, MethodFees> TransactionFees` for storing configurable fees
- `SingletonState<AuthorityInfo> MethodFeeController` for governance authority tracking

In contrast, proper ACS1 implementations like the Election contract include these state variables [5](#0-4)  and implement `SetMethodFee()` with actual state updates [6](#0-5) .

The NFT contract's `GetMethodFee()` returns a hardcoded 100 ELF (100_00000000 base units) for the Create method [7](#0-6) , and `GetMethodFeeController()` returns an empty AuthorityInfo instead of the Parliament default organization [8](#0-7) .

This violates the ACS1 standard documentation, which explicitly states that contracts using hardcoded fees should NOT implement the other governance interfaces: "This implementation can modify the transaction fee only by upgrading the contract, without implementing the other three interfaces." [9](#0-8) 

The AElf fee charging mechanism queries `GetMethodFee()` during pre-execution to determine charges [10](#0-9) , meaning the hardcoded value will always be enforced regardless of governance attempts.

## Impact Explanation

**Governance Authority Bypass**: Parliament governance over NFT contract fees is completely non-functional. When governance participants create proposals to adjust NFT fees through standard workflow:
1. `ParliamentContract.CreateProposal()` targeting `NFTContract.SetMethodFee()` succeeds
2. Proposal receives required miner approvals
3. `ParliamentContract.Release()` executes the proposal successfully
4. `NFTContract.SetMethodFee()` returns Empty (no error)
5. Subsequent `GetMethodFee("Create")` queries still return hardcoded 100 ELF

**Operational Rigidity**: The Create method fee remains permanently at 100 ELF (10,000,000,000 base units), modifiable only via contract upgrade. This prevents:
- Dynamic fee adjustment based on ELF token price volatility
- Governance response to spam attacks or changing economic conditions
- Evolutionary fee structure as the NFT ecosystem matures

**Trust Violation**: The principle of least surprise is violated. The contract publicly exposes governance interfaces that suggest fee adjustability, misleading governance participants into believing they have control when they have none.

**Severity: Medium** - No funds are directly at risk and no unauthorized state changes occur. However, a core governance mechanism is completely bypassed for a fee-generating contract, violating the Authorization & Governance invariant. The issue impacts protocol operational flexibility and governance system integrity.

## Likelihood Explanation

**Immediate Exploitability**: This is not theoretical - the gap exists in production code today. Any governance participant can:
1. Observe ACS1 methods in NFT contract interface
2. Follow standard Parliament proposal workflow
3. Experience successful execution with zero effect

**Attack Complexity: Trivial** - No special privileges needed beyond normal governance participation. The "attack" is simply normal governance operation that silently fails.

**Detection Difficulty**: The silent failure makes this particularly insidious:
- Transactions execute successfully (status: Mined)
- No errors or reverts occur
- No events indicate ineffectiveness
- Only manual query of `GetMethodFee()` reveals unchanged fees
- Test suite contains zero ACS1 governance validation for NFT contract

**Probability: High** - As governance participants discover the NFT contract implements ACS1, attempts to adjust fees are inevitable and will uniformly fail silently.

## Recommendation

**Option 1: Remove Governance Pretense (Quick Fix)**
Remove the `option (aelf.base) = "acs1.proto";` declaration from `nft_contract.proto` and manually implement only `GetMethodFee()` as a view method. Remove `SetMethodFee()`, `ChangeMethodFeeController()`, and `GetMethodFeeController()` entirely.

**Option 2: Implement Full Governance (Proper Fix)**
Add proper state variables to `NFTContractState.cs`:
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

Implement `SetMethodFee()` and `ChangeMethodFeeController()` following the Election contract pattern with authorization checks and state updates. Implement `GetMethodFeeController()` to return the Parliament default organization if not set. Update `GetMethodFee()` to retrieve from state rather than returning hardcoded values.

## Proof of Concept

```csharp
[Fact]
public async Task GovernanceBypass_SetMethodFeeHasNoEffect()
{
    // Query initial fee - should be hardcoded 100 ELF
    var initialFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    initialFee.Fees[0].BasicFee.ShouldBe(100_00000000);
    
    // Create Parliament proposal to change fee to 50 ELF
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var newFee = new MethodFees
    {
        MethodName = "Create",
        Fees = { new MethodFee { Symbol = "ELF", BasicFee = 50_00000000 } }
    };
    
    var proposalId = await CreateProposalAsync(
        NFTContractAddress,
        defaultParliament,
        nameof(NFTContractStub.SetMethodFee),
        newFee
    );
    
    // Approve and release proposal
    await ApproveWithMinersAsync(proposalId);
    var releaseResult = await ParliamentContractStub.Release.SendAsync(proposalId);
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Query fee again - STILL 100 ELF (governance had no effect)
    var finalFee = await NFTContractStub.GetMethodFee.CallAsync(new StringValue { Value = "Create" });
    finalFee.Fees[0].BasicFee.ShouldBe(100_00000000); // Unchanged!
    
    // Governance silently failed - fee remains hardcoded
}
```

## Notes

This vulnerability represents a **governance interface inconsistency** rather than a traditional security exploit. The contract functions correctly for fee charging purposes but misleads governance participants by exposing non-functional governance methods. According to ACS1 standards, contracts with hardcoded fees should either implement full governance or expose only the `GetMethodFee()` view method without the setter interfaces.

The Election contract demonstrates the correct pattern for full ACS1 governance implementation [11](#0-10) , while the NFT contract's hybrid approach creates a deceptive interface that violates governance transparency principles.

### Citations

**File:** protobuf/nft_contract.proto (L20-20)
```text
    option (aelf.base) = "acs1.proto";
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

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L58-63)
```csharp
    public MappedState<string, MethodFees> TransactionFees { get; set; }
    public SingletonState<VoteWeightInterestList> VoteWeightInterestList { get; set; }
    public SingletonState<VoteWeightProportion> VoteWeightProportion { get; set; }
    public SingletonState<AuthorityInfo> VoteWeightInterestController { get; set; }

    public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_ACS1_TransactionFeeProvider.cs (L11-43)
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
```

**File:** docs-sphinx/reference/acs/acs1.rst (L94-143)
```text
On AElf, a pre-transaction is generated by pre-plugin
``FeeChargePreExecutionPlugin`` before the transaction main processing.
It is used to charge the transaction fee.

The generated transaction’s method is ``ChargeTransactionFees``. The
implementation is roughly like that (part of the code is omitted):

.. code:: c#

   /// <summary>
   /// Related transactions will be generated by acs1 pre-plugin service,
   /// and will be executed before the origin transaction.
   /// </summary>
   /// <param name="input"></param>
   /// <returns></returns>
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

**File:** docs-sphinx/reference/acs/acs1.rst (L237-277)
```text
later, they can be implemented as follows:

.. code:: c#

   public override MethodFees GetMethodFee(StringValue input)
   {
       if (input.Value == nameof(Foo1) || input.Value == nameof(Foo2))
       {
           return new MethodFees
           {
               MethodName = input.Value,
               Fees =
               {
                   new MethodFee
                   {
                       BasicFee = 1_00000000,
                       Symbol = Context.Variables.NativeSymbol
                   }
               }
           };
       }
       if (input.Value == nameof(Bar1) || input.Value == nameof(Bar2))
       {
           return new MethodFees
           {
               MethodName = input.Value,
               Fees =
               {
                   new MethodFee
                   {
                       BasicFee = 2_00000000,
                       Symbol = Context.Variables.NativeSymbol
                   }
               }
           };
       }
       return new MethodFees();
   }

This implementation can modify the transaction fee only by upgrading the
contract, without implementing the other three interfaces.
```
