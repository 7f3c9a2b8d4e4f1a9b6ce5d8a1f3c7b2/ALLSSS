# Audit Report

## Title
NFT Contract Spam Prevention Failure - Broken ACS1 Implementation Allows Near-Zero-Cost State Bloat Attack

## Summary
The NFT contract's ACS1 (transaction fee standard) implementation contains critical deficiencies where `SetMethodFee()` and `ChangeMethodFeeController()` are no-op stubs that never persist configuration. Only the `Create` method has a hardcoded 100 ELF fee, while `Mint`, `Transfer`, and `TransferFrom` operations have no base fees. This allows an attacker to spam millions of state-bloating operations for negligible cost (approximately 0.0000000063 ELF per operation), causing permanent blockchain state growth and potential DoS.

## Finding Description

The NFT contract implements ACS1 (method fee standard) incompletely. The `SetMethodFee()` and `ChangeMethodFeeController()` methods immediately return empty without performing any storage operations: [1](#0-0) 

The `GetMethodFee()` method only returns fees for the `Create` method (100 ELF), while all other methods receive empty `MethodFees`: [2](#0-1) 

This contrasts sharply with proper ACS1 implementations in other system contracts, which store fees in state: [3](#0-2) [4](#0-3) 

The NFT contract state definition confirms there are no state variables for storing transaction fees: [5](#0-4) 

The fee charging mechanism in the token contract calls `GetMethodFee()` on the target contract to determine charges: [6](#0-5) 

When empty `MethodFees` are returned, only transaction size fees apply. The size fee formula for transactions under 1MB is: [7](#0-6) 

For a typical 500-byte mint transaction: `500/800 + 1/10000 = 0.6251` base units ≈ 0.0000000063 ELF (with 8 decimals).

Each mint operation creates permanent state entries: [8](#0-7) 

The protocol creator is automatically added as a minter: [9](#0-8) 

## Impact Explanation

**State Bloat and DoS Risk:**
An attacker can create catastrophic state bloat with minimal investment:
- **Initial cost:** 100 ELF for `Create()` 
- **Spam cost:** 1 million mints × 0.63 base units = 630,000 base units = 0.0063 ELF
- **Total attack cost:** ~100.01 ELF to create 1+ million permanent state entries

Each mint creates entries in `NftInfoMap` and `BalanceMap`, consuming blockchain storage permanently. Similarly, `Transfer` and `TransferFrom` operations cost only transaction size fees.

**Chain-Level Impact:**
- Degraded node performance from bloated state
- Increased storage costs for all node operators  
- Potential chain-level DoS if storage/computation limits reached
- No economic deterrent mechanism after initial 100 ELF investment

**Protocol Integrity:**
This violates AElf's fundamental economic security model where resource-intensive operations must have commensurate fees to prevent abuse.

## Likelihood Explanation

**Attack Feasibility: HIGH**

**Attacker Requirements:**
1. 100 ELF to call `Create()` - readily available amount
2. Self-authorization as minter - automatic for protocol creator

**Attack Complexity:** Low - straightforward method calls with minimal preconditions:
```
1. NFTContract.Create() → pay 100 ELF, become minter
2. NFTContract.Mint() → spam millions of calls at ~0.0000000063 ELF each
3. NFTContract.Transfer() → spam transfers at same cost
```

**Permanence:** The broken `SetMethodFee()` stub means fees can NEVER be configured without a contract upgrade, making this a permanent vulnerability in the current deployment.

**Detection Difficulty:** The attack generates legitimate-looking transactions that pass all authorization checks. Distinguishing malicious spam from legitimate high-volume minting is difficult.

**Economic Rationality:** Extremely favorable for attackers - after 100 ELF initial cost, the marginal cost per operation is effectively zero (~0.0000000063 ELF).

## Recommendation

Implement proper ACS1 fee storage and controller mechanisms in the NFT contract:

1. **Add state variables:**
```csharp
public MappedState<string, MethodFees> TransactionFees { get; set; }
public SingletonState<AuthorityInfo> MethodFeeController { get; set; }
```

2. **Implement SetMethodFee() with authorization:**
```csharp
public override Empty SetMethodFee(MethodFees input)
{
    RequireMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

3. **Implement ChangeMethodFeeController():**
```csharp
public override Empty ChangeMethodFeeController(AuthorityInfo input)
{
    RequireMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress,
        "Unauthorized to change controller.");
    State.MethodFeeController.Value = input;
    return new Empty();
}
```

4. **Update GetMethodFee() to retrieve from state:**
```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    if (input.Value == nameof(Create))
        return new MethodFees { /* hardcoded Create fee */ };
    
    return State.TransactionFees[input.Value] ?? new MethodFees();
}
```

5. **Set appropriate fees for Mint/Transfer operations** via governance after deployment.

## Proof of Concept

```csharp
[Fact]
public async Task StateBloa_SpamAttack_NegligibleCost()
{
    // 1. Attacker creates NFT protocol (100 ELF cost)
    var createResult = await NFTContract.Create.SendAsync(new CreateInput {
        ProtocolName = "SPAM",
        TotalSupply = 1_000_000_000,
        NftType = "Attack"
    });
    
    var symbol = createResult.Output.Value;
    var initialBalance = await GetBalance(AttackerAddress);
    
    // 2. Attacker spams 10,000 mints
    for(int i = 0; i < 10000; i++) {
        await NFTContract.Mint.SendAsync(new MintInput {
            Symbol = symbol,
            TokenId = i + 1
        });
    }
    
    var finalBalance = await GetBalance(AttackerAddress);
    var totalCost = initialBalance - finalBalance;
    
    // 3. Verify negligible cost (should be ~0.063 ELF for 10K mints + 100 ELF Create)
    Assert.True(totalCost < 101_00000000, 
        "10,000 mints cost more than 101 ELF - fee mechanism working");
    
    // 4. Verify state bloat occurred
    var protocolInfo = await NFTContract.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    Assert.Equal(10000, protocolInfo.Issued);
}
```

This test demonstrates that an attacker can mint 10,000 NFTs for approximately 100 ELF (Create) + 0.063 ELF (mints) = 100.063 ELF total, proving the vulnerability enables economically viable state bloat attacks.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L38-52)
```csharp
        var methodFees = Context.Call<MethodFees>(input.ContractAddress, nameof(GetMethodFee),
            new StringValue { Value = input.MethodName });
        var fee = new Dictionary<string, long>();
        var isSizeFeeFree = false;
        if (methodFees != null)
        {
            isSizeFeeFree = methodFees.IsSizeFeeFree;
        }

        if (methodFees != null && methodFees.Fees.Any())
        {
            fee = GetBaseFeeDictionary(methodFees);
        }

        return TryToChargeTransactionFee(input, fromAddress, bill, allowanceBill, fee, isSizeFeeFree);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L274-290)
```csharp
    private CalculateFeeCoefficients GetTxFeeInitialCoefficient()
    {
        return new CalculateFeeCoefficients
        {
            FeeTokenType = (int)FeeTypeEnum.Tx,
            PieceCoefficientsList =
            {
                new CalculateFeePieceCoefficients
                {
                    // Interval [0, 1000000]: x / 800 + 1 / 10000
                    Value =
                    {
                        1000000,
                        1, 1, 800,
                        0, 1, 10000
                    }
                },
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L439-441)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```
