# Audit Report

## Title
Missing Validation for Negative Resource Amounts Enables Resource Rental Reversal Attack

## Summary
The `InitializeFromParentChain` method in the MultiToken contract lacks validation for negative `ResourceAmount` values. Non-exclusive side chains bypass the CrossChain contract's `AssertValidResourceTokenAmount` validation, allowing negative resource amounts to be set during side chain initialization. This causes the `PayRental` calculation to reverse payment direction - side chain creators receive tokens instead of paying rental fees, draining the consensus contract.

## Finding Description

**Root Cause: Inconsistent Validation Across Initialization Paths**

The `ResourceAmount` state variable is defined as `MappedState<string, int>`, which allows negative integer values: [1](#0-0) 

The `InitializeFromParentChain` method directly sets resource amounts without any non-negativity validation: [2](#0-1) 

In contrast, the `UpdateRentedResources` method explicitly validates that amounts are non-negative: [3](#0-2) 

**Why Protection Mechanisms Fail:**

On the parent chain, the `AssertValidSideChainCreationRequest` method validates side chain creation requests: [4](#0-3) 

For non-exclusive side chains (`IsPrivilegePreserved = false`), the method returns early, completely bypassing `AssertValidResourceTokenAmount`. The validation that would catch negative values is never executed: [5](#0-4) 

However, `InitialResourceAmount` is included in the `ChainInitializationData` for ALL side chains, regardless of type: [6](#0-5) 

**Exploitation Path:**

When the side chain's `PayRental` method executes, it calculates the rental using the potentially negative `ResourceAmount`: [7](#0-6) 

With a negative `ResourceAmount` (e.g., -100), the rental becomes negative. The balance check at line 1062 passes because any positive `availableBalance` is >= negative rental. The code then adds the negative rental to `donates` and calls `ModifyBalance(creator, symbol, -donates)`, which with a negative `donates` value becomes `ModifyBalance(creator, symbol, POSITIVE_AMOUNT)`, crediting tokens to the creator instead of debiting them: [8](#0-7) 

The consensus contract then loses the corresponding tokens: [9](#0-8) 

## Impact Explanation

**HIGH Severity - Direct Fund Theft and Economic Model Compromise**

This vulnerability enables direct theft of tokens from the consensus contract with the following characteristics:

1. **Direct Fund Loss**: The consensus contract loses tokens with every rental period, proportional to `duration × |ResourceAmount| × Rental`. With typical values (10 minutes duration, ResourceAmount=-100, Rental=1000 tokens/minute), the creator gains 1,000,000 tokens per rental period.

2. **Reversed Economic Flow**: The fundamental economic invariant that resource rental must flow FROM side chain creator TO consensus is violated. Instead, tokens flow from consensus TO creator.

3. **Unbounded Accumulation**: The attack repeats automatically every rental period through normal mining operations, allowing unlimited token theft over time.

4. **Protocol Integrity**: Breaks the core economic model of side chain resource rental, which is essential for the cross-chain ecosystem's sustainability.

The `DonateResourceToken` method is called automatically by miners on side chains: [10](#0-9) 

## Likelihood Explanation

**MEDIUM-HIGH Likelihood - Permitted Operation with Automatic Exploitation**

The attack has realistic preconditions and execution:

1. **Entry Point**: Anyone can call `RequestSideChainCreation` to propose a side chain: [11](#0-10) 

2. **Governance Approval**: Side chain creation requires parliament governance approval, but this is a standard operation that doesn't require compromising system keys. The attacker simply needs to successfully propose and gain approval for a non-exclusive side chain with negative `InitialResourceAmount` values.

3. **Automatic Exploitation**: Once the side chain is initialized with negative `ResourceAmount` values, the attack executes automatically every rental period when miners call `DonateResourceToken`. No additional malicious transactions are required.

4. **No Defense-in-Depth**: The MultiToken contract has no secondary validation that would catch or prevent the negative resource amounts from being used in rental calculations.

5. **Economic Rationality**: The one-time cost of side chain creation is far outweighed by the ongoing token theft that accumulates unbounded over time, making this highly profitable for an attacker.

## Recommendation

Add validation in `InitializeFromParentChain` to ensure all resource amounts are non-negative:

```csharp
public override Empty InitializeFromParentChain(InitializeFromParentChainInput input)
{
    Assert(!State.InitializedFromParentChain.Value, "MultiToken has been initialized");
    State.InitializedFromParentChain.Value = true;
    Assert(input.Creator != null, "creator should not be null");
    
    // Add validation for non-negative resource amounts
    foreach (var pair in input.ResourceAmount)
    {
        Assert(pair.Value >= 0, "Invalid resource amount.");
        State.ResourceAmount[pair.Key] = pair.Value;
    }

    foreach (var pair in input.RegisteredOtherTokenContractAddresses)
        State.CrossChainTransferWhiteList[pair.Key] = pair.Value;

    SetSideChainCreator(input.Creator);
    return new Empty();
}
```

Alternatively, ensure `AssertValidResourceTokenAmount` is called for ALL side chains, not just exclusive ones, by removing the early return in `AssertValidSideChainCreationRequest`.

## Proof of Concept

The vulnerability can be demonstrated through the following execution flow:

1. **Parent Chain**: Call `RequestSideChainCreation` with:
   - `IsPrivilegePreserved = false` (non-exclusive side chain)
   - `InitialResourceAmount = { ["CPU"] = -100, ["RAM"] = -100, ["DISK"] = -100, ["NET"] = -100 }`

2. **Parent Chain**: Obtain governance approval and call `ReleaseSideChainCreation`, which creates the side chain and stores the initialization data including negative resource amounts.

3. **Side Chain Genesis**: The `InitializeFromParentChain` method is automatically called during genesis block initialization, setting `State.ResourceAmount[symbol]` to the negative values without validation.

4. **Side Chain Runtime**: When miners call `DonateResourceToken`:
   - `PayRental()` is invoked
   - Rental calculation: `rental = 10 × (-100) × 1000 = -1,000,000`
   - Balance check passes: `availableBalance >= -1,000,000` is true
   - `donates = -1,000,000`
   - `ModifyBalance(creator, symbol, -(-1,000,000))` adds 1,000,000 tokens to creator
   - `ModifyBalance(consensusContract, symbol, -1,000,000)` deducts 1,000,000 from consensus

The attack repeats automatically every rental period, continuously draining the consensus contract.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs (L26-26)
```csharp
    public MappedState<string, int> ResourceAmount { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L19-19)
```csharp
        foreach (var pair in input.ResourceAmount) State.ResourceAmount[pair.Key] = pair.Value;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L947-950)
```csharp
        if (!isMainChain)
        {
            PayRental();
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1061-1061)
```csharp
            var rental = duration.Mul(State.ResourceAmount[symbol]).Mul(State.Rental[symbol]);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1062-1065)
```csharp
            if (availableBalance >= rental) // Success
            {
                donates = donates.Add(rental);
                ModifyBalance(creator, symbol, -donates);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1085-1087)
```csharp
            var consensusContractAddress =
                Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName);
            ModifyBalance(consensusContractAddress, symbol, donates);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1122-1122)
```csharp
            Assert(pair.Value >= 0, "Invalid amount.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L124-128)
```csharp
        if (!sideChainCreationRequest.IsPrivilegePreserved)
            return; // there is no restriction for non-exclusive side chain creation

        AssertValidResourceTokenAmount(sideChainCreationRequest);

```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L139-145)
```csharp
    private void AssertValidResourceTokenAmount(SideChainCreationRequest sideChainCreationRequest)
    {
        var resourceTokenMap = sideChainCreationRequest.InitialResourceAmount;
        foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayRentalSymbolListName))
            Assert(resourceTokenMap.ContainsKey(resourceTokenSymbol) && resourceTokenMap[resourceTokenSymbol] > 0,
                "Invalid side chain resource token request.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L538-542)
```csharp
        res.ResourceTokenInfo = new ResourceTokenInfo
        {
            ResourceTokenListData = resourceTokenInformation,
            InitialResourceAmount = { sideChainCreationRequest.InitialResourceAmount }
        };
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L90-96)
```csharp
    public override Empty RequestSideChainCreation(SideChainCreationRequest input)
    {
        AssertValidSideChainCreationRequest(input, Context.Sender);
        var sideChainCreationRequestState = ProposeNewSideChain(input, Context.Sender);
        State.ProposedSideChainCreationRequestState[Context.Sender] = sideChainCreationRequestState;
        return new Empty();
    }
```
