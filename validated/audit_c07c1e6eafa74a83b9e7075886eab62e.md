# Audit Report

## Title
Unbounded Miner List Growth in Cross-Chain Synchronization Causes State Bloat and DoS

## Summary
The `UpdateInformationFromCrossChain()` function on side chains accepts main chain miner lists without size validation, directly storing them in contract state and iterating through all entries during token distribution. An excessively large miner list from the main chain causes state bloat and potential denial-of-service by exhausting resources during nested loop token distribution operations.

## Finding Description

The AEDPoS consensus contract on side chains synchronizes miner information from the main chain through cross-chain data indexing. The `UpdateInformationFromCrossChain()` method can only be called by the CrossChain contract and only on side chains. [1](#0-0) 

The CrossChain contract forwards consensus extra data from indexed parent chain blocks directly to the consensus contract without validation. [2](#0-1) 

The consensus contract extracts the miner list from cross-chain consensus information and stores it directly without any size validation. [3](#0-2) 

Before updating the miner list, the contract calls `DistributeResourceTokensToPreviousMiners()`, which performs nested loops iterating over all resource token symbols and all miners. [4](#0-3)  The nested loop structure iterates through PayTxFeeSymbolList union PayRentalSymbolList for the outer loop, and all miners in the inner loop, performing token transfers for each combination. [5](#0-4) 

The root cause is that the main chain's `MaximumMinersCount` defaults to `int.MaxValue`, allowing unbounded growth. [6](#0-5)  The auto-increase mechanism grows the miner count by 2 per interval. [7](#0-6) 

The initial miner count is set to 17 (SupposedMinersCount). [8](#0-7)  Without governance intervention through `SetMaximumMinersCount`, which requires Parliament authorization, [9](#0-8)  the main chain can accumulate hundreds of miners over years of operation. The side chain has no defensive validation to protect against receiving an oversized list from the main chain.

## Impact Explanation

**State Bloat:** Each miner's public key (ByteString) is stored in `State.MainChainCurrentMinerList`. [10](#0-9)  With hundreds or thousands of miners, this causes excessive state storage consumption on the side chain.

**Denial of Service:** The nested loop performs M × N operations where M = number of resource symbols (PayTxFeeSymbolList + PayRentalSymbolList) and N = number of miners. For example, with 5 symbols and 500 miners, that's 2,500 token transfer operations, each involving state reads (balance queries), state writes (balance updates), event emissions, and address conversions from public keys. This could exhaust gas limits, cause transaction timeouts, or fail entirely.

**Cross-Chain Sync Failure:** If `UpdateInformationFromCrossChain()` fails due to resource exhaustion, the side chain cannot synchronize consensus information from the main chain, blocking critical cross-chain operations and disrupting the side chain's ability to distribute resource tokens to main chain miners.

**Affected Parties:**
- Side chain operators (consensus synchronization blocked)
- Main chain miners (cannot receive resource token distributions from side chain)
- Side chain users (cross-chain functionality degraded)

This is a **Medium** severity issue because it requires specific main chain configuration (large miner count) but impacts critical cross-chain infrastructure.

## Likelihood Explanation

**Preconditions:**
1. Main chain must have accumulated a large miner list (hundreds to thousands of miners)
2. Main chain governance has not set a reasonable `MaximumMinersCount` limit via parliament proposal
3. Blockchain has operated long enough for auto-increase mechanism to accumulate significant miner count

**Feasibility:**
The default configuration allows unbounded growth with `MaximumMinersCount = int.MaxValue`. The auto-increase formula grows by 2 miners per `MinerIncreaseInterval` period. Over years of operation without governance limits, this could realistically reach hundreds of miners. For example, with a 1-month interval over 10 years: 17 + (120 intervals × 2) = 257 miners.

**Attacker Capabilities:**
An attacker cannot directly exploit this - it requires the main chain to legitimately have a large miner list. The more likely scenario is governance oversight or misconfiguration where `MaximumMinersCount` is never set to a reasonable bound.

**Probability:** Low-to-Medium - depends on main chain governance practices, but the vulnerability exists by design in the cross-chain trust model.

## Recommendation

Add size validation in `UpdateInformationFromCrossChain()` before storing the miner list:

```csharp
var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;

// Add size validation
const int MaxReasonableMinersCount = 100; // Or configurable value
Assert(minersKeys.Count <= MaxReasonableMinersCount, 
    $"Miner list too large: {minersKeys.Count} exceeds maximum {MaxReasonableMinersCount}");

State.MainChainCurrentMinerList.Value = new MinerList
{
    Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
};
```

Alternatively, implement a configurable maximum miner list size that can be set via governance, similar to the `MaximumMinersCount` on the main chain.

Additionally, consider optimizing the `DistributeResourceTokensToPreviousMiners()` method to batch operations or implement a gas limit check to prevent transaction failures.

## Proof of Concept

A proof of concept would involve:

1. Setting up a main chain with `MaximumMinersCount` at a high value
2. Allowing the auto-increase mechanism to accumulate hundreds of miners over simulated time
3. Creating a side chain that indexes the main chain
4. Triggering cross-chain indexing when the main chain has a large miner list
5. Observing state bloat and measuring gas consumption in `UpdateInformationFromCrossChain()`
6. Demonstrating that the transaction fails or times out with sufficiently large miner counts

The test would verify that no size validation exists and that performance degrades linearly with miner count in the nested loop structure.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L34-38)
```csharp
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-53)
```csharp
        DistributeResourceTokensToPreviousMiners();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L57-61)
```csharp
        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L73-94)
```csharp
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L227-234)
```csharp
    private void UpdateConsensusInformation(ByteString bytes)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        Context.SendInline(State.CrossChainInteractionContract.Value,
            nameof(State.CrossChainInteractionContract.UpdateInformationFromCrossChain),
            new BytesValue { Value = bytes });
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L36-36)
```csharp
    public SingletonState<MinerList> MainChainCurrentMinerList { get; set; }
```
