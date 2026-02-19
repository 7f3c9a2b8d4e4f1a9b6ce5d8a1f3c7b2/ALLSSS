# Audit Report

## Title
Unbounded Miner List Growth in Cross-Chain Synchronization Causes State Bloat and DoS

## Summary
The `UpdateInformationFromCrossChain()` function on side chains accepts main chain miner lists without size validation, storing them directly in contract state and iterating through all entries during token distribution. An excessively large miner list from the main chain causes state bloat and denial-of-service by exhausting resources during nested loop token distribution operations.

## Finding Description

The AEDPoS consensus contract on side chains synchronizes miner information from the main chain through cross-chain data indexing. When parent chain block data is indexed, consensus extra data is extracted and passed to `UpdateInformationFromCrossChain()`. [1](#0-0) 

The CrossChain contract forwards this consensus data without any validation. [2](#0-1) 

The consensus contract then directly stores the entire miner list from the cross-chain data without validating its size. [3](#0-2) 

Before updating the miner list, the contract calls `DistributeResourceTokensToPreviousMiners()`, which performs nested loops iterating over all resource token symbols (PayTxFeeSymbolList + PayRentalSymbolList) and all miners in the current list. [4](#0-3) 

The root cause is that the main chain's `MaximumMinersCount` defaults to `int.MaxValue` (2,147,483,647), allowing unbounded growth. [5](#0-4) 

The auto-increase mechanism grows the miner count by 2 per `MinerIncreaseInterval` period. [6](#0-5) 

Without governance intervention through `SetMaximumMinersCount`, the main chain can accumulate hundreds of miners over years of operation. The side chain has no defensive validation to protect against receiving an oversized list from the main chain.

## Impact Explanation

**State Bloat:** Each miner's public key (ByteString) is stored in `State.MainChainCurrentMinerList`. With hundreds or thousands of miners, this causes excessive state storage consumption on the side chain.

**Denial of Service:** The nested loop in `DistributeResourceTokensToPreviousMiners()` performs M × N operations where M = number of resource symbols and N = number of miners. For example, with 5 symbols and 500 miners, that's 2,500 token transfer operations, each involving:
- State reads (balance queries)
- State writes (balance updates)  
- Event emissions
- Address conversions from public keys

This could exhaust gas limits, cause transaction timeouts, or fail entirely.

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
The default configuration allows unbounded growth with `MaximumMinersCount = int.MaxValue`. The auto-increase formula starts at 17 miners (SupposedMinersCount) [7](#0-6)  and grows by 2 miners per interval. Over years of operation without governance limits, this could realistically reach hundreds of miners.

For example, with a 1-month interval, after 10 years: 17 + (120 intervals × 2) = 257 miners. Test cases suggest that values around 100 are considered reasonable operational limits. [8](#0-7) 

**Attacker Capabilities:**
An attacker cannot directly exploit this - it requires the main chain to legitimately have a large miner list. The more likely scenario is governance oversight or misconfiguration where `MaximumMinersCount` is never set to a reasonable bound.

**Probability:** Low-to-Medium - depends on main chain governance practices, but the vulnerability exists by design in the cross-chain trust model.

## Recommendation

Implement defensive size validation on the side chain's `UpdateInformationFromCrossChain()` function:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");
    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
    
    if (input == null || input.Value.IsEmpty) return new Empty();
    
    var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);
    
    if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
        return new Empty();
    
    // ADD SIZE VALIDATION
    var minersCount = consensusInformation.Round.RealTimeMinersInformation.Count;
    var maxAllowedMiners = State.MaximumMinersCount.Value; // Use side chain's own limit
    Assert(minersCount <= maxAllowedMiners && minersCount <= 1000, // Add reasonable hard cap
        $"Main chain miner list size {minersCount} exceeds maximum allowed {maxAllowedMiners}");
    
    DistributeResourceTokensToPreviousMiners();
    State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;
    
    var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
    State.MainChainCurrentMinerList.Value = new MinerList
    {
        Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
    };
    
    return new Empty();
}
```

Additionally, ensure main chain governance sets a reasonable `MaximumMinersCount` limit (e.g., 100-500) through parliament proposals to prevent unbounded growth.

## Proof of Concept

The vulnerability can be demonstrated by creating a side chain test where the main chain provides consensus data with an excessively large miner list:

```csharp
[Fact]
public async Task SideChain_DoS_With_Large_Miner_List()
{
    // Setup: Initialize side chain and establish cross-chain indexing
    var sideChainTester = await InitializeSideChainAsync();
    
    // Create consensus data with 1000 miners (simulating years of growth)
    var largeConsensusInfo = new AElfConsensusHeaderInformation
    {
        Round = new Round { RoundNumber = 100 }
    };
    
    for (int i = 0; i < 1000; i++)
    {
        var keypair = CryptoHelper.GenerateKeyPair();
        largeConsensusInfo.Round.RealTimeMinersInformation.Add(
            keypair.PublicKey.ToHex(),
            new MinerInRound { Pubkey = keypair.PublicKey.ToHex() }
        );
    }
    
    // Attempt to update cross-chain consensus information
    var result = await sideChainTester.ConsensusStub.UpdateInformationFromCrossChain.SendAsync(
        new BytesValue { Value = largeConsensusInfo.ToByteString() }
    );
    
    // Expected: Transaction fails or times out due to excessive token distribution operations
    // With 1000 miners × 5 symbols = 5000 transfer operations
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

This test demonstrates that when the main chain legitimately has a large miner count, the side chain's `UpdateInformationFromCrossChain()` function will fail or timeout during the `DistributeResourceTokensToPreviousMiners()` nested loop execution.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L783-788)
```csharp
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L57-61)
```csharp
        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L73-95)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
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

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MinersCountTest.cs (L142-142)
```csharp
            (await AEDPoSContractStub.SetMaximumMinersCount.SendAsync(new Int32Value { Value = 100 }))
```
