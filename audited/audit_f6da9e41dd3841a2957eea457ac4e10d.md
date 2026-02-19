### Title
Unbounded Miner List Growth in Cross-Chain Synchronization Causes State Bloat and DoS

### Summary
The `UpdateInformationFromCrossChain()` function accepts main chain miner lists without size validation, storing them directly in contract state and iterating through all entries during token distribution. An excessively large miner list from the main chain could cause state bloat and denial-of-service by exhausting resources during the nested loop token distribution operation.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The function directly assigns the miner list from cross-chain data without validating its size: [2](#0-1) 

**Execution Path**:
1. Cross-chain data flows from main chain through the CrossChain contract: [3](#0-2) 

2. The CrossChain contract forwards consensus data without validation: [4](#0-3) 

3. The consensus contract stores the entire list and calls distribution: [5](#0-4) 

4. Distribution performs nested loops (symbols × miners) with token transfers: [6](#0-5) 

**Why Protections Fail**: The main chain's `MaximumMinersCount` defaults to `int.MaxValue`: [7](#0-6) 

Without governance intervention via `SetMaximumMinersCount`, the auto-increase mechanism can grow the miner count unboundedly: [8](#0-7) 

The side chain has no defensive validation against receiving an oversized list from the main chain.

### Impact Explanation

**State Bloat**: Each public key (ByteString) in the miner list is stored in `State.MainChainCurrentMinerList`. With thousands of miners, this causes excessive state storage consumption on the side chain.

**Denial of Service**: The `DistributeResourceTokensToPreviousMiners()` method performs M × N operations where M = number of resource symbols (PayTxFeeSymbolList + PayRentalSymbolList) and N = number of miners. For example:
- 5 symbols × 10,000 miners = 50,000 token transfer operations
- Each transfer involves state reads, balance updates, and event emissions
- This could cause transaction timeout or failure

**Cross-Chain Sync Failure**: If `UpdateInformationFromCrossChain()` fails due to resource exhaustion, the side chain cannot synchronize consensus information from the main chain, blocking critical cross-chain operations.

**Affected Parties**: 
- Side chain operators (consensus blocked)
- Main chain miners (cannot receive resource token distributions)
- Side chain users (cross-chain functionality degraded)

**Severity**: Medium - requires specific main chain configuration but impacts critical infrastructure.

### Likelihood Explanation

**Preconditions**:
1. Main chain must have a large miner list (hundreds to thousands of miners)
2. Main chain governance has not set a reasonable `MaximumMinersCount` limit
3. Blockchain has run long enough for auto-increase to accumulate significant miner count

**Attacker Capabilities**: 
- Cannot directly exploit (requires main chain to legitimately have large miner list)
- Could manipulate if main chain governance is compromised
- More likely scenario: governance misconfiguration or oversight

**Feasibility**:
- Default configuration allows unbounded growth: [9](#0-8) 
- Auto-increase formula grows by 2 miners per interval
- Over years of operation without governance limits, could reach hundreds of miners
- Test cases show limits like 100 are reasonable: [10](#0-9) 

**Detection**: Easy to monitor miner count, but side chain has no proactive defense

**Probability**: Low-to-Medium - depends on main chain governance practices, but vulnerability exists by design

### Recommendation

**Code-Level Mitigation**:
Add size validation in `UpdateInformationFromCrossChain()` before assignment:

```csharp
// Add after line 55 in AEDPoSContract_ACS11_CrossChainInformationProvider.cs
const int MaxAcceptableMinerCount = 1000; // Or configurable via governance
var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
Assert(minersKeys.Count <= MaxAcceptableMinerCount, 
    $"Main chain miner list too large: {minersKeys.Count} exceeds maximum {MaxAcceptableMinerCount}");
```

**Invariant Checks**:
1. Add maximum miner count configuration for side chains
2. Validate size before storing in `State.MainChainCurrentMinerList`
3. Add early exit in `DistributeResourceTokensToPreviousMiners()` if miner count exceeds safe threshold
4. Consider pagination or batching for token distribution if miner count is large

**Test Cases**:
1. Test with miner list of 100, 1000, 10000 entries
2. Verify transaction succeeds/fails appropriately
3. Measure gas consumption for different miner counts
4. Test cross-chain sync continues with reasonable miner counts
5. Test that size limit rejects oversized lists while accepting valid ones

### Proof of Concept

**Initial State**:
1. Side chain is initialized and connected to main chain
2. Main chain has large miner list (e.g., 5000 miners due to long runtime and no MaximumMinersCount limit)

**Exploitation Steps**:
1. Main chain produces new round with 5000 miners in `RealTimeMinersInformation`
2. Cross-chain indexing captures main chain block with consensus extra data
3. CrossChain contract calls `UpdateInformationFromCrossChain()` with 5000 miner keys
4. Side chain stores all 5000 entries without validation (state bloat occurs)
5. `DistributeResourceTokensToPreviousMiners()` attempts 5 symbols × 5000 miners = 25,000 token transfers
6. Transaction exhausts resources or times out
7. Cross-chain synchronization is blocked, side chain cannot update consensus information

**Expected vs Actual**:
- Expected: Side chain validates miner list size and rejects/handles large lists gracefully
- Actual: Side chain blindly accepts any size list, causing state bloat and potential DoS

**Success Condition**: Transaction fails or times out when miner list exceeds reasonable operational limits, demonstrating the vulnerability's impact on side chain availability.

**Notes**:
- The vulnerability relies on main chain having legitimately large miner list, not malicious data injection
- Main chain's consensus is assumed trusted, but defensive programming suggests side chains should validate bounded inputs
- The default `MaximumMinersCount = int.MaxValue` configuration creates the vulnerability surface
- Real-world impact depends on main chain governance practices regarding miner count limits

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-64)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

        // For now we just extract the miner list from main chain consensus information, then update miners list.
        if (input == null || input.Value.IsEmpty) return new Empty();

        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();

        Context.LogDebug(() =>
            $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
            $"{consensusInformation.Round.ToString("M")}");

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L72-95)
```csharp
        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L43-52)
```csharp
        State.IsMainChain.Value = true;

        State.ElectionContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName);
        State.TreasuryContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

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

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MinersCountTest.cs (L142-142)
```csharp
            (await AEDPoSContractStub.SetMaximumMinersCount.SendAsync(new Int32Value { Value = 100 }))
```
