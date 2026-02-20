# Audit Report

## Title
Insufficient Validation of Cross-Chain Consensus Data Enables Denial of Service via Division by Zero

## Summary
The `UpdateInformationFromCrossChain()` function in the AEDPoS consensus contract accepts cross-chain consensus information without validating that the miner list is non-empty. When an empty miner list is stored, subsequent cross-chain updates trigger a division-by-zero exception during resource token distribution, permanently blocking all future consensus updates from the parent chain.

## Finding Description

The vulnerability exists in the cross-chain consensus information update mechanism for side chains. When the CrossChain contract indexes parent chain block data containing consensus extra data, it forwards this to the consensus contract's `UpdateInformationFromCrossChain()` method. [1](#0-0) 

The consensus contract parses the protobuf data and validates only that the round number is increasing, but performs no validation on the semantic correctness of the miner list. [2](#0-1) 

According to the protobuf definition, the `real_time_miners_information` map in the `Round` message can be empty, as Protocol Buffers only validate binary structure, not business logic constraints. [3](#0-2) 

**Vulnerable Execution Flow:**

**First call with empty miner list:**
1. The function first distributes tokens to the previous miner list (which works normally)
2. Then stores the new miner list from `consensusInformation.Round.RealTimeMinersInformation.Keys`
3. If this Keys collection is empty, a `MinerList` with zero `Pubkeys` is stored [4](#0-3) 

**Second call (with any data):**
1. The function calls `DistributeResourceTokensToPreviousMiners()` which retrieves the stored miner list [5](#0-4) 
2. It retrieves the previously stored miner list and attempts to divide the token balance by `minerList.Count` [6](#0-5) 
3. When the count is 0, this triggers a division-by-zero exception

The `Div` extension method performs standard C# division without zero-checking, which throws `DivideByZeroException` when the divisor is zero. [7](#0-6) 

## Impact Explanation

**Severity: HIGH - Permanent Denial of Service**

1. **Irreversible Cross-Chain Update Failure:** Once an empty miner list is stored, ALL subsequent calls to `UpdateInformationFromCrossChain()` will fail with an unhandled exception. The side chain cannot receive any further consensus updates from the main chain.

2. **Resource Token Distribution Halt:** Side chains distribute transaction fees and rental fees to main chain miners through this mechanism. Once broken, main chain miners stop receiving compensation from the side chain, disrupting the economic incentive model.

3. **Cross-Chain Synchronization Break:** The side chain permanently loses the ability to synchronize its miner list with the main chain, breaking the fundamental parent-child chain relationship in AElf's cross-chain architecture.

4. **No Recovery Mechanism:** There is no built-in way to reset or repair the corrupted miner list state. The side chain remains in a permanently degraded state.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability can be triggered through the following realistic path:

1. **Entry Point:** The function is only callable by the CrossChain contract (trusted system contract), which forwards parent chain block data during cross-chain indexing. [8](#0-7) 

2. **Governance-Based Trigger:** Cross-chain data indexing requires governance approval through Parliament/Association proposals, but validators must approve the entire parent chain block data package.

3. **Validation Gap:** The CrossChain contract validates only structural aspects of parent chain data (chain ID, height, merkle roots) but does NOT validate the semantic correctness of consensus extra data. [9](#0-8) 

4. **Realistic Scenarios:**
   - A bug in parent chain consensus could produce invalid consensus data with an empty miner list
   - Governance validators may not thoroughly inspect binary protobuf consensus data
   - An intentional attack where malicious governance proposals include crafted cross-chain data

5. **Detection Difficulty:** The vulnerability manifests only on the SECOND call after storing invalid data, making it non-obvious during standard testing with single cross-chain updates.

## Recommendation

Add validation in `UpdateInformationFromCrossChain()` to ensure the miner list is non-empty before storing it:

```csharp
var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
Assert(minersKeys.Count > 0, "Miner list cannot be empty.");
State.MainChainCurrentMinerList.Value = new MinerList
{
    Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
};
```

Additionally, add a zero-check in `DistributeResourceTokensToPreviousMiners()` as a defensive measure:

```csharp
var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
if (minerList.Count == 0)
{
    Context.LogDebug(() => "No miners to distribute to, skipping distribution.");
    return;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task UpdateInformationFromCrossChain_EmptyMinerList_CausesDivisionByZero()
{
    SetToSideChain();
    InitialContracts();
    var mockedCrossChain = SampleAccount.Accounts.Last();
    var mockedCrossChainStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
        mockedCrossChain.KeyPair);
    
    // First call: Store empty miner list
    var emptyMinerListInfo = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 2,
            RealTimeMinersInformation = { } // EMPTY
        }
    };
    
    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = emptyMinerListInfo.ToByteString()
    });
    
    // Second call: This will fail with DivideByZeroException
    var normalInfo = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 3,
            RealTimeMinersInformation =
            {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };
    
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
        {
            Value = normalInfo.ToByteString()
        });
    });
    
    Assert.Contains("DivideByZero", exception.ToString());
}
```

## Notes

This vulnerability demonstrates a critical gap in cross-chain data validation where semantic correctness of consensus information is not verified. The attack surface is limited by governance controls, but the permanent nature of the DoS makes this a high-severity issue. The protobuf specification allows empty maps, so explicit validation is essential for protocol safety.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L720-743)
```csharp
    private bool ValidateParentChainBlockData(IList<ParentChainBlockData> parentChainBlockData,
        out Dictionary<int, List<ParentChainBlockData>> validatedParentChainBlockData)
    {
        var parentChainId = State.ParentChainId.Value;
        var currentHeight = State.CurrentParentChainHeight.Value;
        validatedParentChainBlockData = new Dictionary<int, List<ParentChainBlockData>>();
        foreach (var blockData in parentChainBlockData)
        {
            if (parentChainId != blockData.ChainId || currentHeight + 1 != blockData.Height ||
                blockData.TransactionStatusMerkleTreeRoot == null)
                return false;
            if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                    State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
                    State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
                return false;

            currentHeight += 1;
        }

        if (parentChainBlockData.Count > 0)
            validatedParentChainBlockData[parentChainId] = parentChainBlockData.ToList();

        return true;
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L34-36)
```csharp
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L46-47)
```csharp
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L72-81)
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
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```
