# Audit Report

## Title
Insufficient Validation of Cross-Chain Consensus Data Enables Denial of Service via Division by Zero

## Summary
The `UpdateInformationFromCrossChain()` function in the AEDPoS consensus contract accepts cross-chain consensus information without validating that the miner list is non-empty. When an empty miner list is stored, subsequent cross-chain updates trigger a division-by-zero exception during resource token distribution, permanently blocking all future consensus updates from the parent chain.

## Finding Description

The vulnerability exists in the cross-chain consensus information update mechanism for side chains. When the CrossChain contract indexes parent chain block data containing consensus extra data, it forwards this to the consensus contract's `UpdateInformationFromCrossChain()` method. [1](#0-0) 

The consensus contract parses the protobuf data and validates only that the round number is increasing, but performs no validation on the semantic correctness of the miner list. [2](#0-1) 

According to the protobuf definition, the `real_time_miners_information` map in the `Round` message can be empty, as Protocol Buffers only validate binary structure, not business logic constraints. [3](#0-2) 

The vulnerable execution flow:

**First call with empty miner list:**
1. The function first distributes tokens to the previous miner list (which works normally)
2. Then stores the new miner list from `consensusInformation.Round.RealTimeMinersInformation.Keys`
3. If this Keys collection is empty, a `MinerList` with zero `Pubkeys` is stored [4](#0-3) 

**Second call (with any data):**
1. The function calls `DistributeResourceTokensToPreviousMiners()` which retrieves the stored miner list
2. It attempts to divide the token balance by `minerList.Count`
3. When the count is 0, this triggers a division-by-zero exception [5](#0-4) 

The `Div` extension method performs standard C# division without zero-checking, which throws `DivideByZeroException` when the divisor is zero. [6](#0-5) 

## Impact Explanation

**Severity: HIGH - Permanent Denial of Service**

1. **Irreversible Cross-Chain Update Failure:** Once an empty miner list is stored, ALL subsequent calls to `UpdateInformationFromCrossChain()` will fail with an unhandled exception. The side chain cannot receive any further consensus updates from the main chain.

2. **Resource Token Distribution Halt:** Side chains distribute transaction fees and rental fees to main chain miners through this mechanism. Once broken, main chain miners stop receiving compensation from the side chain, disrupting the economic incentive model.

3. **Cross-Chain Synchronization Break:** The side chain permanently loses the ability to synchronize its miner list with the main chain, breaking the fundamental parent-child chain relationship in AElf's cross-chain architecture.

4. **No Recovery Mechanism:** There is no built-in way to reset or repair the corrupted miner list state. The side chain remains in a permanently degraded state.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability can be triggered through the following realistic path:

1. **Entry Point:** The function is only callable by the CrossChain contract (trusted system contract), which forwards parent chain block data during cross-chain indexing. [7](#0-6) 

2. **Governance-Based Trigger:** Cross-chain data indexing requires governance approval through Parliament/Association proposals, but validators must approve the entire parent chain block data package.

3. **Validation Gap:** The CrossChain contract validates only structural aspects of parent chain data (chain ID, height, merkle roots) but does NOT validate the semantic correctness of consensus extra data. [8](#0-7) 

4. **Realistic Scenarios:**
   - A bug in parent chain consensus could produce invalid consensus data with an empty miner list
   - Governance validators may not thoroughly inspect binary protobuf consensus data
   - An intentional attack where malicious governance proposals include crafted cross-chain data

5. **Detection Difficulty:** The vulnerability manifests only on the SECOND call after storing invalid data, making it non-obvious during standard testing with single cross-chain updates.

## Recommendation

Add validation to ensure the miner list is non-empty before storing it:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(
        Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");

    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

    if (input == null || input.Value.IsEmpty) return new Empty();

    var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

    if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
        return new Empty();

    // ADD THIS VALIDATION
    var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
    Assert(minersKeys.Count > 0, "Miner list cannot be empty.");

    Context.LogDebug(() =>
        $"Shared miner list of round {consensusInformation.Round.RoundNumber}:" +
        $"{consensusInformation.Round.ToString("M")}");

    DistributeResourceTokensToPreviousMiners();

    State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

    State.MainChainCurrentMinerList.Value = new MinerList
    {
        Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
    };

    return new Empty();
}
```

Additionally, add defensive checking in the distribution function:

```csharp
private void DistributeResourceTokensToPreviousMiners()
{
    if (State.TokenContract.Value == null)
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

    var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
    
    // ADD THIS DEFENSIVE CHECK
    if (minerList.Count == 0) return;
    
    foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                 .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
    {
        // ... rest of distribution logic
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task UpdateInformationFromCrossChain_EmptyMinerList_CausesDivisionByZero()
{
    // Setup: Initialize side chain and contracts
    SetToSideChain();
    InitialContracts();
    
    var mockedCrossChain = SampleAccount.Accounts.Last();
    var mockedCrossChainStub =
        GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
            ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            mockedCrossChain.KeyPair);

    // First call: Store valid miner list
    var validHeaderInformation = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 2,
            RealTimeMinersInformation =
            {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() },
                { Accounts[1].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };

    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = validHeaderInformation.ToByteString()
    });

    // Transfer some tokens to consensus contract for distribution
    await TokenStub.Transfer.SendAsync(new TransferInput
    {
        Symbol = "ELF",
        Amount = 10_00000000,
        To = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name]
    });

    // Second call: Store EMPTY miner list
    var emptyMinerListHeader = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 3,
            RealTimeMinersInformation = { } // EMPTY!
        }
    };

    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = emptyMinerListHeader.ToByteString()
    });

    // Third call: Triggers division by zero when distributing to empty miner list
    var anyHeaderInformation = new AElfConsensusHeaderInformation
    {
        Round = new Round
        {
            RoundNumber = 4,
            RealTimeMinersInformation =
            {
                { Accounts[0].KeyPair.PublicKey.ToHex(), new MinerInRound() }
            }
        }
    };

    // This should throw DivideByZeroException
    var result = await mockedCrossChainStub.UpdateInformationFromCrossChain.SendWithExceptionAsync(new BytesValue
    {
        Value = anyHeaderInformation.ToByteString()
    });
    
    result.TransactionResult.Error.ShouldContain("DivideByZeroException");
}
```

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L782-788)
```csharp
            // send consensus data shared from main chain  
            if (i == parentChainBlockData.Count - 1 &&
                blockInfo.ExtraData.TryGetValue(ConsensusExtraDataName, out var bytes))
            {
                Context.LogDebug(() => "Updating consensus information..");
                UpdateConsensusInformation(bytes);
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L34-38)
```csharp
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");

        Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L43-47)
```csharp
        var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);

        // check round number of shared consensus, not term number
        if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-61)
```csharp
        DistributeResourceTokensToPreviousMiners();

        State.MainChainRoundNumber.Value = consensusInformation.Round.RoundNumber;

        var minersKeys = consensusInformation.Round.RealTimeMinersInformation.Keys;
        State.MainChainCurrentMinerList.Value = new MinerList
        {
            Pubkeys = { minersKeys.Select(k => ByteStringHelper.FromHexString(k)) }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

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
    }
```

**File:** protobuf/aedpos_contract.proto (L243-264)
```text
message Round {
    // The round number.
    int64 round_number = 1;
    // Current miner information, miner public key -> miner information.
    map<string, MinerInRound> real_time_miners_information = 2;
    // The round number on the main chain
    int64 main_chain_miners_round_number = 3;
    // The time from chain start to current round (seconds).
    int64 blockchain_age = 4;
    // The miner public key that produced the extra block in the previous round.
    string extra_block_producer_of_previous_round = 5;
    // The current term number.
    int64 term_number = 6;
    // The height of the confirmed irreversible block.
    int64 confirmed_irreversible_block_height = 7;
    // The round number of the confirmed irreversible block.
    int64 confirmed_irreversible_block_round_number = 8;
    // Is miner list different from the the miner list in the previous round.
    bool is_miner_list_just_changed = 9;
    // The round id, calculated by summing block producers’ expecting time (second).
    int64 round_id_for_validation = 10;
}
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```
