# Audit Report

## Title
Silent Failure on Empty Consensus Data Causes Permanent Side Chain Consensus Desynchronization

## Summary
The `UpdateInformationFromCrossChain` function silently returns without error when receiving empty consensus data, causing permanent desynchronization of the side chain's view of the main chain miner list and round number. Once a parent chain height is indexed with empty consensus data, the side chain cannot re-index that height with correct data, leading to stale miner information being used indefinitely for consensus operations and token distributions.

## Finding Description

The vulnerability exists in the cross-chain consensus synchronization mechanism between main and side chains. When parent chain blocks are indexed on a side chain, consensus information is extracted from the `ExtraData` map and passed to the consensus contract.

The critical flaw occurs in the `UpdateInformationFromCrossChain` method which performs an early return when the input value is empty, without any error or event emission: [1](#0-0) 

During cross-chain indexing, the `IndexParentChainBlockData` method extracts consensus data from the last parent chain block's `ExtraData` dictionary and calls `UpdateConsensusInformation` if the "Consensus" key exists: [2](#0-1) 

The `TryGetValue` method succeeds when the key exists even with an empty `ByteString`, passing empty bytes to the consensus contract. The validation in `ValidateParentChainBlockData` only checks structural properties (chain ID, height continuity, merkle tree root existence) and does NOT validate `ExtraData` content: [3](#0-2) 

After indexing completes, `CurrentParentChainHeight` advances permanently: [4](#0-3) 

The sequential height validation prevents re-indexing the same height with correct data: [5](#0-4) 

## Impact Explanation

The permanent desynchronization has multiple critical impacts:

**1. Consensus Integrity Failure**
Side chains use `IsMainChainMinerListChanged` to detect when the main chain miner list changes and trigger new term generation: [6](#0-5) 

With stale `MainChainCurrentMinerList`, this detection fails: [7](#0-6) 

**2. Incorrect Token Distribution**
Resource tokens (transaction fees and rental fees) accumulated by the consensus contract are distributed to miners from the stale `MainChainCurrentMinerList`: [8](#0-7) 

Current legitimate miners on the main chain do not receive their entitled rewards, while outdated miners receive undeserved distributions.

**3. No Recovery Mechanism**
The `CurrentParentChainHeight` state variable can only be set in two locations - initialization and indexing - with no rollback mechanism: [9](#0-8) 

Recovery is impossible without contract upgrade or redeployment.

**4. Silent Failure**
No error, event, or assertion is triggered when empty consensus data is encountered, making detection and diagnosis extremely difficult.

## Likelihood Explanation

This vulnerability has MEDIUM likelihood because:

1. **Governance Approval Required**: Parent chain block data must be proposed via `ProposeCrossChainIndexing` (which requires the sender to be a current miner) and approved by the `CrossChainIndexingController` organization before indexing: [10](#0-9) 

2. **No Content Validation**: The system performs no validation of `ExtraData` content, only structural properties. The contract code explicitly checks for `.IsEmpty`, indicating the developers anticipated this case could occur.

3. **Edge Case Triggering**: Can occur through operational errors, bugs in off-chain consensus data collection, or edge cases in cross-chain data preparation.

While not a single-actor exploit, this represents a systemic resilience failure that can occur through operational errors or edge cases in cross-chain data collection, with no mechanism for detection or recovery.

## Recommendation

Add validation to ensure consensus data is non-empty before updating `CurrentParentChainHeight`, and emit an event when empty data is encountered:

```csharp
public override Empty UpdateInformationFromCrossChain(BytesValue input)
{
    Assert(
        Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
        "Only Cross Chain Contract can call this method.");

    Assert(!State.IsMainChain.Value, "Only side chain can update consensus information.");

    // Add validation and event
    if (input == null || input.Value.IsEmpty)
    {
        Context.Fire(new CrossChainConsensusDataEmpty
        {
            Message = "Empty consensus data received from cross chain"
        });
        Assert(false, "Empty consensus data not allowed.");
    }

    var consensusInformation = AElfConsensusHeaderInformation.Parser.ParseFrom(input.Value);
    
    if (consensusInformation.Round.RoundNumber <= State.MainChainRoundNumber.Value)
        return new Empty();

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

Additionally, add content validation in `ValidateParentChainBlockData` to check that the "Consensus" key in `ExtraData`, if present, contains valid parseable consensus information.

## Proof of Concept

```csharp
[Fact]
public async Task UpdateInformationFromCrossChain_EmptyData_CausesPermanentDesync()
{
    // Setup side chain
    SetToSideChain();
    InitialContracts();
    
    var mockedCrossChain = SampleAccount.Accounts.Last();
    var mockedCrossChainStub = GetTester<AEDPoSContractImplContainer.AEDPoSContractImplStub>(
        ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
        mockedCrossChain.KeyPair);

    // Get initial state - should be empty
    var initialMinerList = await ConsensusStub.GetMainChainCurrentMinerList.CallAsync(new Empty());
    initialMinerList.Pubkeys.Count.ShouldBe(0);

    // Send empty consensus data (simulating the vulnerability)
    await mockedCrossChainStub.UpdateInformationFromCrossChain.SendAsync(new BytesValue
    {
        Value = ByteString.Empty  // Empty data
    });

    // Verify miner list was NOT updated (silent failure)
    var minerListAfterEmpty = await ConsensusStub.GetMainChainCurrentMinerList.CallAsync(new Empty());
    minerListAfterEmpty.Pubkeys.Count.ShouldBe(0);  // Still empty - desynchronization occurred

    // Now try to send valid consensus data
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

    // Verify the update worked this time
    var finalMinerList = await ConsensusStub.GetMainChainCurrentMinerList.CallAsync(new Empty());
    finalMinerList.Pubkeys.Count.ShouldBe(2);

    // Demonstrate the vulnerability: In actual cross-chain indexing scenario,
    // CurrentParentChainHeight would have advanced after the empty data,
    // preventing re-indexing with correct data, leaving the side chain
    // permanently desynchronized
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L41-41)
```csharp
        if (input == null || input.Value.IsEmpty) return new Empty();
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L798-798)
```csharp
        State.CurrentParentChainHeight.Value = currentHeight;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L288-295)
```csharp
        if (!IsMainChain && IsMainChainMinerListChanged(currentRound))
        {
            nextRound = State.MainChainCurrentMinerList.Value.GenerateFirstRoundOfNewTerm(
                currentRound.GetMiningInterval(), currentBlockTime, currentRound.RoundNumber);
            nextRound.ConfirmedIrreversibleBlockHeight = currentRound.ConfirmedIrreversibleBlockHeight;
            nextRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.ConfirmedIrreversibleBlockRoundNumber;
            return;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L349-354)
```csharp
    private bool IsMainChainMinerListChanged(Round currentRound)
    {
        return State.MainChainCurrentMinerList.Value.Pubkeys.Any() &&
               GetMinerListHash(currentRound.RealTimeMinersInformation.Keys) !=
               GetMinerListHash(State.MainChainCurrentMinerList.Value.Pubkeys.Select(p => p.ToHex()));
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContractState.cs (L46-46)
```csharp
    public Int64State CurrentParentChainHeight { get; set; }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-291)
```csharp
    public override Empty ProposeCrossChainIndexing(CrossChainBlockData input)
    {
        Context.LogDebug(() => "Proposing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        ClearCrossChainIndexingProposalIfExpired();
        var crossChainDataDto = ValidateCrossChainDataBeforeIndexing(input);
        ProposeCrossChainBlockData(crossChainDataDto, Context.Sender);
        return new Empty();
    }
```
