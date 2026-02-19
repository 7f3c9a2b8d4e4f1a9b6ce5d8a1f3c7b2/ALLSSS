# Audit Report

## Title
Missing Cryptographic Verification of Parent Chain Block Data Enables Consensus Manipulation via ExtraData Injection

## Summary
The cross-chain indexing system lacks cryptographic verification of parent chain block data authenticity. The `ParentChainBlockData` structure contains no signature or proof fields, and validation only checks structural properties. This allows colluding parliament members to approve fabricated parent chain data containing malicious consensus information, enabling arbitrary miner list injection and complete side chain takeover.

## Finding Description

The vulnerability exists in the cross-chain data flow where parent chain consensus information is synchronized to side chains.

**Root Cause:** The `ParentChainBlockData` message structure defined in the protocol lacks any cryptographic authentication fields: [1](#0-0) 

The structure contains only structural fields (height, chain ID, merkle roots, extra data) but no signature, signer public key, or cryptographic proofs linking the data to verified parent chain state.

**Validation Inadequacy:** The `ValidateParentChainBlockData()` function performs only structural checks: [2](#0-1) 

This validation verifies chain ID matches, heights are sequential, and merkle roots are present, but performs zero cryptographic verification that the data originated from the legitimate parent chain.

**Exploitation Flow:**

1. **Proposal**: A malicious miner calls `ProposeCrossChainIndexing()` with fabricated `ParentChainBlockData`: [3](#0-2) 

The method only verifies the sender is a current miner and performs structural validation via `ValidateCrossChainDataBeforeIndexing()`.

2. **Post-Execution Validation**: After transaction execution, `CrossChainIndexingDataProposedLogEventProcessor` performs cache comparison: [4](#0-3) 

However, this validation:
- Occurs after transaction execution (proposal already created)
- Can be bypassed if attackers control the gRPC communication to poison the cache
- Can be disabled via `CrossChainDataValidationIgnored` configuration
- Only affects automatic approval - parliament can still manually approve rejected proposals

3. **Parliament Approval**: With sufficient colluding miners meeting the default thresholds: [5](#0-4) 

The proposal receives the required 66.67% approval despite containing fabricated data.

4. **Release and Indexing**: When released, `RecordCrossChainData()` calls `IndexParentChainBlockData()`: [6](#0-5) [7](#0-6) 

5. **Consensus Injection**: The malicious consensus data from `ExtraData[ConsensusExtraDataName]` is extracted and forwarded: [8](#0-7) 

6. **Miner List Update**: The consensus contract's `UpdateInformationFromCrossChain()` only verifies the caller is the CrossChain contract, then blindly updates the miner list: [9](#0-8) 

The method parses the injected bytes as `AElfConsensusHeaderInformation` and directly updates `State.MainChainCurrentMinerList.Value` without any verification of data authenticity.

## Impact Explanation

**Consensus Takeover**: Attackers gain complete control over the side chain's miner list by injecting arbitrary public keys via crafted `Round.RealTimeMinersInformation`. This allows them to dictate block production, transaction inclusion, and all governance decisions.

**Token Theft**: The `DistributeResourceTokensToPreviousMiners()` function distributes accumulated resource tokens to addresses in the injected miner list: [10](#0-9) 

This enables direct theft of accumulated transaction fees and rental tokens.

**Irreversible Compromise**: Once the malicious miner list is active, attackers control all subsequent blocks and can perpetuate their control indefinitely, effectively capturing the entire side chain.

## Likelihood Explanation

**Attack Requirements**: 
- **Scenario A (Pure Governance)**: Requires corrupting 66.67% of parliament members to manually approve proposals that fail cache validation
- **Scenario B (Network + Governance)**: Requires controlling gRPC communication to poison the cache with fake data, then standard approval process proceeds automatically

**Feasibility**: MEDIUM-HIGH
- Parliament corruption threshold is significant but achievable for high-value targets
- Economic incentive is strong: complete side chain control + accumulated token balances
- Technical execution is straightforward once governance threshold is met
- No cryptographic barriers exist once governance is compromised

**Detection Difficulty**: The malicious updates appear legitimate since they pass all structural checks and have proper governance approval. Detection requires manual comparison against actual parent chain state.

## Recommendation

Implement cryptographic verification of parent chain block data:

1. **Add Signature Fields to ParentChainBlockData**: Include block producer signature and public key in the protobuf definition

2. **Verify Block Signatures**: In `ValidateParentChainBlockData()`, verify that:
   - The signature in the parent chain block data is valid
   - The signer public key matches a known parent chain miner
   - The signature covers all critical fields including `ExtraData`

3. **Implement Merkle Proof Verification**: Link parent chain block data to a verified parent chain state root that the side chain maintains and updates through the cross-chain indexing process

4. **Enforce Verification in Contract**: Update `IndexParentChainBlockData()` to require successful cryptographic verification before extracting consensus data

This ensures that even with corrupted governance, attackers cannot inject fabricated parent chain data without valid cryptographic proofs from the legitimate parent chain.

## Proof of Concept

A complete test demonstrating this vulnerability would require:

1. Setting up a side chain with test parliament members
2. Creating fabricated `ParentChainBlockData` with malicious consensus bytes in `ExtraData`
3. Calling `ProposeCrossChainIndexing()` from a miner account
4. Having colluding parliament members approve the proposal
5. Releasing the proposal via `ReleaseCrossChainIndexingProposal()`
6. Verifying the malicious miner list is now active in `State.MainChainCurrentMinerList`
7. Confirming token distribution goes to attacker-controlled addresses

The test would demonstrate that no cryptographic verification prevents this attack path, and governance approval alone is sufficient to inject arbitrary consensus data.

### Citations

**File:** protobuf/acs7.proto (L109-122)
```text
message ParentChainBlockData {
    // The height of parent chain.
    int64 height = 1;
    // The merkle tree root computing from side chain roots.
    CrossChainExtraData cross_chain_extra_data = 2;
    // The parent chain id.
    int32 chain_id = 3;
    // The merkle tree root computing from transactions status in parent chain block.
    aelf.Hash transaction_status_merkle_tree_root = 4;
    // Indexed block height from side chain and merkle path for this side chain block
    map<int64, aelf.MerklePath> indexed_merkle_path = 5;
    // Extra data map.
    map<string, bytes> extra_data = 6;
}
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L309-336)
```csharp
    private void RecordCrossChainData(IEnumerable<int> chainIdList)
    {
        var indexedSideChainBlockData = new IndexedSideChainBlockData();
        foreach (var chainId in chainIdList)
        {
            var pendingProposalExists = TryGetIndexingProposalWithStatus(chainId,
                CrossChainIndexingProposalStatus.Pending,
                out var pendingCrossChainIndexingProposal);
            Assert(pendingProposalExists, "Chain indexing not proposed.");

            if (chainId == State.ParentChainId.Value)
                IndexParentChainBlockData(pendingCrossChainIndexingProposal.ProposedCrossChainBlockData
                    .ParentChainBlockDataList);
            else
                indexedSideChainBlockData.SideChainBlockDataList.Add(IndexSideChainBlockData(
                    pendingCrossChainIndexingProposal.ProposedCrossChainBlockData.SideChainBlockDataList,
                    pendingCrossChainIndexingProposal.Proposer, chainId));

            SetCrossChainIndexingProposalStatus(pendingCrossChainIndexingProposal,
                CrossChainIndexingProposalStatus.Accepted);
        }

        if (indexedSideChainBlockData.SideChainBlockDataList.Count > 0)
        {
            State.IndexedSideChainBlockData.Set(Context.CurrentHeight, indexedSideChainBlockData);
            Context.Fire(new SideChainBlockDataIndexed());
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L293-302)
```csharp
    public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
    {
        Context.LogDebug(() => "Releasing cross chain data..");
        EnsureTransactionOnlyExecutedOnceInOneBlock();
        AssertAddressIsCurrentMiner(Context.Sender);
        Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
        ReleaseIndexingProposal(input.ChainIdList);
        RecordCrossChainData(input.ChainIdList);
        return new Empty();
    }
```

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataProposedLogEventProcessor.cs (L71-84)
```csharp
                var validationResult =
                    await _crossChainIndexingDataValidationService.ValidateCrossChainIndexingDataAsync(
                        crossChainBlockData,
                        block.GetHash(), block.Height);
                if (validationResult)
                {
                    Logger.LogDebug(
                        $"Valid cross chain indexing proposal found, block height {block.Height}, block hash {block.GetHash()} ");
                    var proposalId = crossChainIndexingDataProposedEvent.ProposalId ?? ProposalCreated.Parser
                        .ParseFrom(transactionResult.Logs
                            .First(l => l.Name == nameof(ProposalCreated)).NonIndexed)
                        .ProposalId;
                    _proposalService.AddNotApprovedProposal(proposalId, block.Height);
                }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Constants.cs (L8-11)
```csharp
    private const int DefaultMinimalApprovalThreshold = 6667;
    private const int DefaultMaximalAbstentionThreshold = 1000;
    private const int DefaultMaximalRejectionThreshold = 1000;
    private const int DefaultMinimalVoteThresholdThreshold = 6667;
```

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
