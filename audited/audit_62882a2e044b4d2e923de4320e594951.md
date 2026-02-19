### Title
Missing Merkle Path Validation Enables Cross-Chain Verification DoS

### Summary
The `ValidateParentChainBlockData` function checks only for duplicate merkle paths but never validates their structural integrity or correctness. [1](#0-0)  A compromised miner or buggy parent chain relay can inject malformed merkle paths that pass validation and get stored, permanently breaking cross-chain transaction verification for affected side chain heights.

### Finding Description

The validation function performs only duplication checks on merkle paths without verifying their structural validity: [2](#0-1) 

These unvalidated merkle paths are subsequently stored without any verification: [3](#0-2) 

The storage function also lacks validation: [4](#0-3) 

When legitimate users retrieve these malformed paths to prove their cross-chain transactions, [5](#0-4)  the paths fail to compute the correct merkle root, causing verification failures. [6](#0-5) 

The entry point is accessible by miners through the proposal mechanism: [7](#0-6) 

### Impact Explanation

**Concrete harm:** Malformed merkle paths prevent legitimate cross-chain transaction verification for affected side chain heights, completely breaking cross-chain interoperability for those blocks.

**Affected parties:** All users attempting cross-chain operations for side chain blocks whose merkle paths have been corrupted. This could permanently disable cross-chain functionality for entire height ranges.

**Protocol damage:** Cross-chain verification is a critical security invariant. [8](#0-7)  When users cannot prove their transactions were indexed in the parent chain, cross-chain token transfers, message passing, and all interoperability features become inoperable.

**Severity:** Medium-High. While this is a denial-of-service rather than theft, it targets a critical invariant (cross-chain proof verification) that the entire interoperability architecture depends on.

### Likelihood Explanation

**Attacker capabilities:** Requires miner role to propose parent chain data through `ProposeCrossChainIndexing`, plus governance approval from the CrossChainIndexingController organization. [9](#0-8) 

**Attack complexity:** Moderate. Attacker must either:
1. Collude with governance to approve malformed data, or
2. Exploit a bug in the parent chain data relay system that generates malformed paths

**Feasibility conditions:** The parent chain data relay mechanism generates merkle paths from indexed side chain blocks. [10](#0-9)  If this mechanism has bugs or is compromised, malformed paths propagate to the contract.

**Detection constraints:** Malformed paths may not be immediately obvious during governance review, as reviewers would need to cryptographically verify each path against the cross-chain merkle root.

**Probability:** Medium. While requiring miner + governance involvement reduces likelihood, bugs in complex cross-chain relay systems are realistic. Additionally, a malicious miner conducting a griefing attack could harm the chain's cross-chain functionality.

### Recommendation

**Code-level mitigation:** Add structural validation in `ValidateParentChainBlockData` before storing merkle paths:

1. Check each merkle path in `IndexedMerklePath` is not null
2. Verify `MerklePathNodes` list is not empty for multi-leaf trees
3. Validate path node hashes are not null/empty
4. If `CrossChainExtraData` is present, verify paths can theoretically compute to `CrossChainExtraData.TransactionStatusMerkleTreeRoot` (though full cryptographic verification requires side chain data not available at validation time)

**Invariant checks:** Assert that stored merkle paths have valid structure before any storage operation in `AddIndexedTxRootMerklePathInParentChain`.

**Test cases:** Add test cases verifying rejection of:
- Null merkle paths in `IndexedMerklePath`
- Empty `MerklePathNodes` lists
- Merkle paths with null hash values
- Parent chain block data with structurally invalid paths

### Proof of Concept

**Initial state:** Side chain connected to parent chain with active cross-chain indexing.

**Attack steps:**
1. Malicious miner crafts `ParentChainBlockData` with valid `TransactionStatusMerkleTreeRoot` but malformed `IndexedMerklePath` (e.g., null paths, empty nodes, or incorrect hash values)
2. Miner calls `ProposeCrossChainIndexing` with this malformed data
3. Governance organization approves the proposal (either maliciously or without detecting the malformation)
4. Another miner calls `ReleaseCrossChainIndexingProposal` to record the data
5. Malformed merkle paths are stored permanently in `State.TxRootMerklePathInParentChain`

**Expected result:** Validation should reject structurally invalid merkle paths.

**Actual result:** Malformed paths are stored successfully. When users call `GetBoundParentChainHeightAndMerklePathByHeight` for affected heights and attempt cross-chain verification, `ComputeRootWithLeafNode` produces incorrect roots, causing all verification attempts to fail permanently.

**Success condition:** Legitimate cross-chain transactions for affected side chain heights cannot be verified, demonstrating complete DoS of cross-chain functionality.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L34-40)
```csharp
    private Hash ComputeRootWithTransactionStatusMerklePath(Hash txId, MerklePath path)
    {
        var txResultStatusRawBytes =
            EncodingHelper.EncodeUtf8(TransactionResultStatus.Mined.ToString());
        var hash = HashHelper.ComputeFrom(ByteArrayHelper.ConcatArrays(txId.ToByteArray(), txResultStatusRawBytes));
        return path.ComputeRootWithLeafNode(hash);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L52-58)
```csharp
    private void AddIndexedTxRootMerklePathInParentChain(long height, MerklePath path)
    {
        var existing = State.TxRootMerklePathInParentChain[height];
        Assert(existing == null,
            $"Merkle path already bound at height {height}.");
        State.TxRootMerklePathInParentChain[height] = path;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L390-447)
```csharp
    private void ProposeCrossChainBlockData(CrossChainDataDto crossChainDataDto, Address proposer)
    {
        var crossChainIndexingController = GetCrossChainIndexingController();
        foreach (var chainId in crossChainDataDto.GetChainIdList())
        {
            Assert(!TryGetIndexingProposal(chainId, out _), "Chain indexing already proposed.");
            var proposalToken =
                HashHelper.ConcatAndCompute(Context.PreviousBlockHash, ConvertChainIdToHash(chainId));
            var proposalCreationInput = new CreateProposalBySystemContractInput
            {
                ProposalInput = new CreateProposalInput
                {
                    Params = new AcceptCrossChainIndexingProposalInput
                    {
                        ChainId = chainId
                    }.ToByteString(),
                    ContractMethodName = nameof(AcceptCrossChainIndexingProposal),
                    ExpiredTime =
                        Context.CurrentBlockTime.AddSeconds(CrossChainIndexingProposalExpirationTimePeriod),
                    OrganizationAddress = crossChainIndexingController.OwnerAddress,
                    ToAddress = Context.Self,
                    Token = proposalToken
                },
                OriginProposer = Context.Sender
            };

            Context.SendInline(crossChainIndexingController.ContractAddress,
                nameof(AuthorizationContractContainer.AuthorizationContractReferenceState
                    .CreateProposalBySystemContract), proposalCreationInput);

            var proposedCrossChainBlockData = new CrossChainBlockData();
            if (crossChainDataDto.ParentChainToBeIndexedData.TryGetValue(chainId,
                    out var parentChainToBeIndexedData))
                proposedCrossChainBlockData.ParentChainBlockDataList.Add(parentChainToBeIndexedData);
            else if (crossChainDataDto.SideChainToBeIndexedData.TryGetValue(chainId,
                         out var sideChainToBeIndexedData))
                proposedCrossChainBlockData.SideChainBlockDataList.Add(sideChainToBeIndexedData);

            var crossChainIndexingProposal = new ChainIndexingProposal
            {
                ChainId = chainId,
                Proposer = proposer,
                ProposedCrossChainBlockData = proposedCrossChainBlockData
            };
            var proposalId = Context.GenerateId(crossChainIndexingController.ContractAddress, proposalToken);
            crossChainIndexingProposal.ProposalId = proposalId;
            SetCrossChainIndexingProposalStatus(crossChainIndexingProposal,
                CrossChainIndexingProposalStatus.Pending);
            Context.Fire(new CrossChainIndexingDataProposedEvent
            {
                ProposedCrossChainData = proposedCrossChainBlockData,
                ProposalId = proposalId
            });

            Context.LogDebug(() =>
                $"Proposed cross chain data for chain {ChainHelper.ConvertChainIdToBase58(chainId)}");
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L776-780)
```csharp
            foreach (var indexedBlockInfo in blockInfo.IndexedMerklePath)
            {
                BindParentChainHeight(indexedBlockInfo.Key, parentChainHeight);
                AddIndexedTxRootMerklePathInParentChain(indexedBlockInfo.Key, indexedBlockInfo.Value);
            }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L19-30)
```csharp
    public override CrossChainMerkleProofContext GetBoundParentChainHeightAndMerklePathByHeight(Int64Value input)
    {
        var boundParentChainHeight = State.ChildHeightToParentChainHeight[input.Value];
        Assert(boundParentChainHeight != 0);
        var merklePath = State.TxRootMerklePathInParentChain[input.Value];
        Assert(merklePath != null);
        return new CrossChainMerkleProofContext
        {
            MerklePathFromParentChain = merklePath,
            BoundParentChainHeight = boundParentChainHeight
        };
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L37-46)
```csharp
    public override BoolValue VerifyTransaction(VerifyTransactionInput input)
    {
        var parentChainHeight = input.ParentChainHeight;
        var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
        Assert(merkleTreeRoot != null,
            $"Parent chain block at height {parentChainHeight} is not recorded.");
        var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);

        return new BoolValue { Value = merkleTreeRoot == rootCalculated };
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

**File:** src/AElf.CrossChain.Core/Application/CrossChainResponseService.cs (L96-118)
```csharp
    private Dictionary<long, MerklePath> GetEnumerableMerklePath(
        IList<SideChainBlockData> indexedSideChainBlockDataResult,
        int sideChainId)
    {
        var binaryMerkleTree = BinaryMerkleTree.FromLeafNodes(
            indexedSideChainBlockDataResult.Select(sideChainBlockData =>
                sideChainBlockData.TransactionStatusMerkleTreeRoot));

        // This is to tell side chain the merkle path for one side chain block,
        // which could be removed with subsequent improvement.
        var res = new Dictionary<long, MerklePath>();
        for (var i = 0; i < indexedSideChainBlockDataResult.Count; i++)
        {
            var info = indexedSideChainBlockDataResult[i];
            if (info.ChainId != sideChainId)
                continue;

            var merklePath = binaryMerkleTree.GenerateMerklePath(i);
            res.Add(info.Height, merklePath);
        }

        return res;
    }
```
