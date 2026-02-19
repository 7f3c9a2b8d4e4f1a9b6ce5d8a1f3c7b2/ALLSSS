### Title
Non-Deterministic Merkle Tree Node Ordering Breaks Cross-Chain Transaction Verification

### Summary
The `ComputeRootWithMultiHash` function constructs order-dependent merkle trees from multiple side chain block data, but the ordering of nodes is controlled by miners without any canonical ordering enforcement. Different miners can use different orderings for the same set of side chains at different parent chain heights, causing merkle proofs to become invalid and breaking cross-chain transaction verification for legitimate transactions.

### Finding Description

The vulnerability exists in the cross-chain indexing and verification flow spanning multiple functions: [1](#0-0) 

The `ComputeRootWithMultiHash` function uses `BinaryMerkleTree.FromLeafNodes` which constructs an order-dependent merkle tree: [2](#0-1) 

The merkle tree hashing uses concatenation (not commutative): [3](#0-2) 

This means `hash(A, B) ≠ hash(B, A)`, so different orderings produce different merkle roots.

The ordering of nodes comes from `SideChainBlockDataList` populated in `RecordCrossChainData`: [4](#0-3) 

The function iterates over `chainIdList` in the provided order (line 312), and this ordering is passed directly from the miner's input: [5](#0-4) 

The `ReleaseCrossChainIndexingProposal` method accepts `chainIdList` as a caller-provided parameter without any validation or sorting to enforce canonical ordering. Only miners can call this method: [6](#0-5) 

The computed merkle root is then used for cross-chain transaction verification: [7](#0-6) 

For side chains, this calls `GetSideChainMerkleTreeRoot` which aggregates ALL side chain data at that parent height: [8](#0-7) 

**Root Cause**: There is no enforcement of deterministic, canonical ordering when multiple side chains are indexed at the same parent chain height. Different miners may naturally choose different orderings (e.g., by chain ID, by proposal approval order, by submission time, etc.).

### Impact Explanation

**Harm that occurs:**
- Cross-chain transaction verification fails for legitimate transactions when users' merkle proofs assume a different ordering than what was actually stored
- Users cannot reliably pre-compute merkle proofs without querying the exact stored ordering after indexing completes
- Cross-chain functionality becomes unreliable and unpredictable across different parent chain heights

**Protocol damage:**
- Denial of Service of cross-chain verification mechanism
- Erosion of trust in cross-chain bridges when legitimate transactions fail verification
- Operational failures requiring users to constantly query and regenerate proofs

**Who is affected:**
- All users attempting cross-chain transaction verification when multiple side chains have blocks indexed at the same parent height
- Side chain operators relying on consistent verification behavior
- DApps building on cross-chain functionality

**Severity justification:** HIGH
- Breaks a critical invariant: cross-chain proof verification integrity
- No malicious intent required - different miners using different implementations could naturally cause this
- Affects core cross-chain functionality in multi-side-chain deployments
- Operational impact is significant and unavoidable in active multi-chain environments

### Likelihood Explanation

**Attacker capabilities:**
- Requires miner privileges to call `ReleaseCrossChainIndexingProposal`
- In AElf's consensus, miners rotate based on the consensus mechanism, so any miner in the validator set can trigger this
- No additional privileges beyond normal miner operation needed

**Attack complexity:**
- Very low - simply provide `chainIdList` in a different order than other miners
- No sophisticated exploit logic required
- Can happen accidentally without malicious intent

**Feasibility conditions:**
- Multiple side chains must have blocks to index at the same parent chain height (common in active multi-chain deployment)
- Different miners must use different ordering preferences (highly likely across diverse miner implementations)

**Detection/operational constraints:**
- Difficult to detect as each individual transaction is valid
- Appears as legitimate miner behavior
- Users only discover the issue when their proofs fail

**Probability reasoning:**
- HIGH probability in production multi-side-chain environments
- As the number of side chains grows, the probability increases (N! possible orderings for N chains)
- Even without malicious actors, implementation differences naturally cause this

### Recommendation

**Code-level mitigation:**

1. Enforce canonical ordering before calling `RecordCrossChainData` in `ReleaseCrossChainIndexingProposal`:

```csharp
public override Empty ReleaseCrossChainIndexingProposal(ReleaseCrossChainIndexingProposalInput input)
{
    Context.LogDebug(() => "Releasing cross chain data..");
    EnsureTransactionOnlyExecutedOnceInOneBlock();
    AssertAddressIsCurrentMiner(Context.Sender);
    Assert(input.ChainIdList.Count > 0, "Empty input not allowed.");
    
    // ADDED: Sort chain IDs to ensure deterministic ordering
    var sortedChainIdList = input.ChainIdList.OrderBy(x => x).ToList();
    
    ReleaseIndexingProposal(sortedChainIdList);
    RecordCrossChainData(sortedChainIdList);
    return new Empty();
}
```

2. Add similar sorting in `RecordCrossChainData` as defense-in-depth:

```csharp
private void RecordCrossChainData(IEnumerable<int> chainIdList)
{
    // ADDED: Ensure consistent ordering
    var orderedChainIdList = chainIdList.OrderBy(x => x).ToList();
    
    var indexedSideChainBlockData = new IndexedSideChainBlockData();
    foreach (var chainId in orderedChainIdList)
    {
        // ... rest of the function
    }
}
```

**Invariant checks to add:**
- Add assertion in tests that merkle root computation is order-independent for the same set of data or that ordering is always canonical
- Document the expected canonical ordering (sorted by chain ID ascending)

**Test cases to prevent regression:**
- Test with multiple side chains indexed at same parent height
- Verify merkle root is identical regardless of input ordering
- Test that verification succeeds with proofs computed using the canonical ordering

### Proof of Concept

**Required initial state:**
- Parent chain with two side chains (chainId=1000 and chainId=2000) both active
- Both side chains have blocks ready to be indexed at parent chain height 100

**Transaction steps:**

1. Miner A calls `ReleaseCrossChainIndexingProposal` at parent height 100 with `chainIdList=[1000, 2000]`
   - `RecordCrossChainData` stores `SideChainBlockDataList=[block1000, block2000]`
   - Merkle root R1 = `ComputeRootWithMultiHash([root1000, root2000])`

2. User creates merkle proof P1 for a transaction in side chain 1000, assuming ordering [1000, 2000]

3. At parent height 200, both side chains again have blocks to index

4. Miner B calls `ReleaseCrossChainIndexingProposal` at parent height 200 with `chainIdList=[2000, 1000]`
   - `RecordCrossChainData` stores `SideChainBlockDataList=[block2000, block1000]`
   - Merkle root R2 = `ComputeRootWithMultiHash([root2000, root1000])`

5. User creates merkle proof P2 for a transaction in side chain 1000, assuming ordering [1000, 2000] (same as before)

**Expected vs actual result:**
- Expected: Proof P2 verifies successfully because it's a legitimate transaction
- Actual: Proof P2 fails verification because `GetSideChainMerkleTreeRoot(200)` returns R2 which was computed with ordering [2000, 1000], but P2 was constructed assuming [1000, 2000]

**Success condition:**
- R1 ≠ R2 (different merkle roots for different orderings)
- Verification with proof constructed for one ordering fails when the stored ordering is different
- This can be confirmed by checking the test that shows ordering matters: [9](#0-8) 

### Notes

The vulnerability stems from an architectural oversight where order-dependent merkle tree construction is combined with non-deterministic ordering of input data. While the merkle tree itself correctly preserves ordering (which is cryptographically sound), the lack of canonical ordering at the application layer breaks the verification mechanism. This is particularly problematic because the ordering is visible only through explicit queries after indexing, making it difficult for users to construct valid proofs proactively.

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L42-45)
```csharp
    private Hash ComputeRootWithMultiHash(IEnumerable<Hash> nodes)
    {
        return BinaryMerkleTree.FromLeafNodes(nodes).Root;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L241-246)
```csharp
    private Hash GetSideChainMerkleTreeRoot(long parentChainHeight)
    {
        var indexedSideChainData = State.IndexedSideChainBlockData[parentChainHeight];
        return ComputeRootWithMultiHash(
            indexedSideChainData.SideChainBlockDataList.Select(d => d.TransactionStatusMerkleTreeRoot));
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

**File:** src/AElf.Types/Types/BinaryMerkleTree.cs (L32-60)
```csharp
        private static void GenerateBinaryMerkleTreeNodesWithLeafNodes(IList<Hash> leafNodes)
        {
            if (!leafNodes.Any()) return;

            if (leafNodes.Count % 2 == 1)
                leafNodes.Add(leafNodes.Last());
            var nodeToAdd = leafNodes.Count / 2;
            var newAdded = 0;
            var i = 0;
            while (i < leafNodes.Count - 1)
            {
                var left = leafNodes[i++];
                var right = leafNodes[i++];
                leafNodes.Add(HashHelper.ConcatAndCompute(left, right));
                if (++newAdded != nodeToAdd)
                    continue;

                // complete this row
                if (nodeToAdd % 2 == 1 && nodeToAdd != 1)
                {
                    nodeToAdd++;
                    leafNodes.Add(leafNodes.Last());
                }

                // start a new row
                nodeToAdd /= 2;
                newAdded = 0;
            }
        }
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L74-78)
```csharp
        public static Hash ConcatAndCompute(Hash hash1, Hash hash2)
        {
            var bytes = ByteArrayHelper.ConcatArrays(hash1.ToByteArray(), hash2.ToByteArray());
            return ComputeFrom(bytes);
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

**File:** test/AElf.CrossChain.Core.Tests/Indexing/CrossChainIndexingDataServiceTests.cs (L706-709)
```csharp
        var merkleTreeRoot = BinaryMerkleTree
            .FromLeafNodes(list1.Concat(list2).Concat(list3).Select(sideChainBlockData =>
                sideChainBlockData.TransactionStatusMerkleTreeRoot)).Root;
        var expected = new CrossChainExtraData { TransactionStatusMerkleTreeRoot = merkleTreeRoot }.ToByteString();
```
