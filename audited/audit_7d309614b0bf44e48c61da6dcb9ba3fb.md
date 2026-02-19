### Title
Missing Merkle Path Structural Validation Allows Malicious Miners to DoS Cross-Chain Operations

### Summary
The `ValidateParentChainBlockData()` function in CrossChainContract_Helper.cs only checks if merkle paths already exist (duplicate detection) but never validates the paths themselves are structurally well-formed. A malicious miner can inject empty or malformed merkle paths that pass on-chain validation, causing all subsequent cross-chain transaction verifications to fail, resulting in complete denial-of-service of cross-chain operations.

### Finding Description
The vulnerability exists in the `ValidateParentChainBlockData()` function where lines 731-734 only check for duplicate merkle paths: [1](#0-0) 

This validation only ensures that merkle paths haven't been indexed before, but performs no structural validation such as:
- Checking if merkle paths are non-empty
- Validating merkle path nodes are well-formed
- Ensuring path nodes contain valid hashes

The malformed paths are then directly stored without validation: [2](#0-1) 

When these stored paths are later used for cross-chain transaction verification, the `ComputeRootWithLeafNode` function simply iterates through nodes without validation: [3](#0-2) 

If the merkle path is empty (no nodes), the function returns just the leaf hash directly. If nodes are malformed, the computed root will be incorrect. Either way, legitimate cross-chain transactions will fail verification: [4](#0-3) 

The root cause is that on-chain validation relies entirely on off-chain validation without implementing defense-in-depth. While miners undergo off-chain validation that compares data against cached parent chain data: [5](#0-4) 

A malicious miner with modified node software can bypass this off-chain check and submit malformed data directly through the `ProposeCrossChainIndexing` entry point: [6](#0-5) 

### Impact Explanation
**Critical Cross-Chain DoS**: If a malicious miner submits parent chain block data with empty or malformed merkle paths, all cross-chain transactions that depend on those paths for verification will fail. This causes complete denial-of-service of cross-chain operations for affected block heights.

**Irreversible State Corruption**: Once malformed merkle paths are stored in contract state, there is no mechanism to correct them without governance intervention. The binding is permanent: [7](#0-6) 

**Protocol Integrity Violation**: Cross-chain verification is a critical security invariant. The inability to verify legitimate transactions breaks the fundamental trust model between parent and side chains, potentially freezing cross-chain assets and operations indefinitely.

**Widespread Impact**: All users attempting cross-chain operations during the affected block range are impacted, including token transfers, data synchronization, and any other cross-chain dependent functionality.

### Likelihood Explanation
**Attacker Profile**: Requires a malicious or compromised miner who can call `ProposeCrossChainIndexing`, which is restricted to current miners: [8](#0-7) 

**Attack Complexity**: Low. A malicious miner simply needs to:
1. Modify their node to bypass off-chain validation
2. Craft `ParentChainBlockData` with valid chain ID, height, and merkle root
3. Include empty or malformed merkle paths in `IndexedMerklePath`
4. Submit via `ProposeCrossChainIndexing`

The on-chain validation will pass because it only checks for duplicates, not structure.

**Feasibility**: While miners are trusted consensus participants, the lack of on-chain structural validation creates a single point of failure. If any miner becomes compromised or malicious (economic incentive, security breach, or Byzantine behavior), the attack is immediately executable.

**Detection Difficulty**: The attack would be detected when legitimate users attempt cross-chain transactions and verification fails. However, by that time the malformed data is already permanently stored on-chain.

### Recommendation
Add structural validation to the `ValidateParentChainBlockData()` function immediately after the duplicate check:

```csharp
if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
        State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
        State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
    return false;

// Add structural validation for merkle paths
foreach (var indexedBlockInfo in blockData.IndexedMerklePath)
{
    var merklePath = indexedBlockInfo.Value;
    
    // Reject null paths
    Assert(merklePath != null, "Merkle path cannot be null.");
    
    // Allow empty paths only for genesis block (height 1)
    if (indexedBlockInfo.Key > 1)
        Assert(merklePath.MerklePathNodes.Count > 0, 
            $"Merkle path for height {indexedBlockInfo.Key} cannot be empty.");
    
    // Validate each node in the path
    foreach (var node in merklePath.MerklePathNodes)
    {
        Assert(node != null, "Merkle path node cannot be null.");
        Assert(node.Hash != null && node.Hash.Value.Length == 32, 
            "Merkle path node hash must be valid 32-byte hash.");
    }
}
```

Additionally, add comprehensive test cases covering:
- Empty merkle path rejection
- Null node rejection  
- Invalid hash length rejection
- Valid merkle path acceptance

### Proof of Concept
**Initial State:**
- Side chain initialized with parent chain ID 123
- Current parent chain height is 10
- Miner has consensus permission

**Attack Steps:**

1. Malicious miner creates `ParentChainBlockData`:
   - ChainId: 123 (valid)
   - Height: 11 (sequential)
   - TransactionStatusMerkleTreeRoot: <valid_hash> (valid)
   - IndexedMerklePath: {1: <empty_merkle_path>} (malformed - empty nodes)

2. Miner calls `ProposeCrossChainIndexing(crossChainBlockData)`

3. On-chain validation passes:
   - Chain ID matches ✓
   - Height is sequential ✓
   - Merkle root not null ✓
   - No duplicates ✓
   - **Missing: Structural validation** ✗

4. Malformed path stored at height 1

5. User attempts cross-chain transaction verification:
   - Calls `VerifyTransaction` with transaction from height 1
   - Retrieves empty merkle path from storage
   - `ComputeRootWithLeafNode` returns just leaf hash (incorrect)
   - Verification fails even for legitimate transaction

**Expected Result:** Validation should reject empty merkle paths

**Actual Result:** Empty merkle paths are accepted and stored, causing all subsequent verifications to fail

**Success Condition:** Cross-chain operations for affected heights become permanently non-functional

### Notes
The parent chain properly generates merkle paths using `BinaryMerkleTree.GenerateMerklePath()`: [9](#0-8) 

However, the on-chain validation does not verify that received paths match this expected structure. This creates a defense-in-depth failure where the contract trusts miner-provided data without validation, violating the principle that smart contracts should validate all inputs regardless of source trust level.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L731-734)
```csharp
            if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                    State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
                    State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
                return false;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L776-780)
```csharp
            foreach (var indexedBlockInfo in blockInfo.IndexedMerklePath)
            {
                BindParentChainHeight(indexedBlockInfo.Key, parentChainHeight);
                AddIndexedTxRootMerklePathInParentChain(indexedBlockInfo.Key, indexedBlockInfo.Value);
            }
```

**File:** src/AElf.Types/Extensions/MerklePathExtensions.cs (L9-14)
```csharp
        public static Hash ComputeRootWithLeafNode(this MerklePath path, Hash leaf)
        {
            return path.MerklePathNodes.Aggregate(leaf, (current, node) => node.IsLeftChildNode
                ? HashHelper.ConcatAndCompute(node.Hash, current)
                : HashHelper.ConcatAndCompute(current, node.Hash));
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

**File:** src/AElf.CrossChain.Core/Indexing/Application/CrossChainIndexingDataValidationService.cs (L161-166)
```csharp
            if (!parentChainBlockDataList[i].Equals(parentChainBlockData))
            {
                Logger.LogDebug(
                    $"Incorrect parent chain data. Parent chain height: {targetHeight}.");
                return false;
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

**File:** src/AElf.CrossChain.Core/Application/CrossChainResponseService.cs (L113-113)
```csharp
            var merklePath = binaryMerkleTree.GenerateMerklePath(i);
```
