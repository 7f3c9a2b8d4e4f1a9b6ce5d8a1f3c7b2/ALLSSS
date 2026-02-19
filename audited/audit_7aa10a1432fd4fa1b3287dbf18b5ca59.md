### Title
Incomplete Validation Allows Null MerklePath Indexing Leading to Permanent Cross-Chain Verification DoS

### Summary
The `ValidateParentChainBlockData` function fails to validate that MerklePath values in `IndexedMerklePath` are non-null, allowing a malicious miner to propose parent chain data containing null merkle paths. Once governance-approved and indexed, this creates an irreversible inconsistent state where `ChildHeightToParentChainHeight` is set but `TxRootMerklePathInParentChain` remains null, permanently breaking cross-chain verification queries for affected side chain heights.

### Finding Description

The vulnerability exists in the validation logic that processes parent chain block data proposals: [1](#0-0) 

This validation checks whether heights are already indexed but **never validates that the proposed MerklePath values (`indexedBlockInfo.Value`) are non-null**. It only checks if the key (height) is already bound or has an existing merkle path stored.

When the data passes validation and gets indexed, both state variables are set from the same source: [2](#0-1) 

The `AddIndexedTxRootMerklePathInParentChain` function accepts null values without validation: [3](#0-2) 

If `path` is null, it passes the assertion (since `existing` is also null for new entries) and stores the null value. This creates an inconsistent state where `ChildHeightToParentChainHeight` contains a non-zero parent chain height, but `TxRootMerklePathInParentChain` contains null for the same side chain height.

Later, when querying this data: [4](#0-3) 

The assertion at line 24 fails because `merklePath` is null, causing the query to revert.

### Impact Explanation

**Operational DoS with Permanent Damage:**
- Cross-chain merkle proof retrieval becomes permanently unavailable for affected side chain heights
- The `GetBoundParentChainHeightAndMerklePathByHeight` function fails with assertion error for any affected height
- Side chains cannot retrieve merkle paths needed to prove their blocks were indexed on the parent chain
- Cross-chain transaction verification is broken for affected heights

**Irreversibility:**
Once the inconsistent state is created, it cannot be corrected through normal re-indexing because the validation explicitly prevents indexing heights where `ChildHeightToParentChainHeight[height] != 0`, which would now evaluate to true. The damage is permanent without manual state intervention.

**Scope:**
Affects the core cross-chain infrastructure, breaking the trust and verification mechanism between parent and side chains. Multiple side chain heights could be compromised in a single malicious proposal.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Must be an authorized miner (enforced by `AssertAddressIsCurrentMiner`): [5](#0-4) 

- Must obtain governance approval from Parliament organization for the proposal: [6](#0-5) 

**Attack Complexity:**
Low - the attacker simply crafts a `ParentChainBlockData` message with null `MerklePath` values in the `IndexedMerklePath` map.

**Feasibility Conditions:**
- Requires a malicious or compromised miner
- Requires governance not detecting null values during proposal review (raw protobuf data may obscure this)
- Both conditions are realistic in adversarial scenarios

**Detection Constraints:**
Governance reviewers would need to inspect raw proposal data to notice null MerklePath values, which may not be part of standard review procedures.

**Probability Assessment:**
Medium-Low likelihood due to dual permission requirements (miner + governance), but the severe and permanent impact elevates the overall risk.

### Recommendation

**Code-Level Mitigation:**
Add explicit null validation in `ValidateParentChainBlockData`: [7](#0-6) 

Insert the following check at line 731-734:
```csharp
if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
        indexedBlockInfo.Value == null ||  // Add this null check
        State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
        State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
    return false;
```

**Invariant Check:**
Enforce that every MerklePath in `IndexedMerklePath` must be non-null before allowing the proposal to proceed.

**Test Case:**
Add a test that attempts to propose parent chain data with null MerklePath values and verifies that validation fails with appropriate error message.

### Proof of Concept

**Required Initial State:**
- Side chain created and active
- Parent chain initialized with `ParentChainId` set
- Current parent chain height at H

**Attack Sequence:**

1. **Malicious Miner Crafts Data:**
   ```csharp
   var parentChainBlockData = new ParentChainBlockData {
       Height = H + 1,
       ChainId = parentChainId,
       TransactionStatusMerkleTreeRoot = validHash
   };
   parentChainBlockData.IndexedMerklePath.Add(100, null); // Null MerklePath
   
   var crossChainBlockData = new CrossChainBlockData {
       ParentChainBlockDataList = { parentChainBlockData }
   };
   ```

2. **Propose:** Miner calls `ProposeCrossChainIndexing(crossChainBlockData)`
   - Passes authorization check (miner)
   - Passes validation (lines 731-734 don't check for null)
   - Proposal created and stored

3. **Governance Approves:** Parliament organization approves the proposal

4. **Release:** Miner calls `ReleaseCrossChainIndexingProposal({parentChainId})`
   - Proposal released
   - `IndexParentChainBlockData` executes
   - Sets `ChildHeightToParentChainHeight[100] = H + 1` (non-zero)
   - Sets `TxRootMerklePathInParentChain[100] = null`

5. **Verification DoS:** Any call to `GetBoundParentChainHeightAndMerklePathByHeight(100)`:
   - Retrieves `boundParentChainHeight = H + 1` (passes assertion at line 22)
   - Retrieves `merklePath = null`
   - **Fails assertion at line 24: `Assert(merklePath != null)`**
   - Transaction reverts with assertion failure

6. **Permanent Damage:** Attempts to re-index height 100:
   - Validation checks `ChildHeightToParentChainHeight[100] != 0` → true
   - Validation fails, preventing correction

**Success Condition:**
Cross-chain verification permanently broken for height 100, with no recovery path through standard contract operations.

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L455-463)
```csharp
    private void HandleIndexingProposal(Hash proposalId)
    {
        var crossChainIndexingController = GetCrossChainIndexingController();
        var proposal = GetCrossChainProposal(crossChainIndexingController, proposalId);
        Assert(proposal.ToBeReleased, "Not approved cross chain indexing proposal.");
        Context.SendInline(crossChainIndexingController.ContractAddress,
            nameof(AuthorizationContractContainer.AuthorizationContractReferenceState.Release),
            proposal.ProposalId); // release if ready
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L776-779)
```csharp
            foreach (var indexedBlockInfo in blockInfo.IndexedMerklePath)
            {
                BindParentChainHeight(indexedBlockInfo.Key, parentChainHeight);
                AddIndexedTxRootMerklePathInParentChain(indexedBlockInfo.Key, indexedBlockInfo.Value);
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L282-290)
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
```
