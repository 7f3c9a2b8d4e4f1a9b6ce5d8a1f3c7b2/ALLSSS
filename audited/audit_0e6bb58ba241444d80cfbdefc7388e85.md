# Audit Report

## Title
Cross-Chain Height Binding DOS via Unchecked Future Child Heights

## Summary
The cross-chain indexing system fails to validate that child chain heights in `IndexedMerklePath` are legitimate (e.g., not future heights beyond current chain state). A malicious miner can propose parent chain block data containing arbitrary future child heights which, if approved by parliament, permanently bind these heights to incorrect parent chain heights, causing irreversible denial-of-service for all cross-chain operations at those heights.

## Finding Description

The vulnerability exists in the cross-chain height binding flow through three interconnected flaws:

**Flaw 1: No Height Legitimacy Validation in BindParentChainHeight**

The `BindParentChainHeight` function only checks if a height is already bound, but performs no validation that the `childHeight` parameter represents a legitimate child chain block or is within reasonable bounds: [1](#0-0) 

The function simply asserts the height hasn't been bound before, then unconditionally stores the binding. There is no check comparing `childHeight` against `Context.CurrentHeight` or any validation that this height corresponds to an actual child chain block.

**Flaw 2: Insufficient Validation in ValidateParentChainBlockData**

The validation logic that processes parent chain block data only verifies that heights in `IndexedMerklePath` haven't been previously bound: [2](#0-1) 

This validation checks two conditions for each height in `IndexedMerklePath`:
1. The height hasn't been bound to a parent chain height before
2. The height doesn't have an existing merkle path

However, it never validates whether these heights are legitimate child chain heights (e.g., not exceeding the current child chain height).

**Flaw 3: Blind Binding During Indexing**

When parent chain block data is indexed, the system blindly binds all heights from `IndexedMerklePath` without additional verification: [3](#0-2) 

The `IndexParentChainBlockData` function iterates through all heights in the merkle path and calls `BindParentChainHeight` for each, with no validation layer between.

**Attack Flow:**

1. Attacker (who is a miner) calls `ProposeCrossChainIndexing` with malicious parent chain data containing future child heights (e.g., heights 10000-20000) in `IndexedMerklePath`: [4](#0-3) 

2. The only authorization check is that the caller must be a current miner: [5](#0-4) 

3. Parliament members vote on the proposal. Since there's no cryptographic way to verify the legitimacy of heights on-chain, they rely on off-chain validation which may be incomplete or skipped.

4. Once approved, the miner calls `ReleaseCrossChainIndexingProposal`, triggering `RecordCrossChainData` which calls `IndexParentChainBlockData`: [6](#0-5) 

5. The malicious future heights are now permanently bound to incorrect parent chain heights.

**Why No Recovery is Possible:**

The state variable `ChildHeightToParentChainHeight` is only ever assigned, never deleted or updated. This is the sole location where height bindings are written, and there's no mechanism to unbind or correct erroneous bindings.

## Impact Explanation

**Direct Harm:**

When applications need to perform cross-chain operations at the affected heights, they call `GetBoundParentChainHeightAndMerklePathByHeight`: [7](#0-6) 

This function retrieves the bound parent chain height and merkle path. For poisoned heights, it returns incorrect merkle paths that don't correspond to actual child chain blocks.

**Cascading Failures:**

Cross-chain token operations depend on correct merkle path verification. The `CrossChainVerify` helper is called by both `CrossChainReceiveToken` and `CrossChainCreateToken`: [8](#0-7) 

When verification is attempted with the incorrect merkle paths from poisoned heights, the `VerifyTransaction` call will fail, causing all cross-chain token transfers and creation operations at those heights to revert permanently.

**Quantified Impact:**
- **Permanence**: Affected heights can NEVER be corrected (no unbind mechanism exists)
- **Scope**: A single malicious proposal can poison hundreds or thousands of future heights
- **Breadth**: All cross-chain functionality breaks at affected heights: token transfers, transaction verification, state synchronization
- **Users Affected**: Any user attempting cross-chain operations from the poisoned height ranges

**Severity Justification: HIGH**
While this doesn't directly steal funds, it causes permanent, irreversible denial-of-service of critical cross-chain infrastructure. The inability to recover makes this a severe protocol integrity violation.

## Likelihood Explanation

**Attacker Prerequisites:**
1. Must be an active miner in the current consensus round
2. Must obtain parliament approval for the malicious proposal

**Attack Feasibility: MEDIUM-HIGH**

The attack is feasible because:

1. **Miner Status is Achievable**: While privileged, miner status can be obtained through the election process. A determined attacker can stake tokens and campaign to become a miner.

2. **Parliament Cannot Cryptographically Verify Heights**: Parliament members voting on proposals have no on-chain mechanism to verify that the child heights in `IndexedMerklePath` are legitimate. They must perform off-chain validation by manually comparing against actual parent chain indexing data, which is error-prone and may be skipped.

3. **Structurally Valid Data**: The malicious data passes all on-chain validation checks. It appears legitimate from a structural perspective (correct parent chain ID, sequential heights, non-null merkle roots, non-duplicate heights).

4. **Detection is Difficult**: The malicious binding only manifests as a problem when the affected heights are reached in the future, potentially months later. By then, identifying the source proposal and responsible parties becomes challenging.

**Probability Assessment:**
Given that parliament approval relies primarily on governance trust rather than cryptographic verification, and that miners have significant influence in the system, a coordinated attack by a malicious miner is practically feasible, especially if they control or influence some parliament votes.

## Recommendation

**Immediate Fix:**

Add validation in `ValidateParentChainBlockData` to ensure child heights in `IndexedMerklePath` don't exceed the current child chain height:

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
        
        // NEW VALIDATION: Check child heights are not in the future
        if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                indexedBlockInfo.Key > Context.CurrentHeight || // Reject future heights
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

**Additional Hardening:**

Consider adding an administrative function to unbind heights in emergency situations, callable only by a high-threshold governance organization. This provides a recovery mechanism if malicious data somehow gets through.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMiner_CanBindFutureHeights_CausingPermanentDOS()
{
    // Setup: Create a side chain and establish initial indexing
    var sideChainId = await GenerateSideChainAsync();
    
    // Current child chain height is low (e.g., 100)
    var currentChildHeight = Context.CurrentHeight; // Assume this is around 100
    
    // Attacker is a miner and proposes parent chain data with future child heights
    var maliciousParentChainBlockData = new ParentChainBlockData
    {
        ChainId = MainChainId,
        Height = GetCurrentParentChainHeight() + 1,
        TransactionStatusMerkleTreeRoot = HashHelper.ComputeFrom("fake_root"),
        IndexedMerklePath = 
        {
            // Attacker specifies child heights far in the future (e.g., 10000)
            { 10000, new MerklePath() },
            { 10001, new MerklePath() },
            { 10002, new MerklePath() }
        }
    };
    
    // Step 1: Miner proposes the malicious data
    var proposeResult = await SideChainCrossChainContractStub.ProposeCrossChainIndexing.SendAsync(
        new CrossChainBlockData 
        { 
            ParentChainBlockDataList = { maliciousParentChainBlockData } 
        });
    proposeResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 2: Parliament approves (simulated by mining to approval threshold)
    // In real scenario, attacker needs parliament votes
    
    // Step 3: Miner releases the proposal
    var releaseResult = await SideChainCrossChainContractStub.ReleaseCrossChainIndexingProposal.SendAsync(
        new ReleaseCrossChainIndexingProposalInput 
        { 
            ChainIdList = { MainChainId } 
        });
    releaseResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 4: Verify the future heights are now bound to wrong parent heights
    // Fast forward child chain to height 10000
    await MineBlocksAsync(10000 - currentChildHeight);
    
    // Step 5: Attempt cross-chain operation at poisoned height - should fail permanently
    var boundData = await SideChainCrossChainContractStub
        .GetBoundParentChainHeightAndMerklePathByHeight.CallAsync(new Int64Value { Value = 10000 });
    
    // The bound parent chain height is wrong (from the malicious proposal)
    // Any cross-chain token transfer will now fail verification
    var crossChainResult = await SideChainTokenContractStub.CrossChainReceiveToken.SendWithExceptionAsync(
        new CrossChainReceiveTokenInput 
        { 
            /* uses boundData.BoundParentChainHeight which is incorrect */ 
        });
    
    crossChainResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    crossChainResult.TransactionResult.Error.ShouldContain("Cross chain verification failed");
    
    // Step 6: Verify there is no way to fix this - height cannot be rebound
    // No function exists to unbind or correct the erroneous binding
    // The DOS is permanent
}
```

**Notes:**
- The vulnerability requires both miner status AND parliament approval, but this is achievable within the system's trust model
- Once heights are bound incorrectly, there is no recovery mechanism - the DOS is permanent
- The impact affects all cross-chain operations (token transfers, verification, state sync) at the poisoned heights
- Detection is difficult because malicious data appears structurally valid and damage only manifests when affected heights are reached

### Citations

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L27-32)
```csharp
    private void BindParentChainHeight(long childHeight, long parentHeight)
    {
        Assert(State.ChildHeightToParentChainHeight[childHeight] == 0,
            $"Already bound at height {childHeight} with parent chain");
        State.ChildHeightToParentChainHeight[childHeight] = parentHeight;
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L288-295)
```csharp
    private void AssertAddressIsCurrentMiner(Address address)
    {
        SetContractStateRequired(State.CrossChainInteractionContract,
            SmartContractConstants.ConsensusContractSystemName);
        var isCurrentMiner = State.CrossChainInteractionContract.CheckCrossChainIndexingPermission.Call(address)
            .Value;
        Assert(isCurrentMiner, "No permission.");
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L319-321)
```csharp
            if (chainId == State.ParentChainId.Value)
                IndexParentChainBlockData(pendingCrossChainIndexingProposal.ProposedCrossChainBlockData
                    .ParentChainBlockDataList);
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L236-250)
```csharp
    private void CrossChainVerify(Hash transactionId, long parentChainHeight, int chainId, MerklePath merklePath)
    {
        var verificationInput = new VerifyTransactionInput
        {
            TransactionId = transactionId,
            ParentChainHeight = parentChainHeight,
            VerifiedChainId = chainId,
            Path = merklePath
        };
        var address = Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName);

        var verificationResult = Context.Call<BoolValue>(address,
            nameof(ACS7Container.ACS7ReferenceState.VerifyTransaction), verificationInput);
        Assert(verificationResult.Value, "Cross chain verification failed.");
    }
```
