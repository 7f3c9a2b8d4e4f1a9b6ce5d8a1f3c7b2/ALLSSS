### Title
Parent Chain Reorganization Enables Verification of Invalid Cross-Chain Transactions

### Summary
The `VerifyTransaction` function in the CrossChain contract does not validate whether the parent chain height being verified remains at or below the parent chain's current Last Irreversible Block (LIB) height. After a parent chain reorganization, attackers can exploit stale merkle roots to verify fraudulent cross-chain transactions, enabling theft of tokens and unauthorized operations across chains.

### Finding Description

The vulnerability exists in the `VerifyTransaction` method which retrieves stored merkle roots without any freshness or finality validation: [1](#0-0) 

The function accepts any `ParentChainHeight` parameter and simply retrieves the previously stored merkle root for that height via `GetMerkleTreeRoot`. It performs NO validation that this height is still finalized on the parent chain. [2](#0-1) 

For parent chain verification, merkle roots are retrieved from state storage that was populated during the indexing process: [3](#0-2) 

These merkle roots are stored ONCE during indexing with no mechanism for updates or invalidation: [4](#0-3) 

The validation logic explicitly PREVENTS re-indexing of the same height, making stored merkle roots permanent: [5](#0-4) 

The contract state does NOT track the parent chain's current LIB height: [6](#0-5) 

Only `CurrentParentChainHeight` (highest indexed) and `ParentChainId` are tracked—there is no `ParentChainLibHeight` field.

This vulnerability is exploited through critical token operations. The token contract's `CrossChainVerify` helper adds no additional validation: [7](#0-6) 

It is used in `CrossChainReceiveToken` for receiving tokens from other chains: [8](#0-7) 

And in `CrossChainCreateToken` for creating tokens based on cross-chain data: [9](#0-8) 

While the system ensures only LIB blocks are transmitted during normal operation, there is no mechanism to detect or handle parent chain reorganizations AFTER blocks have been indexed. [10](#0-9) 

### Impact Explanation

**Direct Fund Impact:**
- Attackers can steal cross-chain transferred tokens by verifying fraudulent transactions using stale merkle roots after parent chain reorganizations
- Unauthorized minting of tokens on the side chain by exploiting invalidated parent chain block data
- Creation of fake tokens based on cross-chain data that is no longer valid on the parent chain

**Cross-Chain Integrity Breach:**
- Complete bypass of cross-chain transaction verification after parent chain consensus failures
- Acceptance of transactions that were never actually confirmed on the current parent chain state
- Corruption of cross-chain state synchronization

**Affected Operations:**
- `CrossChainReceiveToken`: Direct token theft by claiming transfers that never occurred
- `CrossChainCreateToken`: Creation of invalid tokens
- `RegisterCrossChainTokenContractAddress`: Registration of malicious token contracts

**Severity Justification:**
Critical severity due to direct theft potential and fundamental breach of cross-chain security guarantees. Once a parent chain reorganization occurs, all previously indexed blocks beyond the new LIB can be exploited for fraudulent verifications.

### Likelihood Explanation

**Attack Preconditions:**
1. Parent chain experiences a consensus failure, deep reorganization, or LIB regression (e.g., 51% attack, network partition, critical consensus bug)
2. Side chain has already indexed parent chain blocks at heights that are reorganized
3. After reorganization, those heights have different blocks with different merkle roots

**Attack Complexity:**
- LOW: Once parent chain reorganizes, exploitation requires only calling public view/action methods
- No special privileges required - `VerifyTransaction` is a view method callable by anyone
- `CrossChainReceiveToken` is a public action method
- Attacker needs to craft a merkle path matching the OLD (stale) merkle root

**Feasibility:**
- Parent chain consensus failures are LOW FREQUENCY but POSSIBLE events
- 51% attacks, network partitions, and consensus bugs have occurred in major blockchains
- Once reorganization occurs, the attack window remains open indefinitely since stale merkle roots are never invalidated
- Detection is difficult as the verification appears valid using stored contract state

**Economic Rationality:**
- Attack cost: Minimal after parent chain reorg occurs (just transaction fees)
- Potential gain: All cross-chain tokens that can be claimed using stale merkle roots
- Risk/reward ratio heavily favors attackers

### Recommendation

**Immediate Mitigation:**

1. Add parent chain LIB height tracking to contract state:
```
public Int64State ParentChainLibHeight { get; set; }
```

2. Update `IndexParentChainBlockData` to store the parent chain's LIB height when indexing:
```csharp
State.ParentChainLibHeight.Value = parentChainLibHeightAtIndexing;
```

3. Modify `VerifyTransaction` to validate the requested height is at or below recorded parent chain LIB:
```csharp
public override BoolValue VerifyTransaction(VerifyTransactionInput input)
{
    var parentChainHeight = input.ParentChainHeight;
    
    // NEW: Validate height is at or below parent chain LIB at time of indexing
    var parentChainLibHeight = State.ParentChainLibHeight.Value;
    Assert(parentChainHeight <= parentChainLibHeight, 
        $"Parent chain height {parentChainHeight} exceeds recorded LIB {parentChainLibHeight}");
    
    var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
    Assert(merkleTreeRoot != null, 
        $"Parent chain block at height {parentChainHeight} is not recorded.");
    var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);
    
    return new BoolValue { Value = merkleTreeRoot == rootCalculated };
}
```

4. Consider adding a mechanism to update parent chain LIB height periodically and invalidate merkle roots beyond new LIB if regression is detected.

**Invariant to Enforce:**
- Cross-chain verifications must only succeed for parent chain heights that remain finalized (at or below parent chain LIB)
- Merkle roots should be validated against current parent chain state freshness

**Test Cases:**
- Test scenario where parent chain LIB regresses and previously indexed blocks are no longer at LIB
- Verify that `VerifyTransaction` rejects verification attempts for heights beyond parent chain LIB
- Test that cross-chain token operations fail appropriately after parent chain reorganization

### Proof of Concept

**Initial State:**
1. Parent chain LIB is at height 100
2. Side chain has indexed parent chain blocks 1-100 with merkle roots R1-R100
3. `State.CurrentParentChainHeight.Value = 100`
4. `State.ParentChainTransactionStatusMerkleTreeRoot[95] = R95`

**Parent Chain Reorganization:**
1. Parent chain experiences consensus failure or 51% attack
2. Parent chain LIB regresses to height 90
3. Blocks 91-100 are reorganized with different content
4. Height 95 now has a different block with merkle root R95' (R95' ≠ R95)

**Exploitation Steps:**
1. Attacker crafts a fraudulent `CrossChainTransfer` transaction TX_FRAUD that was never actually executed on the current parent chain
2. Attacker computes a merkle path PATH_FRAUD such that `ComputeRootWithTransactionStatusMerklePath(TX_FRAUD.GetHash(), PATH_FRAUD) == R95` (the OLD stale root)
3. Attacker calls `CrossChainReceiveToken`:
   - `transferTransactionBytes` = TX_FRAUD
   - `parentChainHeight` = 95
   - `merklePath` = PATH_FRAUD
   - `fromChainId` = parent_chain_id

**Expected vs Actual Result:**
- **Expected (Secure)**: Verification should FAIL because height 95 is no longer at parent chain LIB or has a different merkle root
- **Actual (Vulnerable)**: Verification SUCCEEDS because `VerifyTransaction` retrieves stale R95 from storage and validates against it, without checking if height 95 is still finalized on the parent chain

**Success Condition:**
Attacker receives tokens that were never actually transferred from the parent chain, confirmed by:
- `State.Balances[attacker_address][symbol]` increases by the claimed amount
- `CrossChainReceived` event is fired with the fraudulent transaction
- `State.VerifiedCrossChainTransferTransaction[TX_FRAUD.GetHash()] = true`

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L236-239)
```csharp
    private Hash GetParentChainMerkleTreeRoot(long parentChainHeight)
    {
        return State.ParentChainTransactionStatusMerkleTreeRoot[parentChainHeight];
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L253-264)
```csharp
    private Hash GetMerkleTreeRoot(int chainId, long parentChainHeight)
    {
        if (chainId == State.ParentChainId.Value)
            // it is parent chain
            return GetParentChainMerkleTreeRoot(parentChainHeight);

        if (State.SideChainInfo[chainId] != null)
            // it is child chain
            return GetSideChainMerkleTreeRoot(parentChainHeight);

        return GetCousinChainMerkleTreeRoot(parentChainHeight);
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L731-734)
```csharp
            if (blockData.IndexedMerklePath.Any(indexedBlockInfo =>
                    State.ChildHeightToParentChainHeight[indexedBlockInfo.Key] != 0 ||
                    State.TxRootMerklePathInParentChain[indexedBlockInfo.Key] != null))
                return false;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L774-775)
```csharp
            State.ParentChainTransactionStatusMerkleTreeRoot[parentChainHeight] =
                blockInfo.TransactionStatusMerkleTreeRoot;
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContractState.cs (L46-48)
```csharp
    public Int64State CurrentParentChainHeight { get; set; }
    public Int32State ParentChainId { get; set; }
    public MappedState<long, Hash> ParentChainTransactionStatusMerkleTreeRoot { get; set; }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L488-488)
```csharp
        CrossChainVerify(originalTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L617-617)
```csharp
        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
```

**File:** src/AElf.CrossChain.Core/Extensions/LocalLibExtensions.cs (L13-15)
```csharp
        var chain = await blockchainService.GetChainAsync();
        if (chain.LastIrreversibleBlockHeight < height + CrossChainConstants.LibHeightOffsetForCrossChainIndex)
            return null;
```
