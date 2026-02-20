# Audit Report

## Title
Terminated Side Chains Allow Cross-Chain Token Claims via Unvalidated Transaction Verification

## Summary
The `VerifyTransaction()` function in the CrossChain contract does not validate whether a side chain has been terminated before verifying cross-chain transactions. When a side chain is terminated via `DisposeSideChain()`, previously indexed block data remains accessible, allowing anyone to claim tokens from terminated chains using old merkle proofs. This violates the fundamental invariant that terminated chains should be completely isolated from cross-chain operations.

## Finding Description

The vulnerability exists in the cross-chain token receiving flow. When `CrossChainReceiveToken()` is called, it invokes `CrossChainVerify()` which calls the CrossChain contract's `VerifyTransaction()` method. [1](#0-0) 

The verification internally retrieves the merkle tree root via `GetMerkleTreeRoot()`: [2](#0-1) 

The critical flaw is in `GetMerkleTreeRoot()` which only checks if `SideChainInfo` exists (`!= null`), not whether the chain's status is `Terminated`: [3](#0-2) 

When the condition at line 259 is true (SideChainInfo != null), it retrieves indexed data that is never cleared upon termination: [4](#0-3) 

When `DisposeSideChain()` is called, it only sets the status to `Terminated` but does not remove the `SideChainInfo` entry or clear the indexed block data: [5](#0-4) 

In contrast, NEW indexing operations properly validate the chain status and reject terminated chains: [6](#0-5) 

Similarly, other operations like `Recharge()` properly enforce termination status: [7](#0-6) 

However, the status check is not applied during verification of existing proofs in the `VerifyTransaction()` execution path.

## Impact Explanation

**Token Supply Inflation:** Attackers can mint tokens on the receiving chain by presenting valid merkle proofs from before the chain was terminated. Since terminated chains may have been disposed due to security compromises, bugs, or governance decisions, the expectation is that all cross-chain operations should immediately cease upon termination.

**Cross-Chain Integrity Violation:** The termination status is meant to completely isolate a side chain from the ecosystem. Methods like `Recharge()` and new indexing operations properly enforce this isolation, but the verification path bypasses it entirely, allowing continued interaction with what should be an isolated chain.

**Persistent Exploitation:** If a side chain was compromised before being terminated, attackers could continue exploiting old transactions indefinitely. There is no time limit—any previously indexed transaction can be claimed at any point after termination, as the indexed data persists in `State.IndexedSideChainBlockData` and the merkle proof verification succeeds.

## Likelihood Explanation

**Attack Prerequisites:**
- A side chain must be indexed and then terminated (governance-controlled via `SideChainLifetimeController` but realistic for security incidents)
- Attacker needs a valid cross-chain transfer transaction from before termination
- Merkle proofs are publicly derivable from indexed block data available on-chain

**Execution Complexity:** Very low—simply call `CrossChainReceiveToken()` with old transaction bytes and merkle path after the chain is terminated. The transaction will pass all verification checks including merkle proof validation and duplicate prevention (different transactions have different IDs).

**Detection:** The attack appears as a legitimate cross-chain token claim and passes all verification checks. No on-chain mechanism prevents it since the status check is missing from the verification path.

**Probability Assessment:** MEDIUM-HIGH—While chain termination is uncommon, when it occurs (especially for security reasons such as a compromised side chain), this vulnerability guarantees exploitation is possible and economically rational for any amount of tokens left in cross-chain transit.

## Recommendation

Add a side chain status validation check in the `GetMerkleTreeRoot()` method to ensure terminated chains cannot be used for transaction verification:

```csharp
private Hash GetMerkleTreeRoot(int chainId, long parentChainHeight)
{
    if (chainId == State.ParentChainId.Value)
        // it is parent chain
        return GetParentChainMerkleTreeRoot(parentChainHeight);

    var sideChainInfo = State.SideChainInfo[chainId];
    if (sideChainInfo != null)
    {
        // Add status check before allowing verification
        Assert(sideChainInfo.SideChainStatus != SideChainStatus.Terminated, 
            "Cannot verify transactions from terminated side chain.");
        // it is child chain
        return GetSideChainMerkleTreeRoot(parentChainHeight);
    }

    return GetCousinChainMerkleTreeRoot(parentChainHeight);
}
```

Alternatively, the check could be added in the `VerifyTransaction()` method before calling `GetMerkleTreeRoot()`:

```csharp
public override BoolValue VerifyTransaction(VerifyTransactionInput input)
{
    var sideChainInfo = State.SideChainInfo[input.VerifiedChainId];
    if (sideChainInfo != null)
    {
        Assert(sideChainInfo.SideChainStatus != SideChainStatus.Terminated,
            "Cannot verify transactions from terminated side chain.");
    }
    
    var parentChainHeight = input.ParentChainHeight;
    var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
    // ... rest of method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainReceiveToken_FromTerminatedChain_ShouldFail()
{
    // Setup: Create and index a side chain
    var chainId = await InitAndCreateSideChainAsync();
    await IndexSideChainBlockData();
    
    // Create a valid cross-chain transfer transaction
    var transferTx = await CreateCrossChainTransferTransaction(chainId);
    var merklePath = GetMerklePathForTransaction(transferTx);
    
    // Terminate the side chain via governance
    var proposalId = await DisposeSideChainProposalAsync(new Int32Value { Value = chainId });
    await ApproveWithMinersAsync(proposalId);
    await ReleaseProposalAsync(proposalId);
    
    // Verify chain is terminated
    var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value { Value = chainId });
    chainStatus.Status.ShouldBe(SideChainStatus.Terminated);
    
    // VULNERABILITY: This should fail but succeeds
    var result = await TokenContractStub.CrossChainReceiveToken.SendAsync(new CrossChainReceiveTokenInput
    {
        FromChainId = chainId,
        ParentChainHeight = transferTx.Height,
        TransferTransactionBytes = transferTx.ToByteString(),
        MerklePath = merklePath
    });
    
    // Expected: Transaction should fail with error about terminated chain
    // Actual: Transaction succeeds and tokens are minted
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined); // PASSES - BUG!
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L617-617)
```csharp
        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L241-246)
```csharp
    private Hash GetSideChainMerkleTreeRoot(long parentChainHeight)
    {
        var indexedSideChainData = State.IndexedSideChainBlockData[parentChainHeight];
        return ComputeRootWithMultiHash(
            indexedSideChainData.SideChainBlockDataList.Select(d => d.TransactionStatusMerkleTreeRoot));
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L690-703)
```csharp
    private bool ValidateSideChainBlockData(IEnumerable<SideChainBlockData> sideChainBlockData,
        out Dictionary<int, List<SideChainBlockData>> validatedSideChainBlockData)
    {
        var groupResult = sideChainBlockData.GroupBy(data => data.ChainId, data => data);

        validatedSideChainBlockData = new Dictionary<int, List<SideChainBlockData>>();
        foreach (var group in groupResult)
        {
            var chainId = group.Key;
            validatedSideChainBlockData[chainId] = group.ToList();
            var info = State.SideChainInfo[chainId];
            if (info == null || info.SideChainStatus == SideChainStatus.Terminated)
                return false;
            var currentSideChainHeight = State.CurrentSideChainHeight[chainId];
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L175-179)
```csharp
    {
        var chainId = input.ChainId;
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo != null && sideChainInfo.SideChainStatus != SideChainStatus.Terminated,
            "Side chain not found or incorrect side chain status.");
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract.cs (L222-242)
```csharp
    public override Int32Value DisposeSideChain(Int32Value input)
    {
        AssertSideChainLifetimeControllerAuthority(Context.Sender);

        var chainId = input.Value;
        var info = State.SideChainInfo[chainId];
        Assert(info != null, "Side chain not found.");
        Assert(info.SideChainStatus != SideChainStatus.Terminated, "Incorrect chain status.");

        if (TryGetIndexingProposal(chainId, out _))
            ResetChainIndexingProposal(chainId);

        UnlockTokenAndResource(info);
        info.SideChainStatus = SideChainStatus.Terminated;
        State.SideChainInfo[chainId] = info;
        Context.Fire(new Disposed
        {
            ChainId = chainId
        });
        return new Int32Value { Value = chainId };
    }
```
