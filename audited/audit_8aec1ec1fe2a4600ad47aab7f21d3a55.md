# Audit Report

## Title
Terminated Side Chains Allow Cross-Chain Token Claims via Unvalidated Transaction Verification

## Summary
The `VerifyTransaction()` function in the CrossChain contract does not validate whether a side chain has been terminated before verifying cross-chain transactions. When `DisposeSideChain()` is called, it sets the status to `Terminated` but leaves previously indexed block data accessible. This allows anyone to claim tokens from terminated chains using old merkle proofs, violating the fundamental invariant that terminated chains should not participate in any cross-chain operations.

## Finding Description

The vulnerability exists in the cross-chain token receiving flow. When `CrossChainReceiveToken()` is called, it invokes `CrossChainVerify()` which calls the CrossChain contract's `VerifyTransaction()` method. [1](#0-0) 

The verification internally retrieves the merkle tree root via `GetMerkleTreeRoot()`: [2](#0-1) 

The critical flaw is in `GetMerkleTreeRoot()` which only checks if `SideChainInfo` exists (`!= null`), not whether the chain's status is `Terminated`: [3](#0-2) 

It then retrieves indexed data that is never cleared upon termination: [4](#0-3) 

When `DisposeSideChain()` is called, it only sets the status to `Terminated` but does not remove the `SideChainInfo` entry or clear the indexed block data: [5](#0-4) 

In contrast, NEW indexing operations properly validate the chain status and reject terminated chains: [6](#0-5) 

However, this check is only applied during indexing, not during verification of existing proofs.

## Impact Explanation

**Token Supply Inflation:** Attackers can mint tokens on the receiving chain by presenting valid merkle proofs from before the chain was terminated. Since terminated chains may have been disposed due to security compromises, bugs, or governance decisions, the expectation is that all cross-chain operations should immediately cease.

**Cross-Chain Integrity Violation:** The termination status is meant to completely isolate a side chain from the ecosystem. Methods like `Recharge()` and new indexing operations properly enforce this isolation, but the verification path bypasses it entirely.

**Persistent Exploitation:** If a side chain was compromised before being terminated, attackers could continue exploiting old transactions indefinitely. There is no time limit—any previously indexed transaction can be claimed at any point after termination.

## Likelihood Explanation

**Attack Prerequisites:**
- A side chain must be indexed and then terminated (governance-controlled but realistic for security incidents)
- Attacker needs a valid cross-chain transfer transaction from before termination
- Merkle proofs are publicly derivable from indexed block data

**Execution Complexity:** Very low—simply call `CrossChainReceiveToken()` with old transaction bytes and merkle path after the chain is terminated.

**Detection:** The attack appears as a legitimate cross-chain token claim and passes all verification checks. No on-chain mechanism prevents it.

**Probability Assessment:** MEDIUM-HIGH—While chain termination is uncommon, when it occurs (especially for security reasons), this vulnerability guarantees exploitation is possible and economically rational.

## Recommendation

Add a chain status validation in `GetMerkleTreeRoot()` before retrieving merkle data for side chains:

```csharp
private Hash GetMerkleTreeRoot(int chainId, long parentChainHeight)
{
    if (chainId == State.ParentChainId.Value)
        return GetParentChainMerkleTreeRoot(parentChainHeight);

    if (State.SideChainInfo[chainId] != null)
    {
        // Add status check
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo.SideChainStatus != SideChainStatus.Terminated, 
            "Cannot verify transactions from terminated side chain.");
        return GetSideChainMerkleTreeRoot(parentChainHeight);
    }

    return GetCousinChainMerkleTreeRoot(parentChainHeight);
}
```

Alternatively, consider clearing indexed block data when `DisposeSideChain()` is called to prevent any future verification attempts.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainReceiveToken_FromTerminatedChain_ShouldFail()
{
    // 1. Setup: Create side chain and perform cross-chain transfer
    var sideChainId = await InitAndCreateSideChainAsync();
    var transferTxBytes = /* valid cross-chain transfer transaction */;
    var merklePath = /* valid merkle path from indexed data */;
    var parentChainHeight = /* height when transaction was indexed */;
    
    // 2. Dispose the side chain (set status to Terminated)
    await DisposeSideChainProposalAsync(sideChainId);
    
    // 3. Verify chain is terminated
    var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value { Value = sideChainId });
    chainStatus.Status.ShouldBe(SideChainStatus.Terminated);
    
    // 4. Attempt to receive tokens from terminated chain
    // This SHOULD fail but currently succeeds
    var result = await TokenContractStub.CrossChainReceiveToken.SendAsync(new CrossChainReceiveTokenInput
    {
        FromChainId = sideChainId,
        ParentChainHeight = parentChainHeight,
        TransferTransactionBytes = transferTxBytes,
        MerklePath = merklePath
    });
    
    // Expected: Transaction should fail with "Cannot verify transactions from terminated side chain"
    // Actual: Transaction succeeds and tokens are minted
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L690-718)
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
            var target = currentSideChainHeight != 0
                ? currentSideChainHeight + 1
                : AElfConstants.GenesisBlockHeight;

            foreach (var blockData in group)
            {
                var sideChainHeight = blockData.Height;
                if (target != sideChainHeight)
                    return false;
                target++;
            }
        }

        return true;
    }
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
