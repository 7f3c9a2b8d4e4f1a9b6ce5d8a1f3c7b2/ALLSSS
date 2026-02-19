# Audit Report

## Title
Side Chain Disposal Permanently Loses Unindexed Cross-Chain Data

## Summary
The `DisposeSideChain` function can terminate side chains without ensuring all cross-chain blocks have been indexed, and actively clears pending indexing proposals during disposal. Once terminated, the chain's status prevents any future indexing attempts, causing permanent loss of cross-chain transaction data and potentially trapping user funds transferred cross-chain but never recorded on the main chain.

## Finding Description

The vulnerability exists across multiple components of the cross-chain disposal mechanism:

**Missing Indexing Completeness Check:**
The `DisposeSideChain` function only validates that the chain exists and is not already terminated, but performs no verification that all side chain blocks have been indexed. [1](#0-0) 

**Pending Proposal Destruction:**
During disposal, any pending indexing proposals are immediately cleared via `ResetChainIndexingProposal(chainId)`, discarding approved-but-unreleased cross-chain data. [2](#0-1) 

**Post-Termination Indexing Prevention:**
After termination, `ValidateSideChainBlockData` explicitly rejects any side chain data where the status is `Terminated`, making it impossible to index blocks from the disposed chain. [3](#0-2) 

**View Function Concealment:**
The `GetSideChainIdAndHeight` function skips terminated chains entirely, making them invisible in queries that check indexing status. [4](#0-3) 

**Cross-Chain Verification Dependency:**
Cross-chain token transfers rely on `VerifyTransaction` to validate merkle proofs against indexed data. [5](#0-4)  When blocks are not indexed, `GetSideChainMerkleTreeRoot` cannot retrieve the merkle tree root, [6](#0-5)  causing `CrossChainReceiveToken` to fail. [7](#0-6) 

## Impact Explanation

**Direct Financial Impact:**
Users who initiated cross-chain transfers from the side chain to the main chain lose their funds if the side chain blocks containing those transactions are not indexed before disposal. The tokens are burned/locked on the side chain but never minted/unlocked on the main chain, resulting in permanent fund loss. The `CrossChainReceiveToken` function requires successful merkle proof verification via `CrossChainVerify`, [8](#0-7)  which fails when the necessary blocks were never indexed.

**Cross-Chain Integrity Violation:**
The main chain's view of side chain state becomes permanently incomplete. Cross-chain merkle proofs cannot be verified for transactions in unindexed blocks, breaking the cross-chain verification mechanism that is fundamental to AElf's multi-chain architecture. The `VerifyTransaction` method requires indexed merkle tree roots to function, [5](#0-4)  and returns false when these are unavailable.

**Severity Justification:**
High impact (fund loss, data loss, protocol invariant violation) but medium likelihood (requires governance oversight or coordinated malicious action). This represents a governance failure scenario rather than an easily exploitable technical vulnerability.

## Likelihood Explanation

**Attacker Capabilities:**
- Requires Parliament approval to execute `DisposeSideChain` (governance-controlled)
- Does not require technical exploit or privilege escalation
- Could occur through governance oversight (accidental) or coordinated malicious governance action

**Feasibility:**
The attack complexity is low - it simply requires calling `DisposeSideChain` through normal governance processes without checking indexing completeness first. No automated safeguards prevent disposal of chains with unindexed blocks.

**Evidence:**
The test suite explicitly demonstrates this scenario in `Release_IndexingSideChain_Terminated`, where indexing proposals are created and approved, then the side chain is disposed, causing subsequent release attempts to fail with "Chain indexing not proposed" and new indexing attempts to fail with "Invalid cross chain data to be indexed". [9](#0-8) 

**Probability:**
Medium - this could realistically occur through governance negligence (not verifying indexing completeness before disposal) or time-pressure scenarios requiring rapid side chain termination.

## Recommendation

Add indexing completeness validation to `DisposeSideChain`:

1. **Check pending proposals:** Before clearing proposals, verify they are expired or explicitly rejected, not approved-and-ready-to-release
2. **Validate indexing status:** Compare `State.CurrentSideChainHeight[chainId]` against the actual side chain height to ensure all blocks are indexed
3. **Add grace period:** Prevent disposal if indexing proposals exist that are not yet expired
4. **Alternative approach:** Allow a "deprecated" status that prevents new operations but allows completing pending indexing before final termination

Example fix structure:
```csharp
public override Int32Value DisposeSideChain(Int32Value input)
{
    // ... existing checks ...
    
    // NEW: Check for pending approved proposals
    if (TryGetIndexingProposalWithStatus(chainId, 
        CrossChainIndexingProposalStatus.Pending, out var proposal))
    {
        var proposalInfo = GetCrossChainProposal(
            GetCrossChainIndexingController(), proposal.ProposalId);
        Assert(proposalInfo.ExpiredTime <= Context.CurrentBlockTime || 
               !proposalInfo.ToBeReleased,
               "Cannot dispose chain with approved pending indexing proposals.");
    }
    
    // Continue with existing disposal logic...
}
```

## Proof of Concept

The existing test `Release_IndexingSideChain_Terminated` in the test suite demonstrates this vulnerability:

1. Creates a side chain and side chain block data for heights 1 and 2
2. Proposes cross-chain indexing via `ProposeCrossChainIndexing`
3. Approves the indexing proposal via `ApproveWithMinersAsync`
4. Disposes the side chain via `DisposeSideChain` (which clears the approved proposal)
5. Attempts to release the proposal via `ReleaseCrossChainIndexingProposal` - fails with "Chain indexing not proposed"
6. Attempts to propose new indexing for height 3 - fails with "Invalid cross chain data to be indexed" [9](#0-8) 

This test confirms that approved indexing data is permanently lost when a side chain is disposed, and no mechanism exists to recover or index that data afterwards.

---

**Notes:**

The vulnerability is particularly concerning because:
- The `GetSideChainIdAndHeight` view function hides terminated chains, making post-disposal verification difficult
- There is no mechanism to "un-terminate" a chain or force indexing of historical blocks
- Users have no way to recover funds trapped in unindexed cross-chain transfers
- The test suite's explicit demonstration of this scenario suggests the behavior may be known but unmitigated

This represents a critical gap in the cross-chain lifecycle management where the disposal operation prioritizes cleanup over data integrity, violating the fundamental guarantee that all cross-chain transactions should be verifiable.

### Citations

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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L241-246)
```csharp
    private Hash GetSideChainMerkleTreeRoot(long parentChainHeight)
    {
        var indexedSideChainData = State.IndexedSideChainBlockData[parentChainHeight];
        return ComputeRootWithMultiHash(
            indexedSideChainData.SideChainBlockDataList.Select(d => d.TransactionStatusMerkleTreeRoot));
    }
```

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L498-504)
```csharp
    private void ResetChainIndexingProposal(int chainId)
    {
        // clear pending proposal
        var proposedIndexingProposal = State.IndexingPendingProposal.Value;
        proposedIndexingProposal.ChainIndexingProposalCollections.Remove(chainId);
        State.IndexingPendingProposal.Value = proposedIndexingProposal;
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L101-116)
```csharp
    public override ChainIdAndHeightDict GetSideChainIdAndHeight(Empty input)
    {
        var dict = new ChainIdAndHeightDict();
        var serialNumber = State.SideChainSerialNumber.Value;
        for (long i = 1; i <= serialNumber; i++)
        {
            var chainId = GetChainId(i);
            var sideChainInfo = State.SideChainInfo[chainId];
            if (sideChainInfo.SideChainStatus == SideChainStatus.Terminated)
                continue;
            var height = State.CurrentSideChainHeight[chainId];
            dict.IdHeightDict.Add(chainId, height);
        }

        return dict;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-638)
```csharp
    public override Empty CrossChainReceiveToken(CrossChainReceiveTokenInput input)
    {
        var transferTransaction = Transaction.Parser.ParseFrom(input.TransferTransactionBytes);
        var transferTransactionId = transferTransaction.GetHash();

        Assert(!State.VerifiedCrossChainTransferTransaction[transferTransactionId],
            "Token already claimed.");

        var crossChainTransferInput =
            CrossChainTransferInput.Parser.ParseFrom(transferTransaction.Params.ToByteArray());
        var symbol = crossChainTransferInput.Symbol;
        var amount = crossChainTransferInput.Amount;
        var receivingAddress = crossChainTransferInput.To;
        var targetChainId = crossChainTransferInput.ToChainId;
        var transferSender = transferTransaction.From;

        var tokenInfo = AssertValidToken(symbol, amount);
        var issueChainId = GetIssueChainId(tokenInfo.Symbol);
        Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.");
        Assert(targetChainId == Context.ChainId, "Unable to claim cross chain token.");
        var registeredTokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        AssertCrossChainTransaction(transferTransaction, registeredTokenContractAddress,
            nameof(CrossChainTransfer));
        Context.LogDebug(() =>
            $"symbol == {tokenInfo.Symbol}, amount == {amount}, receivingAddress == {receivingAddress}, targetChainId == {targetChainId}");

        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);

        State.VerifiedCrossChainTransferTransaction[transferTransactionId] = true;
        tokenInfo.Supply = tokenInfo.Supply.Add(amount);
        Assert(tokenInfo.Supply <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(receivingAddress, tokenInfo.Symbol, amount);

        Context.Fire(new CrossChainReceived
        {
            From = transferSender,
            To = receivingAddress,
            Symbol = tokenInfo.Symbol,
            Amount = amount,
            Memo = crossChainTransferInput.Memo,
            FromChainId = input.FromChainId,
            ParentChainHeight = input.ParentChainHeight,
            IssueChainId = issueChainId,
            TransferTransactionId = transferTransactionId
        });
        return new Empty();
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

**File:** test/AElf.Contracts.CrossChain.Tests/CrossChainIndexingActionTest.cs (L1068-1128)
```csharp
    [Fact]
    public async Task Release_IndexingSideChain_Terminated()
    {
        var parentChainId = 123;
        var lockedToken = 2;
        long parentChainHeightOfCreation = 10;
        var sideChainId =
            await InitAndCreateSideChainAsync(parentChainHeightOfCreation, parentChainId, lockedToken);
        var fakeSideChainBlockHash = HashHelper.ComputeFrom("sideChainBlockHash");
        var fakeTxMerkleTreeRoot = HashHelper.ComputeFrom("txMerkleTreeRoot");
        var sideChainBlockData1 =
            CreateSideChainBlockData(fakeSideChainBlockHash, 1, sideChainId, fakeTxMerkleTreeRoot);
        var sideChainBlockData2 =
            CreateSideChainBlockData(fakeSideChainBlockHash, 2, sideChainId, fakeTxMerkleTreeRoot);

        var crossChainBlockData = new CrossChainBlockData
        {
            SideChainBlockDataList = { sideChainBlockData1, sideChainBlockData2 }
        };

        {
            var txRes = await CrossChainContractStub.ProposeCrossChainIndexing.SendAsync(crossChainBlockData);
            txRes.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
            var proposalId = ProposalCreated.Parser
                .ParseFrom(txRes.TransactionResult.Logs.First(l => l.Name.Contains(nameof(ProposalCreated)))
                    .NonIndexed)
                .ProposalId;
            proposalId.ShouldNotBeNull();
            await ApproveWithMinersAsync(proposalId);
        }

        var disposeSideChainProposalId = await DisposeSideChainProposalAsync(new Int32Value { Value = sideChainId });
        await ApproveWithMinersAsync(disposeSideChainProposalId);
        await ReleaseProposalAsync(disposeSideChainProposalId);

        {
            var chainStatus = await CrossChainContractStub.GetChainStatus.CallAsync(new Int32Value
            {
                Value = sideChainId
            });
            chainStatus.Status.ShouldBe(SideChainStatus.Terminated);
        }

        var releaseResult = await CrossChainContractStub.ReleaseCrossChainIndexingProposal.SendWithExceptionAsync(
            new ReleaseCrossChainIndexingProposalInput
            {
                ChainIdList = { sideChainId }
            });
        releaseResult.TransactionResult.Error.ShouldContain("Chain indexing not proposed.");

        {
            var sideChainBlockData3 =
                CreateSideChainBlockData(fakeSideChainBlockHash, 3, sideChainId, fakeTxMerkleTreeRoot);
            var txRes = await CrossChainContractStub.ProposeCrossChainIndexing.SendWithExceptionAsync(
                new CrossChainBlockData
                {
                    SideChainBlockDataList = { sideChainBlockData3 }
                });
            txRes.TransactionResult.Error.ShouldContain("Invalid cross chain data to be indexed");
        }
    }
```
