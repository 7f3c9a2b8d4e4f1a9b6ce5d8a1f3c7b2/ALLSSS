### Title
Terminated Side Chains Allow Cross-Chain Token Claims via Unvalidated Transaction Verification

### Summary
The `VerifyTransaction()` function does not check if a side chain has been terminated before verifying cross-chain transactions. When a side chain is disposed via `DisposeSideChain()`, its previously indexed block data remains accessible, allowing attackers to claim tokens from terminated chains using old merkle proofs that should no longer be valid.

### Finding Description

The vulnerability exists in the cross-chain verification flow used by `CrossChainReceiveToken()`: [1](#0-0) 

The token receiving function calls `CrossChainVerify()` which internally invokes `VerifyTransaction()`: [2](#0-1) 

The `VerifyTransaction()` method retrieves the merkle tree root without checking chain status: [3](#0-2) 

The critical flaw is in `GetMerkleTreeRoot()` which only checks if `SideChainInfo` exists, not whether the chain is terminated: [4](#0-3) 

It then retrieves indexed data that is never cleared upon termination: [5](#0-4) 

When `DisposeSideChain()` is called, it only sets the status to Terminated but does not clear the indexed block data: [6](#0-5) 

While new indexing operations properly check for terminated status: [7](#0-6) 

The verification path used by `CrossChainReceiveToken()` does not perform this critical check.

### Impact Explanation

**Direct Fund Impact:** Attackers can claim tokens from terminated side chains by presenting valid merkle proofs from before the chain was disposed. If a side chain is terminated due to security compromises, bugs, or governance decisions, the expectation is that all cross-chain operations with that chain should cease. However, any user with a valid cross-chain transfer transaction from before termination can still claim tokens on the main chain.

**Cross-Chain Integrity Violation:** This breaks the fundamental invariant that terminated chains should not participate in any cross-chain operations. The termination is meant to be final - blocking recharges, new indexing, and all interactions. Yet the verification mechanism still accepts proofs from these chains.

**Affected Parties:** The protocol's token supply and users who rely on proper isolation of terminated chains. If a side chain was compromised before termination, attackers could continue exploiting old transactions indefinitely.

### Likelihood Explanation

**Attacker Capabilities:** An attacker needs:
1. A valid cross-chain transfer transaction that was indexed before the chain was terminated
2. The corresponding merkle proof (publicly available from indexed block data)
3. No special privileges required

**Attack Complexity:** Low - simply call `CrossChainReceiveToken()` with old transaction data and proof after the chain is terminated.

**Feasibility Conditions:** 
- A side chain must have been indexed and then terminated (governance-controlled but realistic)
- Attacker must have participated in cross-chain transfers before termination, or obtained proofs from indexed data
- No time restrictions - can be exploited indefinitely after termination

**Detection Constraints:** The attack appears as a normal cross-chain token claim and would pass all verification checks. No on-chain mechanism prevents it.

**Probability:** MEDIUM-HIGH - While chain termination is uncommon, when it does occur (especially for security reasons), this vulnerability guarantees exploitation is possible and profitable.

### Recommendation

Add terminated chain status validation in the `GetMerkleTreeRoot()` function:

```csharp
private Hash GetMerkleTreeRoot(int chainId, long parentChainHeight)
{
    if (chainId == State.ParentChainId.Value)
        return GetParentChainMerkleTreeRoot(parentChainHeight);

    if (State.SideChainInfo[chainId] != null)
    {
        // Add terminated status check
        var sideChainInfo = State.SideChainInfo[chainId];
        Assert(sideChainInfo.SideChainStatus != SideChainStatus.Terminated, 
            "Cannot verify transactions from terminated chain.");
        return GetSideChainMerkleTreeRoot(parentChainHeight);
    }

    return GetCousinChainMerkleTreeRoot(parentChainHeight);
}
```

Additionally, consider clearing indexed data during disposal:
- Clear `State.IndexedSideChainBlockData` entries for the terminated chain
- Reset `State.CurrentSideChainHeight[chainId]` to prevent any confusion

Add regression tests covering:
1. `CrossChainReceiveToken()` should fail for terminated chains
2. `VerifyTransaction()` should reject proofs from terminated chains
3. All view functions should handle terminated chains appropriately

### Proof of Concept

**Initial State:**
1. Side chain (ID: 100) is created and indexed up to height 50
2. A cross-chain transfer transaction exists at side chain height 40, properly indexed on main chain at height 1000
3. User has valid merkle proof for this transaction

**Attack Sequence:**

1. Governance calls `DisposeSideChain(chainId: 100)` due to security concerns
   - Chain status set to `Terminated`
   - Indexed data at height 1000 remains in `State.IndexedSideChainBlockData[1000]`

2. Attacker calls `CrossChainReceiveToken()` with:
   - `TransferTransactionBytes`: the old transfer transaction from height 40
   - `FromChainId`: 100 (now terminated)
   - `ParentChainHeight`: 1000
   - `MerklePath`: valid proof from the indexed data

3. **Expected Result:** Transaction should fail with "Cannot verify transactions from terminated chain"

4. **Actual Result:** 
   - `VerifyTransaction()` succeeds because `GetMerkleTreeRoot()` doesn't check terminated status
   - Merkle proof validates against stale indexed data
   - Tokens are minted to attacker's address
   - Attack can be repeated for any valid pre-termination transactions

**Success Condition:** Attacker successfully receives tokens from a chain that was terminated and should no longer participate in cross-chain operations.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-637)
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_Helper.cs (L701-702)
```csharp
            if (info == null || info.SideChainStatus == SideChainStatus.Terminated)
                return false;
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
