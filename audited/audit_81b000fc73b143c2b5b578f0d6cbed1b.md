### Title
Fee-Free Cross-Chain Receive Enables Computational DoS via Oversized Merkle Paths

### Summary
The `CrossChainReceiveToken` method is completely fee-free and accepts user-controlled merkle paths with no size validation. An attacker can spam transactions with extremely long merkle paths (up to ~15,000 nodes) that force expensive hash computations during verification, consuming block execution resources at zero cost and enabling denial-of-service attacks against cross-chain operations and legitimate token transfers.

### Finding Description

The `CrossChainReceiveToken` method is designated as fee-free in the method fee configuration: [1](#0-0) 

This configuration means no base fees or size-based fees are charged when calling this method. The method accepts a `CrossChainReceiveTokenInput` containing a user-controlled `merkle_path`: [2](#0-1) 

During execution, the method calls `CrossChainVerify` which performs merkle path verification: [3](#0-2) 

The verification process retrieves the expected merkle tree root from state and computes a root from the provided transaction ID and merkle path: [4](#0-3) 

The critical issue is in the root computation which iterates through every node in the attacker-provided merkle path: [5](#0-4) [6](#0-5) 

Each iteration performs a hash computation (`HashHelper.ConcatAndCompute`) which is computationally expensive. The MerklePath proto definition has no size limit on the number of nodes: [7](#0-6) 

An attacker can construct a transaction with up to ~15,000 merkle path nodes (limited only by the execution call threshold): [8](#0-7) 

The transaction size limit of 5MB allows for extremely large merkle paths: [9](#0-8) 

Since the method is fee-free, even though transactions fail verification or hit execution limits, the attacker pays zero transaction fees for consuming these computational resources.

### Impact Explanation

**Operational Impact - High Severity:**

1. **Block Execution Resource Exhaustion**: Each malicious transaction consumes up to 15,000 hash computations (near the execution call limit) for free. An attacker can fill blocks with such transactions, starving legitimate transactions of execution resources.

2. **Cross-Chain Operation DoS**: Legitimate cross-chain token receives compete with spam transactions for block space and execution capacity. Since blocks have a limit of 512 transactions, an attacker could monopolize significant portions of block space at zero cost.

3. **Miner/Validator Load**: Block producers must execute all transactions to determine validity. Fee-free computation-heavy transactions that ultimately fail still consume miner resources during execution, creating asymmetric cost (attacker pays nothing, network pays computation).

4. **Economic Attack Vector**: Legitimate users must pay fees for their transactions, while attackers consume equivalent or greater resources for free. This breaks the economic security model where transaction fees should reflect resource consumption.

Legitimate merkle paths for cross-chain transactions would typically be 10-30 nodes deep (log₂ of transaction count in a block). An attacker providing 10,000-15,000 nodes represents 500-1000× amplification of computational work compared to legitimate use cases.

### Likelihood Explanation

**High Likelihood:**

1. **Reachable Entry Point**: `CrossChainReceiveToken` is a public method callable by any address without restrictions.

2. **Minimal Preconditions**: 
   - Attacker needs: valid `from_chain_id` (known public information) and indexed `parent_chain_height` (observable on-chain)
   - No token holdings, permissions, or governance approvals required
   - Can construct properly formatted but invalid merkle paths trivially

3. **Execution Practicality**: 
   - Attack transactions are valid protobuf messages under transaction size limits
   - Pre-execution fee charging succeeds with zero fees charged
   - Main execution runs expensive computation before failing
   - Can be repeated indefinitely in subsequent blocks

4. **Economic Rationality**: 
   - Attack cost: Zero transaction fees + minimal transaction construction cost
   - Attack impact: Degraded network performance, blocked legitimate cross-chain operations
   - Cost-benefit heavily favors attacker

5. **Detection Constraints**: Individual transactions appear valid until verification fails deep in execution. No obvious pattern distinguishes malicious oversized merkle paths from legitimate ones until full execution.

### Recommendation

**Immediate Mitigations:**

1. **Add Merkle Path Size Validation** in `CrossChainReceiveToken` before verification:
```
Assert(input.MerklePath.MerklePathNodes.Count <= MAX_MERKLE_PATH_DEPTH, 
       "Merkle path exceeds maximum depth.");
```
Set `MAX_MERKLE_PATH_DEPTH` to a reasonable value (e.g., 32-64 nodes, sufficient for blocks with millions of transactions).

2. **Charge Minimum Base Fee** for `CrossChainReceiveToken` to prevent zero-cost spam. Update the fee configuration: [1](#0-0) 

Remove `CrossChainReceiveToken` from the fee-free list and set a minimal base fee via `SetMethodFee`.

3. **Add State Validation** to check if the parent chain height has been indexed BEFORE performing expensive merkle path computation: [10](#0-9) 

Move the merkle tree root existence check earlier to fail fast for invalid heights.

**Additional Hardening:**

4. Add merkle path depth validation to the CrossChain contract's `VerifyTransaction` method as a defense-in-depth measure.

5. Implement rate limiting or increased fees for repeated failed verification attempts from the same address.

6. Add test cases validating rejection of oversized merkle paths and verification that fees are properly charged.

### Proof of Concept

**Attack Sequence:**

1. **Initial State**: 
   - Cross-chain indexing has recorded parent chain height H with merkle tree root R
   - Attacker observes this information on-chain

2. **Attack Construction**:
   - Attacker creates a `CrossChainReceiveTokenInput`:
     - `from_chain_id`: Valid parent chain ID (e.g., MainChainId)
     - `parent_chain_height`: H (the indexed height)
     - `transfer_transaction_bytes`: Any properly formatted CrossChainTransfer transaction bytes
     - `merkle_path`: Artificially constructed with 14,000 MerklePathNode entries (approaching execution limit)

3. **Attack Execution**:
   - Attacker submits transaction calling `CrossChainReceiveToken`
   - Pre-execution: `ChargeTransactionFees` called → Returns success with 0 fees charged (IsSizeFeeFree=true, no base fees set)
   - Main execution begins:
     - Lines 593-616: Parse and validate inputs (minimal cost, all checks pass)
     - Line 617: `CrossChainVerify` called
     - `VerifyTransaction` retrieves merkle root R from state
     - `ComputeRootWithTransactionStatusMerklePath` begins iterating through 14,000 merkle path nodes
     - Each iteration: 1 hash computation via `HashHelper.ConcatAndCompute`
     - After ~14,000 iterations, either:
       - Hits `ExecutionCallThreshold` of 15,000 → Transaction fails with "Execution observer call threshold exceeded"
       - OR completes computation → Computed root ≠ R → Transaction fails with "Cross chain verification failed"

4. **Result**:
   - **Expected**: Transaction should either charge fees proportional to computational cost OR reject oversized merkle paths early
   - **Actual**: Transaction consumes ~14,000 expensive hash computations, then fails, attacker pays $0 in fees

5. **Spam Attack**: Attacker repeats steps 2-4 continuously, filling blocks with computation-heavy zero-cost transactions, degrading network performance and blocking legitimate cross-chain operations.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L39-49)
```csharp
        if (new List<string>
            {
                nameof(ClaimTransactionFees), nameof(DonateResourceToken), nameof(ChargeTransactionFees),
                nameof(CheckThreshold), nameof(CheckResourceToken), nameof(ChargeResourceToken),
                nameof(CrossChainReceiveToken)
            }.Contains(input.Value))
            return new MethodFees
            {
                MethodName = input.Value,
                IsSizeFeeFree = true
            };
```

**File:** protobuf/token_contract.proto (L478-487)
```text
message CrossChainReceiveTokenInput {
    // The source chain id.
    int32 from_chain_id = 1;
    // The height of the transfer transaction.
    int64 parent_chain_height = 2;
    // The raw bytes of the transfer transaction.
    bytes transfer_transaction_bytes = 3;
    // The merkle path created from the transfer transaction.
    aelf.MerklePath merkle_path = 4;
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

**File:** contract/AElf.Contracts.CrossChain/CrossChainContract_View.cs (L38-46)
```csharp
    {
        var parentChainHeight = input.ParentChainHeight;
        var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
        Assert(merkleTreeRoot != null,
            $"Parent chain block at height {parentChainHeight} is not recorded.");
        var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);

        return new BoolValue { Value = merkleTreeRoot == rootCalculated };
    }
```

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

**File:** src/AElf.Types/Extensions/MerklePathExtensions.cs (L9-14)
```csharp
        public static Hash ComputeRootWithLeafNode(this MerklePath path, Hash leaf)
        {
            return path.MerklePathNodes.Aggregate(leaf, (current, node) => node.IsLeftChildNode
                ? HashHelper.ConcatAndCompute(node.Hash, current)
                : HashHelper.ConcatAndCompute(current, node.Hash));
        }
```

**File:** protobuf/aelf/core.proto (L155-165)
```text
message MerklePath {
    // The merkle path nodes.
    repeated MerklePathNode merkle_path_nodes = 1;
}

message MerklePathNode{
    // The node hash.
    Hash hash = 1;
    // Whether it is a left child node.
    bool is_left_child_node = 2;
}
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-7)
```csharp
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```
