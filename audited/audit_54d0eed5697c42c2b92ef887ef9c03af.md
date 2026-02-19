### Title
Fee-Free CrossChainReceiveToken Enables Computational DoS via Unbounded Merkle Proof Verification

### Summary
The `CrossChainReceiveToken` method is marked as completely fee-free and can be called by any user without authorization checks. An attacker can exploit this by providing large merkle paths (up to ~155,000 nodes within the 5MB transaction limit) that force expensive hash computations before the transaction fails validation, consuming computational resources without paying any fees.

### Finding Description

The vulnerability exists in the fee configuration and execution flow of `CrossChainReceiveToken`: [1](#0-0) 

The method returns `IsSizeFeeFree = true` with no base fees configured, meaning NO fees are charged regardless of transaction size or computational cost.

The method can be called by any user without authorization: [2](#0-1) 

The critical issue is that expensive merkle proof verification occurs at line 617, AFTER only cheap preliminary checks (parsing, state reads, simple assertions): [3](#0-2) 

The verification calls the CrossChain contract: [4](#0-3) 

Which performs merkle root computation: [5](#0-4) 

The computation performs one hash operation per merkle path node: [6](#0-5) [7](#0-6) 

The MerklePath structure has no depth limit in its protobuf definition: [8](#0-7) 

With the 5MB transaction size limit, an attacker can include approximately 155,000 merkle path nodes: [9](#0-8) 

**Root Cause**: The method performs expensive computation (merkle proof verification with unbounded path depth) BEFORE validation completes, while being marked as completely fee-free. This violates the principle that computational cost should be reflected in fees.

**Why Existing Protections Fail**:
- The double-claim check (line 596) only prevents reusing the same transaction ID, not new fake IDs
- The registered contract check (line 611) can be satisfied for any chain with cross-chain operations
- The merkle verification (line 617) happens AFTER the attacker has already forced expensive computation
- Even when transactions fail, the computational work was already performed

### Impact Explanation

**Operational Impact - Computational DoS**:
- An attacker can send transactions with massive merkle paths (~155,000 nodes) that consume significant computational resources
- Each transaction forces 155,000 hash operations (SHA256 of 64-byte inputs) without charging any fees
- This can be repeated with different transaction IDs to continuously exhaust node resources
- Legitimate fee-paying transactions bear unfair computational load while attackers consume resources for free
- Nodes processing these transactions experience degraded performance and increased block validation time

**Affected Parties**:
- All network validators processing these transactions
- Legitimate users experiencing slower transaction processing
- Cross-chain operations become less reliable under attack

**Severity Justification**: HIGH
- Violates core fee mechanism invariant that computational cost must be reflected in fees
- Enables asymmetric resource exhaustion (attacker cost: zero fees, defender cost: significant computation)
- No special permissions required
- Can impact entire network's operational capacity

### Likelihood Explanation

**Reachable Entry Point**: `CrossChainReceiveToken` is a public method callable by any address.

**Attacker Capabilities Required**:
1. Query `GetParentChainHeight` or `GetSideChainHeight` to find valid indexed heights (publicly available)
2. Identify a chain ID with a registered token contract (exists for any chain doing cross-chain transfers)
3. Generate unique transaction IDs (trivial - just hash random data)
4. Construct large merkle paths (straightforward - just create array of MerklePathNode)

**Feasible Preconditions**:
- At least one cross-chain connection exists with indexed heights (normal operational state)
- No special accounts or privileges needed
- Attack can be fully automated

**Execution Practicality**:
- Attack steps are straightforward and deterministic
- Can craft transactions programmatically
- Each transaction passes validation and gets included in blocks
- Transaction size limit (5MB) still allows ~155,000 nodes

**Economic Rationality**:
- Attack cost: ZERO fees per transaction (method is fee-free)
- Attack benefit: Force expensive computation on all validators
- Extremely favorable cost-benefit ratio for attacker

**Detection Constraints**: 
- Transactions appear legitimate until merkle verification fails
- No rate limiting or anti-spam mechanisms for this method
- Can use different addresses to evade per-address detection

**Probability**: HIGH - All preconditions are easily satisfied and attack execution is straightforward.

### Recommendation

**Immediate Mitigation**:
1. Remove `CrossChainReceiveToken` from the hardcoded fee-free list in `GetMethodFee`: [1](#0-0) 

Change to only exempt system methods:
```csharp
if (new List<string>
    {
        nameof(ClaimTransactionFees), nameof(DonateResourceToken), 
        nameof(ChargeTransactionFees), nameof(CheckThreshold), 
        nameof(CheckResourceToken), nameof(ChargeResourceToken)
        // Remove CrossChainReceiveToken from this list
    }.Contains(input.Value))
```

2. Add merkle path depth validation in `CrossChainVerify` before computation: [4](#0-3) 

Add at the start:
```csharp
private void CrossChainVerify(Hash transactionId, long parentChainHeight, int chainId, MerklePath merklePath)
{
    const int MaxMerklePathDepth = 20; // Reasonable depth for legitimate transfers
    Assert(merklePath.MerklePathNodes.Count <= MaxMerklePathDepth, 
           $"Merkle path depth exceeds maximum allowed: {MaxMerklePathDepth}");
    // ... rest of method
}
```

**Additional Hardening**:
- Consider making legitimate cross-chain receives subsidized through a different mechanism (e.g., fee rebate after successful verification) rather than completely fee-free
- Add per-address rate limiting for cross-chain receive attempts
- Implement early validation of merkle path structure before expensive computation

**Test Cases to Add**:
1. Test that CrossChainReceiveToken charges appropriate fees for large transactions
2. Test that merkle path depth limit is enforced
3. Test that failed cross-chain receives still charge fees
4. Benchmark computational cost with various merkle path depths

### Proof of Concept

**Required Initial State**:
- Chain has at least one indexed parent/side chain with registered token contract
- Token exists on the chain (e.g., "ELF")

**Attack Sequence**:

1. **Reconnaissance**: Query for valid indexed height
   - Call `GetParentChainHeight()` or `GetSideChainHeight(chainId)` to get a valid indexed height `H`
   - Note: This information is publicly available

2. **Craft Attack Transaction**: Create `CrossChainReceiveToken` call with:
   ```
   Input:
     - TransferTransactionBytes: Fake Transaction {
         From: <any address>
         To: <registered token contract for chainId>
         MethodName: "CrossChainTransfer"
         Params: CrossChainTransferInput { Symbol: "ELF", Amount: 1, To: <attacker>, ... }
         GetHash() = <unique hash each time>
       }
     - ParentChainHeight: H (from step 1)
     - FromChainId: <chain with registered contract>
     - MerklePath: {
         MerklePathNodes: [ 150,000 nodes with random hashes ]
       }
   ```

3. **Execute Attack**: Submit transaction to network
   - Transaction passes validation (fee-free, so no balance check)
   - Gets included in block
   - Executes through preliminary checks (lines 593-615)
   - Reaches CrossChainVerify (line 617)
   - Performs 150,000 hash operations
   - Fails at merkle verification (computed root ≠ stored root)
   - Transaction reverts with "Cross chain verification failed"
   - **NO FEES CHARGED**

4. **Repeat**: Generate new unique transaction ID and repeat steps 2-3

**Expected Result**: Each transaction should charge fees proportional to size and computation

**Actual Result**: Each transaction charges ZERO fees while forcing 150,000+ hash operations on all validators

**Success Condition**: Attacker successfully causes computational resource exhaustion without paying any fees, while legitimate transactions continue to pay normal fees.

**Notes**:
- Most other fee-free methods (ClaimTransactionFees, DonateResourceToken, ChargeTransactionFees, CheckResourceToken, ChargeResourceToken) are properly protected by authorization checks or plugin-only restrictions and cannot be exploited by regular users
- CheckThreshold is also fee-free but only performs cheap state reads, posing minimal risk
- The vulnerability is specific to CrossChainReceiveToken due to its combination of: (1) no authorization check, (2) completely fee-free status, and (3) expensive computation before validation

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-597)
```csharp
    public override Empty CrossChainReceiveToken(CrossChainReceiveTokenInput input)
    {
        var transferTransaction = Transaction.Parser.ParseFrom(input.TransferTransactionBytes);
        var transferTransactionId = transferTransaction.GetHash();

        Assert(!State.VerifiedCrossChainTransferTransaction[transferTransactionId],
            "Token already claimed.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L607-617)
```csharp
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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L7-7)
```csharp

```
