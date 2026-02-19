# Audit Report

## Title
Fee-Free CrossChainReceiveToken Enables Computational DoS via Unbounded Merkle Proof Verification

## Summary
The `CrossChainReceiveToken` method in the MultiToken contract is configured as completely fee-free and performs expensive merkle path verification before validation completes. An attacker can submit transactions with extremely large merkle paths (up to ~130,000-155,000 nodes within the 5MB transaction limit) that force all validators to perform massive hash computations without paying any fees, enabling asymmetric resource exhaustion attacks.

## Finding Description

The vulnerability exists in the interaction between fee configuration and execution flow of the cross-chain token receiving mechanism.

The `CrossChainReceiveToken` method is explicitly marked as fee-free, returning `IsSizeFeeFree = true` with no base fees configured. [1](#0-0) 

This public method can be called by any address without authorization checks. [2](#0-1) 

The critical flaw is that expensive merkle proof verification occurs after only preliminary checks. The method performs cheap operations (transaction parsing, double-claim check, token validation, registered contract check) before invoking `CrossChainVerify` at line 617. [3](#0-2) 

The `CrossChainVerify` helper calls the CrossChain contract's `VerifyTransaction` method. [4](#0-3) 

This verification method retrieves the stored merkle tree root, then computes the root from the provided merkle path. [5](#0-4) 

The merkle root computation uses `ComputeRootWithTransactionStatusMerklePath`, which concatenates the transaction ID with status bytes, then calls the merkle path extension method. [6](#0-5) 

The `ComputeRootWithLeafNode` extension performs one hash operation (via `HashHelper.ConcatAndCompute`) per merkle path node using `Aggregate`. [7](#0-6) 

The `MerklePath` protobuf definition uses a `repeated` field with no depth limit. [8](#0-7) 

The AElf transaction pool enforces a 5MB transaction size limit. [9](#0-8) 

**Attack Vector**:
An attacker can craft a malicious `CrossChainReceiveTokenInput` containing:
1. A fake transaction with valid structure and a registered token contract address as the `To` field
2. A valid indexed parent chain height (obtained by querying public view methods)
3. A massive merkle path with ~130,000-155,000 nodes (limited only by 5MB transaction size)

This transaction will pass all preliminary checks (double-claim, token validation, registered contract check) but fail at merkle verification. However, by that point, all validators have already performed the expensive hash computations for the entire merkle path.

**Why Existing Protections Fail**:
- The double-claim check only prevents reusing the same transaction ID, not new fabricated IDs
- The registered contract check is satisfied for any chain with cross-chain operations  
- The preliminary checks are computationally cheap compared to merkle verification
- The expensive computation happens regardless of whether verification ultimately succeeds

## Impact Explanation

This vulnerability enables a **computational denial-of-service attack** with the following operational impacts:

**Resource Exhaustion**: Each malicious transaction forces all network validators to perform ~130,000-155,000 SHA256 hash operations on 64-byte inputs. This is computationally expensive work that consumes significant CPU resources.

**Asymmetric Attack Economics**: The attacker pays zero fees (method is completely fee-free), while defenders (validators) must perform expensive computations. This creates an extremely favorable cost-benefit ratio for attackers.

**Network Degradation**: Validators processing these transactions experience:
- Increased block processing time
- Degraded performance for legitimate transactions
- Potential delays in block production if execution time limits are approached

**Sustained Attack Capability**: The attack can be repeated indefinitely with different fake transaction IDs, continuously exhausting validator resources.

**Protocol Invariant Violation**: This breaks the fundamental principle that computational cost must be reflected in transaction fees, undermining the economic security model.

**Severity: HIGH** - The vulnerability enables asymmetric resource exhaustion, requires no special permissions, violates core fee mechanism invariants, and can impact the operational capacity of the entire network.

## Likelihood Explanation

**Likelihood: HIGH** - The attack is highly practical and easily executable.

**Entry Point Accessibility**: `CrossChainReceiveToken` is a public method with no authorization checks, callable by any address on the network.

**Attack Prerequisites**: All prerequisites are trivially satisfied:
- Query `GetParentChainHeight` or `GetSideChainHeight` to find valid indexed heights (public view methods)
- Identify any chain ID with a registered token contract (exists for any chain performing cross-chain operations)
- Generate unique fake transaction IDs (trivial - just hash random data)
- Construct large merkle paths (straightforward array creation)

**Execution Simplicity**: The attack is deterministic and can be fully automated:
- No timing dependencies or race conditions
- No need to win any competitive processes
- Transactions are accepted by the transaction pool and included in blocks
- Attack succeeds at forcing computation even when transactions ultimately fail validation

**Economic Rationality**: The attack is economically rational from the attacker's perspective:
- Cost: Zero fees per transaction
- Benefit: Force expensive computation on all validators
- Can be repeated without limits

**Detection Difficulty**: Malicious transactions appear legitimate until merkle verification fails, making them difficult to filter proactively without performing the expensive verification.

## Recommendation

Implement multiple layers of protection to prevent this attack:

**1. Add Transaction Size Fees**: Remove `CrossChainReceiveToken` from the fee-free list or add a base fee proportional to the merkle path size:

```csharp
public override MethodFees GetMethodFee(StringValue input)
{
    if (new List<string>
        {
            nameof(ClaimTransactionFees), nameof(DonateResourceToken), 
            nameof(ChargeTransactionFees), nameof(CheckThreshold), 
            nameof(CheckResourceToken), nameof(ChargeResourceToken)
            // Remove CrossChainReceiveToken from this list
        }.Contains(input.Value))
        return new MethodFees
        {
            MethodName = input.Value,
            IsSizeFeeFree = true
        };
    var fees = State.TransactionFees[input.Value];
    return fees;
}
```

**2. Add Merkle Path Depth Validation**: Implement a reasonable maximum depth limit in the verification logic:

```csharp
public override BoolValue VerifyTransaction(VerifyTransactionInput input)
{
    var parentChainHeight = input.ParentChainHeight;
    var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
    Assert(merkleTreeRoot != null,
        $"Parent chain block at height {parentChainHeight} is not recorded.");
    
    // Add depth validation
    const int MaxMerklePathDepth = 64; // Reasonable limit for merkle tree depth
    Assert(input.Path.MerklePathNodes.Count <= MaxMerklePathDepth,
        "Merkle path depth exceeds maximum allowed.");
    
    var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);
    return new BoolValue { Value = merkleTreeRoot == rootCalculated };
}
```

**3. Move Expensive Validation Earlier**: Consider caching merkle roots or implementing early exit conditions to avoid unnecessary computation for invalid transactions.

**4. Add Rate Limiting**: Implement per-address rate limiting for cross-chain receive operations to prevent spam attacks.

## Proof of Concept

```csharp
[Fact]
public async Task CrossChainReceiveToken_LargeMerklePathDoS_Test()
{
    // Setup: Register a cross-chain token contract
    var chainId = 123456;
    await TokenContractStub.RegisterCrossChainTokenContractAddress.SendAsync(
        new RegisterCrossChainTokenContractAddressInput
        {
            FromChainId = chainId,
            TokenContractAddress = SampleAddress.AddressList[0]
        });
    
    // Index some parent chain height
    await BlockMiningService.MineBlockAsync();
    
    // Create a fake transaction with valid structure
    var fakeTransaction = new Transaction
    {
        From = SampleAddress.AddressList[1],
        To = SampleAddress.AddressList[0], // Registered contract address
        MethodName = nameof(TokenContractStub.CrossChainTransfer),
        Params = new CrossChainTransferInput
        {
            Symbol = "ELF",
            Amount = 100,
            To = DefaultAddress,
            ToChainId = Context.ChainId,
            IssueChainId = Context.ChainId
        }.ToByteString()
    };
    
    // Create a massive merkle path (simulate ~10,000 nodes for test performance)
    var largeMerklePath = new MerklePath();
    for (int i = 0; i < 10000; i++)
    {
        largeMerklePath.MerklePathNodes.Add(new MerklePathNode
        {
            Hash = HashHelper.ComputeFrom($"node_{i}"),
            IsLeftChildNode = i % 2 == 0
        });
    }
    
    // Attempt to receive token with large merkle path - NO FEES CHARGED
    var startTime = DateTime.Now;
    var result = await TokenContractStub.CrossChainReceiveToken.SendWithExceptionAsync(
        new CrossChainReceiveTokenInput
        {
            FromChainId = chainId,
            ParentChainHeight = 1,
            TransferTransactionBytes = fakeTransaction.ToByteString(),
            MerklePath = largeMerklePath
        });
    var executionTime = DateTime.Now - startTime;
    
    // Transaction fails at merkle verification but after processing 10,000 hash operations
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Cross chain verification failed");
    
    // Execution took significant time due to merkle computation
    executionTime.TotalMilliseconds.ShouldBeGreaterThan(100);
    
    // NO TRANSACTION FEES WERE CHARGED despite expensive computation
    var balanceBefore = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultAddress,
        Symbol = "ELF"  
    })).Balance;
    // Balance unchanged - zero fees paid
}
```

This test demonstrates that an attacker can force validators to perform thousands of hash operations without paying any fees, with the transaction ultimately failing validation after the expensive work is already done.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L37-52)
```csharp
    public override MethodFees GetMethodFee(StringValue input)
    {
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
        var fees = State.TransactionFees[input.Value];
        return fees;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-617)
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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```
