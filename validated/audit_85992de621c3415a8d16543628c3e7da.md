# Audit Report

## Title
Unbounded Merkle Path Length Enables Computational DoS in Cross-Chain Transaction Verification

## Summary
The `VerifyTransaction` method in the CrossChain contract processes merkle paths without length validation, allowing attackers to submit transactions with merkle paths containing up to ~158,000 nodes (limited only by the 5MB transaction size). Since both CrossChain and MultiToken are system contracts that are not instrumented with execution observers, the ~158,000 SHA256 hash computations execute without hitting call/branch thresholds, creating an asymmetric computational DoS attack vector.

## Finding Description

The vulnerability exists in the cross-chain transaction verification flow where merkle path length is never validated. The `VerifyTransaction` method directly processes the input path without checking the number of nodes: [1](#0-0) 

This method calls `ComputeRootWithTransactionStatusMerklePath` which iterates through all path nodes using LINQ's `Aggregate` operation: [2](#0-1) [3](#0-2) 

The `MerklePath` protobuf definition uses `repeated` which allows unlimited nodes: [4](#0-3) 

**Attack Vector:**

Attackers can trigger this via the MultiToken contract's `CrossChainReceiveToken` method, which calls `CrossChainVerify`: [5](#0-4) [6](#0-5) 

**Why Existing Protections Fail:**

1. **Transaction size limit is insufficient**: The 5MB limit allows ~158,000 nodes (each `MerklePathNode` is ~33 bytes: 32-byte hash + 1-byte boolean + protobuf overhead): [7](#0-6) 

2. **Execution observer doesn't apply to system contracts**: The CallAndBranchCounts patcher explicitly skips system contracts: [8](#0-7) [9](#0-8) 

Both CrossChain and MultiToken are system contracts: [10](#0-9) 

3. **Default execution thresholds would be bypassed**: Even though the default threshold is 15,000 for both calls and branches, it doesn't apply to system contracts: [11](#0-10) 

## Impact Explanation

**Computational Denial of Service:**

An attacker can force block producers/validators to perform approximately 158,000 SHA256 hash operations per malicious transaction. Each iteration calls `HashHelper.ConcatAndCompute`: [12](#0-11) 

**Concrete Harm:**
- **Block production delays**: Validators must execute all transactions, including malicious ones, before producing blocks. 158,000 hash operations cause measurable CPU time consumption
- **Amplification attack**: Multiple such transactions in the mempool multiply the effect, potentially causing significant block time increases
- **Asymmetric resource consumption**: Attacker pays a fixed transaction fee based on 5MB size, but forces validators to perform computation equivalent to legitimate merkle verification for billions of transactions
- **Cross-chain functionality disruption**: Legitimate cross-chain transactions may be delayed while validators process malicious transactions

**Severity: Medium** - While this doesn't directly steal funds or corrupt state, it impacts chain availability and validator performance, which is critical for a blockchain's operation. The attack is easily repeatable and has low cost for the attacker.

## Likelihood Explanation

**Attack Requirements:**
- No special permissions required - `CrossChainReceiveToken`, `CrossChainCreateToken`, and `RegisterCrossChainTokenContractAddress` are public methods callable by any address
- Attacker only needs ability to submit transactions to the network
- Can craft malicious `MerklePath` with arbitrary number of nodes up to size limit

**Attack Steps:**
1. Create a `MerklePath` message with ~158,000 `MerklePathNode` entries (each with a random 32-byte hash and boolean flag)
2. Construct a `CrossChainReceiveTokenInput` containing this malicious path
3. Submit transaction calling `CrossChainReceiveToken` with this input
4. Transaction passes size validation (5,214,000 bytes ≈ 5MB)
5. When validators execute the transaction, they iterate through all 158,000 nodes performing hash computations
6. Even though the transaction ultimately fails verification, the computational work has already been done

**Economic Analysis:**
- Attack cost: Single transaction fee for 5MB transaction
- Defender cost: ~158,000 SHA256 hash computations per transaction
- Repeatability: Attacker can submit multiple such transactions
- Detection difficulty: Transactions appear valid until execution

**Likelihood: HIGH** - The attack is trivial to execute, requires no special access, has low cost, and can be repeated indefinitely.

## Recommendation

Add merkle path length validation before processing. A reasonable upper bound would be log₂(10^9) ≈ 30 nodes, which covers any legitimate merkle tree for billions of transactions:

```csharp
public override BoolValue VerifyTransaction(VerifyTransactionInput input)
{
    // Add length validation
    const int MaxMerklePathDepth = 64; // Conservative upper bound
    Assert(input.Path == null || input.Path.MerklePathNodes.Count <= MaxMerklePathDepth,
        $"Merkle path too long. Maximum depth is {MaxMerklePathDepth} nodes.");
    
    var parentChainHeight = input.ParentChainHeight;
    var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
    Assert(merkleTreeRoot != null,
        $"Parent chain block at height {parentChainHeight} is not recorded.");
    var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);

    return new BoolValue { Value = merkleTreeRoot == rootCalculated };
}
```

Additionally, consider adding similar validation in `CrossChainVerify` helper method to provide defense-in-depth.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousMerklePathCausesComputationalDoS()
{
    // Arrange: Create a CrossChainReceiveTokenInput with extremely long merkle path
    const int maliciousNodeCount = 150000; // ~5MB when serialized
    var maliciousPath = new MerklePath();
    for (int i = 0; i < maliciousNodeCount; i++)
    {
        maliciousPath.MerklePathNodes.Add(new MerklePathNode
        {
            Hash = HashHelper.ComputeFrom(i),
            IsLeftChildNode = i % 2 == 0
        });
    }

    var maliciousInput = new CrossChainReceiveTokenInput
    {
        FromChainId = 123456,
        ParentChainHeight = 100,
        MerklePath = maliciousPath,
        TransferTransactionBytes = new Transaction().ToByteString()
    };

    // Act: Time the execution
    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
    
    // This will fail validation but forces 150k hash computations
    var exception = await Assert.ThrowsAsync<AssertionException>(async () =>
    {
        await TokenContractStub.CrossChainReceiveToken.SendAsync(maliciousInput);
    });
    
    stopwatch.Stop();

    // Assert: Execution took significant time due to hash computations
    // On a typical validator, this should take noticeably longer than
    // a legitimate cross-chain verification (which has ~30 nodes)
    _testOutputHelper.WriteLine($"Malicious path processing time: {stopwatch.ElapsedMilliseconds}ms");
    Assert.True(stopwatch.ElapsedMilliseconds > 100); // Significant delay
    
    // Size verification
    var serializedSize = maliciousInput.CalculateSize();
    _testOutputHelper.WriteLine($"Transaction size: {serializedSize} bytes");
    Assert.True(serializedSize < 5 * 1024 * 1024); // Under 5MB limit
}
```

**Notes:**
- The vulnerability is confirmed through code analysis showing no path length validation exists
- System contracts (CrossChain and MultiToken) are not instrumented with execution observers, allowing unbounded computation
- The attack is economically viable and easily repeatable
- While transactions will ultimately fail verification, validators must perform the computation before detecting the failure

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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-10)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
}

```

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/CallAndBranchCounts/Patcher.cs (L9-31)
```csharp
public class Patcher : IPatcher<ModuleDefinition>
{
    public bool SystemContactIgnored => true;

    public void Patch(ModuleDefinition module)
    {
        // Check if already injected, do not double inject
        if (module.Types.Select(t => t.Name).Contains(nameof(ExecutionObserverProxy)))
            return;

        // ReSharper disable once IdentifierTypo
        var nmspace = module.Types.Single(m => m.BaseType is TypeDefinition).Namespace;

        var proxyBuilder = new Patch(module, nmspace);

        foreach (var method in module.GetAllTypes().SelectMany(t => t.Methods))
        {
            new MethodPatcher(method, proxyBuilder).DoPatch();
        }

        module.Types.Add(proxyBuilder.ObserverType);
    }
}
```

**File:** src/AElf.CSharp.CodeOps/CSharpContractPatcher.cs (L19-34)
```csharp
    public byte[] Patch(byte[] code, bool isSystemContract)
    {
        var assemblyDef = AssemblyDefinition.ReadAssembly(new MemoryStream(code));
        Patch(assemblyDef.MainModule, isSystemContract);
        var newCode = new MemoryStream();
        assemblyDef.Write(newCode);
        return newCode.ToArray();
    }

    public int Category => 0;

    private void Patch<T>(T t, bool isSystemContract)
    {
        var patchers = _policy.GetPatchers<T>().Where(p => !p.SystemContactIgnored || !isSystemContract).ToList();
        patchers.ForEach(v => v.Patch(t));
    }
```

**File:** src/AElf.Sdk.CSharp/SmartContractConstants.cs (L16-26)
```csharp
    public static readonly Hash TokenContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Token");

    public static readonly Hash ParliamentContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.Parliament");

    public static readonly Hash VoteContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Vote");
    public static readonly Hash ProfitContractSystemHashName = HashHelper.ComputeFrom("AElf.ContractNames.Profit");

    public static readonly Hash CrossChainContractSystemHashName =
        HashHelper.ComputeFrom("AElf.ContractNames.CrossChain");

```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L1-13)
```csharp
namespace AElf.Kernel.SmartContract;

public class SmartContractConstants
{
    public const int ExecutionCallThreshold = 15000;

    public const int ExecutionBranchThreshold = 15000;

    public const int StateSizeLimit = 128 * 1024;

    // The prefix `vs` occupies 2 lengths.
    public const int StateKeyMaximumLength = 255 - 2;
}
```

**File:** src/AElf.Types/Helper/HashHelper.cs (L74-78)
```csharp
        public static Hash ConcatAndCompute(Hash hash1, Hash hash2)
        {
            var bytes = ByteArrayHelper.ConcatArrays(hash1.ToByteArray(), hash2.ToByteArray());
            return ComputeFrom(bytes);
        }
```
