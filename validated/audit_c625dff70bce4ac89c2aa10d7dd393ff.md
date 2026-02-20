# Audit Report

## Title
Unbounded Merkle Path Length Enables Computational DoS in Cross-Chain Transaction Verification

## Summary
The `VerifyTransaction` method in the CrossChain contract processes merkle paths without length validation, allowing attackers to submit transactions with excessively large merkle paths (up to ~158,000 nodes within the 5MB transaction limit). Since CrossChain and MultiToken are system contracts that bypass execution observer instrumentation, validators are forced to perform unbounded SHA256 hash computations, creating an asymmetric computational DoS attack vector.

## Finding Description

The vulnerability exists in the cross-chain transaction verification flow where merkle path length is never validated. The `VerifyTransaction` method directly processes the input merkle path without checking the number of nodes: [1](#0-0) 

This method calls `ComputeRootWithTransactionStatusMerklePath`, which unconditionally iterates through all merkle path nodes: [2](#0-1) 

The iteration happens via `ComputeRootWithLeafNode` which uses LINQ's `Aggregate` operation to process every node in the merkle path: [3](#0-2) 

**Attack Vector:**

Attackers can trigger this vulnerability through the MultiToken contract's `CrossChainReceiveToken` method, which is publicly callable: [4](#0-3) 

This method calls `CrossChainVerify` internally: [5](#0-4) 

**Why Existing Protections Fail:**

1. **Transaction size limit is insufficient**: The 5MB transaction size limit allows approximately 158,000 merkle path nodes: [6](#0-5) 

2. **Execution observer doesn't apply to system contracts**: The CallAndBranchCounts patcher explicitly skips system contracts via the `SystemContactIgnored` flag: [7](#0-6) 

This flag is used to filter patchers based on whether contracts are system contracts: [8](#0-7) 

3. **Both CrossChain and MultiToken are system contracts**: They are defined as system contracts and included in the main chain deployment list: [9](#0-8) [10](#0-9) 

## Impact Explanation

**Computational Denial of Service:**

An attacker can force validators to perform approximately 158,000 SHA256 hash operations per malicious transaction. Each iteration in the merkle path computation calls `HashHelper.ConcatAndCompute`, consuming significant CPU resources.

**Concrete Harm:**
- **Block production delays**: Validators must execute all transactions before producing blocks, including malicious ones with excessive merkle paths
- **Amplification attack**: Multiple such transactions in the mempool multiply the computational burden, potentially causing significant block time increases
- **Asymmetric resource consumption**: Attacker pays only a fixed transaction fee based on 5MB size, but forces validators to perform computation equivalent to processing thousands of legitimate transactions
- **Cross-chain functionality disruption**: Legitimate cross-chain transactions may be delayed or rejected while validators process malicious transactions

**Severity: Medium** - While this doesn't directly steal funds or corrupt state, it significantly impacts chain availability and validator performance. The attack is easily repeatable, has low cost for attackers, and can degrade network operation.

## Likelihood Explanation

**Attack Requirements:**
- No special permissions required - `CrossChainReceiveToken` is a public method callable by any address
- Attacker only needs ability to submit transactions to the network
- Can craft malicious `MerklePath` with arbitrary number of nodes up to transaction size limit

**Attack Steps:**
1. Create a `MerklePath` with ~158,000 `MerklePathNode` entries (each with random 32-byte hash and boolean flag)
2. Construct a `CrossChainReceiveTokenInput` containing this malicious merkle path
3. Submit transaction calling `CrossChainReceiveToken`
4. Transaction passes size validation (under 5MB limit)
5. Validators execute the transaction, iterating through all 158,000 nodes performing hash computations
6. Transaction ultimately fails verification, but computational work has already been done

**Economic Analysis:**
- Attack cost: Single transaction fee for 5MB transaction
- Defender cost: ~158,000 SHA256 operations per transaction
- Repeatability: Unlimited - attacker can submit multiple transactions
- Detection difficulty: Transactions appear valid until execution

**Likelihood: HIGH** - The attack is trivial to execute, requires no special access, has low cost, and can be repeated indefinitely.

## Recommendation

Add merkle path length validation before processing:

```csharp
public override BoolValue VerifyTransaction(VerifyTransactionInput input)
{
    // Add maximum merkle path length validation
    const int MaxMerklePathLength = 64; // Reasonable limit for legitimate merkle trees
    Assert(input.Path == null || input.Path.MerklePathNodes.Count <= MaxMerklePathLength, 
        $"Merkle path length exceeds maximum allowed ({MaxMerklePathLength}).");
    
    var parentChainHeight = input.ParentChainHeight;
    var merkleTreeRoot = GetMerkleTreeRoot(input.VerifiedChainId, parentChainHeight);
    Assert(merkleTreeRoot != null,
        $"Parent chain block at height {parentChainHeight} is not recorded.");
    var rootCalculated = ComputeRootWithTransactionStatusMerklePath(input.TransactionId, input.Path);

    return new BoolValue { Value = merkleTreeRoot == rootCalculated };
}
```

The maximum length should be set based on expected blockchain tree depths (typically logarithmic in block count, so 64 is conservative).

## Proof of Concept

A malicious actor can create a transaction with the following structure:

```csharp
var maliciousMerklePath = new MerklePath();
for (int i = 0; i < 158000; i++)
{
    maliciousMerklePath.MerklePathNodes.Add(new MerklePathNode
    {
        Hash = Hash.FromByteArray(new byte[32]), // Random hash
        IsLeftChildNode = i % 2 == 0
    });
}

var input = new CrossChainReceiveTokenInput
{
    FromChainId = chainId,
    ParentChainHeight = height,
    TransferTransactionBytes = txBytes,
    MerklePath = maliciousMerklePath
};

// Submit transaction calling CrossChainReceiveToken with this input
// Validators will iterate through all 158,000 nodes before failing validation
```

When validators process this transaction, they will execute approximately 158,000 hash operations in `ComputeRootWithLeafNode` before the verification fails. The attacker pays only for the transaction size, while validators bear the full computational cost.

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

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L1-6)
```csharp
namespace AElf.Kernel.TransactionPool;

public class TransactionPoolConsts
{
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
}
```

**File:** src/AElf.CSharp.CodeOps/Patchers/Module/CallAndBranchCounts/Patcher.cs (L9-12)
```csharp
public class Patcher : IPatcher<ModuleDefinition>
{
    public bool SystemContactIgnored => true;

```

**File:** src/AElf.CSharp.CodeOps/CSharpContractPatcher.cs (L30-34)
```csharp
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

**File:** src/AElf.Blockchains.MainChain/MainChainContractDeploymentListProvider.cs (L27-29)
```csharp
            TokenSmartContractAddressNameProvider.Name,
            CrossChainSmartContractAddressNameProvider.Name,
            ConfigurationSmartContractAddressNameProvider.Name,
```
