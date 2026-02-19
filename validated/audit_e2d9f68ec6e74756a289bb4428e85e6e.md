# Audit Report

## Title
Deterministic Random Hash Generation Causes DoS in NFT Protocol Creation for Multiple Transactions per Block

## Summary
The `GenerateSymbolNumber()` function in the NFT contract computes a random hash only once before entering a collision-detection loop, using inputs that are identical for all transactions from the same sender in the same block. When the first transaction marks a symbol number as used, subsequent transactions from the same sender in that block enter an infinite loop, eventually failing after hitting the 15,000 branch execution threshold.

## Finding Description

The vulnerability exists in the random number generation logic for NFT protocol symbol creation. The `GenerateSymbolNumber()` function computes a `randomHash` value from `Context.Sender` and random bytes retrieved for the previous block height. [1](#0-0) 

This `randomHash` is computed **once** before the do-while loop and is never updated inside the loop. The loop attempts to find an unused symbol number by checking if it has been marked as created. [2](#0-1) 

The random bytes are obtained from the consensus contract using `Context.CurrentHeight.Sub(1)` as the height parameter. The consensus contract's `GetRandomBytes` implementation retrieves deterministic random hash values stored per block height. [3](#0-2) 

The `ConvertHashToInt64` function is deterministic - for the same hash input and range parameters, it always returns the same integer value. [4](#0-3) 

When multiple transactions from the same sender are included in the same block:
- All transactions have identical `Context.Sender` values
- All transactions have identical `Context.CurrentHeight` values  
- All transactions receive identical `randomBytes` from the consensus contract
- All transactions compute identical `randomHash` values
- All transactions compute identical `randomNumber` values in each loop iteration

The first transaction succeeds and marks the generated number as used. [5](#0-4) 

Subsequent transactions with the same `randomHash` repeatedly compute the same `randomNumber`, find it marked as used, and loop indefinitely without any mechanism to vary the hash. This continues until the execution branch threshold is exceeded, causing the transaction to fail. [6](#0-5) 

The branch threshold enforcement throws a `RuntimeBranchThresholdExceededException` when the limit is reached. [7](#0-6) 

This vulnerability is triggered through the public `Create` method which is accessible to any user. [8](#0-7) 

## Impact Explanation

**Severity: HIGH**

The impact is severe for the following reasons:

1. **Denial of Service**: Users attempting to create multiple NFT protocols in rapid succession will have all transactions after the first one fail, regardless of intent.

2. **Financial Loss**: Users lose transaction fees for failed transactions that consume maximum execution resources (15,000 branch iterations) before failing.

3. **Resource Exhaustion**: Each failed transaction wastes computational resources executing 15,000 loop iterations before termination.

4. **No Workaround**: Users cannot bypass this issue except by waiting for the next block, which may not be immediately apparent to them.

5. **Core Functionality Impaired**: NFT protocol creation is a fundamental feature of the NFT contract, and its availability is compromised for common usage patterns.

6. **Protocol Invariant Violation**: The NFT uniqueness guarantee mechanism fails to function correctly, as the collision detection loop cannot find alternative numbers when collisions occur within the same block.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur frequently under normal operating conditions:

1. **No Privileges Required**: Any user can call the public `Create` method without special permissions.

2. **Common Scenario**: Users naturally submit multiple transactions in quick succession, especially through automated systems, wallets, or dApps. Transaction batching by block producers also groups multiple user transactions into single blocks.

3. **Deterministic Trigger**: The issue is completely deterministic - it will occur 100% of the time when the conditions are met (same sender, same block).

4. **Easy to Reproduce**: An attacker could intentionally trigger this by submitting multiple NFT creation transactions, or users could inadvertently trigger it through legitimate use.

5. **No Pre-existing Constraints**: There are no rate limits, delays, or other mechanisms preventing multiple transactions from the same sender in a single block.

6. **Immediate Visibility**: The failed transaction attempts occur immediately during block execution, making the issue persistent for any affected user.

## Recommendation

Modify the `GenerateSymbolNumber()` function to incorporate transaction-specific entropy that varies between transactions in the same block. The recommended fix is to include the transaction ID or a nonce in the random hash computation:

```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
    {
        Value = Context.CurrentHeight.Sub(1)
    }.ToBytesValue());
    
    // Include transaction ID to ensure uniqueness per transaction
    var randomHash = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        HashHelper.ComputeFrom(randomBytes),
        HashHelper.ComputeFrom(Context.TransactionId));  // Added transaction-specific entropy
    
    long randomNumber;
    do
    {
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

Alternatively, if the loop must retry, update the hash within the loop:

```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
    {
        Value = Context.CurrentHeight.Sub(1)
    }.ToBytesValue());
    
    var randomHash = HashHelper.ConcatAndCompute(
        HashHelper.ComputeFrom(Context.Sender),
        HashHelper.ComputeFrom(randomBytes));
    
    long randomNumber;
    var nonce = 0;
    do
    {
        var hashWithNonce = HashHelper.ConcatAndCompute(randomHash, HashHelper.ComputeFrom(nonce));
        randomNumber = Context.ConvertHashToInt64(hashWithNonce, from, from.Mul(10));
        nonce++;
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task NFT_Create_MultipleTransactionsFromSameSender_InSameBlock_ShouldFail()
{
    // Arrange: Initialize NFT contract
    await InitializeContracts();
    
    var sender = UserAccounts[0];
    var nftType = NFTType.Art.ToString();
    
    // Create first NFT protocol - this should succeed
    var createInput1 = new CreateInput
    {
        NftType = nftType,
        ProtocolName = "Test NFT 1",
        TotalSupply = 10000,
        IsBurnable = true,
        IssueChainId = ChainId,
        BaseUri = "https://test1.com/",
        IsTokenIdReuse = false
    };
    
    var result1 = await NFTContractStub.Create.SendAsync(createInput1);
    result1.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    var symbol1 = result1.Output.Value;
    
    // Create second NFT protocol from same sender in same block
    // This should fail with branch threshold exceeded
    var createInput2 = new CreateInput
    {
        NftType = nftType,
        ProtocolName = "Test NFT 2",
        TotalSupply = 10000,
        IsBurnable = true,
        IssueChainId = ChainId,
        BaseUri = "https://test2.com/",
        IsTokenIdReuse = false
    };
    
    // Execute in same block by not mining between transactions
    var result2 = await NFTContractStub.Create.SendAsync(createInput2);
    
    // Verify: Second transaction should fail with branch threshold exceeded
    result2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result2.TransactionResult.Error.ShouldContain("Contract branch threshold");
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-27)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-77)
```csharp
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L79-82)
```csharp
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L117-129)
```csharp
    public override Hash GetRandomHash(Int64Value input)
    {
        Assert(input.Value > 1, "Invalid block height.");
        Assert(Context.CurrentHeight >= input.Value, "Block height not reached.");
        return State.RandomHashes[input.Value] ?? Hash.Empty;
    }

    public override BytesValue GetRandomBytes(BytesValue input)
    {
        var height = new Int64Value();
        height.MergeFrom(input.Value);
        return GetRandomHash(height).ToBytesValue();
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L169-177)
```csharp
    public long ConvertHashToInt64(Hash hash, long start = 0, long end = long.MaxValue)
    {
        if (start < 0 || start > end) throw new ArgumentException("Incorrect arguments.");

        var range = end.Sub(start);
        var bigInteger = new BigInteger(hash.Value.ToByteArray());
        // This is safe because range is long type.
        var index = Math.Abs((long)(bigInteger % range));
        return index.Add(start);
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L29-35)
```csharp
    public void BranchCount()
    {
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");

        _branchCount++;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-20)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
```
