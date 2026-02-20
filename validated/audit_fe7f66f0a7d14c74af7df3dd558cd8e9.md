# Audit Report

## Title
Infinite Loop in GenerateSymbolNumber() Causes DOS on NFT Protocol Creation Due to Collision Handling Flaw

## Summary
The NFT contract's `GenerateSymbolNumber()` method contains a critical design flaw where the random hash used for number generation is computed only once before entering a collision-checking loop. When a collision occurs, the deterministic `ConvertHashToInt64()` function produces the same number repeatedly until AElf's 15,000 branch count limit is reached, causing transaction failure and preventing legitimate NFT protocol creation.

## Finding Description

The vulnerability exists in the `GenerateSymbolNumber()` method where collision handling is fundamentally broken. [1](#0-0) 

The method computes `randomHash` once using the consensus contract's random bytes combined with the sender's address (lines 71-77). This hash is then used in a do-while loop to generate numbers (lines 79-82). The critical flaw is that `Context.ConvertHashToInt64()` is a deterministic function. [2](#0-1) 

This implementation uses BigInteger modulo arithmetic, meaning identical inputs always produce identical outputs. Since `randomHash`, `from`, and `from.Mul(10)` never change during loop iterations, the same `randomNumber` is generated repeatedly.

When a collision occurs (the number exists in `State.IsCreatedMap`), the loop continues indefinitely checking the same number until AElf's execution observer terminates the transaction. [3](#0-2) 

**Execution Path:**
1. Any user calls the public `Create()` method [4](#0-3) 
2. `GetSymbol()` invokes `GenerateSymbolNumber()` [5](#0-4) 
3. On collision, the transaction runs 15,000 iterations before failing with a branch count exceeded error [6](#0-5) 

The number space is initially 900 million combinations (100,000,000 to 999,999,999). [7](#0-6) 

While the protocol includes a space expansion mechanism [8](#0-7) , this doesn't help resolve collisions because the loop never regenerates the hash or calls `GetCurrentNumberLength()` again.

## Impact Explanation

This vulnerability causes a **Denial of Service** on the NFT protocol creation functionality with severe consequences:

1. **Transaction Failure**: Users whose generated numbers collide with existing protocols will experience transaction failures after 15,000 iterations, wasting gas fees and blocking protocol creation.

2. **Increasing Collision Probability**: Following the birthday paradox, collision probability grows significantly as the protocol count increases. With 900 million possible numbers, approximately 30,000 protocols create a substantial collision risk.

3. **No Recovery Mechanism**: Affected users cannot retry or work around the issue because the random generation depends on `Context.CurrentHeight` and `Context.Sender`, which produce the same deterministic hash until the block height changes or they use a different account.

4. **Protocol Degradation**: As the NFT ecosystem matures and more protocols are created, the collision rate will increase, eventually rendering the protocol creation functionality unreliable or completely unusable.

5. **Legitimate User Impact**: This affects all users, developers, and platforms attempting to create NFT protocols on the AElf mainchain, degrading the core value proposition of the NFT contract system.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability will manifest naturally over time:

1. **Public Access**: The `Create()` method is publicly accessible with only a chain ID validation check. [9](#0-8)  No rate limiting or permission controls prevent repeated invocations.

2. **Deterministic Randomness**: The pseudo-random generation is deterministic based on block height and sender address, making collisions predictable for sophisticated actors who can calculate which combinations will collide.

3. **Mathematical Inevitability**: Following birthday paradox statistics, collision probability increases with the square root of attempts. In a 900 million number space, significant collision risk emerges around 30,000 protocols.

4. **Natural Accumulation**: Even without malicious intent, legitimate protocol creation will eventually trigger this condition as the ecosystem grows.

5. **No Detection/Prevention**: The system has no mechanism to detect collision patterns or prevent users from encountering this DOS condition.

## Recommendation

Fix the collision handling by regenerating the hash or incrementing a nonce value inside the loop. Here's a recommended approach:

**Option 1: Regenerate hash with loop counter**
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
    
    long randomNumber;
    var nonce = 0L;
    do
    {
        var randomHash = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes),
            HashHelper.ComputeFrom(nonce));
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        nonce++;
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

**Option 2: Use transaction ID as additional entropy**
```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    long randomNumber;
    var nonce = 0L;
    do
    {
        var randomHash = HashHelper.ConcatAndCompute(
            Context.TransactionId,
            HashHelper.ComputeFrom(nonce));
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        nonce++;
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

Both solutions ensure that each loop iteration generates a different hash, preventing the infinite loop on collision.

## Proof of Concept

A test demonstrating this vulnerability would:

1. Pre-populate `State.IsCreatedMap` with a specific number
2. Mock the consensus contract to return predictable random bytes
3. Craft sender address such that the generated number collides
4. Call `Create()` and observe `RuntimeBranchThresholdExceededException`

The test would verify that when collision occurs, the loop executes exactly 15,000 times before failing, confirming the deterministic behavior and branch count limit enforcement.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-27)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L65-85)
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
        var randomHash =
            HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(Context.Sender),
                HashHelper.ComputeFrom(randomBytes));
        long randomNumber;
        do
        {
            randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        } while (State.IsCreatedMap[randomNumber]);

        return randomNumber;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L87-116)
```csharp
    private int GetCurrentNumberLength()
    {
        if (State.CurrentSymbolNumberLength.Value == 0) State.CurrentSymbolNumberLength.Value = NumberMinLength;

        var flag = State.NftProtocolNumberFlag.Value;

        if (flag == 0)
        {
            // Initial protocol number flag.
            var protocolNumber = 1;
            for (var i = 1; i < State.CurrentSymbolNumberLength.Value; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            flag = protocolNumber;
        }

        var upperNumberFlag = flag.Mul(2);
        if (upperNumberFlag.ToString().Length > State.CurrentSymbolNumberLength.Value)
        {
            var newSymbolNumberLength = State.CurrentSymbolNumberLength.Value.Add(1);
            State.CurrentSymbolNumberLength.Value = newSymbolNumberLength;
            var protocolNumber = 1;
            for (var i = 1; i < newSymbolNumberLength; i++) protocolNumber = protocolNumber.Mul(10);

            State.NftProtocolNumberFlag.Value = protocolNumber;
            return newSymbolNumberLength;
        }

        return State.CurrentSymbolNumberLength.Value;
    }
```

**File:** src/AElf.Kernel.SmartContract/HostSmartContractBridgeContext.cs (L169-178)
```csharp
    public long ConvertHashToInt64(Hash hash, long start = 0, long end = long.MaxValue)
    {
        if (start < 0 || start > end) throw new ArgumentException("Incorrect arguments.");

        var range = end.Sub(start);
        var bigInteger = new BigInteger(hash.Value.ToByteArray());
        // This is safe because range is long type.
        var index = Math.Abs((long)(bigInteger % range));
        return index.Add(start);
    }
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
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

**File:** src/AElf.Sdk.CSharp/ExecutionObserver.cs (L29-36)
```csharp
    public void BranchCount()
    {
        if (_branchThreshold != -1 && _branchCount == _branchThreshold)
            throw new RuntimeBranchThresholdExceededException(
                $"Contract branch threshold {_branchThreshold} exceeded.");

        _branchCount++;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```
