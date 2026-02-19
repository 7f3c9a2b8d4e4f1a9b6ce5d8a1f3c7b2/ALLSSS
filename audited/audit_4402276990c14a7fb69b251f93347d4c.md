# Audit Report

## Title
Infinite Loop in GenerateSymbolNumber() Causes DOS on NFT Protocol Creation Due to Collision Handling Flaw

## Summary
The `GenerateSymbolNumber()` method in the NFT contract contains a critical flaw where a collision-checking loop uses a static `randomHash` value that never changes between iterations. When a generated protocol number collides with an existing entry, the loop repeatedly checks the same number until AElf's branch count limit (15,000) is reached, causing transaction failure and preventing legitimate NFT protocol creation.

## Finding Description

The vulnerability exists in the `GenerateSymbolNumber()` private method which generates unique random numbers for NFT protocol symbols. The method computes a `randomHash` once before entering a collision-checking do-while loop. [1](#0-0) 

This static hash is then used repeatedly in the do-while loop to generate a number via `Context.ConvertHashToInt64()`. [2](#0-1) 

The `ConvertHashToInt64()` method is deterministic - it converts a hash to an integer using BigInteger modulo arithmetic, always returning the same value for identical inputs. [3](#0-2) 

**Attack Path:**

1. Any user calls the public `Create()` method to create an NFT protocol. [4](#0-3) 

2. `Create()` invokes `GetSymbol()` which calls `GenerateSymbolNumber()`. [5](#0-4) 

3. If the generated `randomNumber` already exists in `State.IsCreatedMap[randomNumber]`, the loop continues indefinitely because the same number is checked repeatedly.

4. After 15,000 iterations (AElf's branch count threshold), the transaction fails with a `RuntimeBranchThresholdExceededException`. [6](#0-5) 

**Why Existing Protections Fail:**

The `NumberMinLength` constant provides 900 million combinations (100,000,000 to 999,999,999). [7](#0-6) 

The `GetCurrentNumberLength()` expansion mechanism is ineffective for collision resolution because it only adjusts the number space based on static flag calculations, not actual protocol creation count. Furthermore, even if the space expands, the collision loop never regenerates the random hash to find an available number. [8](#0-7) 

## Impact Explanation

**HIGH Severity** - This vulnerability creates a Denial of Service condition for core NFT protocol creation functionality:

1. **Inevitable Failure**: As the number of NFT protocols increases, collision probability rises according to the birthday paradox. With a 900 million number space, approximately 30,000 protocols create significant collision risk.

2. **Permanent Degradation**: Users attempting to create protocols will experience transaction failures when their deterministically generated number collides with existing entries. There is no recovery mechanism - users must retry in the next block hoping for different randomness.

3. **No Workaround**: The randomness is based on `Context.CurrentHeight` and `Context.Sender`, making it difficult for users to control or predict successful outcomes.

4. **Protocol Unusability**: The NFT protocol creation functionality becomes increasingly unreliable and eventually unusable as the protocol count grows, affecting all legitimate users, NFT platform operators, and DApp developers building on AElf's NFT infrastructure.

## Likelihood Explanation

**MEDIUM-HIGH Likelihood** - This vulnerability will manifest naturally as the NFT ecosystem matures:

1. **Public Access**: The `Create()` method is public and only requires a chain ID check (must be mainchain), with no rate limiting or additional permission checks. [9](#0-8) 

2. **Low Attack Complexity**: An attacker can simply call `Create()` repeatedly with valid parameters to increase collision probability.

3. **Inevitable Collision**: The birthday paradox ensures that collisions become increasingly likely as legitimate protocols accumulate over time. The vulnerability will trigger naturally without malicious intent.

4. **Deterministic Behavior**: The same sender in the same block will always generate the same random number, making collision effects predictable and reproducible.

## Recommendation

Regenerate the random hash inside the collision-checking loop to ensure a different number is attempted on each iteration:

```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    long randomNumber;
    var attemptCount = 0;
    do
    {
        // Regenerate random hash on each attempt
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1).Add(attemptCount)
        }.ToBytesValue());
        var randomHash = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes),
            HashHelper.ComputeFrom(attemptCount));
        
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
        attemptCount++;
        
        // Add safety limit to prevent infinite loop
        if (attemptCount > 100)
        {
            throw new AssertionException("Unable to generate unique protocol number after 100 attempts");
        }
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task InfiniteLoop_DOS_On_Collision_Test()
{
    // Step 1: Create first protocol successfully - this marks a number as used
    var createInput1 = new CreateInput
    {
        NftType = NFTType.Art.ToString(),
        ProtocolName = "Test Protocol 1",
        TotalSupply = 10000,
        BaseUri = "https://test.com/",
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    };
    var result1 = await NFTContractStub.Create.SendAsync(createInput1);
    result1.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 2: Manually set State.IsCreatedMap for a specific number
    // to simulate collision scenario
    var collisionNumber = 123456789L;
    await NFTContractStub.TestSetIsCreatedMap.SendAsync(new Int64Value { Value = collisionNumber });
    
    // Step 3: Mock the random number generation to return our collision number
    // This requires modifying RandomNumberProviderContract to return predictable value
    await MockRandomToReturnSpecificNumber(collisionNumber);
    
    // Step 4: Attempt to create second protocol - should hit infinite loop
    var createInput2 = new CreateInput
    {
        NftType = NFTType.Music.ToString(),
        ProtocolName = "Test Protocol 2",
        TotalSupply = 5000,
        BaseUri = "https://test2.com/",
        IsBurnable = false,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    };
    
    // Transaction should fail with branch count exceeded
    var result2 = await NFTContractStub.Create.SendWithExceptionAsync(createInput2);
    result2.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result2.TransactionResult.Error.ShouldContain("branch count");
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L7-7)
```csharp
    public const int ExecutionBranchThreshold = 15000;
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```
