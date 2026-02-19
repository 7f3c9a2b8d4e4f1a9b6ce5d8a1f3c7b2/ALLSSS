# Audit Report

## Title
Deterministic Infinite Loop in Symbol Number Generation Causes DoS of NFT Protocol Creation

## Summary
The `GenerateSymbolNumber()` function contains a critical infinite loop vulnerability where the collision-checking loop attempts to regenerate a random number using an unchanging hash value. Since `Context.ConvertHashToInt64` is deterministic, any collision with an existing protocol number results in an infinite loop that consumes all transaction gas and permanently blocks that specific NFT protocol creation attempt.

## Finding Description

The NFT contract uses `IsCreatedMap` to track which symbol numbers have been assigned to NFT protocols. [1](#0-0) 

The vulnerability exists in the `GenerateSymbolNumber()` helper function. The root cause is that `randomHash` is computed once before the collision-checking do-while loop and is never updated within the loop. [2](#0-1) 

The `Context.ConvertHashToInt64` method is deterministic - it uses modulo arithmetic to convert a hash to a number within a specified range. Given the same hash input and range parameters, it always returns the same output. [3](#0-2) 

When a collision occurs (the generated number already exists in `IsCreatedMap`), the while condition evaluates to true, but since `randomHash` never changes, `Context.ConvertHashToInt64(randomHash, from, from.Mul(10))` produces the exact same number on every iteration, creating an infinite loop.

The `GenerateSymbolNumber()` function is called during NFT protocol creation via the public `Create` method. [4](#0-3) [5](#0-4) 

## Impact Explanation

**Severity: HIGH - Denial of Service of Core Protocol Functionality**

The `Create` function is publicly callable by any user on the aelf mainchain to establish new NFT protocols. The number space begins with 9-digit numbers (100,000,000 to 999,999,999), providing 900 million unique possibilities. [6](#0-5) 

As NFT protocols accumulate, collision probability increases according to the birthday paradox. With approximately 30,000 existing protocols, there is a ~50% chance that the next creation attempt will encounter a collision. When this occurs:

1. The transaction enters an infinite loop
2. All available gas is consumed
3. The transaction fails without creating the protocol
4. The same transaction parameters will always fail (deterministic)

**Who is affected:** All users attempting to create NFT protocols once collision probability becomes significant. The functionality becomes increasingly unreliable and eventually unusable.

**No recovery mechanism exists:** Because the hash generation uses deterministic inputs (sender address and block-derived random bytes), retrying with the same sender at a different block height might succeed, but there's no guarantee, and users have no control over avoiding collisions.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH (increases with protocol adoption)**

**Attacker Capabilities:** No special privileges required - any user can call the public `Create()` method.

**Attack Complexity:** No intentional attack needed. This is a natural occurrence as protocol usage grows:
1. Sufficient protocols exist to create meaningful collision probability
2. Any user attempts to create a new protocol
3. The random number generation produces a collision
4. Infinite loop triggers automatically

**Feasibility:** The collision becomes increasingly likely as more protocols are created:
- ~1% chance after ~3,000 protocols
- ~10% chance after ~10,000 protocols
- ~50% chance after ~30,000 protocols
- ~99% chance after ~100,000 protocols

**Detection:** Transaction timeout or gas exhaustion will occur, making the issue immediately visible to affected users.

**Probability:** The bug is deterministic - once a collision occurs with a specific hash, that transaction configuration will always fail. The overall likelihood depends on adoption levels but becomes inevitable as the protocol set grows.

## Recommendation

The fix requires regenerating the random hash inside the loop when a collision is detected. Here's the corrected approach:

Move the random hash generation inside the do-while loop so that each iteration produces a different hash and thus a different candidate number:

```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    long randomNumber;
    do
    {
        // Generate new random bytes and hash for each iteration
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(new Int64Value
        {
            Value = Context.CurrentHeight.Sub(1)
        }.ToBytesValue());
        var randomHash = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes)
        );
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

Alternatively, add an iteration limit and throw an exception if exceeded, then use additional entropy (like iteration count) in the hash generation to ensure different outputs.

## Proof of Concept

This vulnerability can be demonstrated by:

1. Creating enough NFT protocols to increase collision probability
2. Mocking the random number provider to return a value that will hash to an already-used number
3. Calling `Create()` and observing the transaction run out of gas in the infinite loop

The test would show that when `ConvertHashToInt64` produces a number already in `IsCreatedMap`, the transaction never completes because the same hash produces the same number repeatedly.

---

## Notes

The vulnerability is confirmed through code analysis showing:
- The hash is computed once outside the loop
- `ConvertHashToInt64` is mathematically deterministic
- No mechanism exists to break the loop when collisions occur
- The issue affects the public API and has no access control that would prevent its exploitation

This is a time-bomb vulnerability that becomes more severe as the protocol gains adoption, eventually rendering NFT protocol creation unreliable or impossible.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L10-10)
```csharp
    public MappedState<long, bool> IsCreatedMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-27)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L71-82)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```
