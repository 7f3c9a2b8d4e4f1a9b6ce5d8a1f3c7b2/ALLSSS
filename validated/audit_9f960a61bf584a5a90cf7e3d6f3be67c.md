# Audit Report

## Title
Deterministic Collision Causes Infinite Loop DoS in NFT Protocol Creation Due to Broken Length Expansion Logic

## Summary
The NFT contract's symbol generation mechanism contains two critical flaws that combine to create a permanent DoS vulnerability in NFT protocol creation: (1) a mathematically broken length expansion check that permanently caps the symbol number space at 9 digits, and (2) a deterministic collision loop that causes infinite hangs when duplicate numbers are generated.

## Finding Description

The vulnerability manifests in two interconnected components within the NFT contract's symbol generation logic:

**Component 1: Broken Length Expansion Logic**

The `GetCurrentNumberLength()` method attempts to expand the symbol number length when available space is exhausted. [1](#0-0)  However, the expansion condition is mathematically impossible to satisfy.

The initial length is set to 9 [2](#0-1) , and the flag is initialized to `10^(length-1)` = `10^8` = 100,000,000 [3](#0-2) . The expansion check multiplies this flag by 2 and checks if the resulting string length exceeds the current length [4](#0-3) .

Mathematical proof: When length = 9, flag = 100,000,000, and flag × 2 = 200,000,000 (still 9 digits). The condition checks if `9 > 9`, which is FALSE. Since `2 × 10^(n-1)` always produces exactly n digits (not n+1), the expansion will never trigger, permanently capping the symbol space at 9 digits (100,000,000 to 999,999,999).

**Component 2: Deterministic Infinite Loop**

The `GenerateSymbolNumber()` method computes a hash from the sender address and random bytes from the consensus contract once before entering the collision-detection loop [5](#0-4) . Inside the do-while loop, this unchanging hash is repeatedly passed to `Context.ConvertHashToInt64()` [6](#0-5) .

The `ConvertHashToInt64()` method performs deterministic BigInteger modulo arithmetic [7](#0-6) . Since the hash, start value, and end value never change between loop iterations, the same number is generated every time. If this number already exists in `IsCreatedMap` [8](#0-7) , the loop condition remains true forever, causing an infinite loop.

**Root Cause:** The code lacks mechanisms to (1) properly expand the number space when approaching exhaustion, and (2) regenerate fresh randomness when collisions occur.

## Impact Explanation

This vulnerability causes a **Critical-severity Denial of Service**:

**Operational Impact:**
Once a collision occurs, any transaction calling the `Create` method [9](#0-8)  will hang indefinitely in the collision loop. This completely blocks NFT protocol creation functionality on the mainchain, as the contract specifically restricts creation to the AELF mainchain [10](#0-9) .

**Probability Escalation:**
With 900 million possible 9-digit numbers (100,000,000 to 999,999,999), collision probability follows the birthday paradox. After approximately 30,000-50,000 NFT protocols are created, collision probability becomes significant. The first collision triggers permanent DoS.

**No Recovery Mechanism:**
The contract provides no administrative function to reset the symbol number space or clear collision states. Once triggered, the DoS is permanent unless the contract is replaced.

**Ecosystem Impact:**
All users attempting to create NFT protocols are affected. Since protocol creation is foundational for the NFT ecosystem, this breaks core functionality.

## Likelihood Explanation

**High Likelihood** for the following reasons:

**Public Entry Point:**
The `Create` method is a public override method callable by any user without special privileges [11](#0-10) .

**Natural Trigger Through Normal Usage:**
No attack is required. The vulnerability manifests naturally as more NFT protocols are created through legitimate operations. The call chain is: `Create()` → `GetSymbol()` [12](#0-11)  → `GenerateSymbolNumber()` [13](#0-12) .

**Deterministic Behavior:**
The execution path is completely deterministic. Once a hash that maps to an already-used number is generated, the infinite loop is inevitable due to the unchanging inputs to the hash-to-integer conversion function.

**Increasing Probability Over Time:**
As the NFT ecosystem grows and more protocols are created, collision probability increases quadratically according to the birthday paradox formula, making the vulnerability inevitable given sufficient usage.

## Recommendation

**Fix 1: Correct the Length Expansion Logic**
Change the expansion condition to properly detect when the number space needs to grow:
```csharp
// Instead of checking if flag*2 has more digits than current length
// Check if we've used most of the current space
var upperNumberFlag = flag.Mul(10); // Use 10x instead of 2x
if (upperNumberFlag.ToString().Length > State.CurrentSymbolNumberLength.Value)
{
    // Expansion logic...
}
```

**Fix 2: Regenerate Randomness on Collision**
Move the hash generation inside the loop to ensure fresh randomness on each iteration:
```csharp
private long GenerateSymbolNumber()
{
    var length = GetCurrentNumberLength();
    var from = 1L;
    for (var i = 1; i < length; i++) from = from.Mul(10);

    long randomNumber;
    do
    {
        // Generate fresh random bytes on each iteration
        var randomBytes = State.RandomNumberProviderContract.GetRandomBytes.Call(
            new Int64Value { Value = Context.CurrentHeight.Sub(1) }.ToBytesValue());
        var randomHash = HashHelper.ConcatAndCompute(
            HashHelper.ComputeFrom(Context.Sender),
            HashHelper.ComputeFrom(randomBytes));
        randomNumber = Context.ConvertHashToInt64(randomHash, from, from.Mul(10));
    } while (State.IsCreatedMap[randomNumber]);

    return randomNumber;
}
```

**Fix 3: Add Exhaustion Protection**
Implement a counter to prevent infinite loops and revert gracefully when collisions persist:
```csharp
const int MaxCollisionRetries = 100;
int attempts = 0;
do
{
    // ... generate randomNumber ...
    attempts++;
    Assert(attempts < MaxCollisionRetries, "Symbol number space exhausted, please expand length.");
} while (State.IsCreatedMap[randomNumber]);
```

## Proof of Concept

The vulnerability can be demonstrated with the following test scenario:

1. Create 50,000+ NFT protocols to fill the symbol number space and increase collision probability
2. Call `Create()` with parameters that generate a hash mapping to an already-used number
3. Observe that the transaction hangs indefinitely in the `GenerateSymbolNumber()` loop
4. The transaction will never complete because the same hash is used repeatedly, generating the same colliding number forever

The deterministic nature of `Context.ConvertHashToInt64()` [7](#0-6)  combined with the static hash in the loop [6](#0-5)  makes this a guaranteed infinite loop scenario once a collision occurs.

---

## Notes

This vulnerability is particularly severe because:
1. It affects core NFT functionality on the mainchain
2. It will inevitably occur through normal protocol usage (no attack required)
3. There is no recovery mechanism without contract replacement
4. The broken expansion logic ensures the problem cannot self-resolve by growing the number space
5. The deterministic collision behavior makes the DoS permanent once triggered

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L26-26)
```csharp
        var randomNumber = GenerateSymbolNumber();
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

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L10-10)
```csharp
    public MappedState<long, bool> IsCreatedMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-73)
```csharp
    public override StringValue Create(CreateInput input)
    {
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
        MakeSureTokenContractAddressSet();
        MakeSureRandomNumberProviderContractAddressSet();
        var symbol = GetSymbol(input.NftType);
        var tokenExternalInfo = GetTokenExternalInfo(input);
        var creator = input.Creator ?? Context.Sender;
        var tokenCreateInput = new MultiToken.CreateInput
        {
            Symbol = symbol,
            Decimals = 0, // Fixed
            Issuer = creator,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId,
            TokenName = input.ProtocolName,
            TotalSupply = input.TotalSupply,
            ExternalInfo = tokenExternalInfo
        };
        State.TokenContract.Create.Send(tokenCreateInput);

        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;

        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;

        Context.Fire(new NFTProtocolCreated
        {
            Symbol = tokenCreateInput.Symbol,
            Creator = tokenCreateInput.Issuer,
            IsBurnable = tokenCreateInput.IsBurnable,
            IssueChainId = tokenCreateInput.IssueChainId,
            ProtocolName = tokenCreateInput.TokenName,
            TotalSupply = tokenCreateInput.TotalSupply,
            Metadata = protocolInfo.Metadata,
            BaseUri = protocolInfo.BaseUri,
            IsTokenIdReuse = protocolInfo.IsTokenIdReuse,
            NftType = protocolInfo.NftType
        });

        return new StringValue
        {
            Value = symbol
        };
    }
```
