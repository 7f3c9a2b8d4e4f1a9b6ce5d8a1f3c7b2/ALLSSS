# Audit Report

## Title
Integer Overflow DoS in NFT Protocol Number Generation Due to Incorrect Type Inference

## Summary
The `GetCurrentNumberLength()` function uses C# type inference to declare a local variable `protocolNumber` as `int` when calculating powers of 10. When `CurrentSymbolNumberLength` reaches 11, the calculation attempts to compute 10^10 (10,000,000,000), which exceeds `int.MaxValue` (2,147,483,647). SafeMath's checked arithmetic throws an `OverflowException`, causing permanent denial-of-service for all NFT protocol creation operations.

## Finding Description

The vulnerability exists in the `GetCurrentNumberLength()` helper function at two critical locations. [1](#0-0) [2](#0-1) 

The root cause is C# type inference. The local variable is initialized with the integer literal `1`, causing the compiler to infer it as `int` (32-bit) rather than `long` (64-bit). The loop calculates 10^(length-1) through repeated multiplication by 10.

Starting from the minimum length of 9, the system tracks a protocol number flag. [3](#0-2) 

When `CurrentSymbolNumberLength` reaches 11, the calculation attempts 10^10 = 10,000,000,000. SafeMath multiplication uses checked arithmetic that explicitly throws on overflow: [4](#0-3) 

While the state variables are properly typed as `Int64State` to handle large values [5](#0-4) , the local variable calculation fails before the value can be stored.

The vulnerable code path is triggered through the public `Create()` method: [6](#0-5) 

Which calls `GetSymbol()`, then `GenerateSymbolNumber()`, and finally `GetCurrentNumberLength()`: [7](#0-6) [8](#0-7) 

## Impact Explanation

**Severity: High** - Complete operational DoS of core NFT functionality.

Once `CurrentSymbolNumberLength` reaches 11, all calls to `Create()` will fail permanently with an `OverflowException`. The NFT protocol creation functionality becomes completely unusable with no recovery mechanism.

**Affected Parties:**
- All users attempting to create new NFT protocols
- NFT creators unable to deploy new collections
- Platform operations dependent on NFT protocol creation
- The entire NFT ecosystem on the chain

**Why High Severity:**
1. Causes permanent, unrecoverable DoS of a core contract function
2. No administrative action can restore functionality without contract upgrade
3. The threshold (length 11) is reachable through normal protocol usage
4. Once triggered, the impact is immediate and total
5. Affects all users system-wide, not just individual actors

## Likelihood Explanation

**Probability: Medium to High**

**Natural Occurrence:** The vulnerability will trigger through normal platform growth. Starting at length 9, the system can generate approximately 900 million unique protocols before incrementing to length 10. At length 10, another ~9 billion protocols can be created before reaching length 11, where overflow occurs immediately.

**Attack Acceleration:** An attacker can deliberately accelerate reaching this threshold by creating multiple NFT protocols. Each call to `Create()` is public and unrestricted (only requires being on mainchain and paying gas fees). The attack complexity is low - simply call `Create()` repeatedly with valid inputs.

**Execution Practicality:**
- Entry point is the public `Create()` method - no special permissions required
- No preconditions beyond standard transaction fees and mainchain validation
- Attack is executable under normal AElf contract execution model
- Economic cost is reasonable for an attacker seeking to DoS the protocol
- Detection is difficult - appears as legitimate protocol creation until overflow occurs

The vulnerability is certain to occur given sufficient time and protocol growth, and can be deliberately triggered by malicious actors.

## Recommendation

Change the type inference for `protocolNumber` from `int` to `long` by using the `L` suffix on the literal or explicit type declaration:

**Option 1 - Use long literal suffix:**
```csharp
var protocolNumber = 1L;  // Inferred as long
```

**Option 2 - Explicit type declaration:**
```csharp
long protocolNumber = 1;
```

Apply this fix at both locations (lines 96 and 108) in the `GetCurrentNumberLength()` function. This ensures the calculation can handle values up to 10^18 without overflow, well beyond any realistic protocol count.

## Proof of Concept

```csharp
[Fact]
public async Task IntegerOverflowDoS_WhenLengthReaches11()
{
    // Simulate state where CurrentSymbolNumberLength would increment to 11
    // This would happen naturally after ~9 billion protocols at length 10
    
    // Set up state to trigger overflow
    var nftContractState = GetRequiredService<NFTContractState>();
    nftContractState.CurrentSymbolNumberLength.Value = 10;
    
    // Set flag to a value that will trigger length increment
    // When flag * 2 has more digits than CurrentSymbolNumberLength
    long flagValue = 5_000_000_000L; // 10 digits, * 2 = 10 billion (11 digits)
    nftContractState.NftProtocolNumberFlag.Value = flagValue;
    
    // Attempt to create NFT protocol - this will call GetCurrentNumberLength()
    // which will try to calculate 10^10 in an int variable
    var exception = await Assert.ThrowsAsync<OverflowException>(async () =>
    {
        await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = "ipfs://test/",
            Creator = DefaultAddress,
            IsBurnable = true,
            NftType = NFTType.Art.ToString(),
            ProtocolName = "TEST",
            TotalSupply = 1_000_000
        });
    });
    
    exception.ShouldNotBeNull();
    // After this point, ALL Create() calls will fail permanently
}
```

**Notes:**
- The vulnerability is deterministic and will occur when the calculated length reaches 11
- State variables `NftProtocolNumberFlag` (Int64State) and `CurrentSymbolNumberLength` (Int32State) are correctly typed
- The bug is isolated to the local variable type inference in the calculation loop
- The fix is straightforward: change `var protocolNumber = 1;` to `var protocolNumber = 1L;` at both locations

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-27)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L65-67)
```csharp
    private long GenerateSymbolNumber()
    {
        var length = GetCurrentNumberLength();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L96-97)
```csharp
            var protocolNumber = 1;
            for (var i = 1; i < State.CurrentSymbolNumberLength.Value; i++) protocolNumber = protocolNumber.Mul(10);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L108-109)
```csharp
            var protocolNumber = 1;
            for (var i = 1; i < newSymbolNumberLength; i++) protocolNumber = protocolNumber.Mul(10);
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L13-19)
```csharp
    public static int Mul(this int a, int b)
    {
        checked
        {
            return a * b;
        }
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L8-9)
```csharp
    public Int64State NftProtocolNumberFlag { get; set; }
    public Int32State CurrentSymbolNumberLength { get; set; }
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
