# Audit Report

## Title
Mathematically Impossible Length Increase Check Permanently Caps NFT Protocol Symbol Space at 900 Million

## Summary
The `GetCurrentNumberLength()` function contains a mathematically flawed condition that can never evaluate to true, preventing the symbol number length from increasing beyond 9. This permanently caps the NFT protocol symbol space at approximately 900 million symbols, eventually causing denial of service when the number space approaches exhaustion.

## Finding Description

The vulnerability exists in the length increase logic that is designed to dynamically scale the symbol number space as more NFT protocols are created. [1](#0-0) 

The system initializes `CurrentSymbolNumberLength` to 9 and calculates the protocol number flag as 10^(length-1). [2](#0-1) 

The critical flaw lies in the condition that should trigger a length increase: [3](#0-2) 

**Mathematical Proof of Impossibility:**

For currentLength = n:
- flag = 10^(n-1)
- upperNumberFlag = 2 × 10^(n-1) = 0.2 × 10^n
- A number requires ≥ 10^n to have (n+1) digits
- Since 0.2 × 10^n < 10^n, upperNumberFlag always has exactly n digits
- Therefore, `upperNumberFlag.ToString().Length > n` is always false

**Concrete Example (n=9):**
- flag = 100,000,000 (10^8)
- upperNumberFlag = 200,000,000
- "200000000".Length = 9
- Check: 9 > 9? **FALSE** ✗

The flag is only updated during initialization (when flag=0) and inside the length increase block. Since the condition never triggers, this creates an impossible circular dependency where the length can never increase.

**Execution Path:**

The vulnerability is triggered through normal NFT protocol creation flow: [4](#0-3) 

This calls `GetSymbol()` which invokes: [5](#0-4) 

Which calls `GenerateSymbolNumber()`: [6](#0-5) 

## Impact Explanation

**Operational Impact - Denial of Service:**

The symbol generation space is permanently capped at the range [100,000,000, 1,000,000,000), providing only 900 million possible protocol symbols. The random number generation uses a do-while loop that continues until finding an unused number. [7](#0-6) 

Used numbers are tracked in the state: [8](#0-7) 

**Progressive Degradation:**
1. As symbols are created and marked as used, collision probability increases exponentially (birthday paradox)
2. The do-while loop requires more iterations to find unused numbers
3. Transaction gas costs increase as the space fills
4. Eventually, the loop becomes unable to find unused numbers within reasonable time/gas limits
5. Once approaching 900 million protocols, new protocol creation permanently fails

**Who Is Affected:**
- All users attempting to create new NFT protocols after space exhaustion
- The entire NFT ecosystem becomes unable to expand
- No new NFT collections can be registered

**Severity Justification:**
While 900 million is substantial, this represents a hard cap with no recovery mechanism. The intended dynamic expansion logic is completely non-functional, fundamentally breaking the system's design invariant that it should scale as needed.

## Likelihood Explanation

**Certainty:** The vulnerability is deterministic and always present due to the mathematical impossibility of the condition. This is not a "might happen" scenario - the logic is provably broken.

**Preconditions:** None required beyond normal system operation. The `Create()` method is publicly accessible with only a chain ID assertion: [9](#0-8) 

**Feasibility:** This is not an active attack but an inevitable consequence of the flawed logic. As the protocol grows and more NFT collections are created through normal usage, the space will eventually fill.

**Timeline Consideration:** While reaching 900 million protocols may take considerable time in practice, the bug fundamentally breaks the intended auto-scaling mechanism. Earlier impact manifests through:
- Increased collision rates causing progressively slower symbol generation
- Unpredictable transaction failures as the space fills
- System behavior diverging from design expectations

**Economic Rationality:** No attack cost - this occurs through normal legitimate usage patterns.

## Recommendation

Fix the length increase condition to properly detect when the flag has grown to require more digits. The issue is that multiplying by 2 never produces enough digits to trigger the expansion.

**Option 1:** Change the multiplier from 2 to 10:
```csharp
var upperNumberFlag = flag.Mul(10); // Instead of Mul(2)
if (upperNumberFlag.ToString().Length > State.CurrentSymbolNumberLength.Value)
```

**Option 2:** Track the actual count of created protocols and trigger expansion at predefined thresholds:
```csharp
var protocolCount = State.ProtocolCount.Value;
var maxForCurrentLength = (long)Math.Pow(10, State.CurrentSymbolNumberLength.Value) - 
                          (long)Math.Pow(10, State.CurrentSymbolNumberLength.Value - 1);
if (protocolCount >= maxForCurrentLength * 0.9) // Trigger at 90% capacity
{
    // Increase length
}
```

**Option 3:** Direct comparison against the upper bound:
```csharp
var upperBound = (long)Math.Pow(10, State.CurrentSymbolNumberLength.Value);
if (flag >= upperBound / 2) // When flag reaches half of upper bound
{
    // Increase length
}
```

## Proof of Concept

```csharp
[Fact]
public void Test_LengthNeverIncreases()
{
    // Simulate the GetCurrentNumberLength logic
    int currentLength = 9; // NumberMinLength
    long flag = 1;
    
    // Initialize flag as the contract does
    for (int i = 1; i < currentLength; i++)
        flag = flag * 10;
    
    // flag = 100,000,000 (10^8)
    Assert.Equal(100_000_000, flag);
    
    // Calculate upperNumberFlag
    long upperNumberFlag = flag * 2;
    Assert.Equal(200_000_000, upperNumberFlag);
    
    // Check the condition
    int upperDigits = upperNumberFlag.ToString().Length;
    Assert.Equal(9, upperDigits);
    
    // The condition that should trigger length increase
    bool shouldIncrease = upperDigits > currentLength;
    
    // This proves the condition NEVER triggers
    Assert.False(shouldIncrease);
    
    // Mathematically, for any length n:
    // flag = 10^(n-1)
    // upperNumberFlag = 2 * 10^(n-1)
    // upperNumberFlag always has exactly n digits
    // Therefore n > n is always false
}
```

## Notes

This vulnerability represents a fundamental design flaw in the auto-scaling mechanism. The mathematical impossibility means the system will never behave as intended, regardless of usage patterns. While the 900 million cap may seem sufficient for current needs, the broken scaling logic represents a violation of the protocol's design guarantees and will eventually lead to a hard DoS condition with no recovery path.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L87-101)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L103-113)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L10-10)
```csharp
    public MappedState<long, bool> IsCreatedMap { get; set; }
```
