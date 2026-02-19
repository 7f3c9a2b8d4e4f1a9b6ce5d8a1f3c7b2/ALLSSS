### Title
Hash Collision via Ambiguous String Concatenation in CalculateTokenHash()

### Summary
The `CalculateTokenHash()` function concatenates NFT symbol and tokenId without a delimiter, creating potential hash collisions across different (symbol, tokenId) pairs. While the specific example in the question (tokenId='C123') is impossible due to type constraints (tokenId is `long`, not string), numeric collisions are feasible when protocols have varying symbol lengths, leading to Denial of Service where legitimate NFT minting fails.

### Finding Description

The root cause is in the `CalculateTokenHash()` function: [1](#0-0) 

The function uses ambiguous string interpolation `$"{symbol}{tokenId}"` without a delimiter. This creates collision scenarios:
- Symbol="ABC1", tokenId=23 → hash("ABC123")
- Symbol="ABC", tokenId=123 → hash("ABC123") ← COLLISION

**Important Clarification**: The question's example "tokenId=C123" is **impossible** because tokenId is type `long` (numeric only). [1](#0-0) 

In the NFT contract context, symbols follow the format: 2-character NFT type prefix + random number (minimum 9 digits). [2](#0-1) [3](#0-2) 

Realistic collision example:
- Protocol A (early creation): Symbol="VW12345678" (10 chars), tokenId=91 → hash("VW123456789 1")
- Protocol B (later creation): Symbol="VW123456789" (11 chars), tokenId=1 → hash("VW1234567891") ← SAME HASH

The tokenHash is used as the key in critical state mappings: [4](#0-3) 

The minting process includes a collision check: [5](#0-4) 

This check prevents data corruption but **creates a DoS vector**: when a collision occurs, the second mint fails with "Token id already exists", blocking legitimate NFT creation even though they're from different protocols.

User-specified tokenIds are allowed in `MintInput`: [6](#0-5) 

Symbol lengths can vary through cross-chain protocol imports: [7](#0-6) 

### Impact Explanation

**Concrete Impact**:
1. **Denial of Service**: Legitimate users cannot mint NFTs with specific tokenIds because the hash is already occupied by a different protocol's NFT
2. **Protocol Disruption**: Malicious minters can strategically occupy hash values to block future NFT creation across protocols
3. **User Experience Degradation**: Confusing error messages ("Token id already exists") when the tokenId doesn't actually exist in the current protocol

**Affected Parties**:
- Legitimate NFT creators who encounter pre-occupied hash values
- NFT protocol owners whose tokenId space is effectively reduced
- End users who cannot mint desired tokenIds

**Severity Justification**: Medium - While this creates operational disruption and DoS, it doesn't result in direct fund theft. The impact is limited to specific tokenId values and requires preconditions to exploit.

### Likelihood Explanation

**Attacker Capabilities Required**:
1. Minter privileges in a protocol with appropriate symbol length
2. Knowledge of or ability to predict target protocol symbols
3. Ability to mint with specific tokenIds

**Attack Complexity**: Medium
- Requires protocols with different symbol lengths to exist (e.g., 10-char vs 11-char symbols)
- With `NumberMinLength=9`, all locally created protocols have 11+ character symbols
- Varying lengths likely only through cross-chain imports or historical protocols
- Attacker must calculate collision-producing tokenId values

**Feasibility Conditions**:
- Cross-chain protocol imports that may have shorter symbols
- Historical protocols created before symbol length increases
- Attacker holds minter role in at least one protocol

**Detection/Operational Constraints**:
- Collisions manifest as failed mint transactions
- Defensive monitoring could detect systematic collision attempts
- Impact limited to specific tokenId values per protocol pair

**Probability Reasoning**: LOW to MEDIUM
- Preconditions (varying symbol lengths) are uncommon but possible
- Cross-chain scenarios increase likelihood
- Economic incentive mainly griefing rather than profit
- Exploitation requires coordination and specific preconditions

### Recommendation

**Code-Level Mitigation**:
Replace ambiguous concatenation with a delimiter-based approach:

```csharp
private Hash CalculateTokenHash(string symbol, long tokenId)
{
    return HashHelper.ComputeFrom($"{symbol}:{tokenId}");
    // Or use structured hashing: HashHelper.ConcatAndCompute(HashHelper.ComputeFrom(symbol), HashHelper.ComputeFrom(tokenId))
}
```

**Invariant Checks**:
- Add validation to ensure tokenHash uniqueness check includes symbol verification
- Consider storing (symbol, tokenId) tuple directly rather than relying solely on hash

**Test Cases**:
1. Create two protocols with symbols differing by one character suffix
2. Attempt to mint NFTs with calculated collision tokenIds
3. Verify that both mints succeed without interference
4. Test cross-chain imported protocols with varying symbol lengths
5. Validate that all (symbol, tokenId) combinations produce unique hashes

**Migration Strategy**:
- Fix can be deployed as an upgrade
- Existing NFTs use current hash scheme (preserved in mappings)
- New mints use delimiter-based hashing
- Consider migration path for existing NFTs if hash scheme changes

### Proof of Concept

**Required Initial State**:
1. Protocol A exists with symbol "VW12345678" (10 characters) - imported via CrossChainCreate
2. Protocol B created with symbol "VW123456789" (11 characters) - standard local creation
3. Attacker has minter privileges in Protocol A

**Transaction Steps**:
1. Attacker calculates collision: hash("VW1234567891") can be created by:
   - Protocol A: symbol="VW12345678", tokenId=91
   - Protocol B: symbol="VW123456789", tokenId=1

2. Attacker calls `Mint()` on Protocol A with:
   - Symbol: "VW12345678"
   - TokenId: 91
   - Result: NFT minted successfully, occupies hash("VW123456789 1")

3. Legitimate user calls `Mint()` on Protocol B with:
   - Symbol: "VW123456789"
   - TokenId: 1
   - Expected: NFT minted successfully
   - **Actual**: Transaction fails with "Token id 1 already exists"

**Success Condition**:
The legitimate user's mint transaction fails due to hash collision with Protocol A's NFT, even though tokenId=1 does not exist in Protocol B's namespace. The DoS is confirmed when `State.NftInfoMap[tokenHash]` returns Protocol A's NFT info during Protocol B's mint attempt.

### Notes

1. **Critical Clarification**: The question's specific example "tokenId=C123" is **technically impossible** because tokenId parameter is type `long` (numeric integer), not string. The character 'C' cannot be part of a long value.

2. **Actual Exploitable Scenario**: The vulnerability manifests with **numeric tokenIds** creating collisions through ambiguous concatenation (e.g., "ABC1"+23 vs "ABC"+123).

3. **Practical Constraints**: With `NumberMinLength=9`, locally created protocols have consistent symbol lengths (minimum 11 characters), reducing collision likelihood. Varying lengths primarily arise from cross-chain imports.

4. **Severity Downgrade**: While the question labels this "High", the actual severity is **Medium** due to low exploitation likelihood and DoS-only impact (no fund theft).

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L52-54)
```csharp
        Assert(State.BalanceMap[tokenHash][from] >= amount, "Insufficient balance.");
        State.BalanceMap[tokenHash][from] = State.BalanceMap[tokenHash][from].Sub(amount);
        State.BalanceMap[tokenHash][to] = State.BalanceMap[tokenHash][to].Add(amount);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L330-333)
```csharp
    private Hash CalculateTokenHash(string symbol, long tokenId)
    {
        return HashHelper.ComputeFrom($"{symbol}{tokenId}");
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L392-396)
```csharp
        var tokenId = input.TokenId == 0 ? protocolInfo.Issued.Add(1) : input.TokenId;
        var tokenHash = CalculateTokenHash(input.Symbol, tokenId);
        var nftInfo = State.NftInfoMap[tokenHash];
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContractConstants.cs (L5-5)
```csharp
    private const int NumberMinLength = 9;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L24-37)
```csharp
    private string GetSymbol(string nftType)
    {
        var randomNumber = GenerateSymbolNumber();
        State.IsCreatedMap[randomNumber] = true;
        var shortName = State.NFTTypeShortNameMap[nftType];
        if (shortName == null)
        {
            InitialNFTTypeNameMap();
            shortName = State.NFTTypeShortNameMap[nftType];
            if (shortName == null) throw new AssertionException($"Short name of NFT Type {nftType} not found.");
        }

        return $"{shortName}{randomNumber}";
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L75-93)
```csharp
    public override Empty CrossChainCreate(CrossChainCreateInput input)
    {
        MakeSureTokenContractAddressSet();
        InitialNFTTypeNameMap();
        Assert(State.NftProtocolMap[input.Symbol] == null, $"Protocol {input.Symbol} already created.");
        var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
        {
            Symbol = input.Symbol
        });
        if (string.IsNullOrEmpty(tokenInfo.Symbol))
            throw new AssertionException($"Token info {input.Symbol} not exists.");

        var baseUri = tokenInfo.ExternalInfo.Value[NftBaseUriMetadataKey];
        var isTokenIdReuse = bool.Parse(tokenInfo.ExternalInfo.Value[NftTokenIdReuseMetadataKey]);
        var nftTypeShortName = input.Symbol.Substring(0, 2);
        var nftTypeFullName = State.NFTTypeFullNameMap[nftTypeShortName];
        if (nftTypeFullName == null)
            throw new AssertionException(
                $"Full name of {nftTypeShortName} not found. Use AddNFTType to add this new pair.");
```
