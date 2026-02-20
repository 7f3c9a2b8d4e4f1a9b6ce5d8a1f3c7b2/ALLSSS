# Audit Report

## Title
Asset Duplication via Disassemble with Multiple NFT Copies

## Summary
The `Disassemble` function contains a critical logic flaw where it hardcodes the burn amount to 1 while unconditionally removing all assembled asset mappings. When combined with the `IsTokenIdReuse` protocol setting, attackers with minting privileges can create multiple copies of an assembled NFT, disassemble once to recover all underlying assets, and retain fraudulent copies with no backing.

## Finding Description

The vulnerability stems from the interaction between three NFT contract mechanisms:

**1. Disassemble burns exactly 1 token but removes all assembled asset mappings**

The `Disassemble` function hardcodes the burn amount regardless of the token's total quantity: [1](#0-0) 

It then unconditionally removes the entire assembled asset mappings from state: [2](#0-1) [3](#0-2) 

**2. Assemble enforces token uniqueness during creation**

The `Assemble` function passes `isTokenIdMustBeUnique=true` to `PerformMint`, ensuring initial uniqueness: [4](#0-3) 

**3. Mint can add quantity to existing tokens when IsTokenIdReuse=true**

The public `Mint` function calls `PerformMint` with the default `isTokenIdMustBeUnique=false` parameter: [5](#0-4) 

In `PerformMint`, the uniqueness check evaluates as follows: [6](#0-5) 

When `IsTokenIdReuse=true` (a legitimate protocol configuration setting), this condition becomes `if (!true || false)` = `if (false)`, skipping the assertion and executing the else branch to add quantity: [7](#0-6) 

**4. State mappings are per-token hash, not per-quantity**

The assembled asset mappings are keyed only by token hash: [8](#0-7) 

This design means all copies of an assembled NFT with the same token ID reference the same single set of underlying assets stored in state.

**Attack Sequence:**
1. Attacker (with minter privileges) assembles valuable NFTs/FTs into a new assembled NFT (initial quantity=1)
2. Attacker calls `Mint` with the same token ID, increasing quantity to 2 or more
3. Attacker calls `Disassemble` once, burning only 1 token but recovering ALL underlying assets
4. Attacker retains remaining copies which appear legitimate but have no backing assets

## Impact Explanation

This vulnerability enables **HIGH severity** direct asset theft with concrete, measurable consequences:

- **Direct Asset Theft**: Attackers extract all underlying NFTs and fungible tokens locked in assembled tokens while retaining unbacked copies, directly stealing protocol-held assets
- **Fraudulent Token Creation**: Unbacked assembled NFTs circulate in the market appearing legitimate but having zero redeemable value
- **Buyer Fraud**: Innocent purchasers of these fraudulent tokens suffer complete loss of investment when they attempt to disassemble and discover no underlying assets exist
- **Protocol Integrity Damage**: Complete loss of trust in the assembly system, potential systemic failure if the attack is widely exploited
- **Unlimited Scope**: The attack works regardless of the value of underlying assets, enabling theft of any valuable NFT/FT combination locked via assembly

The impact is concrete and quantifiable - direct theft of protocol-owned assets with immediate financial consequences for both the protocol and secondary market participants.

## Likelihood Explanation

The attack requires two preconditions that make it **MEDIUM likelihood**:

**Precondition 1: Protocol has IsTokenIdReuse=true**

This is a legitimate protocol configuration option set during creation: [9](#0-8) 

Protocols may enable this setting for valid operational reasons such as allowing token ID reuse after burns in game mechanics, collectible systems, or other legitimate use cases.

**Precondition 2: Attacker has minter privileges**

Required by the `Burn` function's permission check: [10](#0-9) 

Minter privileges are granted by protocol creators and may be distributed to business partners, game operators, or other semi-trusted parties. This is NOT a fully trusted role - minters should be able to mint and burn tokens within protocol rules but should NOT be able to break protocol invariants and steal locked assets.

**Attack Complexity: LOW**
- Simple 3-step sequence: Assemble → Mint → Disassemble
- No timing dependencies or race conditions required
- No complex state manipulation needed
- Difficult to detect until assets are actually withdrawn
- Easily reproducible once preconditions are met

## Recommendation

Implement one of the following fixes:

**Option 1: Prevent minting additional copies of assembled NFTs**
Add a check in `PerformMint` to prevent increasing quantity for tokens that have assembled asset mappings, regardless of `IsTokenIdReuse` setting.

**Option 2: Track quantity in disassembly logic**
Modify `Disassemble` to only remove assembled asset mappings when the last token is being burned (quantity will reach 0).

**Option 3: Proportional asset distribution**
Store assembled assets per-instance rather than per-token-hash, or implement proportional distribution where each disassembly returns 1/N of the total assets.

**Recommended Fix (Option 2):**
Modify the `Disassemble` function to check remaining quantity before removing mappings. Only remove the mappings when burning the final token.

## Proof of Concept

To create a test demonstrating this vulnerability:

1. Create an NFT protocol with `IsTokenIdReuse=true` and grant minter privileges to test account
2. Assemble valuable NFTs/FTs into a new assembled NFT (quantity becomes 1)
3. Call `Mint` with the same token ID to increase quantity to 2
4. Call `Disassemble` once - observe that ALL assembled assets are returned but 1 token remains
5. Verify remaining token has no backing by checking AssembledNftsMap and AssembledFtsMap return null
6. Demonstrate the remaining unbacked token can be transferred/sold to victims

The test would verify that after step 4, the attacker possesses both the original underlying assets AND an unbacked copy of the assembled NFT, proving direct asset duplication and theft.

## Notes

This vulnerability represents a critical invariant violation in the NFT assembly mechanism. The core issue is the mismatch between:
- State design (mappings keyed per-token-hash)  
- Quantity semantics (allowing multiple copies via `IsTokenIdReuse`)
- Disassembly logic (assuming 1:1 relationship between token and assembled assets)

While `IsTokenIdReuse=true` is a legitimate feature for non-assembled NFTs, its interaction with the assembly system creates an exploitable condition where minters can duplicate locked assets.

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
