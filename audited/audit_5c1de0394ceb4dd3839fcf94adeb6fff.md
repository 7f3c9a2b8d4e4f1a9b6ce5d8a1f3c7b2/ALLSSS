### Title
Null Reference Exception in Disassemble() Bricks Legitimate Disassembly Operations

### Summary
The `Disassemble()` function contains a critical null reference vulnerability where calling `Clone()` on potentially null state map entries causes transaction failures. NFTs assembled with only fungible tokens (FTs) or only non-fungible tokens (NFTs) cannot be disassembled, permanently bricking the disassembly process for these legitimate assets.

### Finding Description

**Location**: [1](#0-0) 

**Root Cause**: The code calls `.Clone()` on state map values without first checking for null: [2](#0-1) 

The same vulnerability exists for `AssembledFtsMap`: [3](#0-2) 

**Why Protections Fail**: The null check occurs AFTER the `Clone()` call (line 204 for NFTs, line 213 for FTs), but the exception is thrown during the `Clone()` invocation itself when the map returns null.

**Vulnerable Execution Path**: 

The `Assemble()` function conditionally populates state maps only when components exist:
- [4](#0-3)  - Only sets `AssembledNftsMap` if `input.AssembledNfts.Value.Any()` is true
- [5](#0-4)  - Only sets `AssembledFtsMap` if `input.AssembledFts.Value.Any()` is true

This creates scenarios where:
1. NFT assembled with **only FTs** → `AssembledNftsMap[tokenHash]` returns null → line 203 crashes
2. NFT assembled with **only NFTs** → `AssembledFtsMap[tokenHash]` returns null → line 212 crashes

### Impact Explanation

**Operational Impact**: Complete DoS of disassembly functionality for legitimately assembled NFTs that contain only one component type (either NFTs or FTs, but not both).

**Affected Users**: 
- NFT minters who assembled NFTs using only fungible tokens
- NFT minters who assembled NFTs using only other NFTs
- Any authorized minter attempting to disassemble such NFTs

**Severity Justification**: Medium severity because:
- The NFT itself is not lost (transaction reverts prevent state corruption)
- Disassembly operation becomes permanently unavailable for affected NFTs
- Requires minter privileges to exploit (not fully permissionless)
- Affects legitimate use cases, not just malicious scenarios
- Assets remain locked in the contract indefinitely

### Likelihood Explanation

**Attacker Capabilities**: Requires minter privileges on a burnable NFT protocol. [6](#0-5) 

**Attack Complexity**: Extremely low - simply call `Assemble()` with only FTs or only NFTs, then attempt `Disassemble()`.

**Feasibility**: Highly feasible as this represents a legitimate use case:
- Users may want to assemble NFTs containing only fungible token reserves
- Users may want to assemble NFTs containing only other NFT collections
- The `Assemble()` function explicitly supports both scenarios independently [7](#0-6) 

**Probability**: High - this will occur naturally in normal protocol usage, not just adversarial scenarios. Any minter following documented assembly patterns with single-component types will encounter this issue.

### Recommendation

**Code-Level Mitigation**: Move the null check BEFORE the `Clone()` call:

```csharp
var assembledNfts = State.AssembledNftsMap[tokenHash];
if (assembledNfts != null)
{
    var nfts = assembledNfts.Clone();
    foreach (var pair in nfts.Value) 
        DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, receiver, pair.Value);
    State.AssembledNftsMap.Remove(tokenHash);
}

var assembledFts = State.AssembledFtsMap[tokenHash];
if (assembledFts != null)
{
    var fts = assembledFts.Clone();
    foreach (var pair in fts.Value)
        State.TokenContract.Transfer.Send(new MultiToken.TransferInput
        {
            Symbol = pair.Key,
            Amount = pair.Value,
            To = receiver
        });
    State.AssembledFtsMap.Remove(tokenHash);
}
```

**Test Cases**: Add regression tests for:
1. Disassembling NFT assembled with only FTs (no NFTs)
2. Disassembling NFT assembled with only NFTs (no FTs)
3. Disassembling NFT assembled with both NFTs and FTs (existing happy path)

### Proof of Concept

**Initial State**:
- User is a minter on a burnable NFT protocol
- User has sufficient FT balance (e.g., 100 ELF)
- User has approved the NFT contract to spend FTs

**Exploitation Steps**:

1. Call `Assemble()` with only FTs (no NFTs):
   ```
   Input: {
     Symbol: "TEST",
     AssembledNfts: { Value: {} },  // Empty
     AssembledFts: { Value: { "ELF": 100 } }
   }
   ```
   Result: Assembled NFT created, `AssembledNftsMap[tokenHash]` remains null

2. Call `Disassemble()` on the assembled NFT:
   ```
   Input: {
     Symbol: "TEST",
     TokenId: <assembled_token_id>
   }
   ```

**Expected Result**: NFT disassembled successfully, 100 ELF returned to sender

**Actual Result**: Transaction fails with `NullReferenceException` at line 203 when `State.AssembledNftsMap[tokenHash].Clone()` attempts to call `Clone()` on null. The burn operation at lines 193-198 is reverted, but the NFT cannot be disassembled through normal means.

**Success Condition**: Transaction reverts, disassembly permanently blocked for this NFT.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L120-163)
```csharp
        if (input.AssembledNfts.Value.Any())
        {
            metadata.Value[AssembledNftsKey] = input.AssembledNfts.ToString();
            // Check owner.
            foreach (var pair in input.AssembledNfts.Value)
            {
                var nftHash = Hash.LoadFromHex(pair.Key);
                var nftInfo = GetNFTInfoByTokenHash(nftHash);
                Assert(State.BalanceMap[nftHash][Context.Sender] >= pair.Value,
                    $"Insufficient balance of {nftInfo.Symbol}{nftInfo.TokenId}.");
                DoTransfer(nftHash, Context.Sender, Context.Self, pair.Value);
            }
        }

        if (input.AssembledFts.Value.Any())
        {
            metadata.Value[AssembledFtsKey] = input.AssembledFts.ToString();
            // Check balance and allowance.
            foreach (var pair in input.AssembledFts.Value)
            {
                var symbol = pair.Key;
                var amount = pair.Value;
                var balance = State.TokenContract.GetBalance.Call(new MultiToken.GetBalanceInput
                {
                    Owner = Context.Sender,
                    Symbol = symbol
                }).Balance;
                Assert(balance >= amount, $"Insufficient balance of {symbol}");
                var allowance = State.TokenContract.GetAllowance.Call(new MultiToken.GetAllowanceInput
                {
                    Owner = Context.Sender,
                    Spender = Context.Self,
                    Symbol = symbol
                }).Allowance;
                Assert(allowance >= amount, $"Insufficient allowance of {symbol}");
                State.TokenContract.TransferFrom.Send(new MultiToken.TransferFromInput
                {
                    From = Context.Sender,
                    To = Context.Self,
                    Symbol = symbol,
                    Amount = amount
                });
            }
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-176)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L178-178)
```csharp
        if (input.AssembledFts.Value.Any()) State.AssembledFtsMap[nftMinted.TokenHash] = input.AssembledFts;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L203-210)
```csharp
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
        if (assembledNfts != null)
        {
            var nfts = assembledNfts;
            foreach (var pair in nfts.Value) DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, receiver, pair.Value);

            State.AssembledNftsMap.Remove(tokenHash);
        }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L212-225)
```csharp
        var assembledFts = State.AssembledFtsMap[tokenHash].Clone();
        if (assembledFts != null)
        {
            var fts = assembledFts;
            foreach (var pair in fts.Value)
                State.TokenContract.Transfer.Send(new MultiToken.TransferInput
                {
                    Symbol = pair.Key,
                    Amount = pair.Value,
                    To = receiver
                });

            State.AssembledFtsMap.Remove(tokenHash);
        }
```
