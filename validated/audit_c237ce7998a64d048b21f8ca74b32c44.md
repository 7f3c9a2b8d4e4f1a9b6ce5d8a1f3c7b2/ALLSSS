# Audit Report

## Title
Null Reference Exception in Disassemble() Prevents Legitimate Disassembly Operations

## Summary
The `Disassemble()` function in the NFT contract contains a null reference vulnerability where calling `Clone()` on potentially null state map entries causes transaction failures. NFTs assembled with only fungible tokens or only non-fungible tokens cannot be disassembled, permanently locking component tokens in the contract.

## Finding Description

The root cause is in the unsafe invocation of `Clone()` on state map values without null-checking. [1](#0-0) 

The same vulnerability exists for the FT component map. [2](#0-1) 

The null checks occur too late—after the `Clone()` call has already been executed. [3](#0-2) [4](#0-3) 

The vulnerability manifests because `Assemble()` conditionally populates state maps only when components exist. [5](#0-4) [6](#0-5) 

When accessing a non-existent key in AElf's `MappedState`, it returns `default(T)`. [7](#0-6)  For protobuf message reference types like `AssembledNfts` and `AssembledFts`, this evaluates to `null`.

The execution flow through `MappedState` confirms this behavior—when a key is not found, it loads null bytes and deserializes them to null. [8](#0-7) 

This contrasts with defensive patterns used elsewhere in the codebase that employ the null-conditional operator. [9](#0-8) 

## Impact Explanation

The vulnerability causes complete denial-of-service for the disassembly functionality affecting NFTs assembled with only one component type. Users who create composite NFTs using exclusively fungible tokens or exclusively other NFTs will find their component tokens permanently locked in the contract, as any disassembly attempt will revert with a `NullReferenceException`.

While the assembled NFT itself is not lost (the transaction revert prevents state corruption), the disassembly operation becomes permanently unavailable. The locked component tokens (FTs or NFTs) remain trapped in the contract indefinitely, with no recovery mechanism available to the legitimate owner.

This breaks the fundamental protocol guarantee that assembled NFTs can be disassembled to retrieve their components. The severity is medium because it requires minter privileges and doesn't result in total fund loss, but it does cause indefinite fund lock and operational DoS for legitimate use cases.

## Likelihood Explanation

The likelihood is **high** because this represents a natural protocol usage pattern rather than an adversarial edge case. The `Assemble()` function explicitly supports creating composite NFTs with either FTs alone, NFTs alone, or both. [10](#0-9) [11](#0-10) 

Attack complexity is extremely low—a minter simply needs to call `Assemble()` with only one component type populated, then attempt `Disassemble()`. The minter privilege requirement is standard for burnable NFT protocols. [12](#0-11) 

Users may legitimately want to create NFTs backed by fungible token reserves alone, or create collections composed purely of other NFTs. This will occur naturally during normal protocol operations, affecting any user following documented assembly patterns with single-component types.

## Recommendation

Replace the unsafe `Clone()` calls with null-conditional operators to safely handle null values:

```csharp
var assembledNfts = State.AssembledNftsMap[tokenHash]?.Clone();
```

and

```csharp
var assembledFts = State.AssembledFtsMap[tokenHash]?.Clone();
```

This pattern is already used elsewhere in the codebase for similar scenarios and will prevent the `NullReferenceException` while maintaining the intended null-check logic.

## Proof of Concept

```csharp
[Fact]
public async Task DisassembleWithOnlyFTsTest_ShouldFail()
{
    // Create a burnable NFT protocol
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    // Approve NFT contract to transfer ELF tokens
    await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });
    
    // Assemble an NFT with ONLY FTs (no NFTs)
    // This sets State.AssembledFtsMap but NOT State.AssembledNftsMap
    var assembleResult = await MinterNFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts(), // Empty - no NFTs
        AssembledFts = new AssembledFts
        {
            Value = { ["ELF"] = 100 }
        }
    });
    
    var assembledTokenHash = assembleResult.Output;
    var assembledTokenId = (await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(assembledTokenHash)).TokenId;
    
    // Attempt to disassemble - this throws NullReferenceException
    // because State.AssembledNftsMap[tokenHash].Clone() is called on null
    var exception = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await MinterNFTContractStub.Disassemble.SendAsync(new DisassembleInput
        {
            Symbol = symbol,
            TokenId = assembledTokenId
        });
    });
    
    // Verify the exception indicates a NullReferenceException occurred
    exception.Message.ShouldContain("NullReference");
}
```

This test demonstrates that when an NFT is assembled with only FTs, attempting to disassemble it results in a `NullReferenceException`, permanently blocking access to the locked component tokens.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L89-93)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L120-132)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L134-163)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L203-203)
```csharp
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L204-204)
```csharp
        if (assembledNfts != null)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L212-212)
```csharp
        var assembledFts = State.AssembledFtsMap[tokenHash].Clone();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L213-213)
```csharp
        if (assembledFts != null)
```

**File:** src/AElf.Types/Helper/SerializationHelper.cs (L90-91)
```csharp
            if (bytes == null)
                return default;
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L95-100)
```csharp
    private ValuePair LoadKey(TKey key)
    {
        var path = GetSubStatePath(key.ToString());
        var bytes = Provider.Get(path);
        var value = SerializationHelper.Deserialize<TEntity>(bytes);
        var originalValue = SerializationHelper.Deserialize<TEntity>(bytes);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L783-783)
```csharp
        var maybePreviousTokenInfo = State.TokenInfos[newTokenInfo.Symbol]?.Clone();
```
