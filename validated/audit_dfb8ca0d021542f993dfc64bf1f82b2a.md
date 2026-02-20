# Audit Report

## Title
Assembled NFTs Can Be Burned Directly Without Releasing Locked Components

## Summary
The `Burn` method lacks validation to prevent burning assembled NFTs, allowing minters to destroy assembled tokens without going through the proper `Disassemble` flow. This permanently locks component NFTs and FTs in the contract with no recovery mechanism, as the state map entries cannot be cleaned up after the assembled token is destroyed.

## Finding Description

The NFT contract implements an assembly system where multiple NFTs and fungible tokens (FTs) can be locked together to create a new assembled NFT. The proper destruction flow requires calling `Disassemble`, which burns the assembled token, releases the locked components, and cleans up state maps.

However, the `Burn` method does not verify whether an NFT is assembled before allowing destruction. The method only validates protocol burnability and minter permissions, but never checks if the token has entries in `AssembledNftsMap` or `AssembledFtsMap`. [1](#0-0) 

During assembly, component tokens are transferred to the contract address (`Context.Self`) and tracked in state maps: [2](#0-1) [3](#0-2) 

The assembly state is stored in dedicated maps: [4](#0-3) 

The proper disassembly flow burns the token and removes state map entries: [5](#0-4) 

When `Burn` is called directly on an assembled NFT, the token is destroyed but:
1. Component NFTs/FTs remain locked at the contract address
2. State map entries (`AssembledNftsMap` and `AssembledFtsMap`) become orphaned
3. `Disassemble` cannot be called since the token no longer exists
4. No recovery mechanism exists to retrieve the locked components

The state maps are defined as: [6](#0-5) 

## Impact Explanation

**HIGH severity** - This vulnerability results in permanent, irreversible loss of assets:

1. **Permanent Fund Loss:** Component NFTs and FTs transferred to the contract during assembly remain permanently locked with no way to retrieve them. The tokens exist in the contract's balance but are inaccessible.

2. **State Corruption:** Orphaned entries in `AssembledNftsMap` and `AssembledFtsMap` cannot be removed since removal only occurs in `Disassemble`, which requires the assembled token to exist.

3. **No Recovery Path:** Once the assembled token is burned:
   - The token hash no longer maps to a valid NFT
   - `Disassemble` cannot be called (it would fail when trying to burn a non-existent token)
   - No admin function exists to manually release locked components
   - No mechanism to clean up orphaned state map entries

4. **Broad Impact:** Affects any user who owns assembled NFTs and has minter permissions, including protocol creators and authorized minters.

## Likelihood Explanation

**HIGH likelihood** - This vulnerability can be triggered with minimal requirements:

1. **Attacker Capabilities:** The caller must be in the protocol's `MinterListMap` and own the assembled NFT. Minter status is a common role in NFT systems, typically granted to protocol creators and trusted parties.

2. **Attack Complexity:** Extremely low - requires only a single `Burn` transaction with the assembled NFT's symbol and token ID.

3. **Realistic Scenarios:**
   - **User Error:** A minter accidentally calls `Burn` instead of `Disassemble` when intending to destroy an assembled NFT
   - **API Confusion:** Developers unfamiliar with the assembly system may call the more obvious `Burn` method
   - **No Warning:** The contract provides no error message or warning that an assembled NFT should use `Disassemble`

4. **No Protection:** Unlike other critical operations, there is no validation to prevent this misuse. The contract allows the operation to succeed, giving no indication that something went wrong until users realize their locked components are inaccessible.

## Recommendation

Add validation to the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Check if NFT is assembled
    Assert(State.AssembledNftsMap[tokenHash] == null && State.AssembledFtsMap[tokenHash] == null,
        "Cannot burn assembled NFT. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
    Assert(nftProtocolInfo.IsBurnable,
        $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
    // ... rest of the method
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_LocksComponentsPermanently()
{
    // Setup: Create NFT protocol and mint component NFT
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    var (_, componentTokenHash) = await MintTest();
    
    // Approve contract to transfer ELF tokens
    await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });
    
    // Assemble: Lock component NFT and 100 ELF into new assembled NFT
    var assembleResult = await NFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts
        {
            Value = { [componentTokenHash.ToHex()] = 1 }
        },
        AssembledFts = new AssembledFts
        {
            Value = { ["ELF"] = 100 }
        }
    });
    var assembledTokenId = assembleResult.Output;
    
    // Verify components are locked in contract
    var contractNftBalance = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = symbol,
        TokenId = 1
    });
    contractNftBalance.Balance.ShouldBe(1); // Component NFT locked
    
    var contractElfBalance = await TokenContractStub.GetBalance.CallAsync(new MultiToken.GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = "ELF"
    });
    contractElfBalance.Balance.ShouldBeGreaterThanOrEqualTo(100); // ELF locked
    
    // VULNERABILITY: Burn assembled NFT directly instead of using Disassemble
    await NFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = assembledTokenId,
        Amount = 1
    });
    
    // Verify assembled NFT is destroyed
    var nftInfo = await NFTContractStub.GetNFTInfo.CallAsync(new GetNFTInfoInput
    {
        Symbol = symbol,
        TokenId = assembledTokenId
    });
    nftInfo.Quantity.ShouldBe(0);
    
    // IMPACT: Components remain locked in contract
    var lockedNftBalance = await NFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = symbol,
        TokenId = 1
    });
    lockedNftBalance.Balance.ShouldBe(1); // Still locked!
    
    var lockedElfBalance = await TokenContractStub.GetBalance.CallAsync(new MultiToken.GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = "ELF"
    });
    lockedElfBalance.Balance.ShouldBeGreaterThanOrEqualTo(100); // Still locked!
    
    // Cannot call Disassemble anymore since token doesn't exist
    // Components are permanently locked with no recovery mechanism
}
```

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L82-111)
```csharp
    public override Empty Burn(BurnInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(nftProtocolInfo.IsBurnable,
            $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
        State.BalanceMap[tokenHash][Context.Sender] = State.BalanceMap[tokenHash][Context.Sender].Sub(input.Amount);
        nftProtocolInfo.Supply = nftProtocolInfo.Supply.Sub(input.Amount);
        nftInfo.Quantity = nftInfo.Quantity.Sub(input.Amount);

        State.NftProtocolMap[input.Symbol] = nftProtocolInfo;
        if (nftInfo.Quantity == 0 && !nftProtocolInfo.IsTokenIdReuse) nftInfo.IsBurned = true;

        State.NftInfoMap[tokenHash] = nftInfo;

        Context.Fire(new Burned
        {
            Burner = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            TokenId = input.TokenId
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-178)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;

        if (input.AssembledFts.Value.Any()) State.AssembledFtsMap[nftMinted.TokenHash] = input.AssembledFts;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L191-236)
```csharp
    public override Empty Disassemble(DisassembleInput input)
    {
        Burn(new BurnInput
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Amount = 1
        });

        var receiver = input.Owner ?? Context.Sender;

        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
        if (assembledNfts != null)
        {
            var nfts = assembledNfts;
            foreach (var pair in nfts.Value) DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, receiver, pair.Value);

            State.AssembledNftsMap.Remove(tokenHash);
        }

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

        Context.Fire(new Disassembled
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            DisassembledNfts = assembledNfts ?? new AssembledNfts(),
            DisassembledFts = assembledFts ?? new AssembledFts()
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-33)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```
