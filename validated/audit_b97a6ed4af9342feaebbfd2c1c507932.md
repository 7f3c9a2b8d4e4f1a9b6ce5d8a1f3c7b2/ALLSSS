# Audit Report

## Title
Permanent Loss of Fungible Tokens When Assembled NFTs Are Burned Directly

## Summary
The NFT contract's `Burn` method allows minters to destroy assembled NFTs without returning the locked fungible tokens to the owner. This creates an irreversible loss of funds as the `AssembledFtsMap` state remains orphaned with no recovery mechanism.

## Finding Description

The NFT contract provides an `Assemble` functionality that allows users to lock fungible tokens (FTs) inside NFTs. When assembling, FTs are transferred from the user to the contract and tracked in the `AssembledFtsMap` state variable. [1](#0-0) 

The assembled FTs mapping is stored in contract state: [2](#0-1) 

The intended disassembly flow retrieves these FTs and returns them to the receiver, then removes the state mapping: [3](#0-2) 

However, the `Burn` method provides an alternative path that only validates burnable status, balance, and minter permissions. It does NOT check whether the NFT has assembled FTs, nor does it clean up the `AssembledFtsMap` entry or return the locked tokens: [4](#0-3) 

When a minter calls `Burn` directly on an assembled NFT:
1. The NFT is destroyed (balance reduced, supply decreased, potentially marked as burned)
2. The `AssembledFtsMap[tokenHash]` entry persists in state
3. The FTs locked in the contract become permanently inaccessible

The `Disassemble` method cannot be used for recovery because it first calls `Burn`, which would fail when the NFT no longer exists (zero balance check at line 91-93 would fail).

Codebase analysis confirms `AssembledFtsMap` is only accessed in three locations in `NFTContract_UseChain.cs` (line 178 to write during Assemble, lines 212 and 224 to read and delete during Disassemble), with no administrative recovery functions.

## Impact Explanation

**Critical Fund Loss**: Fungible tokens become permanently locked in the NFT contract address with no retrieval mechanism. For example, if 100 ELF tokens are assembled into an NFT and the NFT is subsequently burned directly, those 100 ELF tokens remain in the contract forever.

**Irreversible Consequences**:
- The `AssembledFtsMap` entry persists indefinitely but becomes inaccessible since the tokenHash no longer corresponds to any existing NFT
- The `Disassemble` method cannot be invoked because its internal `Burn` call requires the caller to own the NFT (balance check fails)
- No administrative recovery functions exist in the contract to retrieve orphaned FTs
- The tokens are effectively removed from circulating supply without proper accounting

**Affected Parties**:
- NFT holders who accidentally burn assembled NFTs lose all locked FTs (user error scenario)
- Malicious minters could intentionally lock and destroy value
- The protocol experiences unexpected token supply reduction without burn events for the FTs
- Given minters have elevated privileges and may assemble significant value, potential losses are HIGH

## Likelihood Explanation

**Required Conditions**: 
1. Minter authorization (in the protocol's minter list for the NFT symbol)
2. Ownership of the assembled NFT (sufficient balance)
3. Protocol must have `IsBurnable` set to true

**Attack Complexity**: LOW
- Direct public method invocation with standard parameters
- No complex state setup or multi-step transactions required
- Can occur accidentally through user error or intentionally
- Single transaction execution

**Feasibility**: HIGH
- Minters are trusted but fallible roles that can make mistakes or have compromised private keys
- No safeguards exist in the code to prevent this scenario
- The test suite includes an `AssembleTest` demonstrating the assembly functionality, but lacks corresponding disassembly or burn validation tests [5](#0-4) 

The absence of test coverage for this edge case indicates it was not considered during development.

**Detection**: The loss would only be discovered when attempting to retrieve the FTs, at which point recovery is mathematically impossible within the contract's logic.

## Recommendation

Add a check in the `Burn` method to prevent burning of assembled NFTs, or automatically trigger disassembly before burning:

**Option 1 - Prevent burning assembled NFTs:**
```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Add check for assembled FTs/NFTs
    var assembledFts = State.AssembledFtsMap[tokenHash];
    var assembledNfts = State.AssembledNftsMap[tokenHash];
    Assert(assembledFts == null || !assembledFts.Value.Any(), 
        "Cannot burn assembled NFT directly. Use Disassemble instead.");
    Assert(assembledNfts == null || !assembledNfts.Value.Any(), 
        "Cannot burn assembled NFT directly. Use Disassemble instead.");
    
    // ... rest of existing burn logic
}
```

**Option 2 - Auto-disassemble before burning:**
```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Check and clean up assembled FTs/NFTs
    var assembledFts = State.AssembledFtsMap[tokenHash];
    if (assembledFts != null && assembledFts.Value.Any())
    {
        foreach (var pair in assembledFts.Value)
        {
            State.TokenContract.Transfer.Send(new MultiToken.TransferInput
            {
                Symbol = pair.Key,
                Amount = pair.Value,
                To = Context.Sender
            });
        }
        State.AssembledFtsMap.Remove(tokenHash);
    }
    
    var assembledNfts = State.AssembledNftsMap[tokenHash];
    if (assembledNfts != null && assembledNfts.Value.Any())
    {
        foreach (var pair in assembledNfts.Value)
        {
            DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, Context.Sender, pair.Value);
        }
        State.AssembledNftsMap.Remove(tokenHash);
    }
    
    // ... rest of existing burn logic
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_LocksTokensPermanently()
{
    // Setup: Create NFT protocol with IsBurnable=true
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    // Mint an NFT
    var (nftSymbol, tokenHash) = await MintTest();
    
    // Approve NFT contract to spend ELF
    await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = 100
    });
    
    // Assemble 100 ELF into the NFT
    await NFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = nftSymbol,
        AssembledFts = new AssembledFts
        {
            Value = { ["ELF"] = 100 }
        }
    });
    
    // Verify FTs are locked in contract
    var contractBalance = await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = NFTContractAddress, Symbol = "ELF" });
    contractBalance.Balance.ShouldBe(100);
    
    // VULNERABILITY: Burn the assembled NFT directly (instead of using Disassemble)
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = nftSymbol,
        TokenId = 2, // The assembled NFT's token ID
        Amount = 1
    });
    
    // IMPACT VERIFICATION:
    // 1. NFT is destroyed - balance is 0
    var nftBalance = await NFTContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = DefaultAddress, Symbol = nftSymbol, TokenId = 2 });
    nftBalance.Balance.ShouldBe(0);
    
    // 2. FTs remain locked in contract (not returned to user)
    contractBalance = await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput { Owner = NFTContractAddress, Symbol = "ELF" });
    contractBalance.Balance.ShouldBe(100); // Still locked!
    
    // 3. Cannot use Disassemble for recovery (will fail on balance check)
    var disassembleException = await Assert.ThrowsAsync<Exception>(async () =>
    {
        await NFTContractStub.Disassemble.SendAsync(new DisassembleInput
        {
            Symbol = nftSymbol,
            TokenId = 2
        });
    });
    disassembleException.Message.ShouldContain("No permission"); // Balance check fails
    
    // RESULT: 100 ELF tokens are permanently locked in the contract with no recovery mechanism
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L134-178)
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

        var mingInput = new MintInput
        {
            Symbol = input.Symbol,
            Alias = input.Alias,
            Owner = input.Owner,
            Uri = input.Uri,
            Metadata = metadata,
            TokenId = input.TokenId
        };

        var nftMinted = PerformMint(mingInput, true);
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L33-33)
```csharp
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L230-261)
```csharp
    [Fact]
    public async Task AssembleTest()
    {
        var (symbol, tokenHash) = await MintTest();

        await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
        {
            Spender = NFTContractAddress,
            Symbol = "ELF",
            Amount = long.MaxValue
        });

        await NFTContractStub.Assemble.SendAsync(new AssembleInput
        {
            Symbol = symbol,
            AssembledNfts = new AssembledNfts
            {
                Value = { [tokenHash.ToHex()] = 1 }
            },
            AssembledFts = new AssembledFts
            {
                Value = { ["ELF"] = 100 }
            },
            Metadata = new Metadata
            {
                Value =
                {
                    ["Advanced Property"] = "whatever"
                }
            }
        });
    }
```
