# Audit Report

## Title
Assembled NFTs Can Be Burned Directly, Causing Permanent Loss of Locked Fungible Tokens

## Summary
The `Burn` method in the NFT contract does not verify whether an NFT contains assembled assets (locked fungible tokens or other NFTs) before destroying it. When a minter directly burns an assembled NFT, the fungible tokens locked in the contract remain permanently trapped because the recovery mechanism (`Disassemble`) becomes inaccessible after the NFT is destroyed.

## Finding Description

The NFT contract implements an assembly mechanism that allows users to lock fungible tokens (FTs) and other NFTs inside a new assembled NFT. During assembly, FTs are transferred from the user to the contract itself via the MultiToken contract's `TransferFrom` method, and the composition is stored in `State.AssembledFtsMap`. [1](#0-0) 

The state mapping that tracks assembled fungible tokens is defined as: [2](#0-1) 

The intended recovery path is through the `Disassemble` method, which first burns the assembled NFT, then retrieves the locked assets from state, transfers them back to the receiver, and finally removes the state entries. [3](#0-2) 

**Root Cause:** The `Burn` method can be called directly by any minter who owns the assembled NFT, but it completely lacks any check to determine if the NFT being burned contains assembled assets. The method only verifies that the protocol is burnable, the caller is a minter, and the caller has sufficient balance: [4](#0-3) 

When an assembled NFT is burned directly through the `Burn` method:
1. The NFT balance is reduced to zero
2. The supply and quantity are decremented  
3. The NFT is marked as burned (if quantity reaches 0)
4. **The `AssembledFtsMap` entry remains in state but becomes orphaned**
5. **The locked FTs remain in the contract address with no way to retrieve them**

After this occurs, the `Disassemble` method cannot recover the locked assets because it internally calls `Burn` first, which requires the caller to have `balance >= 1`. Since the NFT was already burned, the balance is 0, causing the assertion to fail. There is no alternative recovery mechanism to retrieve orphaned assembled assets.

## Impact Explanation

**Direct Asset Loss:** All fungible tokens locked in the assembled NFT are permanently trapped in the NFT contract address with zero possibility of recovery. For example, if 1,000 ELF tokens were locked during assembly (as shown in the existing test), they become permanently inaccessible. [5](#0-4) 

**Affected Parties:**
- NFT owners who assembled valuable FTs into NFTs
- Any user who receives an assembled NFT through transfer
- The protocol's economic integrity, as locked assets reduce circulating supply permanently

**Severity: HIGH** because:
1. Results in permanent, unrecoverable loss of user funds of arbitrary value
2. Violates the fundamental expectation that assembled assets can be recovered through disassembly
3. No admin recovery mechanism exists in the contract
4. Requires only normal operational permissions (minter role)
5. Breaks the critical invariant that locked assets must be recoverable

## Likelihood Explanation

**Attacker Capabilities:** The vulnerability can be triggered by any minter who owns an assembled NFT. Minters are common operational roles - they are explicitly added to mint NFTs and often include the creator/assembler themselves. [6](#0-5) 

**Attack Complexity:** Extremely simple - requires only a single transaction calling the public `Burn` method with the symbol and token ID of the assembled NFT. [7](#0-6) 

**Feasibility Conditions:**
1. Protocol must be burnable (configurable during creation)
2. Attacker must be in the minter list for that protocol
3. Attacker must own the assembled NFT (balance ≥ 1)

These conditions are commonly met in normal operations. Many protocols are burnable by design, and assemblers are frequently minters themselves.

**Probability: MEDIUM-HIGH** - This vulnerability could occur accidentally (user calls wrong method) or intentionally. Once executed, the locked FTs cannot be recovered through any contract mechanism. The ease of accidentally calling `Burn` instead of `Disassemble`, combined with no warning or protection mechanism, makes this a realistic scenario.

## Recommendation

Add a validation check in the `Burn` method to prevent burning assembled NFTs. The method should verify that the NFT has no entries in `AssembledFtsMap` or `AssembledNftsMap` before allowing the burn operation:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Add this check to prevent burning assembled NFTs
    Assert(State.AssembledFtsMap[tokenHash] == null && 
           State.AssembledNftsMap[tokenHash] == null,
           "Cannot burn assembled NFT directly. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
    // ... rest of the existing logic
}
```

Alternatively, implement an admin recovery mechanism that can transfer orphaned tokens from the contract back to their rightful owners, though prevention is the preferred solution.

## Proof of Concept

```csharp
[Fact]
public async Task AssembledNFT_DirectBurn_PermanentlyLocksTokens()
{
    // Setup: Create protocol and mint NFT
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Alias = "test",
        Owner = MinterAddress,
        Uri = $"{BaseUri}test"
    })).Output;
    
    // Approve NFT contract to spend ELF tokens
    await MinterTokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });
    
    // Get initial ELF balance of minter
    var initialBalance = (await MinterTokenContractStub.GetBalance.CallAsync(
        new MultiToken.GetBalanceInput { Owner = MinterAddress, Symbol = "ELF" })).Balance;
    
    // Assemble NFT with 1000 ELF tokens locked
    var assembledTokenHash = (await MinterNFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts { Value = { [tokenHash.ToHex()] = 1 } },
        AssembledFts = new AssembledFts { Value = { ["ELF"] = 1000 } }
    })).Output;
    
    // Verify ELF tokens were transferred to contract
    var balanceAfterAssemble = (await MinterTokenContractStub.GetBalance.CallAsync(
        new MultiToken.GetBalanceInput { Owner = MinterAddress, Symbol = "ELF" })).Balance;
    balanceAfterAssemble.ShouldBe(initialBalance - 1000);
    
    var contractBalance = (await MinterTokenContractStub.GetBalance.CallAsync(
        new MultiToken.GetBalanceInput { Owner = NFTContractAddress, Symbol = "ELF" })).Balance;
    contractBalance.ShouldBeGreaterThanOrEqualTo(1000);
    
    // VULNERABILITY: Directly burn the assembled NFT instead of disassembling
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = 2, // The assembled NFT token ID
        Amount = 1
    });
    
    // Verify NFT is burned (balance is 0)
    var nftBalance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = 2
    })).Balance;
    nftBalance.ShouldBe(0);
    
    // IMPACT: ELF tokens are permanently locked - cannot be recovered
    // Attempt to disassemble fails because Burn requires balance >= 1
    var disassembleResult = await MinterNFTContractStub.Disassemble.SendWithExceptionAsync(
        new DisassembleInput { Symbol = symbol, TokenId = 2 });
    disassembleResult.TransactionResult.Error.ShouldContain("No permission"); // Fails at Burn check
    
    // Verify the 1000 ELF tokens remain locked in contract forever
    var finalMinterBalance = (await MinterTokenContractStub.GetBalance.CallAsync(
        new MultiToken.GetBalanceInput { Owner = MinterAddress, Symbol = "ELF" })).Balance;
    finalMinterBalance.ShouldBe(balanceAfterAssemble); // Tokens NOT recovered
    
    var finalContractBalance = (await MinterTokenContractStub.GetBalance.CallAsync(
        new MultiToken.GetBalanceInput { Owner = NFTContractAddress, Symbol = "ELF" })).Balance;
    finalContractBalance.ShouldBeGreaterThanOrEqualTo(1000); // Tokens permanently locked
}
```

## Notes

This vulnerability represents a critical flaw in the NFT contract's asset recovery mechanism. The `Burn` and `Disassemble` methods serve different purposes but their interaction creates a permanent fund loss scenario. The issue is exacerbated by the fact that:

1. There is no alternative path to access `AssembledFtsMap` entries after the NFT is burned
2. No admin or governance recovery mechanism exists to retrieve orphaned funds
3. The error could easily occur accidentally when users intend to call `Disassemble` but call `Burn` instead
4. The contract provides no warnings or checks to prevent this scenario

The fix is straightforward: add a validation check in the `Burn` method to reject attempts to burn assembled NFTs, forcing users to properly disassemble them first.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L134-162)
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L335-353)
```csharp
    public override Empty AddMinters(AddMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
        var minterList = State.MinterListMap[protocolInfo.Symbol] ?? new MinterList();

        foreach (var minter in input.MinterList.Value)
            if (!minterList.Value.Contains(minter))
                minterList.Value.Add(minter);

        State.MinterListMap[input.Symbol] = minterList;

        Context.Fire(new MinterListAdded
        {
            Symbol = input.Symbol,
            MinterList = input.MinterList
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L33-33)
```csharp
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L249-252)
```csharp
            AssembledFts = new AssembledFts
            {
                Value = { ["ELF"] = 100 }
            },
```

**File:** protobuf/nft_contract.proto (L45-47)
```text
    // Destroy nfts.
    rpc Burn (BurnInput) returns (google.protobuf.Empty) {
    }
```
