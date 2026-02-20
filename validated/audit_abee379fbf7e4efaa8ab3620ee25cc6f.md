# Audit Report

## Title
Orphaned AssembledNftsMap Entries Enable Permanent Locking of NFTs When Assembled Tokens Are Burned

## Summary
The NFT contract's `Burn` method lacks validation to prevent burning assembled NFTs and fails to clean up `AssembledNftsMap` entries. When a minter directly burns an assembled NFT instead of calling `Disassemble`, all component NFTs/FTs locked during assembly become permanently irrecoverable, as they remain in the contract's balance with no mechanism to retrieve them.

## Finding Description

The vulnerability exists in the `Burn` method's failure to account for assembled NFTs that contain locked components.

**The Assemble/Disassemble Pattern:**

When users create composite NFTs via `Assemble`, component NFTs are transferred to `Context.Self` (the contract address) [1](#0-0)  and tracked in `AssembledNftsMap` [2](#0-1) . Similarly, FTs are stored in `AssembledFtsMap` [3](#0-2) .

The `Disassemble` method correctly handles cleanup by: (1) burning the assembled NFT [4](#0-3) , (2) retrieving locked components from `AssembledNftsMap` [5](#0-4) , (3) transferring them back to the receiver, and (4) removing the map entry [6](#0-5) .

**The Vulnerability:**

The `Burn` method only validates that the protocol is burnable and that the caller has sufficient balance AND is a minter [7](#0-6) . Critically, the entire `Burn` method [8](#0-7)  contains NO reference to `AssembledNftsMap` or `AssembledFtsMap` - it performs no checks to detect assembled NFTs and no cleanup of map entries.

**Why Recovery is Impossible:**

Once an assembled NFT is burned directly:
1. The NFT's balance becomes 0 [9](#0-8) 
2. The locked components remain in `Context.Self`'s balance
3. The `AssembledNftsMap` entry persists as an orphaned record (defined in state [10](#0-9) )
4. `Disassemble` cannot be called because it first calls `Burn`, which will fail when the balance check fails [11](#0-10) 
5. No emergency withdrawal or administrative rescue mechanism exists in the contract interface [12](#0-11) 

## Impact Explanation

**HIGH severity** due to:

1. **Permanent Asset Loss**: All NFTs and FTs locked in an assembled NFT become permanently irrecoverable when the assembled NFT is burned directly. The assets remain in the contract's balance but are inaccessible by any method.

2. **No Recovery Mechanism**: The NFT contract contains no emergency withdrawal functionality or administrative override to retrieve orphaned assets, as confirmed by the complete contract interface definition [12](#0-11) .

3. **Broken Invariant**: This violates the fundamental lock/unlock correctness guarantee - assets that are locked together via `Assemble` should always be retrievable through the proper unlock mechanism (`Disassemble`).

4. **Potential Value Loss**: Locked NFTs may have substantial value (rare collectibles, utility NFTs with access rights, etc.), and third parties who transferred valuable NFTs to a minter for assembly lose their assets permanently.

## Likelihood Explanation

**MEDIUM-HIGH probability** because:

1. **Low Attack Complexity**: A single direct call to `Burn` on an assembled NFT triggers the vulnerability - no complex transaction sequencing required.

2. **Realistic Preconditions**: 
   - The caller must be a minter (automatically true for anyone who assembled NFTs, as `Assemble` calls `PerformMint` [13](#0-12)  which requires minter permission [14](#0-13) )
   - The protocol must have `IsBurnable = true` (common configuration, as seen in tests [15](#0-14) )
   - The caller must own the assembled NFT (natural state after assembling)

3. **High User Error Probability**: Users may not understand the critical difference between `Burn` and `Disassemble`. Natural user behavior when wanting to "destroy" an NFT is to call `Burn`, with no warning in the code or interface that this is unsafe for assembled NFTs.

4. **No Protection**: The contract provides no guard rails - `Burn` treats assembled NFTs identically to regular NFTs.

## Recommendation

Add a check in the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Add this check before burning
    Assert(State.AssembledNftsMap[tokenHash] == null && State.AssembledFtsMap[tokenHash] == null, 
        "Cannot burn assembled NFT directly. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
    // ... rest of existing Burn logic
}
```

Alternatively, automatically call `Disassemble` logic when burning an assembled NFT, or prevent the `IsBurnable` flag from applying to assembled NFTs.

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_LocksComponentsPermanently()
{
    // Setup: Create protocol and mint NFT
    var symbol = await CreateTest(); // Creates burnable protocol
    await AddMinterAsync(symbol);
    
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Owner = MinterAddress,
        Uri = "test"
    })).Output;
    
    // Approve ELF for assembly
    await MinterTokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = 1000
    });
    
    // Assemble: Lock the NFT with ELF tokens
    var assembleResult = await MinterNFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts { Value = { [tokenHash.ToHex()] = 1 } },
        AssembledFts = new AssembledFts { Value = { ["ELF"] = 100 } }
    });
    
    var assembledTokenId = assembleResult.TransactionResult.Logs
        .First(l => l.Name == nameof(NFTMinted))
        .Indexed.First(i => i.Name == "token_id").Value;
    
    // Vulnerability: Directly burn the assembled NFT instead of disassembling
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = long.Parse(assembledTokenId),
        Amount = 1
    });
    
    // Verify components are locked forever:
    // 1. Original NFT is in contract's balance
    var contractBalance = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput { Owner = NFTContractAddress, TokenHash = tokenHash });
    contractBalance.Balance.ShouldBe(1); // Locked in contract
    
    // 2. Disassemble fails because assembled NFT no longer exists
    var disassembleException = await Assert.ThrowsAsync<Exception>(async () =>
        await MinterNFTContractStub.Disassemble.SendAsync(new DisassembleInput
        {
            Symbol = symbol,
            TokenId = long.Parse(assembledTokenId)
        }));
    disassembleException.Message.ShouldContain("No permission"); // Balance check fails
    
    // 3. Components remain permanently locked with no recovery method
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L130-130)
```csharp
                DoTransfer(nftHash, Context.Sender, Context.Self, pair.Value);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L175-175)
```csharp
        var nftMinted = PerformMint(mingInput, true);
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L203-207)
```csharp
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
        if (assembledNfts != null)
        {
            var nfts = assembledNfts;
            foreach (var pair in nfts.Value) DoTransfer(Hash.LoadFromHex(pair.Key), Context.Self, receiver, pair.Value);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L209-209)
```csharp
            State.AssembledNftsMap.Remove(tokenHash);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L399-399)
```csharp
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-33)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
    public MappedState<Hash, AssembledFts> AssembledFtsMap { get; set; }
```

**File:** protobuf/nft_contract.proto (L18-101)
```text
service NFTContract {
    option (aelf.csharp_state) = "AElf.Contracts.NFT.NFTContractState";
    option (aelf.base) = "acs1.proto";

    // Create a new nft protocol.
    rpc Create (CreateInput) returns (google.protobuf.StringValue) {
    }
    rpc CrossChainCreate (CrossChainCreateInput) returns (google.protobuf.Empty) {
    }
    // Mint (Issue) an amount of nft.
    rpc Mint (MintInput) returns (aelf.Hash) {
    }
    // Transfer nft to another address.
    rpc Transfer (TransferInput) returns (google.protobuf.Empty) {
    }
    // Transfer nft from one address to another.
    rpc TransferFrom (TransferFromInput) returns (google.protobuf.Empty) {
    }
    // Approve another address to transfer nft from own account.
    rpc Approve (ApproveInput) returns (google.protobuf.Empty) {
    }
    // De-approve.
    rpc UnApprove (UnApproveInput) returns (google.protobuf.Empty) {
    }
    // Approve or de-approve another address as the operator of all NFTs of a certain protocol.
    rpc ApproveProtocol (ApproveProtocolInput) returns (google.protobuf.Empty) {
    }
    // Destroy nfts.
    rpc Burn (BurnInput) returns (google.protobuf.Empty) {
    }
    // Lock several nfts and fts to mint one nft.
    rpc Assemble (AssembleInput) returns (aelf.Hash) {
    }
    // Disassemble one assembled nft to get locked nfts and fts back.
    rpc Disassemble (DisassembleInput) returns (google.protobuf.Empty) {
    }
    // Modify metadata of one nft.
    rpc Recast (RecastInput) returns (google.protobuf.Empty) {
    }

    rpc AddMinters (AddMintersInput) returns (google.protobuf.Empty) {
    }
    rpc RemoveMinters (RemoveMintersInput) returns (google.protobuf.Empty) {
    }
    
    rpc AddNFTType (AddNFTTypeInput) returns (google.protobuf.Empty) {
    }
    rpc RemoveNFTType (google.protobuf.StringValue) returns (google.protobuf.Empty) {
    }

    rpc GetNFTProtocolInfo (google.protobuf.StringValue) returns (NFTProtocolInfo) {
        option (aelf.is_view) = true;
    }
    rpc GetNFTInfo (GetNFTInfoInput) returns (NFTInfo) {
        option (aelf.is_view) = true;
    }
    rpc GetNFTInfoByTokenHash (aelf.Hash) returns (NFTInfo) {
        option (aelf.is_view) = true;
    }
    rpc GetBalance (GetBalanceInput) returns (GetBalanceOutput) {
        option (aelf.is_view) = true;
    }
    rpc GetBalanceByTokenHash (GetBalanceByTokenHashInput) returns (GetBalanceOutput) {
        option (aelf.is_view) = true;
    }
    rpc GetAllowance (GetAllowanceInput) returns (GetAllowanceOutput) {
        option (aelf.is_view) = true;
    }
    rpc GetAllowanceByTokenHash (GetAllowanceByTokenHashInput) returns (GetAllowanceOutput) {
        option (aelf.is_view) = true;
    }
    rpc GetMinterList (google.protobuf.StringValue) returns (MinterList) {
        option (aelf.is_view) = true;
    }
    rpc CalculateTokenHash (CalculateTokenHashInput) returns (aelf.Hash) {
        option (aelf.is_view) = true;
    }
    rpc GetNFTTypes (google.protobuf.Empty) returns (NFTTypes) {
        option (aelf.is_view) = true;
    }
    rpc GetOperatorList (GetOperatorListInput) returns (AddressList) {
        option (aelf.is_view) = true;
    }
}
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L34-34)
```csharp
            IsBurnable = true,
```
