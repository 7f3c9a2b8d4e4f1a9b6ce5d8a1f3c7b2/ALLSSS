# Audit Report

## Title
Orphaned AssembledNftsMap Entries Enable Permanent Locking of NFTs When Assembled Tokens Are Burned

## Summary
The NFT contract's `Burn` method fails to check or clean up `AssembledNftsMap` entries when burning assembled NFTs, allowing minters to directly burn assembled NFTs instead of properly disassembling them. This permanently locks all component NFTs and fungible tokens in the contract address with no recovery mechanism, as the burned assembled NFT can no longer be disassembled.

## Finding Description

The vulnerability exists in the interaction between the `Burn` and `Disassemble` methods in the NFT contract.

**The Assembly Mechanism:**

When users create assembled NFTs via the `Assemble` method, component NFTs are transferred to the contract's own address (`Context.Self`) [1](#0-0) , and the mapping is stored in `AssembledNftsMap` state variable [2](#0-1) [3](#0-2) . Similarly, fungible tokens are stored in `AssembledFtsMap` [4](#0-3) .

**The Correct Disassembly Path:**

The `Disassemble` method properly handles cleanup by: (1) burning the assembled NFT [5](#0-4) , (2) retrieving locked components from `AssembledNftsMap` [6](#0-5) , (3) transferring them back to the receiver [7](#0-6) , and (4) removing the map entry [8](#0-7) .

**The Vulnerability:**

However, the `Burn` method only validates that: (1) the protocol is burnable, (2) the caller has sufficient balance AND is a minter [9](#0-8) . It then reduces balances and supply, but **completely ignores `AssembledNftsMap`** and performs no cleanup. There is no check to prevent burning assembled NFTs, and no validation to detect that `AssembledNftsMap[tokenHash]` contains locked components.

The entire `Burn` method implementation shows no reference to checking or cleaning up assembled NFT state, treating all NFTs identically regardless of whether they have locked components.

**No Recovery Mechanism:**

The NFT contract interface contains no emergency withdrawal or admin rescue functionality [10](#0-9) . Once an assembled NFT is burned directly, the locked component NFTs/FTs remain in `Context.Self` forever with no method to retrieve them.

## Impact Explanation

This vulnerability results in **permanent, unrecoverable loss of assets**:

1. **Direct Fund Loss**: All NFTs and fungible tokens locked in an assembled NFT become permanently irrecoverable when the assembled NFT is burned directly through `Burn` instead of `Disassemble`.

2. **Locked in Contract**: The component assets remain in the contract's balance (`Context.Self`) but cannot be accessed by any existing method since the assembled NFT that references them no longer exists.

3. **Orphaned State**: The `AssembledNftsMap` entry persists indefinitely as an orphaned record that points to a non-existent assembled NFT.

4. **Affected Users**: Any minter who assembles NFTs (including valuable rare collectibles or utility NFTs) is at risk. Third parties who transferred valuable assets to the minter for assembly lose their assets permanently.

5. **Critical Invariant Violation**: The vulnerability breaks the fundamental "lock/unlock correctness" guarantee that any locked assets can always be recovered through proper disassembly.

The severity is HIGH because there is no administrative override, no rescue mechanism, and the loss is permanent and irreversible.

## Likelihood Explanation

The likelihood of this vulnerability being triggered is **MEDIUM-HIGH**:

**Attacker Prerequisites:**
- Must have minter permission for the NFT protocol
- Must own an assembled NFT

Both conditions are naturally met by anyone who legitimately creates assembled NFTs, since the `Assemble` method calls `PerformMint`, which requires the caller to be in the minter list [11](#0-10) .

**Attack Complexity:**
LOW - A single direct call to `Burn` on an assembled NFT triggers the vulnerability. No complex transaction sequencing or state manipulation is required.

**Probability Factors:**
1. **User Error**: Users may not understand the critical distinction between `Burn` and `Disassemble`, naturally thinking "I want to destroy my NFT" and calling `Burn`.
2. **No Warning**: The code provides no error message, revert, or warning when burning an assembled NFT.
3. **API Ambiguity**: The contract interface does not indicate that `Burn` is unsafe for assembled NFTs or that `Disassemble` must be used instead.
4. **Common Configuration**: The vulnerability only requires `IsBurnable = true`, which is a common protocol configuration.

## Recommendation

Add a check in the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Add this check to prevent burning assembled NFTs
    var assembledNfts = State.AssembledNftsMap[tokenHash];
    var assembledFts = State.AssembledFtsMap[tokenHash];
    Assert(assembledNfts == null && assembledFts == null, 
        "Cannot burn assembled NFT directly. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
    Assert(nftProtocolInfo.IsBurnable,
        $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
    // ... rest of the burn logic
}
```

Alternatively, implement an emergency recovery function that allows the contract creator or governance to retrieve orphaned NFTs, though prevention is preferable.

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_LocksComponentsForever_Vulnerability()
{
    // Setup: Create protocol and mint component NFT
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    var (_, componentTokenHash) = await MintTest();

    // Setup: Approve contract to spend FTs
    await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });

    // Step 1: Assemble NFT with component
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
    var assembledTokenId = 2; // Assembled NFT gets tokenId 2

    // Verify component is locked in contract
    var contractBalance = (await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = NFTContractAddress,
            TokenHash = componentTokenHash
        })).Balance;
    contractBalance.ShouldBe(1); // Component locked in contract

    // Step 2: VULNERABILITY - Burn assembled NFT directly instead of Disassemble
    await NFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = assembledTokenId,
        Amount = 1
    });

    // Step 3: IMPACT - Component NFT is permanently locked
    // The component is still in contract but cannot be retrieved
    var stillLocked = (await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput
        {
            Owner = NFTContractAddress,
            TokenHash = componentTokenHash
        })).Balance;
    stillLocked.ShouldBe(1); // Still locked!

    // Step 4: Cannot disassemble because assembled NFT is burned
    // This will fail because assembled NFT no longer exists
    var disassembleAttempt = await Assert.ThrowsAsync<Exception>(() =>
        NFTContractStub.Disassemble.SendAsync(new DisassembleInput
        {
            Symbol = symbol,
            TokenId = assembledTokenId
        }));

    // VULNERABILITY CONFIRMED:
    // - Assembled NFT is burned
    // - Component NFT permanently locked in contract
    // - No method to recover it
    // - Permanent loss of assets
}
```

**Notes:**

This vulnerability is confirmed through comprehensive code analysis. The `Burn` method has no awareness of the assembled NFT state mappings, while `Disassemble` is the only method that properly cleans up these mappings. The NFT contract provides no emergency recovery mechanisms, making any assets locked through this path permanently irrecoverable. This represents a critical break in the lock/unlock invariant that is fundamental to the assembled NFT feature.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L203-203)
```csharp
        var assembledNfts = State.AssembledNftsMap[tokenHash].Clone();
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L207-207)
```csharp
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-32)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
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
