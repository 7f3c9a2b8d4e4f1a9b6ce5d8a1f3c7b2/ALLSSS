# Audit Report

## Title
Orphaned AssembledNftsMap Entries Enable Permanent Locking of NFTs When Assembled Tokens Are Burned

## Summary
The NFT contract's `Burn` method fails to validate or clean up `AssembledNftsMap` entries when burning assembled NFTs. This allows minters to directly burn assembled NFTs instead of properly disassembling them, permanently locking all component NFTs/FTs in the contract with no recovery mechanism.

## Finding Description

The vulnerability exists in the interaction between NFT assembly/disassembly and the burn mechanism.

**The Vulnerable Flow:**

The `AssembledNftsMap` state variable tracks which NFTs have been locked to create composite NFTs. [1](#0-0) 

When users call `Assemble`, component NFTs are transferred to the contract address (`Context.Self`) and the mapping is stored in `AssembledNftsMap`. [2](#0-1) [3](#0-2) 

The `Disassemble` method properly handles cleanup by burning the assembled NFT, retrieving locked components from the map, transferring them back to the receiver, and removing the map entry. [4](#0-3) 

However, the `Burn` method only validates that: (1) the protocol is burnable, (2) the caller has sufficient balance, and (3) the caller is a minter. It completely ignores `AssembledNftsMap` and performs no cleanup of locked components. [5](#0-4) 

**Why Protections Fail:**

There is no check in `Burn` to prevent burning assembled NFTs. The method treats assembled NFTs identically to regular NFTs, checking only balance ownership and minter permissions. No validation exists to detect that locked components would become irrecoverable.

The NFT contract interface confirms no emergency withdrawal or rescue functionality exists. [6](#0-5) 

## Impact Explanation

**Direct Fund Impact:**
- All NFTs/FTs locked in an assembled NFT become permanently irrecoverable when the assembled NFT is burned directly
- The locked components remain in the contract's balance (`Context.Self`) but cannot be accessed by any method
- The `AssembledNftsMap` entry persists as an orphaned record

**Who is Affected:**
- Any minter who assembles NFTs is at risk of accidentally calling `Burn` instead of `Disassemble`
- Third parties who transferred valuable NFTs to the minter for assembly lose their assets permanently

**Severity Justification - HIGH:**
1. Results in permanent, unrecoverable loss of assets
2. No administrative rescue mechanism exists
3. Simple user error (calling `Burn` vs `Disassemble`) causes irreversible damage
4. Violates the critical invariant of "lock/unlock correctness" for token assets

## Likelihood Explanation

**Attacker Capabilities:**
- Requires minter permission for the NFT protocol
- Must own the assembled NFT being burned
- Both conditions are met by anyone who legitimately creates assembled NFTs, since `Assemble` calls `PerformMint` which requires minter permission [7](#0-6) [8](#0-7) 

**Attack Complexity:**
LOW - A single direct call to `Burn` on an assembled NFT triggers the vulnerability. No complex transaction sequencing required.

**Feasibility Conditions:**
- The NFT protocol must have `IsBurnable = true`
- Caller must be in the protocol's minter list
- Caller must own an assembled NFT
- All conditions are realistic in normal protocol operation

**Probability - MEDIUM-HIGH:**
- Simple mistake: users may not understand the critical difference between `Burn` and `Disassemble`
- No warning, error message, or protection in the code
- Natural user behavior: "I want to destroy my NFT" → calls `Burn`
- The contract API does not indicate `Burn` is unsafe for assembled NFTs

## Recommendation

Add validation in the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // NEW: Check if this is an assembled NFT
    Assert(State.AssembledNftsMap[tokenHash] == null && State.AssembledFtsMap[tokenHash] == null,
        "Cannot burn assembled NFT directly. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    var nftProtocolInfo = State.NftProtocolMap[input.Symbol];
    // ... rest of existing burn logic
}
```

This prevents users from accidentally locking NFTs permanently while still allowing proper disassembly through the `Disassemble` method.

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_LocksComponentsPermanently()
{
    // Setup: Create and mint NFTs
    var (symbol, tokenHash1) = await MintTest();
    var tokenId1 = (await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(tokenHash1)).TokenId;
    
    // Approve ELF for assembly
    await TokenContractStub.Approve.SendAsync(new MultiToken.ApproveInput
    {
        Spender = NFTContractAddress,
        Symbol = "ELF",
        Amount = long.MaxValue
    });
    
    // Assemble NFT with component NFTs
    var assembleResult = await NFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts
        {
            Value = { [tokenHash1.ToHex()] = 1 }
        },
        AssembledFts = new AssembledFts
        {
            Value = { ["ELF"] = 100 }
        }
    });
    
    var assembledTokenHash = assembleResult.Output;
    var assembledNftInfo = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(assembledTokenHash);
    
    // Verify component is locked in contract
    var contractBalance = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput { TokenHash = tokenHash1, Owner = NFTContractAddress });
    contractBalance.Balance.ShouldBe(1);
    
    // VULNERABILITY: Call Burn directly instead of Disassemble
    await NFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = assembledNftInfo.TokenId,
        Amount = 1
    });
    
    // Assembled NFT is burned
    var assembledBalance = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput { TokenHash = assembledTokenHash, Owner = MinterAddress });
    assembledBalance.Balance.ShouldBe(0);
    
    // Component NFT is STILL locked in contract - permanently irrecoverable
    var stillLocked = await NFTContractStub.GetBalanceByTokenHash.CallAsync(
        new GetBalanceByTokenHashInput { TokenHash = tokenHash1, Owner = NFTContractAddress });
    stillLocked.Balance.ShouldBe(1); // Still locked!
    
    // Cannot call Disassemble - it would fail trying to burn already-burned NFT
    // No other method exists to retrieve the locked component NFT
    // The component NFT is permanently lost
}
```

This test demonstrates that calling `Burn` on an assembled NFT leaves component NFTs permanently locked in the contract with no recovery mechanism.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L32-32)
```csharp
    public MappedState<Hash, AssembledNfts> AssembledNftsMap { get; set; }
```

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L120-131)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L175-175)
```csharp
        var nftMinted = PerformMint(mingInput, true);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-176)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```

**File:** protobuf/nft_contract.proto (L18-100)
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
```
