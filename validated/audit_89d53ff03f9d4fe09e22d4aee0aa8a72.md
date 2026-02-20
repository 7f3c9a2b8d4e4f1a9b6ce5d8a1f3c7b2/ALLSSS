# Audit Report

## Title
Permanent Loss of Fungible Tokens When Assembled NFTs Are Burned Directly

## Summary
The NFT contract's `Burn` method allows minters to destroy assembled NFTs without returning the locked fungible tokens to the owner, creating an irreversible loss of funds as the `AssembledFtsMap` state remains orphaned with no recovery mechanism.

## Finding Description

The NFT contract provides an `Assemble` functionality that allows users to lock fungible tokens (FTs) inside NFTs. When assembling, FTs are transferred from the user to the contract via the MultiToken contract and tracked in the `AssembledFtsMap` state variable. [1](#0-0) 

The assembled FTs mapping is stored in contract state: [2](#0-1) 

The intended disassembly flow retrieves these FTs and returns them to the receiver, then removes the state mapping: [3](#0-2) 

However, the `Burn` method provides an alternative path that only validates burnable status, balance, and minter permissions. It does NOT check whether the NFT has assembled FTs, nor does it clean up the `AssembledFtsMap` entry or return the locked tokens: [4](#0-3) 

When a minter calls `Burn` directly on an assembled NFT:
1. The NFT is destroyed (balance reduced, supply decreased, potentially marked as burned)
2. The `AssembledFtsMap[tokenHash]` entry persists in state
3. The FTs locked in the contract become permanently inaccessible

The `Disassemble` method cannot be used for recovery because it first calls `Burn`, which would fail when the NFT no longer exists (zero balance check at line 91-93 of the Burn method): [5](#0-4) 

Analysis of the entire codebase confirms `AssembledFtsMap` is only accessed in three locations (Assemble to write, Disassemble to read and delete), with no admin recovery functions. The contract interface provides no emergency withdrawal or recovery mechanisms: [6](#0-5) 

## Impact Explanation

**Critical Fund Loss**: Fungible tokens become permanently locked in the NFT contract address with no retrieval mechanism. For example, the test suite demonstrates assembling with 100 ELF tokens: [7](#0-6) 

If this assembled NFT is subsequently burned directly via the `Burn` method, those 100 ELF tokens remain in the contract forever.

**Irreversible Consequences**:
- The `AssembledFtsMap` entry persists indefinitely but becomes inaccessible since the tokenHash no longer corresponds to any existing NFT
- The `Disassemble` method cannot be invoked because its internal `Burn` call requires the caller to own the NFT (balance check)
- No administrative recovery functions exist in the contract to retrieve orphaned FTs
- The tokens are effectively removed from circulating supply without proper accounting

**Affected Parties**:
- NFT holders who accidentally burn assembled NFTs lose all locked FTs (user error scenario)
- Malicious minters could intentionally lock and destroy value
- The protocol experiences unexpected token supply reduction without burn events for the FTs
- Given minters have elevated privileges and may assemble significant value, potential losses are HIGH

## Likelihood Explanation

**Required Conditions**: The attacker/user must satisfy:
1. Minter authorization (in the protocol's minter list for the NFT symbol)
2. Ownership of the assembled NFT (sufficient balance)
3. Protocol must have `IsBurnable` set to true (common setting, used in tests) [8](#0-7) 

**Attack Complexity**: LOW
- Direct public method invocation with standard parameters
- No complex state setup or multi-step transactions required
- Can occur accidentally through user error or intentionally
- Single transaction execution

**Feasibility**: HIGH
- Minters are trusted but fallible roles that can make mistakes or have compromised private keys
- No safeguards exist in the code to prevent this scenario
- The test suite includes an `AssembleTest` but lacks corresponding disassembly or burn validation tests, indicating this edge case was not considered during development

## Recommendation

The `Burn` method should be modified to check for assembled tokens and either:

**Option 1: Prevent burning assembled NFTs**
```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Check if NFT has assembled tokens
    var assembledFts = State.AssembledFtsMap[tokenHash];
    var assembledNfts = State.AssembledNftsMap[tokenHash];
    Assert(assembledFts == null || !assembledFts.Value.Any(), 
        "Cannot burn NFT with assembled FTs. Please disassemble first.");
    Assert(assembledNfts == null || !assembledNfts.Value.Any(), 
        "Cannot burn NFT with assembled NFTs. Please disassemble first.");
    
    // Existing burn logic...
}
```

**Option 2: Auto-disassemble before burning**
```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Auto-disassemble if assembled tokens exist
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
    
    // Similar handling for assembledNfts...
    
    // Existing burn logic...
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BurnAssembledNFT_CausesPermanentFTLoss()
{
    // Setup: Create NFT protocol with IsBurnable = true
    var symbol = await CreateTest();
    await AddMinterAsync(symbol);
    
    // Mint an NFT
    var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
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
    
    // Check initial ELF balance
    var initialBalance = (await MinterTokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = "ELF"
    })).Balance;
    
    // Assemble NFT with 100 ELF tokens
    await MinterNFTContractStub.Assemble.SendAsync(new AssembleInput
    {
        Symbol = symbol,
        AssembledNfts = new AssembledNfts
        {
            Value = { [tokenHash.ToHex()] = 1 }
        },
        AssembledFts = new AssembledFts
        {
            Value = { ["ELF"] = 100 }
        }
    });
    
    // Verify FTs are locked in NFT contract
    var nftContractBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = "ELF"
    })).Balance;
    nftContractBalance.ShouldBeGreaterThanOrEqualTo(100);
    
    // Get assembled NFT token ID (should be token_id 2)
    var assembledTokenId = 2;
    
    // VULNERABILITY: Burn the assembled NFT directly
    await MinterNFTContractStub.Burn.SendAsync(new BurnInput
    {
        Symbol = symbol,
        TokenId = assembledTokenId,
        Amount = 1
    });
    
    // Verify NFT is burned (balance should be 0)
    var nftBalance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = MinterAddress,
        Symbol = symbol,
        TokenId = assembledTokenId
    })).Balance;
    nftBalance.ShouldBe(0);
    
    // CRITICAL: FTs remain locked in NFT contract with no recovery mechanism
    var finalNftContractBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = NFTContractAddress,
        Symbol = "ELF"
    })).Balance;
    finalNftContractBalance.ShouldBeGreaterThanOrEqualTo(100); // FTs still locked!
    
    // Attempting to disassemble fails because NFT no longer exists
    var disassembleResult = await MinterNFTContractStub.Disassemble.SendWithExceptionAsync(new DisassembleInput
    {
        Symbol = symbol,
        TokenId = assembledTokenId
    });
    disassembleResult.TransactionResult.Error.ShouldContain("No permission"); // Burn fails due to zero balance
    
    // The 100 ELF tokens are permanently lost
}
```

**Notes**

This vulnerability represents a critical design flaw in the NFT contract's token lifecycle management. The `Burn` method operates independently of the `Assemble/Disassemble` mechanism, creating an inconsistent state where:

1. The NFT contract holds FTs that were assembled into now-destroyed NFTs
2. The `AssembledFtsMap` contains orphaned entries that can never be accessed
3. Users have no recourse to recover their locked funds

The issue is particularly severe because:
- Minters are expected to have this capability but may not understand the implications
- The test coverage gap suggests this scenario was not considered during development
- No admin or governance functions exist to rescue locked tokens
- The loss is permanent and irreversible within the contract's logic

The recommended fix should enforce that assembled NFTs can only be destroyed through the `Disassemble` method, which properly returns all locked assets before burning the NFT.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L191-198)
```csharp
    public override Empty Disassemble(DisassembleInput input)
    {
        Burn(new BurnInput
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Amount = 1
        });
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

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L33-33)
```csharp
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

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L242-252)
```csharp
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
```
