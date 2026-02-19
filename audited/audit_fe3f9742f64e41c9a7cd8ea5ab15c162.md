### Title
Orphaned AssembledNftsMap Entries Enable Permanent Locking of NFTs When Assembled Tokens Are Burned

### Summary
The NFT contract's `Burn` method fails to check or clean up `AssembledNftsMap` entries when burning assembled NFTs. This allows minters who own assembled NFTs to directly burn them instead of disassembling, permanently locking all component NFTs/FTs in the contract with no recovery mechanism. The orphaned map entries prevent legitimate retrieval while the burned assembled NFT no longer exists.

### Finding Description

The vulnerability exists in the interaction between the `Burn` and `Disassemble` methods in the NFT contract.

**Root Cause:**

The `AssembledNftsMap` state variable tracks which NFTs have been locked together to create composite/assembled NFTs. [1](#0-0) 

When creating an assembled NFT via the `Assemble` method, component NFTs are transferred to the contract address (`Context.Self`) and the mapping is stored in `AssembledNftsMap`. [2](#0-1) [3](#0-2) 

The `Disassemble` method properly handles cleanup by: (1) burning the assembled NFT, (2) retrieving locked components from `AssembledNftsMap`, (3) transferring them back to the receiver, and (4) removing the map entry. [4](#0-3) 

However, the `Burn` method only validates: (1) protocol is burnable, (2) caller has sufficient balance AND is a minter. It completely ignores `AssembledNftsMap` and performs no cleanup. [5](#0-4) 

**Why Protections Fail:**

There is no check in `Burn` to prevent burning assembled NFTs. The method treats assembled NFTs identically to regular NFTs, checking only balance ownership and minter permissions. No validation exists to detect that `AssembledNftsMap[tokenHash]` contains locked components that would become irrecoverable.

The NFT contract interface confirms no emergency withdrawal or rescue functionality exists to retrieve orphaned NFTs. [6](#0-5) 

### Impact Explanation

**Direct Fund Impact:**
- All NFTs/FTs locked in an assembled NFT become permanently irrecoverable when the assembled NFT is burned directly
- The locked components remain in the contract's balance (`Context.Self`) but cannot be accessed by any method
- The `AssembledNftsMap` entry persists indefinitely as an orphaned record

**Who is Affected:**
- Any minter who assembles NFTs is at risk of accidentally calling `Burn` instead of `Disassemble`
- The locked NFTs may have substantial value (rare collectibles, utility NFTs, etc.)
- Third parties who transferred valuable NFTs to the minter for assembly lose their assets permanently

**Severity Justification:**
HIGH severity because:
1. Results in permanent, unrecoverable loss of assets
2. No administrative rescue mechanism exists
3. Simple user error (calling `Burn` vs `Disassemble`) causes irreversible damage
4. Violates the critical invariant of "lock/unlock correctness" for token assets

### Likelihood Explanation

**Attacker Capabilities:**
- Requires minter permission for the NFT protocol
- Must own the assembled NFT being burned
- Both conditions are met by anyone who legitimately creates assembled NFTs (since `Assemble` calls `PerformMint` which requires minter permission) [7](#0-6) 

**Attack Complexity:**
LOW - A single direct call to `Burn` on an assembled NFT triggers the vulnerability. No complex transaction sequencing or state manipulation required.

**Feasibility Conditions:**
- The NFT protocol must have `IsBurnable = true`
- Attacker must be in the protocol's minter list
- Attacker must own an assembled NFT
- All conditions are realistic in normal protocol operation

**Probability:**
MEDIUM-HIGH due to:
- Simple mistake: users may not understand the critical difference between `Burn` and `Disassemble`
- No warning, error message, or protection in the code
- Natural user behavior: "I want to destroy my NFT" → calls `Burn`
- The contract API does not indicate `Burn` is unsafe for assembled NFTs

### Recommendation

**Immediate Mitigation:**

Add a check in the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // NEW: Prevent burning assembled NFTs
    Assert(State.AssembledNftsMap[tokenHash] == null, 
        "Cannot burn assembled NFT. Use Disassemble method to retrieve locked components.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    // ... rest of existing Burn logic
}
```

**Additional Safeguards:**

1. Add similar check for `AssembledFtsMap[tokenHash]`
2. Add invariant validation in test suite confirming `AssembledNftsMap` entries are always cleaned up when NFTs are burned
3. Update documentation to clearly distinguish `Burn` vs `Disassemble` for user education
4. Consider adding an emergency rescue function (governance-controlled) to retrieve orphaned NFTs in case of bugs

**Test Cases:**

1. Test that `Burn` reverts when called on an assembled NFT
2. Test that `Disassemble` successfully cleans up both `AssembledNftsMap` and `AssembledFtsMap`
3. Test that after burning a regular NFT, no entries exist in assembly maps
4. Fuzz test various sequences of Assemble/Disassemble/Burn/Transfer operations

### Proof of Concept

**Initial State:**
- Protocol "GAME" exists with `IsBurnable = true`
- Alice is a minter for "GAME"
- Alice owns NFT1 (GAME-001, tokenHash: 0xAAA) 
- Alice owns NFT2 (GAME-002, tokenHash: 0xBBB)

**Transaction Sequence:**

1. Alice calls `Assemble`:
   - Input: `{ symbol: "GAME", assembled_nfts: { "0xAAA": 1, "0xBBB": 1 } }`
   - Result: NFT1 and NFT2 transferred to contract, assembled NFT (GAME-003, tokenHash: 0xCCC) minted
   - State: `AssembledNftsMap[0xCCC] = { "0xAAA": 1, "0xBBB": 1 }`
   - State: `BalanceMap[0xAAA][ContractAddress] = 1`, `BalanceMap[0xBBB][ContractAddress] = 1`

2. Alice calls `Burn` (instead of `Disassemble`):
   - Input: `{ symbol: "GAME", token_id: 3, amount: 1 }`
   - Result: GAME-003 burned successfully (balance reduced, supply updated)
   - State: `AssembledNftsMap[0xCCC]` STILL EXISTS (orphaned)
   - State: NFT1 and NFT2 remain locked at `ContractAddress`

3. Alice attempts to retrieve NFT1 and NFT2:
   - Calling `Disassemble` fails: GAME-003 no longer exists (burned)
   - Calling `Transfer` fails: Alice doesn't own NFT1/NFT2 (contract does)
   - No other method can access contract-owned NFTs

**Expected vs Actual Result:**

Expected: Either (1) `Burn` should revert with error, or (2) `Burn` should clean up `AssembledNftsMap` and return locked NFTs

Actual: `Burn` succeeds, NFT1 and NFT2 are permanently locked, `AssembledNftsMap[0xCCC]` becomes orphaned data

**Success Condition:**
The vulnerability is successfully exploited when `AssembledNftsMap` contains an entry for a burned (non-existent) token, and the locked NFTs cannot be retrieved by any contract method.

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L124-131)
```csharp
            foreach (var pair in input.AssembledNfts.Value)
            {
                var nftHash = Hash.LoadFromHex(pair.Key);
                var nftInfo = GetNFTInfoByTokenHash(nftHash);
                Assert(State.BalanceMap[nftHash][Context.Sender] >= pair.Value,
                    $"Insufficient balance of {nftInfo.Symbol}{nftInfo.TokenId}.");
                DoTransfer(nftHash, Context.Sender, Context.Self, pair.Value);
            }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-176)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L191-210)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
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
