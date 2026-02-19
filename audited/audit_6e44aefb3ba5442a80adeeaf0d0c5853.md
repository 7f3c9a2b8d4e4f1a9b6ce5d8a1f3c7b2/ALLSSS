### Title
Permanent Asset Lock in NFT Contract Due to Disassemble Function Failure Without Recovery Mechanism

### Summary
The NFT contract's `Assemble` function transfers user assets (NFTs and FTs) to the contract address (`Context.Self`) but the only recovery path through `Disassemble` can be permanently blocked due to burn permission checks. When `Disassemble` fails, there is no alternative recovery mechanism, resulting in permanent asset loss for users.

### Finding Description

**Asset Transfer to Contract:**
The `Assemble` function transfers NFTs from users to the contract itself at line 130, and FTs at lines 155-161. [1](#0-0) [2](#0-1) 

These assets are stored in state maps for later retrieval. [3](#0-2) 

**Critical Failure Point - Burn Permission Check:**
The `Disassemble` function is the ONLY method to recover locked assets, and it requires burning the assembled NFT first. [4](#0-3) 

However, the `Burn` function enforces two critical checks that can permanently block asset recovery:

1. **Protocol Burnability Check:** The protocol must have been created with `IsBurnable = true`. [5](#0-4) 

2. **Minter Permission Check:** The caller must be in the minter list for that protocol. [6](#0-5) 

**Failure Scenarios:**
- If a protocol is created with `IsBurnable = false`, ALL assembled NFTs from that protocol can NEVER be disassembled
- Users who are not minters cannot disassemble assembled NFTs they own
- Users who receive assembled NFTs via transfer typically won't be minters
- Secondary market buyers are permanently blocked from recovering underlying assets

**No Recovery Mechanism:**
A comprehensive review of all NFT contract methods confirms there is NO alternative recovery path. [7](#0-6) 

The contract has no admin emergency withdrawal, no governance override, no timelock mechanism, and no fallback recovery function. Assets transferred to `Context.Self` can only be retrieved through `Disassemble`, making the burn permission checks a single point of failure.

### Impact Explanation

**Direct Financial Loss:**
Users lose 100% of the value of NFTs and FTs locked in assembled tokens when `Disassemble` fails. This includes:
- Valuable NFTs that may be unique or limited supply
- Fungible tokens (FTs) of any amount
- All future utility and transferability of these assets

**Affected Users:**
- Any user who assembles NFTs from a non-burnable protocol
- Users who are not protocol minters but hold assembled NFTs
- Secondary market participants who purchase assembled NFTs
- All users if protocol creators make mistakes in initial configuration

**Severity:** CRITICAL
This violates the fundamental "Token Supply & Fees" invariant requiring correct lock/unlock mechanisms. Assets become permanently inaccessible through normal user operations without any malicious intent required.

### Likelihood Explanation

**Attack Complexity:** None required - this is a design flaw, not an attack.

**Realistic Preconditions:**
1. User calls `Assemble` with legitimate NFTs/FTs (normal operation)
2. Protocol was created with `IsBurnable = false` OR user is not a minter
3. User attempts to call `Disassemble` to recover assets

**Execution Practicality:**
The vulnerability triggers through normal contract usage:
- Step 1: User approves FTs and calls `Assemble` [8](#0-7) 
- Step 2: Assets are transferred to contract
- Step 3: `Disassemble` fails on burn check
- Step 4: No recovery possible

**Probability:** HIGH
- Protocol creators may intentionally set `IsBurnable = false` for legitimate reasons
- Most NFT holders are not minters by design
- The test suite only tests `Assemble` but NOT `Disassemble`, suggesting this path was not validated [9](#0-8) 

### Recommendation

**Immediate Fix - Remove Minter Check from Disassemble Path:**
Modify the `Burn` function to accept a parameter indicating whether the call is from `Disassemble`. When disassembling, skip the minter check since the user already proved ownership by holding the assembled NFT.

```
Alternative 1: Add a separate internal burn function for disassemble that only checks balance
Alternative 2: Check if caller is Context.Self and skip permission checks
Alternative 3: Store assembled assets in a separate escrow mechanism with direct withdrawal rights
```

**Invariant to Add:**
- Users who own an assembled NFT must ALWAYS be able to recover the underlying locked assets
- The burn permission check should not apply to disassembly operations

**Required Test Cases:**
1. Test disassembly by non-minter users who received assembled NFTs via transfer
2. Test disassembly of assembled NFTs from non-burnable protocols
3. Test recovery after protocol creator removes user from minter list
4. Add comprehensive disassembly tests (currently missing from test suite)

**Additional Safety Measures:**
- Add a governance-controlled emergency withdrawal function for stuck assets
- Emit warnings during `Assemble` if the protocol is non-burnable
- Document burn requirements clearly for protocol creators

### Proof of Concept

**Initial State:**
1. Protocol "SYMBOL1" created with `IsBurnable = false`
2. User mints NFT with `tokenId = 1` from SYMBOL1
3. User has ELF balance > 100

**Transaction Sequence:**

**Step 1 - Assemble (Success):**
```
User calls Assemble:
- Symbol: SYMBOL1
- AssembledNfts: {tokenHash: 1}
- AssembledFts: {"ELF": 100}
```
Expected: NFT and 100 ELF transferred to Context.Self, new assembled NFT minted
Actual: ✅ Success - assets locked in contract

**Step 2 - Disassemble (Permanent Failure):**
```
User calls Disassemble:
- Symbol: SYMBOL1
- TokenId: 2 (assembled NFT)
```
Expected: Should recover locked NFT and 100 ELF
Actual: ❌ Transaction reverts at Burn line 87-88: "NFT Protocol SYMBOL1 is not burnable"

**Step 3 - Verify No Recovery:**
Check all contract methods - NONE can retrieve assets from `Context.Self` for this user.
Result: Assets permanently locked, user loses all value.

**Success Condition for Exploit:**
Assets remain in contract balance forever with zero methods available to recover them, confirming permanent loss.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L87-88)
```csharp
        Assert(nftProtocolInfo.IsBurnable,
            $"NFT Protocol {nftProtocolInfo.ProtocolName} of symbol {nftProtocolInfo.Symbol} is not burnable.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L90-93)
```csharp
        Assert(
            State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
            minterList.Value.Contains(Context.Sender),
            "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L130-130)
```csharp
                DoTransfer(nftHash, Context.Sender, Context.Self, pair.Value);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L155-161)
```csharp
                State.TokenContract.TransferFrom.Send(new MultiToken.TransferFromInput
                {
                    From = Context.Sender,
                    To = Context.Self,
                    Symbol = symbol,
                    Amount = amount
                });
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L176-178)
```csharp
        if (input.AssembledNfts.Value.Any()) State.AssembledNftsMap[nftMinted.TokenHash] = input.AssembledNfts;

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
