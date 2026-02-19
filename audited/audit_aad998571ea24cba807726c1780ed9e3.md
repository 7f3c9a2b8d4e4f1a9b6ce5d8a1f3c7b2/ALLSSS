### Title
Permanent Loss of Fungible Tokens When Assembled NFTs Are Burned Directly

### Summary
The NFT contract allows minters to burn assembled NFTs directly via the `Burn` method without cleaning up the `AssembledFtsMap` state or returning the locked fungible tokens. This results in permanent loss of the FTs that were locked during assembly, as there is no recovery mechanism and the only retrieval path (`Disassemble`) requires the NFT to exist.

### Finding Description

The root cause is in the `Burn` method which lacks validation for assembled NFTs: [1](#0-0) 

When an NFT is assembled, fungible tokens are transferred to the contract and tracked in `AssembledFtsMap`: [2](#0-1) [3](#0-2) 

The `AssembledFtsMap` state variable stores this mapping: [4](#0-3) 

The correct disassembly flow retrieves and returns the FTs, then removes the mapping: [5](#0-4) 

However, if a minter calls `Burn` directly on an assembled NFT, the method only validates burnable status, balance, and minter permissions—it does NOT check for or clean up `AssembledFtsMap` entries. The NFT is destroyed, but the FT mapping remains orphaned with no retrieval mechanism.

### Impact Explanation

**Direct Fund Loss**: Fungible tokens become permanently locked in the contract address. For example, if 100 ELF tokens are assembled into an NFT and then the NFT is burned directly, those 100 ELF remain in the contract forever.

**Irreversible Damage**: 
- The `AssembledFtsMap` entry persists but becomes inaccessible because the tokenHash no longer corresponds to any existing NFT
- The `Disassemble` method cannot be used because it requires NFT ownership (checked in the internal `Burn` call)
- No admin recovery functions exist in the contract
- The tokens are effectively burned from circulation without proper accounting

**Affected Parties**: 
- NFT holders who accidentally burn assembled NFTs lose all locked FTs
- The protocol suffers from unexpected token supply reduction
- Given that minters have elevated privileges and could have significant value locked, potential losses are HIGH

### Likelihood Explanation

**Attacker Capabilities**: The attacker must be:
1. A minter (authorized in the protocol's minter list)
2. Owner of the assembled NFT
3. Operating on a burnable NFT protocol [6](#0-5) 

**Attack Complexity**: LOW
- Direct function call with no complex preconditions
- Can be accidental (user error) or intentional
- Single transaction execution

**Feasibility**: HIGH
- The test suite demonstrates assembly functionality but lacks disassembly/burn validation tests: [7](#0-6) 

- No protection exists to prevent this scenario
- Minters are trusted roles but can still make mistakes or have compromised keys

**Detection**: The loss would only be discovered when attempting to retrieve the FTs, by which time recovery is impossible.

### Recommendation

Add validation in the `Burn` method to prevent burning assembled NFTs:

```csharp
public override Empty Burn(BurnInput input)
{
    var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
    
    // Add this check:
    Assert(State.AssembledFtsMap[tokenHash] == null && State.AssembledNftsMap[tokenHash] == null,
        "Cannot burn assembled NFT directly. Use Disassemble method instead.");
    
    var nftInfo = GetNFTInfoByTokenHash(tokenHash);
    // ... rest of existing code
}
```

Alternative/additional mitigations:
1. Add an emergency recovery function callable by Parliament to transfer orphaned FTs
2. Implement invariant checks: `AssembledFtsMap` entries should only exist for valid (non-burned) NFTs
3. Add comprehensive test cases covering the burn→orphan scenario

### Proof of Concept

**Initial State**:
- User is a minter for a burnable NFT protocol
- User has 100 ELF tokens and approval set for NFT contract

**Exploitation Steps**:

1. User calls `Assemble` with 100 ELF tokens:
   - FTs transferred: User → NFT Contract
   - `AssembledFtsMap[tokenHash] = {"ELF": 100}` set
   - New assembled NFT minted to user

2. User calls `Burn` directly on the assembled NFT:
   - NFT balance decremented to 0
   - NFT marked as burned
   - **AssembledFtsMap[tokenHash] entry NOT removed**
   - **FTs NOT returned to user**

3. User attempts recovery via `Disassemble`:
   - Fails at internal `Burn` call due to zero balance
   - No alternative recovery path exists

**Expected Result**: FTs returned to user upon disassembly or burn prevented

**Actual Result**: 100 ELF permanently locked in contract with no recovery mechanism

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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L178-178)
```csharp
        if (input.AssembledFts.Value.Any()) State.AssembledFtsMap[nftMinted.TokenHash] = input.AssembledFts;
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

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L231-261)
```csharp
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
