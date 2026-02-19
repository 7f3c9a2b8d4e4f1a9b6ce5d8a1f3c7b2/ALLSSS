### Title
NFT Burn Function Incorrectly Requires Minter Status, Preventing Legitimate Token Owners from Burning Their Own Assets

### Summary
The `Burn()` function in the NFT contract enforces that callers must be in the minter list to burn tokens, even if they legitimately own those tokens. This prevents non-minter owners from burning NFTs they rightfully possess through transfer or direct minting, violating fundamental ownership rights and creating a protocol inconsistency where burnable NFTs cannot actually be burned by their owners.

### Finding Description

**Location:** [1](#0-0) 

**Root Cause:** The authorization check at lines 90-93 requires both conditions to be true using AND logic: [2](#0-1) 

This means a user must:
1. Have sufficient balance (legitimate ownership check)
2. Be in the minter list (incorrect restriction)

**Why Protections Fail:**

The minter list is designed to control who can mint new tokens, not who can burn existing ones. However, the burn function conflates these two separate authorization concerns. 

Users can legitimately acquire NFTs without being minters through:
1. **Direct minting to non-minter owners:** When minting, the owner can be specified separately from the minter [3](#0-2) 

2. **Transfer operations:** Any owner can transfer NFTs to non-minters [4](#0-3) 

3. **TransferFrom operations:** Approved spenders can transfer to non-minters [5](#0-4) 

**Additional Impact:** The `Disassemble()` function internally calls `Burn()`, preventing non-minters from disassembling NFTs they own to recover underlying assets: [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
- **Ownership Rights Violation:** Users who legitimately own NFTs cannot destroy assets they possess, violating basic property rights in digital asset systems
- **Protocol Inconsistency:** NFT protocols can be created with `IsBurnable = true` [7](#0-6) , but this flag is meaningless for non-minter owners
- **Asset Lock-in:** Users with assembled NFTs cannot disassemble them to recover underlying assets, causing permanent loss of access to constituent tokens
- **Economic Impact:** Users cannot reduce supply or exit positions, affecting token economics and user autonomy

**Affected Parties:**
- Any NFT owner who is not in the minter list (the vast majority of NFT holders in typical ecosystems)
- Users who receive NFTs via marketplace transfers, airdrops, or gifts
- Users with assembled NFTs containing valuable underlying assets

**Severity Justification:** HIGH
- Violates fundamental ownership invariant that owners control their assets
- Affects core NFT functionality with no workaround except adding every owner to minter list (impractical)
- Contradicts protocol design intent (burnable flag exists but doesn't work for owners)

### Likelihood Explanation

**Attacker Capabilities:** No attack needed - this is a design flaw affecting normal users. Any non-minter owner is blocked from burning their own tokens.

**Attack Complexity:** Trivial to trigger:
1. User receives NFT via transfer or is designated as owner during mint
2. User attempts to burn their NFT
3. Transaction fails with "No permission"

**Feasibility Conditions:**
- Extremely common: NFTs are designed to be transferable and most owners are not minters
- Minter lists are typically restricted to protocol creators/operators [8](#0-7) 
- No existing tests verify non-minter burn capability [9](#0-8) 

**Probability:** Very High - occurs in every scenario where a non-minter legitimately owns an NFT and wants to burn it

### Recommendation

**Code-Level Mitigation:**

Remove the minter status check from the `Burn()` function. The authorization should only verify ownership (balance), not minting privileges:

```csharp
// In Burn() function at line 90-93, change:
Assert(
    State.BalanceMap[tokenHash][Context.Sender] >= input.Amount &&
    minterList.Value.Contains(Context.Sender),
    "No permission.");

// To:
Assert(
    State.BalanceMap[tokenHash][Context.Sender] >= input.Amount,
    "Insufficient balance.");
```

**Invariant Checks:**
- Add check: "Any address with sufficient token balance can burn their own tokens"
- Ensure minter status only gates minting operations, not burning operations
- Verify IsBurnable flag correctly controls burn capability at protocol level, not per-user level

**Test Cases to Add:**
1. Test non-minter receiving NFT via Transfer and successfully burning it
2. Test non-minter specified as owner during Mint and successfully burning their NFT
3. Test non-minter disassembling an assembled NFT they own
4. Test that minter status gates only Mint operations, not Burn operations

### Proof of Concept

**Initial State:**
- NFT protocol "EXAMPLE" created with `IsBurnable = true`
- MinterAddress is in the minter list for "EXAMPLE"
- UserAddress is NOT in the minter list
- UserAddress has 0 balance

**Step 1: Mint NFT to non-minter owner**
- MinterAddress calls `Mint()` with:
  - Symbol: "EXAMPLE"
  - TokenId: 1
  - Owner: UserAddress (explicitly specified)
  - Amount: 1
- Expected: Mint succeeds, UserAddress receives 1 NFT
- Actual: ✓ Mint succeeds (verified by balance check at line 441)

**Step 2: Non-minter owner attempts to burn**
- UserAddress calls `Burn()` with:
  - Symbol: "EXAMPLE"
  - TokenId: 1
  - Amount: 1
- Expected: Burn should succeed (user owns the token and protocol is burnable)
- Actual: ✗ **Transaction FAILS with "No permission."**

**Verification:**
- Line 91: `State.BalanceMap[tokenHash][Context.Sender] >= input.Amount` → TRUE (user has balance)
- Line 92: `minterList.Value.Contains(Context.Sender)` → FALSE (user is not a minter)
- Line 90-93: Assert fails because TRUE && FALSE = FALSE

**Success Condition:** The burn should succeed based solely on balance ownership, not minter status. The current implementation incorrectly blocks legitimate token destruction by owners.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L21-35)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        DoTransfer(tokenHash, Context.Sender, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L57-80)
```csharp
    public override Empty TransferFrom(TransferFromInput input)
    {
        var tokenHash = CalculateTokenHash(input.Symbol, input.TokenId);
        var operatorList = State.OperatorMap[input.Symbol][input.From];
        var isOperator = operatorList?.Value.Contains(Context.Sender) ?? false;
        if (!isOperator)
        {
            var allowance = State.AllowanceMap[tokenHash][input.From][Context.Sender];
            Assert(allowance >= input.Amount, "Not approved.");
            State.AllowanceMap[tokenHash][input.From][Context.Sender] = allowance.Sub(input.Amount);
        }

        DoTransfer(tokenHash, input.From, input.To, input.Amount);
        Context.Fire(new Transferred
        {
            From = input.From,
            To = input.To,
            Amount = input.Amount,
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            Memo = input.Memo
        });
        return new Empty();
    }
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

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L440-441)
```csharp
        var owner = input.Owner ?? Context.Sender;
        State.BalanceMap[tokenHash][owner] = State.BalanceMap[tokenHash][owner].Add(quantity);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L28-28)
```csharp
            IsBurnable = input.IsBurnable,
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L14-274)
```csharp
    [Fact]
    public async Task<string> CreateTest()
    {
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "ELF",
            Amount = 1_00000000_00000000,
            To = DefaultAddress
        });
        await TokenContractStub.Issue.SendAsync(new IssueInput
        {
            Symbol = "ELF",
            Amount = 1_00000000_00000000,
            To = MinterAddress
        });

        var executionResult = await NFTContractStub.Create.SendAsync(new CreateInput
        {
            BaseUri = BaseUri,
            Creator = DefaultAddress,
            IsBurnable = true,
            Metadata = new Metadata
            {
                Value =
                {
                    { "Description", "Stands for the human race." }
                }
            },
            NftType = NFTType.VirtualWorlds.ToString(),
            ProtocolName = "HUMAN",
            TotalSupply = 1_000_000_000 // One billion
        });
        var symbol = executionResult.Output.Value;

        symbol.Length.ShouldBe(11);

        var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue
        {
            Value = symbol
        });
        protocolInfo.Symbol.ShouldBe(symbol);
        protocolInfo.Metadata.Value.ShouldContainKey("Description");
        protocolInfo.Creator.ShouldBe(DefaultAddress);
        protocolInfo.NftType.ShouldBe(NFTType.VirtualWorlds.ToString());
        protocolInfo.TotalSupply.ShouldBe(1_000_000_000);

        var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput
        {
            Symbol = symbol
        });

        tokenInfo.Decimals.ShouldBe(0);
        tokenInfo.Symbol.ShouldBe(symbol);
        tokenInfo.Issuer.ShouldBe(DefaultAddress);
        tokenInfo.ExternalInfo.Value["Description"].ShouldBe("Stands for the human race.");
        tokenInfo.ExternalInfo.Value["aelf_nft_type"].ShouldBe("VirtualWorlds");
        tokenInfo.ExternalInfo.Value["aelf_nft_base_uri"].ShouldBe(BaseUri);

        return symbol;
    }

    [Fact]
    public async Task<(string, Hash)> MintTest()
    {
        var symbol = await CreateTest();
        await AddMinterAsync(symbol);

        var tokenHash = (await MinterNFTContractStub.Mint.SendAsync(new MintInput
        {
            Symbol = symbol,
            Alias = "could be anything",
            Metadata = new Metadata
            {
                Value =
                {
                    { "Special Property", "A Value" }
                }
            },
            Owner = DefaultAddress,
            Uri = $"{BaseUri}foo"
        })).Output;

        {
            var nftInfo = await NFTContractStub.GetNFTInfoByTokenHash.CallAsync(tokenHash);
            nftInfo.Creator.ShouldBe(DefaultAddress);
            nftInfo.Minters.ShouldContain(MinterAddress);
        }

        {
            var nftInfo = await NFTContractStub.GetNFTInfo.CallAsync(new GetNFTInfoInput
            {
                Symbol = symbol,
                TokenId = 1
            });
            nftInfo.Creator.ShouldBe(DefaultAddress);
            nftInfo.Minters.ShouldContain(MinterAddress);
        }

        {
            var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue
            {
                Value = symbol
            });
            protocolInfo.Metadata.Value.ShouldNotContainKey("Special Property");
        }

        return (symbol, tokenHash);
    }

    [Fact(Skip = "Dup in TransferTest")]
    public async Task<string> MintMultiTokenTest()
    {
        var symbol = await CreateTest();
        await AddMinterAsync(symbol);

        await MinterNFTContractStub.Mint.SendAsync(new MintInput
        {
            Symbol = symbol,
            Alias = "could be anything",
            Metadata = new Metadata
            {
                Value =
                {
                    { "Max Health Points", "0" },
                    { "Max Mana Points", "0" },
                    { "Skill Points", "0" },
                    { "Level", "0" },
                    { "Experience", "0" }
                }
            },
            Quantity = 100,
            Uri = $"{BaseUri}foo"
        });

        return symbol;
    }

    [Fact]
    public async Task<string> TransferTest()
    {
        var symbol = await MintMultiTokenTest();
        await MinterNFTContractStub.Transfer.SendAsync(new TransferInput
        {
            To = User1Address,
            Symbol = symbol,
            TokenId = 1,
            Amount = 10
        });

        {
            var balance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = User1Address,
                Symbol = symbol,
                TokenId = 1
            })).Balance;
            balance.ShouldBe(10);
        }

        {
            var balance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = MinterAddress,
                Symbol = symbol,
                TokenId = 1
            })).Balance;
            balance.ShouldBe(90);
        }

        return symbol;
    }

    [Fact]
    public async Task ApproveTest()
    {
        var symbol = await TransferTest();

        await MinterNFTContractStub.Approve.SendAsync(new ApproveInput
        {
            Spender = DefaultAddress,
            Symbol = symbol,
            TokenId = 1,
            Amount = 10
        });

        {
            var allowance = (await NFTContractStub.GetAllowance.CallAsync(new GetAllowanceInput
            {
                Owner = MinterAddress,
                Spender = DefaultAddress,
                Symbol = symbol,
                TokenId = 1
            })).Allowance;
            allowance.ShouldBe(10);
        }

        await NFTContractStub.TransferFrom.SendAsync(new TransferFromInput
        {
            To = User1Address,
            Symbol = symbol,
            TokenId = 1,
            Amount = 9,
            From = MinterAddress
        });

        {
            var balance = (await MinterNFTContractStub.GetBalance.CallAsync(new GetBalanceInput
            {
                Owner = User1Address,
                Symbol = symbol,
                TokenId = 1
            })).Balance;
            balance.ShouldBe(19);
        }
    }

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

    private async Task AddMinterAsync(string symbol)
    {
        await NFTContractStub.AddMinters.SendAsync(new AddMintersInput
        {
            Symbol = symbol,
            MinterList = new MinterList
            {
                Value = { MinterAddress }
            }
        });
    }
}
```
