### Title
Post-Minting URI Manipulation via Recast Method Enables Content Fraud

### Summary
The NFT contract's `Recast` method allows minters to modify the URI of NFTs after minting, enabling bait-and-switch attacks where legitimate content URIs are replaced with malicious or fraudulent content. While the method requires the caller to own all tokens of a specific tokenId, this protection is insufficient as it doesn't prevent pre-sale manipulation or coordinated buyback attacks. This violates the fundamental NFT immutability assumption that users rely on when purchasing digital assets.

### Finding Description

The `NftInfoMap` state variable stores NFT metadata including the URI field. [1](#0-0) 

The NFTInfo structure contains a mutable `uri` field that points to the NFT's content. [2](#0-1) 

The `Recast` method allows modification of the URI post-minting through direct state updates. [3](#0-2) [4](#0-3) 

The access control for `Recast` requires two conditions: (1) the caller must be in the minter list, and (2) the caller must own ALL tokens of that specific tokenId. [5](#0-4) 

**Why protections fail:**

1. **Pre-sale manipulation**: A minter can mint an NFT with a legitimate URI, then immediately use `Recast` to change it to malicious content before any sale occurs, as they own all tokens initially.

2. **Protocol creator permanence**: The protocol creator is always added to the minter list during creation [6](#0-5)  and only the creator can manage the minter list. [7](#0-6) 

3. **Buyback attack feasibility**: For valuable NFTs, a minter can purchase back all distributed tokens from the market and then use `Recast` to modify the URI.

4. **No immutability enforcement**: Unlike typical NFT standards where metadata URIs are immutable after minting, this implementation explicitly allows modification through `Recast`.

### Impact Explanation

**Harm to users:**
- **Content fraud**: Users purchase NFTs expecting the URI to point to specific content (artwork, collectibles, etc.), but minters can change this to completely different or malicious content
- **Phishing attacks**: URIs can be redirected to phishing sites targeting NFT holders
- **Value destruction**: Changing a popular NFT's content destroys its market value, defrauding holders
- **Reputation damage**: The entire protocol's trustworthiness is compromised if URI manipulation is discovered

**Who is affected:**
- NFT buyers who expect immutable metadata
- Secondary market participants relying on NFT authenticity
- The protocol's reputation and adoption

**Severity justification:**
This is a **Medium to High severity** issue because:
- It violates core NFT expectations of immutability
- Enables direct financial fraud against users
- Can be executed with moderate economic cost (buyback scenario) or zero cost (pre-sale scenario)
- No technical sophistication required to exploit
- Affects the fundamental trust model of NFTs

### Likelihood Explanation

**Attacker capabilities required:**
- Must be a minter for the protocol (either creator or added by creator)
- Must own all tokens of the target tokenId

**Attack complexity:**
- **Low for pre-sale**: Mint → Recast → Sell (trivial)
- **Medium for post-sale**: Acquire all tokens → Recast (requires capital but feasible)

**Feasibility conditions:**
1. **Pre-sale scenario**: 100% feasible, zero additional cost beyond minting
2. **Buyback scenario**: Feasible for high-value NFTs where the attacker has sufficient capital to acquire all tokens from the market
3. **Creator scenario**: Protocol creators retain permanent ability if they can acquire tokens

**Detection constraints:**
- The `Recasted` event is fired [8](#0-7)  but users may not monitor for it
- No notification system alerts current holders of URI changes
- Changes can happen silently after initial purchase

**Probability reasoning:**
Given that:
- Minting and recasting are straightforward operations
- Pre-sale manipulation requires no additional resources
- The economic incentive exists for bait-and-switch fraud
- No tests exist for this functionality suggesting it may not be widely understood [9](#0-8) 

The likelihood is **Medium to High**, especially for pre-sale manipulation scenarios.

### Recommendation

**Immediate mitigations:**

1. **Remove URI mutability**: Make the URI field immutable after initial minting by removing the URI update capability from `Recast`:
```
// Remove this line from Recast method:
if (input.Uri != null) nftInfo.Uri = input.Uri;
```

2. **Implement timelock for any retained mutability**: If URI updates are a required feature, add:
   - Minimum timelock period (e.g., 7 days) before URI changes take effect
   - Governance approval requirement for URI modifications
   - Mandatory notification to all token holders

3. **Add immutability flag**: Introduce an `isUriImmutable` flag in NFTProtocolInfo that can be set during creation to permanently disable URI modifications for that protocol.

4. **Enhanced access control**: If mutability is retained, restrict it to:
   - Require multi-sig approval from protocol governance
   - Only allow within a specific time window after minting (e.g., 24 hours)
   - Require consensus from all token holders

**Invariant checks to add:**
- Assert that URI cannot be changed if any tokens are held by addresses other than the minter
- Assert that URI changes can only occur within a defined grace period after minting
- Add a counter for URI change attempts to detect suspicious behavior

**Test cases to prevent regression:**
- Test that URI cannot be modified after token distribution
- Test that Recast reverts when caller doesn't own all tokens
- Test timelock enforcement if implemented
- Test immutability flag enforcement
- Test that `Recasted` events are properly emitted and logged

### Proof of Concept

**Required initial state:**
- Attacker is the protocol creator or an authorized minter
- NFT protocol has been created

**Transaction steps:**

1. **Attacker mints NFT with legitimate URI:**
```
Mint({
  symbol: "MYART-0",
  uri: "ipfs://legitimate-artwork-hash",
  owner: Attacker,
  quantity: 1
})
```

2. **Attacker advertises and potentially sells partial quantity** (for multi-quantity NFTs, keeps all tokens for single-quantity)

3. **Attacker changes URI to malicious content:**
```
Recast({
  symbol: "MYART-0", 
  tokenId: 1,
  uri: "https://malicious-phishing-site.com"
})
```

**Expected vs actual result:**
- **Expected**: URI modification should be blocked after minting or require governance approval
- **Actual**: URI is successfully changed to malicious content with only minter permission check and full ownership requirement

**Success condition:**
The NFT's URI in `NftInfoMap` is updated to the malicious URL, and subsequent calls to `GetNFTInfoByTokenHash` return the modified URI, redirecting users to malicious content.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContractState.cs (L17-17)
```csharp
    public MappedState<Hash, NFTInfo> NftInfoMap { get; set; }
```

**File:** protobuf/nft_contract.proto (L303-303)
```text
    string uri = 8;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L259-263)
```csharp
        var minterList = State.MinterListMap[input.Symbol] ?? new MinterList();
        Assert(minterList.Value.Contains(Context.Sender), "No permission.");
        var nftInfo = GetNFTInfoByTokenHash(tokenHash);
        Assert(nftInfo.Quantity != 0 && nftInfo.Quantity == State.BalanceMap[tokenHash][Context.Sender],
            "Do not support recast.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L266-266)
```csharp
        if (input.Uri != null) nftInfo.Uri = input.Uri;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L282-282)
```csharp
        State.NftInfoMap[tokenHash] = nftInfo;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L283-291)
```csharp
        Context.Fire(new Recasted
        {
            Symbol = input.Symbol,
            TokenId = input.TokenId,
            OldMetadata = oldMetadata,
            NewMetadata = nftInfo.Metadata,
            Alias = nftInfo.Alias,
            Uri = nftInfo.Uri
        });
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L337-338)
```csharp
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```

**File:** test/AElf.Contracts.NFT.Tests/NFTContractTests.cs (L1-274)
```csharp
using System.Threading.Tasks;
using AElf.Contracts.MultiToken;
using AElf.Types;
using Google.Protobuf.WellKnownTypes;
using Shouldly;
using Xunit;

namespace AElf.Contracts.NFT;

public partial class NFTContractTests : NFTContractTestBase
{
    private const string BaseUri = "ipfs://aelf/";

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
