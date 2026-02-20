# Audit Report

## Title
Creator Impersonation Vulnerability in NFT Protocol Creation

## Summary
The NFT contract's `Create()` function accepts arbitrary creator addresses without validating that the transaction sender has authorization to create protocols on behalf of that address. This allows any attacker to create NFT protocols falsely attributed to victim addresses, causing permanent reputation damage and unwanted administrative responsibilities.

## Finding Description
The vulnerability exists in the `Create()` method where the creator address is accepted from user input without authorization checks. [1](#0-0) 

The code uses the null-coalescing operator to assign either the provided creator or the sender, but crucially does not validate that `input.Creator` matches `Context.Sender` when a creator is explicitly provided. This arbitrary creator value is then used to:

1. **Set the token issuer in MultiToken contract**: The creator becomes the issuer in the underlying token system, granting them exclusive rights to issue tokens. [2](#0-1) 

2. **Add creator to minter list automatically**: The creator is automatically added as a minter if not already present. [3](#0-2) 

3. **Store creator in protocol info**: The creator is permanently recorded in the NFT protocol information. [4](#0-3) 

The MultiToken contract's `RegisterTokenInfo` method only validates that the issuer is not null, but performs no authorization check to verify the caller has permission to set that particular address as issuer. [5](#0-4) 

Furthermore, **only the falsely attributed creator** can manage the minter list. The `AddMinters` function enforces that `Context.Sender` must equal the protocol creator. [6](#0-5) 

The same restriction applies to `RemoveMinters`. [7](#0-6) 

The `Issue` method in MultiToken restricts token issuance to the issuer address (or zero contract). [8](#0-7) 

## Impact Explanation
**Reputation Damage**: Attackers can create unlimited NFT protocols falsely attributed to any blockchain address, including prominent community members, DAOs, or competitor projects. Victims appear in on-chain records and events as having created protocols they never authorized, damaging their credibility.

**Unwanted Protocol Ownership**: Victims become the exclusive managers of minter lists and token issuers for protocols they never created. This creates administrative burdens and potential legal liability if the NFT content contains malicious material, copyright violations, or scam elements.

**Irreversible Attribution**: The codebase provides no mechanism to delete NFT protocols or transfer the creator role. Victims are permanently associated with unwanted protocols unless they actively discover the issue and transfer the token issuer role through `ModifyTokenIssuerAndOwner` - which they may never know to do. [9](#0-8) 

**Protocol Spam**: The blockchain becomes polluted with fake protocol creations that cannot be distinguished from legitimate ones without external verification, degrading ecosystem trust.

## Likelihood Explanation
**Attack Complexity**: Trivial - requires only a single transaction with the victim's address in the `creator` field of `CreateInput`.

**Attacker Capabilities**: Any user with the ability to submit transactions to the NFT contract can execute this attack. No special privileges, governance approval, or economic holdings are required.

**Preconditions**: The `Create` function only validates that the transaction is submitted on the AELF mainchain. [10](#0-9)  There is no validation that `input.Creator` has authorized the protocol creation.

**Economic Cost**: Only standard gas fees for the Create transaction. No token holdings or collateral required.

**Detection Difficulty**: Victims are unlikely to detect the attack proactively. Discovery typically occurs only when they monitor NFT protocol creation events, users question their association with unknown collections, or they investigate unexpected issuer responsibilities.

## Recommendation
Add an authorization check to ensure that when `input.Creator` is provided, it must match `Context.Sender`. The fix should be implemented at the beginning of the `Create()` method:

```csharp
public override StringValue Create(CreateInput input)
{
    Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
        "NFT Protocol can only be created at aelf mainchain.");
    
    // Authorization check: if creator is specified, it must be the sender
    if (input.Creator != null)
    {
        Assert(input.Creator == Context.Sender, 
            "Cannot create NFT protocol on behalf of another address.");
    }
    
    var creator = input.Creator ?? Context.Sender;
    // ... rest of implementation
}
```

Alternatively, remove the ability to specify a creator entirely and always use `Context.Sender` as the creator.

## Proof of Concept
```csharp
[Fact]
public async Task CreatorImpersonation_Attack_Test()
{
    // Setup: Alice is the victim whose address will be impersonated
    var aliceAddress = Address.FromPublicKey(SampleECKeyPairs.KeyPairs[0].PublicKey);
    
    // Attacker (using default sender) creates NFT protocol with Alice as creator
    var createInput = new CreateInput
    {
        NftType = NFTType.Art.ToString(),
        ProtocolName = "Malicious Collection",
        TotalSupply = 10000,
        IsBurnable = true,
        IssueChainId = _chainId,
        Creator = aliceAddress,  // Impersonating Alice
        BaseUri = "https://attacker.com/nft/",
        Metadata = new Metadata()
    };
    
    // Attack succeeds - protocol created with Alice as creator
    var result = await NFTContractStub.Create.SendAsync(createInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var symbol = result.Output.Value;
    
    // Verify: Alice is recorded as the creator
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(new StringValue { Value = symbol });
    protocolInfo.Creator.ShouldBe(aliceAddress);
    
    // Verify: Alice is in the minter list
    var minterList = await NFTContractStub.GetMinterList.CallAsync(new StringValue { Value = symbol });
    minterList.Value.ShouldContain(aliceAddress);
    
    // Verify: Alice is the token issuer in MultiToken contract
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = symbol });
    tokenInfo.Issuer.ShouldBe(aliceAddress);
    
    // Impact: Only Alice can manage minters, not the actual creator (attacker)
    // Attacker cannot add themselves as minter
    var addMinterResult = await NFTContractStub.AddMinters.SendWithExceptionAsync(new AddMintersInput
    {
        Symbol = symbol,
        MinterList = new MinterList { Value = { DefaultSender } }
    });
    addMinterResult.TransactionResult.Error.ShouldContain("No permission");
}
```

## Notes
This vulnerability breaks the fundamental security guarantee that users can only create NFT protocols for themselves. The attack is realistic, requires no special privileges, and causes permanent damage to victim reputations. The fix is straightforward: add a single authorization check to ensure `input.Creator` matches `Context.Sender` when provided.

### Citations

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L16-17)
```csharp
        Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
            "NFT Protocol can only be created at aelf mainchain.");
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

**File:** contract/AElf.Contracts.NFT/NFTContract_Create.cs (L40-53)
```csharp
        var protocolInfo = new NFTProtocolInfo
        {
            Symbol = symbol,
            BaseUri = input.BaseUri,
            TotalSupply = tokenCreateInput.TotalSupply,
            Creator = tokenCreateInput.Issuer,
            Metadata = new Metadata { Value = { tokenExternalInfo.Value } },
            ProtocolName = tokenCreateInput.TokenName,
            IsTokenIdReuse = input.IsTokenIdReuse,
            IssueChainId = tokenCreateInput.IssueChainId,
            IsBurnable = tokenCreateInput.IsBurnable,
            NftType = input.NftType
        };
        State.NftProtocolMap[symbol] = protocolInfo;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L224-234)
```csharp
    private void RegisterTokenInfo(TokenInfo tokenInfo)
    {
        Assert(!string.IsNullOrEmpty(tokenInfo.Symbol) && IsValidSymbol(tokenInfo.Symbol),
            "Invalid symbol.");
        Assert(!string.IsNullOrEmpty(tokenInfo.TokenName), "Token name can neither be null nor empty.");
        Assert(tokenInfo.TotalSupply > 0, "Invalid total supply.");
        Assert(tokenInfo.Issuer != null, "Invalid issuer address.");
        Assert(tokenInfo.Owner != null, "Invalid owner address.");
        State.TokenInfos[tokenInfo.Symbol] = tokenInfo;
        State.InsensitiveTokenExisting[tokenInfo.Symbol.ToUpper()] = true;
    }
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L335-352)
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
```

**File:** contract/AElf.Contracts.NFT/NFTContract_UseChain.cs (L355-373)
```csharp
    public override Empty RemoveMinters(RemoveMintersInput input)
    {
        var protocolInfo = State.NftProtocolMap[input.Symbol];
        Assert(Context.Sender == protocolInfo.Creator, "No permission.");
        var minterList = State.MinterListMap[protocolInfo.Symbol];

        foreach (var minter in input.MinterList.Value)
            if (minterList.Value.Contains(minter))
                minterList.Value.Remove(minter);

        State.MinterListMap[input.Symbol] = minterList;

        Context.Fire(new MinterListRemoved
        {
            Symbol = input.Symbol,
            MinterList = input.MinterList
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L154-178)
```csharp
    public override Empty Issue(IssueInput input)
    {
        Assert(input.To != null, "To address not filled.");
        AssertValidMemo(input.Memo);
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
        Assert(tokenInfo.Issuer == Context.Sender || Context.Sender == Context.GetZeroSmartContractAddress(),
            $"Sender is not allowed to issue token {input.Symbol}.");

        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(input.To, input.Symbol, input.Amount);

        Context.Fire(new Issued
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = input.To,
            Memo = input.Memo
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L642-659)
```csharp
    public override Empty ModifyTokenIssuerAndOwner(ModifyTokenIssuerAndOwnerInput input)
    {
        Assert(!State.TokenIssuerAndOwnerModificationDisabled.Value, "Set token issuer and owner disabled.");
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        Assert(input.Issuer != null && !input.Issuer.Value.IsNullOrEmpty(), "Invalid input issuer.");
        Assert(input.Owner != null && !input.Owner.Value.IsNullOrEmpty(), "Invalid input owner.");

        var tokenInfo = GetTokenInfo(input.Symbol);

        Assert(tokenInfo != null, "Token is not found.");
        Assert(tokenInfo.Issuer == Context.Sender, "Only token issuer can set token issuer and owner.");
        Assert(tokenInfo.Owner == null, "Can only set token which does not have owner.");
        
        tokenInfo.Issuer = input.Issuer;
        tokenInfo.Owner = input.Owner;

        return new Empty();
    }
```
