# Audit Report

## Title
Creator Impersonation Vulnerability in NFT Protocol Creation

## Summary
The `Create()` method in the NFT Contract allows the `input.Creator` field to be set to an arbitrary address without validation, while the seed NFT cost is deducted from `Context.Sender`. This creates a dangerous privilege mismatch where an attacker can gain complete control over an NFT protocol (including exclusive minting rights and minter management) while the victim who paid the seed NFT cost receives no control over the protocol they funded.

## Finding Description

The vulnerability exists in the NFT Contract's `Create()` method where the creator address is determined without proper validation: [1](#0-0) 

This allows `input.Creator` to be any arbitrary address. If `input.Creator` is null, it defaults to `Context.Sender`, but critically, there is no validation ensuring that when `input.Creator` is explicitly provided, it matches `Context.Sender`.

This creator address is then used as the token issuer when creating the underlying token in the MultiToken contract: [2](#0-1) 

The MultiToken contract's `Create` method validates and burns the seed NFT from `Context.Sender` (the transaction initiator), not from the `Issuer` field: [3](#0-2) 

This creates a critical privilege mismatch: the seed NFT is burned from `Context.Sender`'s balance, but all protocol control privileges are granted to the arbitrary `input.Creator` address.

The creator is stored in the NFT protocol info with exclusive management rights: [4](#0-3) 

Only the creator can add minters to the protocol: [5](#0-4) 

Only the creator can remove minters from the protocol: [6](#0-5) 

Additionally, the creator becomes the token issuer in the MultiToken contract, granting exclusive `Issue()` rights: [7](#0-6) 

## Impact Explanation

**Direct Financial Loss:**
- The victim loses their seed NFT, which is a scarce and valuable resource required for token creation
- Seed NFTs have economic value and are necessary for protocol creation rights
- The victim pays the cost but receives no control over the protocol

**Authorization Impact:**
- The attacker gains exclusive creator privileges over the NFT protocol without authorization
- The attacker has sole authority to add/remove minters, controlling who can mint NFTs for the protocol
- The attacker becomes the token issuer, with exclusive rights to issue tokens via the MultiToken contract
- The victim who paid for the protocol creation cannot manage, modify, or control the protocol in any way

**Who is Affected:**
- Any user creating NFT protocols through interfaces (dApps, wallets, SDKs) that could populate `input.Creator` incorrectly
- Users interacting with malicious or compromised frontends
- Less technical users who may not understand the significance of the creator parameter

**Severity Classification:**
This represents a high-severity authorization bypass vulnerability:
- Complete loss of protocol control for the legitimate payer
- Complete privilege escalation to an unauthorized attacker
- Concrete economic loss (seed NFT value)
- No on-chain mechanism to detect or prevent the attack before execution

## Likelihood Explanation

**Attack Feasibility:**
The attack requires the victim to call the `Create()` method with `input.Creator` set to the attacker's address. This can occur through:

1. **Malicious dApp Interfaces**: An attacker-controlled or compromised dApp could populate the `input.Creator` field with the attacker's address in the transaction parameters
2. **Compromised SDKs/Libraries**: If the SDK or library used to interact with the contract is compromised, it could inject the wrong creator address
3. **Frontend Vulnerabilities**: Man-in-the-middle attacks or XSS vulnerabilities could modify transaction parameters before signing
4. **Social Engineering**: Less sophisticated users could be convinced to copy-paste specific parameters

**Probability Assessment:**
- The attack requires user interaction but exploits a missing contract-level validation
- As web3 adoption grows, malicious dApps and compromised frontends become increasingly common
- Users typically trust frontend interfaces to populate parameters correctly
- There is no on-chain warning or validation to alert users when creator ≠ sender

**Detection Constraints:**
- The transaction appears valid and will succeed without any error
- No event or log indicates that the creator differs from the sender
- The victim may not notice until attempting to manage the protocol later

The likelihood is medium-to-high given the prevalence of malicious dApps and the complete absence of contract-level validation.

## Recommendation

Add validation in the `Create()` method to ensure that if `input.Creator` is explicitly provided, it must match `Context.Sender`:

```csharp
public override StringValue Create(CreateInput input)
{
    Assert(Context.ChainId == ChainHelper.ConvertBase58ToChainId("AELF"),
        "NFT Protocol can only be created at aelf mainchain.");
    
    // Add validation
    if (input.Creator != null)
    {
        Assert(input.Creator == Context.Sender, 
            "Creator must match transaction sender.");
    }
    
    MakeSureTokenContractAddressSet();
    MakeSureRandomNumberProviderContractAddressSet();
    var symbol = GetSymbol(input.NftType);
    var tokenExternalInfo = GetTokenExternalInfo(input);
    var creator = input.Creator ?? Context.Sender;
    // ... rest of the method
}
```

Alternatively, remove the `Creator` field from `CreateInput` entirely and always use `Context.Sender` as the creator, eliminating the possibility of mismatch:

```csharp
var creator = Context.Sender; // Always use Context.Sender
```

## Proof of Concept

```csharp
[Fact]
public async Task CreatorImpersonationVulnerability_Test()
{
    // Setup: Victim has seed NFT and funds
    var victimAddress = DefaultAddress;
    var attackerAddress = MinterAddress;
    
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "ELF",
        Amount = 1_00000000_00000000,
        To = victimAddress
    });

    // Victim calls Create() with attacker's address as creator
    // (simulating malicious dApp providing wrong parameters)
    var executionResult = await NFTContractStub.Create.SendAsync(new CreateInput
    {
        BaseUri = "ipfs://test/",
        Creator = attackerAddress, // ATTACKER'S ADDRESS
        IsBurnable = true,
        NftType = NFTType.Art.ToString(),
        ProtocolName = "EXPLOITED",
        TotalSupply = 1_000_000
    });
    
    var symbol = executionResult.Output.Value;
    
    // Verify victim's seed NFT was burned (victim paid the cost)
    // [Seed NFT balance check would go here]
    
    // Verify attacker became the creator (attacker got control)
    var protocolInfo = await NFTContractStub.GetNFTProtocolInfo.CallAsync(
        new StringValue { Value = symbol });
    protocolInfo.Creator.ShouldBe(attackerAddress); // Attacker is creator!
    
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = symbol });
    tokenInfo.Issuer.ShouldBe(attackerAddress); // Attacker is issuer!
    
    // Victim cannot add minters (no permission)
    var addMinterResult = await NFTContractStub.AddMinters.SendWithExceptionAsync(
        new AddMintersInput
        {
            Symbol = symbol,
            MinterList = new MinterList { Value = { victimAddress } }
        });
    addMinterResult.TransactionResult.Error.ShouldContain("No permission");
    
    // Attacker can add minters (has full control)
    await MinterNFTContractStub.AddMinters.SendAsync(new AddMintersInput
    {
        Symbol = symbol,
        MinterList = new MinterList { Value = { attackerAddress } }
    });
    
    // Result: Victim paid (seed NFT burned) but attacker controls the protocol
}
```

## Notes

This vulnerability represents a critical flaw in access control design where the contract fails to validate that the entity paying the cost (via seed NFT burn) matches the entity receiving the privileges (creator/issuer rights). While the exploitation vector involves the victim providing incorrect parameters, the root cause is the contract's missing validation logic. The contract should enforce the invariant that only `Context.Sender` can become the creator of a protocol they are funding, similar to how other authorization checks in the codebase validate sender identity before granting privileges.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L56-65)
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L154-162)
```csharp
    public override Empty Issue(IssueInput input)
    {
        Assert(input.To != null, "To address not filled.");
        AssertValidMemo(input.Memo);
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
        Assert(tokenInfo.Issuer == Context.Sender || Context.Sender == Context.GetZeroSmartContractAddress(),
            $"Sender is not allowed to issue token {input.Symbol}.");

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
