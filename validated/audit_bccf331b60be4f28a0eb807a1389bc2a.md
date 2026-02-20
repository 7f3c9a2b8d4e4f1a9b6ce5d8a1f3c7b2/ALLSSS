# Audit Report

## Title
Reserved External Info Key Collision Enables Arbitrary Contract Execution During Token Operations

## Summary
The MultiToken contract accepts user-provided ExternalInfo during token creation without validating against reserved callback keys. Attackers can create tokens with malicious callbacks that execute automatically during transfer, lock, and unlock operations, enabling denial-of-service attacks, gas exhaustion, and potential reentrancy exploitation.

## Finding Description

The vulnerability exists in the token creation flow where user-provided ExternalInfo is accepted without validation. The `CreateToken` method directly assigns user input to the token's ExternalInfo without checking for reserved keys. [1](#0-0) 

The system defines four reserved callback keys intended for system use. [2](#0-1) 

A view function `GetReservedExternalInfoKeyList` exposes these keys. [3](#0-2)  However, grep search confirms it is never called for validation during token creation - it only exists in the proto definition and Views implementation.

The input validation method `AssertValidCreateInput` performs checks on token name, symbol, and decimals but does NOT validate ExternalInfo against reserved keys. [4](#0-3) 

When tokens are transferred, the contract unconditionally executes any callback specified in ExternalInfo. [5](#0-4) 

Similar callback execution occurs during lock operations. [6](#0-5) 

And unlock operations. [7](#0-6) 

The CallbackInfo structure allows specifying arbitrary contract addresses and method names. [8](#0-7) 

The token creation process requires SEED NFT ownership for non-whitelisted users, which are obtainable through normal token creation mechanisms. [9](#0-8) 

## Impact Explanation

**Guaranteed Denial of Service (HIGH)**: An attacker can create a token with a callback that reverts. Any user attempting to transfer, lock, or unlock this malicious token will have their transaction fail because `Context.SendInline()` executes synchronously and reverts the entire transaction if the callback reverts. This is a straightforward, easily exploitable DoS that affects all holders of the malicious token.

**Gas Exhaustion (HIGH)**: Callbacks can contain expensive operations, forcing victims to pay excessive gas fees for attacker-controlled code execution during routine token operations. The victim has no way to avoid this cost when interacting with the malicious token.

**Reentrancy Risk (MEDIUM-HIGH)**: Callbacks execute via `Context.SendInline()` during the middle of token operations (after balance changes but during the operation flow), creating a reentrancy vector. While direct fund theft requires additional conditions (such as victims having approved the attacker's contract), the reentrancy itself violates the expected execution model during token transfers.

**Event Log Pollution (MEDIUM)**: The `aelf_log_event` key allows injecting arbitrary events that appear to originate from the MultiToken contract, potentially misleading indexers and applications relying on MultiToken events.

**Trust Model Breakdown**: The existence of `GetReservedExternalInfoKeyList` indicates these keys were intended to be system-controlled. Allowing user-set values breaks this security boundary and enables the attacks described above.

## Likelihood Explanation

**Attack Prerequisites (LOW BARRIER)**:
- Attacker needs a SEED NFT to create the malicious token, obtainable through normal token creation mechanisms
- No special permissions or whitelist membership required beyond SEED ownership
- Cost is minimal (just SEED NFT acquisition)

**Attack Steps**:
1. Acquire SEED NFT for desired token symbol
2. Create malicious token with ExternalInfo containing reserved callback key (e.g., `"aelf_transfer_callback": "{\"contract_address\":\"<attacker_contract>\",\"method_name\":\"MaliciousCallback\"}"`)
3. Distribute tokens to victims via airdrops or legitimate-looking distributions
4. When victims transfer/lock/unlock the token, callbacks execute automatically

**No Detection or Prevention**:
- Malicious tokens are indistinguishable from legitimate ones at creation time
- No on-chain validation prevents setting reserved keys
- No mechanism exists to blacklist malicious callbacks after discovery
- Users cannot opt-out of callback execution when transferring tokens

**High Probability**: The attack is straightforward, economically viable (low cost), requires no special privileges beyond SEED NFT ownership, and is difficult to detect until exploited.

## Recommendation

Add validation during token creation to prevent users from setting reserved callback keys in ExternalInfo:

```csharp
private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
{
    Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
           && input.Symbol.Length > 0
           && input.Decimals >= 0
           && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

    // Add validation for reserved external info keys
    if (input.ExternalInfo != null && input.ExternalInfo.Value.Count > 0)
    {
        var reservedKeys = new[]
        {
            TokenContractConstants.TransferCallbackExternalInfoKey,
            TokenContractConstants.LockCallbackExternalInfoKey,
            TokenContractConstants.UnlockCallbackExternalInfoKey,
            TokenContractConstants.LogEventExternalInfoKey
        };
        
        foreach (var reservedKey in reservedKeys)
        {
            Assert(!input.ExternalInfo.Value.ContainsKey(reservedKey), 
                $"Reserved external info key '{reservedKey}' cannot be set during token creation.");
        }
    }

    CheckSymbolLength(input.Symbol, symbolType);
    if (symbolType == SymbolType.Nft) return;
    CheckTokenAndCollectionExists(input.Symbol);
    if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
}
```

Alternatively, implement a whitelist mechanism where only authorized addresses (e.g., governance contracts) can set reserved callback keys.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousCallbackCausesDoS()
{
    // 1. Deploy malicious callback contract that always reverts
    var maliciousContract = await DeployMaliciousCallbackContract();
    
    // 2. Acquire SEED NFT
    var seedSymbol = await CreateSeedNFT("EVIL");
    
    // 3. Create token with malicious callback in ExternalInfo
    var createInput = new CreateInput
    {
        Symbol = "EVIL",
        TokenName = "Evil Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = DefaultSender,
        IsBurnable = true,
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                {
                    "aelf_transfer_callback", 
                    $"{{\"contract_address\":\"{maliciousContract}\",\"method_name\":\"RevertAlways\"}}"
                }
            }
        }
    };
    
    await TokenContractStub.Create.SendAsync(createInput);
    
    // 4. Issue tokens and distribute to victim
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "EVIL",
        Amount = 1000,
        To = VictimAddress
    });
    
    // 5. Victim attempts to transfer token - transaction should FAIL
    var result = await VictimTokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = AnotherAddress,
        Symbol = "EVIL",
        Amount = 100
    });
    
    // Assertion: Transfer fails due to malicious callback
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Malicious callback reverted");
}
```

This proof of concept demonstrates that:
1. An attacker can create a token with a malicious callback in ExternalInfo
2. When victims attempt to transfer the token, the callback executes
3. If the callback reverts, the entire transfer transaction fails
4. This creates a permanent DoS for all holders of the malicious token

**Notes**

The vulnerability is particularly severe because:
- Token holders cannot opt-out of callback execution
- No mechanism exists to update or remove malicious callbacks after token creation
- The attack affects fundamental token operations (transfer, lock, unlock)
- Multiple reserved keys can be exploited (transfer, lock, unlock, log_event callbacks)
- Reentrancy concerns compound the risk during complex DeFi operations

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L51-66)
```csharp
        if (symbolType == SymbolType.Token || symbolType == SymbolType.NftCollection)
        {
            // can not call create on side chain
            Assert(State.SideChainCreator.Value == null,
                "Failed to create token if side chain creator already set.");
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
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L68-79)
```csharp
        var tokenInfo = new TokenInfo
        {
            Symbol = input.Symbol,
            TokenName = input.TokenName,
            TotalSupply = input.TotalSupply,
            Decimals = input.Decimals,
            Issuer = input.Issuer,
            IsBurnable = input.IsBurnable,
            IssueChainId = input.IssueChainId == 0 ? Context.ChainId : input.IssueChainId,
            ExternalInfo = input.ExternalInfo ?? new ExternalInfo(),
            Owner = input.Owner
        };
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L13-16)
```csharp
    public const string TransferCallbackExternalInfoKey = "aelf_transfer_callback";
    public const string LockCallbackExternalInfoKey = "aelf_lock_callback";
    public const string UnlockCallbackExternalInfoKey = "aelf_unlock_callback";
    public const string LogEventExternalInfoKey = "aelf_log_event";
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L238-250)
```csharp
    public override StringList GetReservedExternalInfoKeyList(Empty input)
    {
        return new StringList
        {
            Value =
            {
                TokenContractConstants.LockCallbackExternalInfoKey,
                TokenContractConstants.LogEventExternalInfoKey,
                TokenContractConstants.TransferCallbackExternalInfoKey,
                TokenContractConstants.UnlockCallbackExternalInfoKey
            }
        };
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L272-283)
```csharp
    private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
    {
        Assert(input.TokenName.Length <= TokenContractConstants.TokenNameLength
               && input.Symbol.Length > 0
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");

        CheckSymbolLength(input.Symbol, symbolType);
        if (symbolType == SymbolType.Nft) return;
        CheckTokenAndCollectionExists(input.Symbol);
        if (IsAddressInCreateWhiteList(Context.Sender)) CheckSymbolSeed(input.Symbol);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L322-335)
```csharp
    private void DealWithExternalInfoDuringLocking(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.LockCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.LockCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L337-350)
```csharp
    private void DealWithExternalInfoDuringTransfer(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.TransferCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.TransferCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L352-365)
```csharp
    private void DealWithExternalInfoDuringUnlock(TransferFromInput input)
    {
        var tokenInfo = GetTokenInfo(input.Symbol);
        if (tokenInfo.ExternalInfo == null) return;
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.UnlockCallbackExternalInfoKey))
        {
            var callbackInfo =
                JsonParser.Default.Parse<CallbackInfo>(
                    tokenInfo.ExternalInfo.Value[TokenContractConstants.UnlockCallbackExternalInfoKey]);
            Context.SendInline(callbackInfo.ContractAddress, callbackInfo.MethodName, input);
        }

        FireExternalLogEvent(tokenInfo, input);
    }
```

**File:** protobuf/token_contract.proto (L530-533)
```text
message CallbackInfo {
    aelf.Address contract_address = 1;
    string method_name = 2;
}
```
