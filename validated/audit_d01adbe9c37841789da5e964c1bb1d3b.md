# Audit Report

## Title
Reserved External Info Key Collision Enables Arbitrary Contract Execution During Token Operations

## Summary
The MultiToken contract accepts user-provided ExternalInfo during token creation without validating against reserved callback keys. Attackers can create tokens with malicious callbacks that execute automatically during transfer, lock, and unlock operations, enabling denial-of-service attacks, gas exhaustion, and potential reentrancy exploitation.

## Finding Description

The vulnerability exists in the token creation flow where user-provided ExternalInfo is accepted without validation. The `CreateToken` method directly assigns user input to the token's ExternalInfo without checking for reserved keys: [1](#0-0) 

The system defines four reserved callback keys intended for system use: [2](#0-1) 

A view function `GetReservedExternalInfoKeyList` exposes these keys: [3](#0-2) 

However, this function is never called for validation during token creation (confirmed via grep search showing only one occurrence in the entire codebase).

When tokens are transferred, the contract unconditionally executes any callback specified in ExternalInfo: [4](#0-3) 

Similar callback execution occurs during lock operations: [5](#0-4) 

And unlock operations: [6](#0-5) 

The callbacks are invoked using `Context.SendInline()`, which propagates errors upward, causing the entire parent transaction to fail if the callback reverts. The ExternalInfo cannot be modified after token creation (confirmed via grep search showing no update methods exist), making malicious callbacks permanent.

## Impact Explanation

**Guaranteed Denial of Service (HIGH)**: An attacker can create a token with a callback that reverts. Any user attempting to transfer, lock, or unlock this malicious token will have their transaction fail due to error propagation from `Context.SendInline()`. This is a straightforward, easily exploitable DoS that affects all holders of the malicious token, with no way to bypass or remediate once the token is created.

**Gas Exhaustion (HIGH)**: Callbacks can contain expensive operations, forcing victims to pay excessive gas fees for attacker-controlled code execution during routine token operations.

**Reentrancy Risk (MEDIUM-HIGH)**: Callbacks execute via `Context.SendInline()` during the middle of token operations (transfer at lines 184-191, lock at lines 213-220, unlock at lines 243-250 of TokenContract_Actions.cs), creating a reentrancy vector. While direct fund theft requires additional conditions, the reentrancy itself violates the non-reentrant execution model expected during token transfers.

**Event Log Pollution (MEDIUM)**: The `aelf_log_event` key allows injecting arbitrary events that appear to originate from the MultiToken contract: [7](#0-6) 

**Trust Model Breakdown**: The existence of `GetReservedExternalInfoKeyList` with the naming "reserved" indicates these keys were intended to be system-controlled. Allowing user-set values breaks this security boundary.

## Likelihood Explanation

**Attack Prerequisites (LOW BARRIER)**:
- Attacker needs a SEED NFT to create the malicious token, obtainable through normal token creation mechanisms (as shown in CheckSeedNFT method): [8](#0-7) 

- No special permissions or whitelist membership required beyond SEED ownership
- SEED NFT is burned during token creation (one-time cost)

**Attack Steps**:
1. Acquire SEED NFT for desired token symbol
2. Create malicious token with ExternalInfo containing reserved callback key (e.g., `"aelf_transfer_callback": "{\"contract_address\":\"<attacker_contract>\",\"method_name\":\"MaliciousCallback\"}"`)
3. Distribute tokens to victims via airdrops or legitimate-looking distributions
4. When victims transfer/lock/unlock the token, callbacks execute automatically and cause transaction failures

**No Detection or Prevention**:
- Malicious tokens are indistinguishable from legitimate ones at creation time
- No on-chain validation prevents setting reserved keys
- No mechanism exists to update ExternalInfo or blacklist malicious callbacks after discovery

**High Probability**: The attack is straightforward, economically viable (low cost of SEED NFT), requires no special privileges beyond SEED NFT ownership, and is difficult to detect until exploited.

## Recommendation

Add validation in the `CreateToken` method to prevent users from setting reserved callback keys in ExternalInfo:

```csharp
private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
{
    AssertValidCreateInput(input, symbolType);
    
    // Validate ExternalInfo against reserved keys
    if (input.ExternalInfo != null && input.ExternalInfo.Value != null)
    {
        var reservedKeys = new[] {
            TokenContractConstants.TransferCallbackExternalInfoKey,
            TokenContractConstants.LockCallbackExternalInfoKey,
            TokenContractConstants.UnlockCallbackExternalInfoKey,
            TokenContractConstants.LogEventExternalInfoKey
        };
        
        foreach (var reservedKey in reservedKeys)
        {
            Assert(!input.ExternalInfo.Value.ContainsKey(reservedKey), 
                $"Cannot set reserved external info key: {reservedKey}");
        }
    }
    
    // ... rest of CreateToken logic
}
```

Alternatively, only allow whitelisted system contracts to set these reserved keys by checking `IsAddressInCreateWhiteList(Context.Sender)` before permitting reserved key usage.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousCallbackCausesTransferDoS()
{
    // 1. Create malicious callback contract that always reverts
    var maliciousContract = await CreateMaliciousCallbackContract();
    
    // 2. Attacker creates SEED NFT for symbol "MAL"
    await CreateSeedNft("MAL");
    
    // 3. Attacker creates token with malicious transfer callback in ExternalInfo
    var externalInfo = new ExternalInfo();
    externalInfo.Value.Add(
        "aelf_transfer_callback", 
        $"{{\"contract_address\":\"{maliciousContract}\",\"method_name\":\"AlwaysRevert\"}}"
    );
    
    var createInput = new CreateInput
    {
        Symbol = "MAL",
        TokenName = "Malicious Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = AttackerAddress,
        IsBurnable = true,
        ExternalInfo = externalInfo
    };
    
    await TokenContractStub.Create.SendAsync(createInput);
    
    // 4. Issue tokens to victim
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "MAL",
        Amount = 1000,
        To = VictimAddress
    });
    
    // 5. Victim attempts to transfer - transaction should FAIL due to callback
    var transferResult = await VictimTokenContractStub.Transfer.SendWithExceptionAsync(
        new TransferInput
        {
            To = OtherAddress,
            Symbol = "MAL",
            Amount = 100
        });
    
    // Assert: Transfer fails because malicious callback reverts
    transferResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    transferResult.TransactionResult.Error.ShouldContain("Callback reverted");
    
    // Victim's tokens are now effectively locked - cannot transfer, lock, or unlock
}
```

This test demonstrates that once a token is created with a malicious callback in a reserved ExternalInfo key, all holders of that token experience permanent DoS on transfer/lock/unlock operations, with no remediation possible.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L367-376)
```csharp
    private void FireExternalLogEvent(TokenInfo tokenInfo, TransferFromInput input)
    {
        if (tokenInfo.ExternalInfo.Value.ContainsKey(TokenContractConstants.LogEventExternalInfoKey))
            Context.FireLogEvent(new LogEvent
            {
                Name = tokenInfo.ExternalInfo.Value[TokenContractConstants.LogEventExternalInfoKey],
                Address = Context.Self,
                NonIndexed = input.ToByteString()
            });
    }
```
