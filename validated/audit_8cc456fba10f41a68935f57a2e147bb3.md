# Audit Report

## Title
Reserved External Info Key Collision Enables Arbitrary Contract Execution During Token Operations

## Summary
The MultiToken contract accepts user-provided ExternalInfo during token creation without validating against reserved callback keys. Attackers can create tokens with malicious callbacks that execute automatically during transfer, lock, and unlock operations, enabling denial-of-service attacks, gas exhaustion, and potential reentrancy exploitation.

## Finding Description

The vulnerability exists in the token creation flow where user-provided ExternalInfo is accepted without validation. The `CreateToken` method directly assigns user input to the token's ExternalInfo without checking for reserved keys: [1](#0-0) 

The system defines four reserved callback keys intended for system use: [2](#0-1) 

A view function `GetReservedExternalInfoKeyList` exposes these keys, but grep search confirms it is never called for validation during token creation: [3](#0-2) 

When tokens are transferred, the contract unconditionally executes any callback specified in ExternalInfo: [4](#0-3) 

Similar callback execution occurs during lock operations: [5](#0-4) 

And unlock operations: [6](#0-5) 

The CallbackInfo structure allows specifying arbitrary contract addresses and method names: [7](#0-6) 

## Impact Explanation

**Guaranteed Denial of Service (HIGH)**: An attacker can create a token with a callback that reverts. Any user attempting to transfer, lock, or unlock this malicious token will have their transaction fail. This is a straightforward, easily exploitable DoS that affects all holders of the malicious token.

**Gas Exhaustion (HIGH)**: Callbacks can contain expensive operations, forcing victims to pay excessive gas fees for attacker-controlled code execution during routine token operations.

**Reentrancy Risk (MEDIUM-HIGH)**: Callbacks execute via `Context.SendInline()` during the middle of token operations, creating a reentrancy vector. While direct fund theft requires additional conditions (such as victims having approved the attacker's contract), the reentrancy itself violates the non-reentrant execution model expected during token transfers.

**Event Log Pollution (MEDIUM)**: The `aelf_log_event` key allows injecting arbitrary events that appear to originate from the MultiToken contract, potentially misleading indexers and applications.

**Trust Model Breakdown**: The existence of `GetReservedExternalInfoKeyList` indicates these keys were intended to be system-controlled. Allowing user-set values breaks this security boundary.

## Likelihood Explanation

**Attack Prerequisites (LOW BARRIER)**:
- Attacker needs a SEED NFT to create the malicious token, obtainable through normal token creation mechanisms
- No special permissions or whitelist membership required beyond SEED ownership

**Attack Steps**:
1. Acquire SEED NFT for desired token symbol
2. Create malicious token with ExternalInfo containing reserved callback key (e.g., `"aelf_transfer_callback": "{\"contract_address\":\"<attacker_contract>\",\"method_name\":\"MaliciousCallback\"}"`)
3. Distribute tokens to victims via airdrops or legitimate-looking distributions
4. When victims transfer/lock/unlock the token, callbacks execute automatically

**No Detection or Prevention**:
- Malicious tokens are indistinguishable from legitimate ones at creation time
- No on-chain validation prevents setting reserved keys
- No mechanism exists to blacklist malicious callbacks after discovery

**High Probability**: The attack is straightforward, economically viable (low cost), requires no special privileges beyond SEED NFT ownership, and is difficult to detect until exploited.

## Recommendation

Implement validation during token creation to prevent users from setting reserved ExternalInfo keys:

```csharp
private void ValidateExternalInfo(ExternalInfo externalInfo)
{
    if (externalInfo == null || externalInfo.Value.Count == 0)
        return;
        
    var reservedKeys = new HashSet<string>
    {
        TokenContractConstants.LockCallbackExternalInfoKey,
        TokenContractConstants.LogEventExternalInfoKey,
        TokenContractConstants.TransferCallbackExternalInfoKey,
        TokenContractConstants.UnlockCallbackExternalInfoKey
    };
    
    foreach (var key in externalInfo.Value.Keys)
    {
        Assert(!reservedKeys.Contains(key), 
            $"ExternalInfo key '{key}' is reserved and cannot be set by users.");
    }
}
```

Call this validation in the `CreateToken` method before line 77:
```csharp
private Empty CreateToken(CreateInput input, SymbolType symbolType = SymbolType.Token)
{
    AssertValidCreateInput(input, symbolType);
    ValidateExternalInfo(input.ExternalInfo); // Add this line
    
    // ... rest of method
}
```

Additionally, consider implementing a whitelist of authorized contracts that can set callback keys, similar to the lock whitelist mechanism.

## Proof of Concept

```csharp
[Fact]
public async Task ExternalInfoCallbackCollision_ShouldEnableDoS()
{
    // Step 1: Create malicious token with transfer callback
    var maliciousCallbackInfo = new CallbackInfo
    {
        ContractAddress = MaliciousContractAddress, // Contract that reverts
        MethodName = "RevertingCallback"
    };
    
    var createInput = new CreateInput
    {
        Symbol = "EVIL",
        TokenName = "Malicious Token",
        TotalSupply = 1000000,
        Decimals = 8,
        Issuer = AttackerAddress,
        IsBurnable = true,
        Owner = AttackerAddress,
        ExternalInfo = new ExternalInfo
        {
            Value =
            {
                // Attacker sets reserved callback key
                { TokenContractConstants.TransferCallbackExternalInfoKey, 
                  maliciousCallbackInfo.ToString() }
            }
        }
    };
    
    // Step 2: Attacker creates token - SHOULD FAIL but doesn't
    var result = await AttackerTokenStub.Create.SendAsync(createInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Step 3: Issue tokens to victim
    await AttackerTokenStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "EVIL",
        Amount = 100,
        To = VictimAddress
    });
    
    // Step 4: Victim attempts to transfer - transaction FAILS due to callback revert
    var transferResult = await VictimTokenStub.Transfer.SendWithExceptionAsync(new TransferInput
    {
        Symbol = "EVIL",
        Amount = 50,
        To = AnotherAddress
    });
    
    // Vulnerability confirmed: DoS enabled by malicious callback
    transferResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
}
```

## Notes

The vulnerability is confirmed through code analysis:
1. No validation exists in `CreateToken` or `AssertValidCreateInput` methods to check ExternalInfo against reserved keys
2. Grep search confirms `GetReservedExternalInfoKeyList` is only defined (in protobuf and Views), never called for validation
3. Callbacks execute unconditionally via `Context.SendInline()` when reserved keys exist in ExternalInfo
4. The attack requires only a SEED NFT, obtainable through legitimate means

The severity is CRITICAL due to the combination of:
- Easy exploitability (LOW attack complexity)
- HIGH likelihood (no barriers beyond SEED NFT ownership)
- Guaranteed DoS impact + potential reentrancy vectors
- Breaks intended security model (reserved keys should be system-controlled)

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

**File:** protobuf/token_contract.proto (L530-533)
```text
message CallbackInfo {
    aelf.Address contract_address = 1;
    string method_name = 2;
}
```
