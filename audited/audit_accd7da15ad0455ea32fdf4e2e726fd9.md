### Title
Missing Validation of Reserved ExternalInfo Callback Keys Allows Unauthorized Contract Callbacks

### Summary
The MultiToken contract defines reserved external info keys for callbacks (transfer, lock, unlock, log events) via `GetReservedExternalInfoKeyList()`, but this list is never used for validation during token creation. Attackers can create tokens with arbitrary callback addresses in the ExternalInfo, which execute automatically during token operations (transfer/lock/unlock), enabling unauthorized contract calls, reentrancy attacks, DOS, and information leakage.

### Finding Description

The `GetReservedExternalInfoKeyList()` function returns four reserved callback keys: [1](#0-0) 

However, this function is **never called for validation** anywhere in the codebase. When creating a token via the `Create` method, the user-provided `ExternalInfo` is directly assigned without any validation: [2](#0-1) 

The `AssertValidCreateInput()` validation function only checks symbol, decimals, and token name - it does not validate ExternalInfo at all: [3](#0-2) 

When token operations occur (transfer/lock/unlock), the contract checks if callback keys exist in ExternalInfo and automatically executes them without authorization checks: [4](#0-3) 

The callbacks are invoked via `Context.SendInline()` with no validation of the contract address or authorization of who set the callback. The callback receives full transaction details including from/to addresses, amounts, and memos.

### Impact Explanation

**Direct Operational Impact:**
- **Unauthorized Contract Execution**: Attacker-controlled contracts execute during any transfer/lock/unlock of the malicious token, bypassing intended access controls
- **Reentrancy Attacks**: Callbacks execute inline during state changes, enabling reentrancy to manipulate balances or allowances
- **Denial of Service**: Malicious callbacks can revert, making the token non-transferable/non-lockable
- **Information Leakage**: Transaction details (addresses, amounts, memos) are sent to attacker's contract, revealing user behavior and private transaction data

**Who is Affected:**
- Any user who receives, holds, or trades tokens created with malicious callbacks
- Contracts that integrate with such tokens become vulnerable to unexpected callback behavior
- The entire ecosystem trust model is compromised as token operations can trigger arbitrary logic

**Severity Justification:**
This violates the fundamental security invariant that only authorized system contracts should receive inline calls during token operations. The callback mechanism was clearly intended for privileged use (as evidenced by the "reserved" designation), but lacks enforcement, creating a critical authorization bypass.

### Likelihood Explanation

**Attacker Capabilities Required:**
- Ability to create tokens, which requires either:
  - Being in the token creation whitelist (system contracts, unlikely for attacker)
  - Possessing a SEED NFT for the desired symbol (publicly obtainable)
  - Owning an NFT collection and creating items within it (most practical)

**Attack Complexity:**
Low - The exploit is straightforward:
1. Deploy malicious contract with callback methods
2. Create token with ExternalInfo containing callback keys pointing to malicious contract: [5](#0-4) 
3. Distribute token to victims or wait for trading
4. Callbacks automatically execute when victims perform token operations

**Feasibility:**
The attack is highly practical. NFT collection creators can embed malicious callbacks in their NFT items without restrictions. The validation gap is systematic - the reserved list exists but is completely unused.

**Contrast with NFT Contract:**
The NFT contract properly validates metadata keys against reserved keys: [6](#0-5) 

This demonstrates the developers understood the need for such validation but failed to implement it in the MultiToken contract.

### Recommendation

**Immediate Fix:**
Add validation in `AssertValidCreateInput()` to reject tokens with reserved callback keys:

```csharp
private void AssertValidCreateInput(CreateInput input, SymbolType symbolType)
{
    // ... existing validations ...
    
    // Add validation for reserved external info keys
    if (input.ExternalInfo != null && input.ExternalInfo.Value.Count > 0)
    {
        var reservedKeys = GetReservedExternalInfoKeyList().Value;
        foreach (var key in input.ExternalInfo.Value.Keys)
        {
            Assert(!reservedKeys.Contains(key), 
                $"External info key {key} is reserved and cannot be set by users.");
        }
    }
}
```

**Alternative Approach (if callbacks are intended for certain tokens):**
If callback functionality is intended for specific trusted tokens, implement a whitelist:
1. Create state mapping for callback-authorized tokens
2. Add governance method to authorize specific tokens for callbacks
3. Check authorization in `DealWithExternalInfoDuring*` methods before executing callbacks

**Additional Validations:**
- Validate `CallbackInfo.ContractAddress` is a legitimate contract
- Consider restricting callbacks to system contracts only
- Add event logging when callbacks execute for audit trails

**Test Cases:**
- Verify token creation fails when reserved keys are in ExternalInfo
- Test cross-chain token creation also enforces validation
- Verify NFT item creation respects the same restrictions
- Add integration tests attempting callback exploitation

### Proof of Concept

**Initial State:**
- Attacker has ability to create tokens (e.g., owns NFT collection "EVIL-0")
- Attacker deploys malicious contract `MaliciousCallback` with method `OnTransfer(TransferFromInput input)`

**Attack Sequence:**

1. **Attacker creates malicious NFT item:**
   - Call `TokenContract.Create()` with:
     - Symbol: "EVIL-1"  
     - ExternalInfo contains:
       - Key: `"aelf_transfer_callback"` 
       - Value: `"{\"contract_address\":\"<MaliciousCallback address>\",\"method_name\":\"OnTransfer\"}"`

2. **Attacker distributes token:**
   - Airdrops "EVIL-1" to victim addresses
   - Lists on marketplace for unsuspecting buyers

3. **Victim performs normal transfer:**
   - Victim calls `Transfer()` to send "EVIL-1" to another address
   - Expected: Simple transfer completes
   - **Actual**: Transfer succeeds AND malicious callback executes: [7](#0-6) 

4. **Malicious callback executes:**
   - `MaliciousCallback.OnTransfer()` receives victim's transaction details
   - Can reenter token contract to manipulate state
   - Can DOS by reverting
   - Can log sensitive data

**Success Condition:**
The attack succeeds if the malicious callback executes during the victim's transfer operation, which it will due to the unchecked callback mechanism shown in the code.

### Notes

The NFT contract demonstrates proper implementation of reserved key validation, showing this vulnerability is a systematic oversight rather than intentional design. The existence of `GetReservedExternalInfoKeyList()` indicates developers intended to protect these keys but failed to implement the validation logic that uses this list. This creates a dangerous authorization bypass where user-created tokens can execute privileged callback operations during standard token interactions.

### Citations

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L322-365)
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

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L13-16)
```csharp
    public const string TransferCallbackExternalInfoKey = "aelf_transfer_callback";
    public const string LockCallbackExternalInfoKey = "aelf_lock_callback";
    public const string UnlockCallbackExternalInfoKey = "aelf_unlock_callback";
    public const string LogEventExternalInfoKey = "aelf_log_event";
```

**File:** contract/AElf.Contracts.NFT/NFTContract_Helpers.cs (L118-123)
```csharp
    private void AssertMetadataKeysAreCorrect(IEnumerable<string> metadataKeys)
    {
        var reservedMetadataKey = GetNftMetadataReservedKeys();
        foreach (var metadataKey in metadataKeys)
            Assert(!reservedMetadataKey.Contains(metadataKey), $"Metadata key {metadataKey} is reserved.");
    }
```
