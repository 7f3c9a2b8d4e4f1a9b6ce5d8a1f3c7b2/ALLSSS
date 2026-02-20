# Audit Report

## Title
Transfer Blacklist Bypass - Recipient Address Not Validated

## Summary
The transfer blacklist implementation in the MultiToken contract only validates the sender (FROM) address but fails to check the recipient (TO) address. This allows blacklisted addresses to receive tokens through multiple paths including Transfer, Unlock, Issue, and CrossChainReceiveToken operations, fundamentally breaking the blacklist's intended purpose of freezing an address's token activity.

## Finding Description

The root cause is in the `DoTransfer` method which only validates the FROM address against the blacklist. [1](#0-0) 

The blacklist check only validates the `from` parameter but never checks if `to` is blacklisted. This creates multiple bypass vectors:

**Primary Bypass Path - Unlock to Blacklisted Address:**

A blacklisted user can unlock their previously locked tokens. The `Unlock` method uses `SendVirtualInline` to transfer tokens from a virtual address. [2](#0-1) 

When `Unlock` is called with `input.Address` being a blacklisted user, the virtual address becomes the sender. Since `DoTransfer` only checks if the FROM address (virtual address) is blacklisted - and it's not - the transfer succeeds, allowing the blacklisted user to reclaim their locked tokens.

**Additional Bypass Vectors:**

1. **Direct Transfer TO blacklisted addresses**: The `Transfer` method calls `DoTransfer` with sender and recipient. [3](#0-2) 
Since only the FROM address is checked, any user can send tokens TO a blacklisted address.

2. **Issue operations bypass blacklist** by calling `ModifyBalance` directly without any blacklist validation. [4](#0-3) 

3. **CrossChainReceiveToken bypasses blacklist** by calling `ModifyBalance` directly. [5](#0-4) 

The test suite confirms the flaw - tests verify that Lock is blocked for blacklisted senders but do NOT test whether Unlock to blacklisted recipients is blocked. [6](#0-5) 

## Impact Explanation

**Direct Operational Impact:** The transfer blacklist feature is rendered ineffective. When governance blacklists an address (for regulatory compliance, compromised keys, or malicious actors), the expectation is that the address is frozen from ALL token activity. However:

- Blacklisted addresses can receive tokens from any sender via Transfer
- Blacklisted users can unlock previously locked tokens from Election/Vote contracts  
- Token issuers can issue new tokens to blacklisted addresses
- Cross-chain transfers can deliver tokens to blacklisted addresses

**Most Critical Scenario:** A user locks tokens in Election/Vote contracts, then engages in malicious behavior and gets blacklisted by governance. The user can simply call `Unlock` to reclaim their locked funds, completely bypassing the blacklist restriction.

**Severity:** HIGH - The core security feature (blacklist) is fundamentally broken. Governance cannot effectively enforce blacklist decisions, allowing malicious actors to retain token access and regain locked funds.

## Likelihood Explanation

**Exploitability:** HIGH

1. **Direct Transfer Path:** Any address can immediately send tokens to a blacklisted address. No special permissions or conditions required.

2. **Unlock Path:** A blacklisted user can unlock their own tokens if they locked them before being blacklisted. The `Unlock` authorization check allows `Context.Origin == input.Address`. [7](#0-6) 
The user simply calls Unlock with their own address, and the virtual address mechanism bypasses the blacklist.

**Attack Complexity:** TRIVIAL
- No race conditions or timing dependencies
- No economic cost beyond gas fees  
- Works immediately on any blacklisted address
- Exploitable through standard public methods

**Probability:** 100% - This is a permanent logic gap that affects all blacklisted addresses and is immediately exploitable.

## Recommendation

Add blacklist validation for the recipient address in all token transfer paths:

1. **DoTransfer method** - Add recipient blacklist check:
```csharp
private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
{
    Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
    Assert(!IsInTransferBlackListInternal(to), "To address is in transfer blacklist.");
    // ... rest of the method
}
```

2. **Issue method** - Add blacklist check before ModifyBalance:
```csharp
Assert(!IsInTransferBlackListInternal(input.To), "To address is in transfer blacklist.");
```

3. **CrossChainReceiveToken method** - Add blacklist check before ModifyBalance:
```csharp
Assert(!IsInTransferBlackListInternal(receivingAddress), "Receiving address is in transfer blacklist.");
```

## Proof of Concept

```csharp
[Fact]
public async Task BlacklistedAddress_Can_Receive_Tokens_Via_Transfer()
{
    // Setup: Create tokens and blacklist User1Address
    await CreateAndIssueMultiTokensAsync();
    var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
    var proposalId = await CreateProposalAsync(TokenContractAddress, defaultParliament, 
        nameof(TokenContractStub.AddToTransferBlackList), User1Address);
    await ApproveWithMinersAsync(proposalId);
    await ParliamentContractStub.Release.SendAsync(proposalId);
    
    // Verify User1Address is blacklisted
    var isBlacklisted = await TokenContractStub.IsInTransferBlackList.CallAsync(User1Address);
    isBlacklisted.Value.ShouldBe(true);
    
    // EXPLOIT: Transfer TO blacklisted address succeeds
    var transferResult = await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        Amount = 1000L,
        Symbol = AliceCoinTokenInfo.Symbol,
        To = User1Address  // Blacklisted address as recipient
    });
    
    // Vulnerability proven: Transaction succeeds despite recipient being blacklisted
    transferResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify blacklisted address received tokens
    var balance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Symbol = AliceCoinTokenInfo.Symbol,
        Owner = User1Address
    });
    balance.Balance.ShouldBe(1000L);
}
```

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L99-114)
```csharp
    private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
    {
        Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
        Assert(from != to, "Can't do transfer to sender itself.");
        AssertValidMemo(memo);
        ModifyBalance(from, symbol, -amount);
        ModifyBalance(to, symbol, amount);
        Context.Fire(new Transferred
        {
            From = from,
            To = to,
            Symbol = symbol,
            Amount = amount,
            Memo = memo ?? string.Empty
        });
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L164-178)
```csharp
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L224-252)
```csharp
    public override Empty Unlock(UnlockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Unlock behaviour should be initialed by origin address.");

        AssertValidToken(input.Symbol, input.Amount);
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        Context.SendVirtualInline(fromVirtualAddress, Context.Self, nameof(Transfer), new TransferInput
        {
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        DealWithExternalInfoDuringUnlock(new TransferFromInput
        {
            From = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress),
            To = input.Address,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L591-638)
```csharp
    public override Empty CrossChainReceiveToken(CrossChainReceiveTokenInput input)
    {
        var transferTransaction = Transaction.Parser.ParseFrom(input.TransferTransactionBytes);
        var transferTransactionId = transferTransaction.GetHash();

        Assert(!State.VerifiedCrossChainTransferTransaction[transferTransactionId],
            "Token already claimed.");

        var crossChainTransferInput =
            CrossChainTransferInput.Parser.ParseFrom(transferTransaction.Params.ToByteArray());
        var symbol = crossChainTransferInput.Symbol;
        var amount = crossChainTransferInput.Amount;
        var receivingAddress = crossChainTransferInput.To;
        var targetChainId = crossChainTransferInput.ToChainId;
        var transferSender = transferTransaction.From;

        var tokenInfo = AssertValidToken(symbol, amount);
        var issueChainId = GetIssueChainId(tokenInfo.Symbol);
        Assert(issueChainId == crossChainTransferInput.IssueChainId, "Incorrect issue chain id.");
        Assert(targetChainId == Context.ChainId, "Unable to claim cross chain token.");
        var registeredTokenContractAddress = State.CrossChainTransferWhiteList[input.FromChainId];
        AssertCrossChainTransaction(transferTransaction, registeredTokenContractAddress,
            nameof(CrossChainTransfer));
        Context.LogDebug(() =>
            $"symbol == {tokenInfo.Symbol}, amount == {amount}, receivingAddress == {receivingAddress}, targetChainId == {targetChainId}");

        CrossChainVerify(transferTransactionId, input.ParentChainHeight, input.FromChainId, input.MerklePath);

        State.VerifiedCrossChainTransferTransaction[transferTransactionId] = true;
        tokenInfo.Supply = tokenInfo.Supply.Add(amount);
        Assert(tokenInfo.Supply <= tokenInfo.TotalSupply, "Total supply exceeded");
        SetTokenInfo(tokenInfo);
        ModifyBalance(receivingAddress, tokenInfo.Symbol, amount);

        Context.Fire(new CrossChainReceived
        {
            From = transferSender,
            To = receivingAddress,
            Symbol = tokenInfo.Symbol,
            Amount = amount,
            Memo = crossChainTransferInput.Memo,
            FromChainId = input.FromChainId,
            ParentChainHeight = input.ParentChainHeight,
            IssueChainId = issueChainId,
            TransferTransactionId = transferTransactionId
        });
        return new Empty();
    }
```

**File:** test/AElf.Contracts.MultiToken.Tests/BVT/TokenApplicationTests.cs (L1914-2000)
```csharp
    public async Task MultiTokenContract_Transfer_BlackList_Test()
    {
        await MultiTokenContract_Approve_Test();
        
        var trafficToken = "TRAFFIC";
        await CreateAndIssueCustomizeTokenAsync(DefaultAddress, trafficToken, 10000, 10000);

        // Non-owner cannot add to blacklist
        var addBlackListResult = await TokenContractStubUser.AddToTransferBlackList.SendWithExceptionAsync(DefaultAddress);
        addBlackListResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
        addBlackListResult.TransactionResult.Error.ShouldContain("No permission");
        var isInTransferBlackList = await TokenContractStubUser.IsInTransferBlackList.CallAsync(DefaultAddress);
        isInTransferBlackList.Value.ShouldBe(false);

        // Owner adds DefaultAddress to blacklist via parliament proposal
        var defaultParliament = await ParliamentContractStub.GetDefaultOrganizationAddress.CallAsync(new Empty());
        var proposalId = await CreateProposalAsync(TokenContractAddress, defaultParliament, nameof(TokenContractStub.AddToTransferBlackList), DefaultAddress);
        await ApproveWithMinersAsync(proposalId);
        await ParliamentContractStub.Release.SendAsync(proposalId);
        isInTransferBlackList = await TokenContractStubUser.IsInTransferBlackList.CallAsync(DefaultAddress);
        isInTransferBlackList.Value.ShouldBe(true);

        // Transfer should fail when sender is in blacklist
        var transferResult = (await TokenContractStub.Transfer.SendWithExceptionAsync(new TransferInput
        {
            Amount = Amount,
            Memo = "blacklist test",
            Symbol = AliceCoinTokenInfo.Symbol,
            To = User1Address
        })).TransactionResult;
        transferResult.Status.ShouldBe(TransactionResultStatus.Failed);
        transferResult.Error.ShouldContain("From address is in transfer blacklist");

        // TransferFrom should fail when from address is in blacklist
        var user1Stub = GetTester<TokenContractImplContainer.TokenContractImplStub>(TokenContractAddress, User1KeyPair);
        var transferFromResult = (await user1Stub.TransferFrom.SendWithExceptionAsync(new TransferFromInput
        {
            Amount = Amount,
            From = DefaultAddress,
            Memo = "blacklist test",
            Symbol = AliceCoinTokenInfo.Symbol,
            To = User1Address
        })).TransactionResult;
        transferFromResult.Status.ShouldBe(TransactionResultStatus.Failed);
        transferFromResult.Error.ShouldContain("From address is in transfer blacklist");

        // CrossChainTransfer should fail when sender is in blacklist
        var crossChainTransferResult = (await TokenContractStub.CrossChainTransfer.SendWithExceptionAsync(new CrossChainTransferInput
        {
            Symbol = AliceCoinTokenInfo.Symbol,
            Amount = Amount,
            To = User1Address,
            IssueChainId = 9992731,
            Memo = "blacklist test",
            ToChainId = 9992732
        })).TransactionResult;
        crossChainTransferResult.Status.ShouldBe(TransactionResultStatus.Failed);
        crossChainTransferResult.Error.ShouldContain("Sender is in transfer blacklist");
        
        // Lock should fail when sender is in blacklist
        var lockId = HashHelper.ComputeFrom("lockId");
        var lockTokenResult = (await BasicFunctionContractStub.LockToken.SendWithExceptionAsync(new LockTokenInput
        {
            Address = DefaultAddress,
            Amount = Amount,
            Symbol = AliceCoinTokenInfo.Symbol,
            LockId = lockId,
            Usage = "Testing."
        })).TransactionResult;
        lockTokenResult.Status.ShouldBe(TransactionResultStatus.Failed);
        lockTokenResult.Error.ShouldContain("From address is in transfer blacklist");

        // Transfer to contract should fail when sender is in blacklist
        var transferToContractResult = (await BasicFunctionContractStub.TransferTokenToContract.SendWithExceptionAsync(
            new TransferTokenToContractInput
            {
                Amount = Amount,
                Symbol = AliceCoinTokenInfo.Symbol
            })).TransactionResult;
        transferToContractResult.Status.ShouldBe(TransactionResultStatus.Failed);
        transferToContractResult.Error.ShouldContain("From address is in transfer blacklist");
        
        // AdvanceResourceToken should fail when sender is in blacklist
        var advanceRet = await TokenContractStub.AdvanceResourceToken.SendWithExceptionAsync(
            new AdvanceResourceTokenInput
            {
                ContractAddress = BasicFunctionContractAddress,
```
