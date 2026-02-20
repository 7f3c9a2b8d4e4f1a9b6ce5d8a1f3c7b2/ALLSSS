# Audit Report

## Title
VOTE/SHARE Token Transfer Restriction Bypass Enabling Vote Market Creation and Permanent Fund Lockup

## Summary
VOTE and SHARE tokens lack transfer restrictions, allowing users to freely trade these tokens after receiving them through voting. This enables vote buying/selling that undermines election integrity and permanently locks voters' native ELF tokens when they cannot return the required VOTE/SHARE tokens during withdrawal.

## Finding Description

The AElf election system assumes voting power is tied to locked native ELF tokens. However, VOTE and SHARE tokens can be freely transferred, breaking this fundamental security guarantee.

When VOTE and SHARE tokens are created during economic system initialization, they only include a `LockWhiteList` containing the Election and Vote contracts, with no `ExternalInfo` field configured to restrict transfers [1](#0-0) 

The MultiToken `Transfer` implementation only checks if the sender is in the transfer blacklist and that sender != receiver, with no symbol-specific restrictions [2](#0-1)  The core transfer logic performs only basic validation without token-specific callbacks [3](#0-2) 

When users vote, they receive VOTE and SHARE tokens via standard transfer to their address, which sit in their balance as freely transferable assets [4](#0-3) 

During withdrawal, the Election Contract attempts to retrieve tokens using `TransferFrom` [5](#0-4) 

While the Election Contract is whitelisted to bypass allowance checks in `DoTransferFrom` [6](#0-5) 

The whitelist check only bypasses allowance requirements, not balance requirements. The subsequent `DoTransfer` call still performs balance validation [7](#0-6) 

If a voter has transferred their VOTE/SHARE tokens to another address, the `ModifyBalance` call will fail with "Insufficient balance", causing the entire withdrawal transaction to revert.

The withdrawal sequence shows that native token unlock happens before VOTE/SHARE token retrieval in the same transaction [8](#0-7)  When the retrieval fails, the entire transaction reverts, leaving the ELF tokens permanently locked.

## Impact Explanation

**Vote Market Creation**: Users who receive VOTE/SHARE tokens can sell them to other addresses via the standard `Transfer` method, creating a secondary market for voting power. Buyers accumulate voting power without locking native tokens, while sellers profit while keeping their ELF locked until the lock period expires.

**Permanent Token Lockup**: When voters who sold their VOTE/SHARE tokens attempt withdrawal after the lock period, the `RetrieveTokensFromVoter` call fails due to insufficient balance, causing the entire withdrawal transaction to revert and permanently locking their native ELF tokens.

**Election Integrity Compromise**: The election system's fundamental assumption that voting power is tied to locked native tokens is violated. Free transferability of VOTE tokens allows concentration of voting power without corresponding token locks, enabling governance attacks and undermining the stake-weighted security model.

**Quantified Impact**: With 100 billion VOTE tokens issued per the constants, the entire voting power distribution can be manipulated through market trading, fundamentally compromising the election mechanism.

## Likelihood Explanation

**Attack Complexity**: Trivial - requires only calling the standard `Transfer` method available to all token holders. No special contract interactions or complex transaction sequences required.

**Attacker Capabilities**: Any user who has voted and received VOTE/SHARE tokens can execute this. No special permissions, whitelisting, or governance approvals required.

**Preconditions**: User must have voted to receive VOTE/SHARE tokens through the normal voting flow. This is a standard operation expected in the protocol.

**Economic Rationality**: Highly profitable - sellers receive immediate payment while their locked ELF remains secure until the lock period expires (at which point they face the consequence). Buyers gain voting power without any capital lockup. The economic incentives strongly favor exploitation.

**Detection**: Difficult to prevent as transfers appear as legitimate token operations indistinguishable from other token transfers on the chain.

## Recommendation

Add transfer restrictions to VOTE and SHARE tokens during creation by setting the `ExternalInfo` field with a transfer callback that validates transfers are only allowed to/from the Election Contract:

```csharp
private void CreateElectionTokens()
{
    var lockWhiteListBackups = new List<Address>
    {
        Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
        Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName)
    };
    var lockWhiteList = lockWhiteListBackups.Where(address => address != null).ToList();
    
    // Add transfer callback configuration
    var transferCallback = new CallbackInfo
    {
        ContractAddress = Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
        MethodName = "ValidateVoteTokenTransfer"
    };
    
    var externalInfo = new ExternalInfo();
    externalInfo.Value[TokenContractConstants.TransferCallbackExternalInfoKey] = 
        JsonFormatter.Default.Format(transferCallback);
    
    foreach (var symbol in new List<string>
                 { EconomicContractConstants.ElectionTokenSymbol, EconomicContractConstants.ShareTokenSymbol })
    {
        State.TokenContract.Create.Send(new CreateInput
        {
            Symbol = symbol,
            TokenName = $"{symbol} Token",
            TotalSupply = EconomicContractConstants.ElectionTokenTotalSupply,
            Decimals = EconomicContractConstants.ElectionTokenDecimals,
            Issuer = Context.Self,
            IsBurnable = true,
            LockWhiteList = { lockWhiteList },
            ExternalInfo = externalInfo,  // Add this
            Owner = Context.Self
        });
        // ... rest of creation logic
    }
}
```

Then implement the validation callback in the Election Contract to only allow transfers to/from the Election Contract itself.

## Proof of Concept

```csharp
// Test demonstrating the vulnerability
[Fact]
public async Task VoteTokenTransferCausesPermanentLockup()
{
    // Setup: Alice votes and receives VOTE/SHARE tokens
    var aliceAccount = Accounts[0].KeyPair;
    var bobAccount = Accounts[1].KeyPair;
    
    // Alice votes 100 ELF
    await ElectionContractStub.Vote.SendAsync(new VoteMinerInput
    {
        CandidatePubkey = ValidationDataCenterKeyPairs[0].PublicKey.ToHex(),
        Amount = 100_00000000,
        EndTimestamp = TimestampHelper.GetUtcNow().AddDays(365)
    });
    
    // Verify Alice received VOTE and SHARE tokens
    var aliceVoteBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = Accounts[0].Address,
        Symbol = "VOTE"
    });
    aliceVoteBalance.Balance.ShouldBe(100_00000000);
    
    // Alice transfers VOTE and SHARE tokens to Bob (vote selling)
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = Accounts[1].Address,
        Symbol = "VOTE",
        Amount = 100_00000000
    });
    
    await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = Accounts[1].Address,
        Symbol = "SHARE",
        Amount = 100_00000000
    });
    
    // Advance time past lock period
    BlockTimeProvider.SetBlockTime(TimestampHelper.GetUtcNow().AddDays(366));
    
    // Alice attempts to withdraw - this will fail due to insufficient VOTE/SHARE balance
    var withdrawResult = await ElectionContractStub.Withdraw.SendWithExceptionAsync(voteId);
    
    // Transaction reverts with insufficient balance error
    withdrawResult.TransactionResult.Error.ShouldContain("Insufficient balance");
    
    // Alice's ELF remains permanently locked
    var lockedBalance = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = Accounts[0].Address,
        Symbol = "ELF",
        LockId = voteId
    });
    lockedBalance.Amount.ShouldBe(100_00000000); // Still locked!
}
```

## Notes

This vulnerability exists because the token creation logic treats VOTE/SHARE tokens as standard transferable tokens without implementing the transfer restriction mechanisms available in the MultiToken contract (ExternalInfo callbacks). The Election Contract correctly uses whitelist-based `TransferFrom` for retrieval, but this only bypasses the allowance check - the balance check still occurs and will fail if tokens were transferred away, permanently locking the voter's ELF tokens since the transaction atomically reverts.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L106-136)
```csharp
    private void CreateElectionTokens()
    {
        var lockWhiteListBackups = new List<Address>
        {
            Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
            Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName)
        };
        var lockWhiteList = lockWhiteListBackups.Where(address => address != null).ToList();
        foreach (var symbol in new List<string>
                     { EconomicContractConstants.ElectionTokenSymbol, EconomicContractConstants.ShareTokenSymbol })
        {
            State.TokenContract.Create.Send(new CreateInput
            {
                Symbol = symbol,
                TokenName = $"{symbol} Token",
                TotalSupply = EconomicContractConstants.ElectionTokenTotalSupply,
                Decimals = EconomicContractConstants.ElectionTokenDecimals,
                Issuer = Context.Self,
                IsBurnable = true,
                LockWhiteList = { lockWhiteList },
                Owner = Context.Self
            });
            State.TokenContract.Issue.Send(new IssueInput
            {
                Symbol = symbol,
                Amount = EconomicContractConstants.ElectionTokenTotalSupply,
                To = Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
                Memo = "Issue all election tokens to Election Contract."
            });
        }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L116-125)
```csharp
    private void ModifyBalance(Address address, string symbol, long addAmount)
    {
        var before = GetBalance(address, symbol);
        if (addAmount < 0 && before < -addAmount)
            Assert(false,
                $"{address}. Insufficient balance of {symbol}. Need balance: {-addAmount}; Current balance: {before}");

        var target = before.Add(addAmount);
        State.Balances[address][symbol] = target;
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L282-294)
```csharp
    private void RetrieveTokensFromVoter(long amount, Address voterAddress = null)
    {
        foreach (var symbol in new List<string>
                     { ElectionContractConstants.ShareSymbol, ElectionContractConstants.VoteSymbol })
            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = voterAddress ?? Context.Sender,
                To = Context.Self,
                Amount = amount,
                Symbol = symbol,
                Memo = $"Return {symbol} tokens."
            });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L344-355)
```csharp
    private void TransferTokensToVoter(long amount)
    {
        foreach (var symbol in new List<string>
                     { ElectionContractConstants.ShareSymbol, ElectionContractConstants.VoteSymbol })
            State.TokenContract.Transfer.Send(new TransferInput
            {
                Symbol = symbol,
                To = Context.Sender,
                Amount = amount,
                Memo = $"Transfer {symbol}."
            });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L662-664)
```csharp
        UnlockTokensOfVoter(input, votingRecord.Amount);
        RetrieveTokensFromVoter(votingRecord.Amount);
        WithdrawTokensOfVoter(input);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_NFT_Actions.cs (L69-95)
```csharp
    private void DoTransferFrom(Address from, Address to, Address spender, string symbol, long amount, string memo)
    {
        AssertValidInputAddress(from);
        AssertValidInputAddress(to);
        
        // First check allowance.
        var allowance = GetAllowance(from, spender, symbol, amount, out var allowanceSymbol);
        if (allowance < amount)
        {
            if (IsInWhiteList(new IsInWhiteListInput { Symbol = symbol, Address = spender }).Value)
            {
                DoTransfer(from, to, symbol, amount, memo);
                DealWithExternalInfoDuringTransfer(new TransferFromInput()
                    { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
                return;
            }

            Assert(false,
                $"[TransferFrom]Insufficient allowance. Token: {symbol}; {allowance}/{amount}.\n" +
                $"From:{from}\tSpender:{spender}\tTo:{to}");
        }

        DoTransfer(from, to, symbol, amount, memo);
        DealWithExternalInfoDuringTransfer(new TransferFromInput()
            { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo });
        State.Allowances[from][spender][allowanceSymbol] = allowance.Sub(amount);
    }
```
