# Audit Report

## Title
VOTE/SHARE Token Transfer Restriction Bypass Enabling Vote Market Creation

## Summary
VOTE and SHARE tokens lack transfer restrictions, allowing users to freely trade these tokens on external markets after receiving them through the voting process. This enables vote buying/selling that undermines election integrity and can permanently lock voters' native tokens when they cannot return the required VOTE/SHARE tokens during withdrawal.

## Finding Description

The AElf election system is designed with the assumption that voting power is tied to locked native ELF tokens. However, VOTE and SHARE tokens can be freely transferred, breaking this fundamental security guarantee.

When VOTE and SHARE tokens are created during economic system initialization, they only include a `LockWhiteList` containing the Election and Vote contracts, with no `ExternalInfo` field set to configure transfer callbacks: [1](#0-0) 

The token `Transfer` implementation only checks if the sender is in the transfer blacklist and that sender != receiver, with no symbol-specific restrictions: [2](#0-1) 

When users vote, they receive VOTE and SHARE tokens via standard transfer, which sit in their balance as freely transferable assets: [3](#0-2) 

During withdrawal, the Election Contract attempts to retrieve tokens using `TransferFrom`: [4](#0-3) 

While the Election Contract is whitelisted to bypass allowance checks in `DoTransferFrom`: [5](#0-4) 

The whitelist check via `IsInWhiteList` only bypasses allowance requirements, not balance requirements: [6](#0-5) 

If a voter has transferred their VOTE/SHARE tokens to another address, the `DoTransfer` call within the whitelisted path will still fail when `ModifyBalance` attempts to deduct tokens from an insufficient balance.

The withdrawal sequence shows that native token unlock happens before VOTE/SHARE token retrieval, meaning a failed retrieval will revert the entire transaction: [7](#0-6) 

## Impact Explanation

**Vote Market Creation**: Users who receive VOTE/SHARE tokens can sell them to other addresses via the standard `Transfer` method, creating a secondary market for voting power. Buyers accumulate voting power without locking native tokens, while sellers profit while keeping their ELF locked until the lock period expires.

**Permanent Token Lockup**: When voters who sold their VOTE/SHARE tokens attempt withdrawal after the lock period, the `RetrieveTokensFromVoter` call will fail due to insufficient balance, causing the entire withdrawal transaction to revert and permanently locking their native ELF tokens.

**Election Integrity Compromise**: The election system's fundamental assumption that voting power is tied to locked native tokens is violated. Free transferability of VOTE tokens allows concentration of voting power without corresponding token locks, enabling governance attacks and undermining the stake-weighted security model.

**Quantified Impact**: With 1 billion VOTE tokens issued, the entire voting power distribution can be manipulated through market trading, fundamentally compromising the election mechanism.

## Likelihood Explanation

**Attack Complexity**: Trivial - requires only calling the standard `Transfer` method available to all token holders. No special contract interactions or complex transaction sequences required.

**Attacker Capabilities**: Any user who has voted and received VOTE/SHARE tokens can execute this. No special permissions, whitelisting, or governance approvals required.

**Preconditions**: User must have voted to receive VOTE/SHARE tokens through the normal voting flow. This is a standard operation expected in the protocol.

**Economic Rationality**: Highly profitable - sellers receive immediate payment while their locked ELF remains secure until the lock period expires (at which point they face the consequence). Buyers gain voting power without any capital lockup. The economic incentives strongly favor exploitation.

**Detection**: Difficult to prevent as transfers appear as legitimate token operations indistinguishable from other token transfers on the chain.

## Recommendation

Implement one of the following solutions:

**Solution 1: Add ExternalInfo Transfer Callback**
Configure `ExternalInfo` during VOTE/SHARE token creation to include a transfer callback that validates transfers. The callback should only allow transfers to/from the Election Contract:

```csharp
private void CreateElectionTokens()
{
    var lockWhiteList = new List<Address>
    {
        Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
        Context.GetContractAddressByName(SmartContractConstants.VoteContractSystemName)
    }.Where(address => address != null).ToList();
    
    foreach (var symbol in new List<string>
                 { EconomicContractConstants.ElectionTokenSymbol, EconomicContractConstants.ShareTokenSymbol })
    {
        var externalInfo = new ExternalInfo();
        externalInfo.Value.Add(TokenContractConstants.TransferCallbackExternalInfoKey, 
            new CallbackInfo 
            { 
                ContractAddress = Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
                MethodName = nameof(ValidateVoteTokenTransfer)
            }.ToString());
        
        State.TokenContract.Create.Send(new CreateInput
        {
            Symbol = symbol,
            TokenName = $"{symbol} Token",
            TotalSupply = EconomicContractConstants.ElectionTokenTotalSupply,
            Decimals = EconomicContractConstants.ElectionTokenDecimals,
            Issuer = Context.Self,
            IsBurnable = true,
            LockWhiteList = { lockWhiteList },
            Owner = Context.Self,
            ExternalInfo = externalInfo
        });
        // ... Issue code
    }
}
```

**Solution 2: Check LockWhiteList in DoTransfer**
Modify the `DoTransfer` method to check if the token has a `LockWhiteList` and if so, verify that the sender/receiver is whitelisted:

```csharp
private void DoTransfer(Address from, Address to, string symbol, long amount, string memo = null)
{
    Assert(!IsInTransferBlackListInternal(from), "From address is in transfer blacklist.");
    Assert(from != to, "Can't do transfer to sender itself.");
    
    // Check if token has lock whitelist restrictions
    var tokenInfo = GetTokenInfo(symbol);
    if (tokenInfo.LockWhiteList != null && tokenInfo.LockWhiteList.Count > 0)
    {
        Assert(State.LockWhiteLists[symbol][from] || State.LockWhiteLists[symbol][to], 
            "Transfer not allowed for this token.");
    }
    
    AssertValidMemo(memo);
    ModifyBalance(from, symbol, -amount);
    ModifyBalance(to, symbol, amount);
    Context.Fire(new Transferred { From = from, To = to, Symbol = symbol, Amount = amount, Memo = memo ?? string.Empty });
}
```

**Solution 3: Make VOTE/SHARE Non-Transferable**
Since VOTE/SHARE tokens represent voting rights that should be tied to the original voter, consider making them completely non-transferable by adding them to a transfer blacklist during creation.

## Proof of Concept

```csharp
[Fact]
public async Task VoteTokenTransferBypassTest()
{
    // User1 votes for a candidate
    var amount = 100_00000000;
    var lockTime = 90 * 86400; // 90 days
    var voteInput = new VoteMinerInput
    {
        CandidatePubkey = ValidationDataCenterKeyPairs[0].PublicKey.ToHex(),
        Amount = amount,
        EndTimestamp = TimestampHelper.GetUtcNow().AddSeconds(lockTime)
    };
    
    var voteResult = await ElectionContractStub.Vote.SendAsync(voteInput);
    var voteId = voteResult.Output;
    
    // Verify User1 received VOTE tokens
    var voteBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = DefaultSender,
        Symbol = "VOTE"
    });
    voteBalance.Balance.ShouldBe(amount);
    
    // User1 transfers VOTE tokens to User2 (This should not be allowed but is)
    var transferResult = await TokenContractStub.Transfer.SendAsync(new TransferInput
    {
        To = User2Address,
        Symbol = "VOTE",
        Amount = amount
    });
    transferResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify User2 now has the VOTE tokens
    var user2VoteBalance = await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
    {
        Owner = User2Address,
        Symbol = "VOTE"
    });
    user2VoteBalance.Balance.ShouldBe(amount);
    
    // Wait for lock period to expire
    BlockTimeProvider.SetBlockTime(TimestampHelper.GetUtcNow().AddSeconds(lockTime + 1));
    
    // User1 attempts to withdraw - this will fail with "Insufficient balance"
    var withdrawResult = await ElectionContractStub.Withdraw.SendWithExceptionAsync(voteId);
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.TransactionResult.Error.ShouldContain("Insufficient balance");
    
    // User1's native tokens remain permanently locked
    var lockedAmount = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = DefaultSender,
        Symbol = "ELF",
        LockId = voteId
    });
    lockedAmount.Amount.ShouldBe(amount); // Still locked!
}
```

## Notes

This vulnerability represents a fundamental design flaw in the election token mechanics. The `LockWhiteList` mechanism was likely intended to restrict transfers of VOTE/SHARE tokens, but its implementation only affects Lock/Unlock operations and TransferFrom allowance checks, not regular Transfer operations. This creates an exploitable gap where users can freely trade voting power tokens, undermining the core security assumption that voting power must be backed by locked native tokens. The permanent lockup consequence makes this particularly severe, as users who participate in such markets risk losing access to their locked capital indefinitely.

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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L96-99)
```csharp
    public override BoolValue IsInWhiteList(IsInWhiteListInput input)
    {
        return new BoolValue { Value = State.LockWhiteLists[input.Symbol][input.Address] };
    }
```
