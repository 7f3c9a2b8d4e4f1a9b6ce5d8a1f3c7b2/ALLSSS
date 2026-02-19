### Title
Missing Validation of Zero/Negative Vote Amount in Delegated Voting Allows Vote Manipulation

### Summary
In delegated (non-token-locked) voting mode, the `Vote()` function in `VoteContract` fails to validate the `amount` field of the `VoteInput`. As a result, sponsors can cast votes with zero or negative amounts, which are accepted and processed by the contract. This leads to inaccurate vote totals, inflated voter counts, and undermines the voting process.

### Finding Description
- In `VoteContract.cs`, the `Vote()` method at line 90 assigns `input.Amount` directly to the local variable `amount` for non-quadratic voting (line 96).
- No validation (such as `amount > 0`) is performed in this branch for delegated voting scenarios (when `IsLockToken == false`).
- If `IsLockToken` is `true`, zero or negative amounts are rejected by the token contract's `Lock` method (which calls `AssertValidToken` and then `AssertValidSymbolAndAmount`, requiring `amount > 0`), thus preventing any further execution with invalid amounts.
- For delegated voting, however, the function simply updates the vote result and voter counters, with no token being locked or additional validation performed.
- The result is that votes with zero or negative amounts are accepted, which can decrease the total votes or artificially inflate the voter count, violating protocol invariants and enabling manipulation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation
- Zero-amount votes: increases the voter count while not increasing the vote total, skewing quorum and turnout metrics.
- Negative-amount votes: reduces the total number of votes for a given option, allowing sponsors to manipulate results by subtracting votes.
- This can allow malicious sponsors to intentionally or accidentally corrupt the voting process—an operational failure with a potentially high impact on protocol governance, elections, and any on-chain decisions relying on this mechanism.

### Likelihood Explanation
- The issue arises in any voting item created in delegated mode (`IsLockToken == false`), a supported and used contract feature.
- Any address authorized to act as sponsor for a voting item may submit votes with zero or negative amounts.
- No special capabilities or malicious VM behavior are needed—simply sending a transaction with an invalid amount triggers the vulnerability.
- The issue is deterministic, reliably reproducible, and not prevented by standard execution checks.

### Recommendation
- In the `Vote` function, add validation in the non-quadratic, delegated voting branch to require `input.Amount > 0` before proceeding.
- This check should be consistent with the validation applied in the token locking branch.
- Add negative/zero amount test cases for delegated and non-delegated voting to prevent regression.
- Optionally, reject votes with unreasonably large or otherwise suspicious amounts.

### Proof of Concept
1. Deploy a voting item using `Register` with `IsLockToken = false`.
2. As sponsor, call `Vote()` providing an existing `VotingItemId`, valid `Option`, and `Amount = 0` or `Amount = -1`.
3. Observe transaction success and view the voting result:
   - Voter count increases by one.
   - Vote tally is unchanged (`Amount=0`) or reduced (`Amount<0`).
4. Repeat to demonstrate arbitrary manipulation of voter and vote counts.

The result: the protocol’s voting semantics are broken without triggering an error, and the exploit path does not require any trusted role compromise beyond sponsor privileges for the voting item.

---

Notes:
- This issue does not affect quadratic mode, as `amount` is always derived from ticket cost and vote count.
- Direct token-locking voting correctly blocks invalid amounts via MultiToken contract validation.
- The problem is strictly a logic error caused by missing input validation in the delegated, non-token-locked voting scenario.
- Tests do not currently cover delegated-vote zero/negative amount scenarios, indicating a need for regression coverage.

### Citations

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L90-144)
```csharp
    public override Empty Vote(VoteInput input)
    {
        var votingItem = AssertValidVoteInput(input);
        var amount = 0L;
        if (!votingItem.IsQuadratic)
        {
            amount = input.Amount;
        }
        else
        {
            var currentVotesCount = State.QuadraticVotesCountMap[input.VoteId].Add(1);
            State.QuadraticVotesCountMap[input.VoteId] = currentVotesCount;
            amount = votingItem.TicketCost.Mul(currentVotesCount);
        }

        var votingRecord = new VotingRecord
        {
            VotingItemId = input.VotingItemId,
            Amount = amount,
            SnapshotNumber = votingItem.CurrentSnapshotNumber,
            Option = input.Option,
            IsWithdrawn = false,
            VoteTimestamp = Context.CurrentBlockTime,
            Voter = input.Voter,
            IsChangeTarget = input.IsChangeTarget
        };

        State.VotingRecords[input.VoteId] = votingRecord;

        UpdateVotingResult(votingItem, input.Option, votingItem.IsQuadratic ? 1 : amount);
        UpdateVotedItems(input.VoteId, votingRecord.Voter, votingItem);

        if (votingItem.IsLockToken)
            // Lock voted token.
            State.TokenContract.Lock.Send(new LockInput
            {
                Address = votingRecord.Voter,
                Symbol = votingItem.AcceptedCurrency,
                LockId = input.VoteId,
                Amount = amount
            });

        Context.Fire(new Voted
        {
            VoteId = input.VoteId,
            VotingItemId = votingRecord.VotingItemId,
            Voter = votingRecord.Voter,
            Amount = votingRecord.Amount,
            Option = votingRecord.Option,
            SnapshotNumber = votingRecord.SnapshotNumber,
            VoteTimestamp = votingRecord.VoteTimestamp
        });

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Vote/VoteContract.cs (L377-401)
```csharp
    private VotingItem AssertValidVoteInput(VoteInput input)
    {
        var votingItem = AssertVotingItem(input.VotingItemId);
        Assert(input.Option.Length <= VoteContractConstants.OptionLengthLimit, "Invalid input.");
        Assert(votingItem.Options.Contains(input.Option), $"Option {input.Option} not found.");
        Assert(votingItem.CurrentSnapshotNumber <= votingItem.TotalSnapshotNumber,
            "Current voting item already ended.");
        if (!votingItem.IsLockToken)
        {
            Assert(votingItem.Sponsor == Context.Sender, "Sender of delegated voting event must be the Sponsor.");
            Assert(input.Voter != null, "Voter cannot be null if voting event is delegated.");
            Assert(input.VoteId != null, "Vote Id cannot be null if voting event is delegated.");
        }
        else
        {
            var votingResultHash = GetVotingResultHash(votingItem.VotingItemId, votingItem.CurrentSnapshotNumber);
            var votingResult = State.VotingResults[votingResultHash];
            // Voter = Transaction Sender
            input.Voter = Context.Sender;
            // VoteId = Transaction Id;
            input.VoteId = Context.GenerateId(Context.Self, votingResult.VotesAmount.ToBytes(false));
        }

        return votingItem;
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L195-222)
```csharp
    public override Empty Lock(LockInput input)
    {
        Assert(!string.IsNullOrWhiteSpace(input.Symbol), "Invalid input symbol.");
        AssertValidInputAddress(input.Address);
        AssertSystemContractOrLockWhiteListAddress(input.Symbol);
        
        Assert(IsInLockWhiteList(Context.Sender) || Context.Origin == input.Address,
            "Lock behaviour should be initialed by origin address.");

        var allowance = State.Allowances[input.Address][Context.Sender][input.Symbol];
        if (allowance >= input.Amount)
            State.Allowances[input.Address][Context.Sender][input.Symbol] = allowance.Sub(input.Amount);
        AssertValidToken(input.Symbol, input.Amount);
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
        var virtualAddress = Context.ConvertVirtualAddressToContractAddress(fromVirtualAddress);
        // Transfer token to virtual address.
        DoTransfer(input.Address, virtualAddress, input.Symbol, input.Amount, input.Usage);
        DealWithExternalInfoDuringLocking(new TransferFromInput
        {
            From = input.Address,
            To = virtualAddress,
            Symbol = input.Symbol,
            Amount = input.Amount,
            Memo = input.Usage
        });
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L33-86)
```csharp
    private TokenInfo AssertValidToken(string symbol, long amount)
    {
        AssertValidSymbolAndAmount(symbol, amount);
        var tokenInfo = GetTokenInfo(symbol);
        Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol), $"Token is not found. {symbol}");
        return tokenInfo;
    }

    private void AssertValidApproveTokenAndAmount(string symbol, long amount)
    {
        Assert(amount > 0, "Invalid amount.");
        AssertApproveToken(symbol);
    }

    private void ValidTokenExists(string symbol)
    {
        var tokenInfo = State.TokenInfos[symbol];
        Assert(tokenInfo != null && !string.IsNullOrEmpty(tokenInfo.Symbol),
            $"Token is not found. {symbol}");
    }
    
    private void AssertApproveToken(string symbol)
    {
        Assert(!string.IsNullOrEmpty(symbol), "Symbol can not be null.");
        var words = symbol.Split(TokenContractConstants.NFTSymbolSeparator);
        var symbolPrefix = words[0];
        var allSymbolIdentifier = GetAllSymbolIdentifier();
        Assert(symbolPrefix.Length > 0 && (IsValidCreateSymbol(symbolPrefix) || symbolPrefix.Equals(allSymbolIdentifier)), "Invalid symbol.");
        if (words.Length == 1)
        {
            if (!symbolPrefix.Equals(allSymbolIdentifier))
            {
                ValidTokenExists(symbolPrefix);
            }
            return;
        }
        Assert(words.Length == 2, "Invalid symbol length.");
        var itemId = words[1];
        Assert(itemId.Length > 0 && (IsValidItemId(itemId) || itemId.Equals(allSymbolIdentifier)), "Invalid NFT Symbol.");
        var nftSymbol = itemId.Equals(allSymbolIdentifier) ? GetCollectionSymbol(symbolPrefix) : symbol;
        ValidTokenExists(nftSymbol);
    }
    
    private string GetCollectionSymbol(string symbolPrefix)
    {
        return $"{symbolPrefix}-{TokenContractConstants.CollectionSymbolSuffix}";
    }

    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```
