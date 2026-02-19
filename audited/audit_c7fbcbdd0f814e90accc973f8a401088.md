### Title
Election Token Supply Exhaustion Leading to Voting System DoS

### Summary
The `CreateElectionTokens()` function issues the entire 1 billion supply of VOTE and SHARE tokens to the ElectionContract with no reserve mechanism. [1](#0-0)  If cumulative active votes exceed this supply, the contract will have insufficient balance to distribute tokens to new voters, causing a denial-of-service condition for the voting system.

### Finding Description

**Root Cause:**

During economic system initialization, `CreateElectionTokens()` creates VOTE and SHARE tokens with a hardcoded total supply of 1 billion tokens each. [2](#0-1)  The entire supply is immediately issued to the ElectionContract address. [3](#0-2) 

**Token Distribution Mechanism:**

When users call the `Vote()` function, the ElectionContract transfers VOTE and SHARE tokens to them via `TransferTokensToVoter()`, with amounts equal to their voting amount (1:1 ratio). [4](#0-3) [5](#0-4) 

**Balance Validation:**

The MultiToken contract's `DoTransfer()` method enforces balance checks. If a transfer would result in negative balance, it fails with "Insufficient balance" error. [6](#0-5) 

**No Additional Issuance:**

Once the total supply is issued, no more tokens can be minted. The `Issue()` method enforces this constraint. [7](#0-6)  The `IssueNativeToken()` method only works for native tokens, not VOTE/SHARE tokens. [8](#0-7) 

**Configuration Risk:**

While the election token supply is hardcoded at 1 billion, the native token supply is configurable and defaults to 1 billion but can be set higher. [9](#0-8)  If the native token supply exceeds the election token supply, the risk increases significantly.

### Impact Explanation

**Operational DoS:**
When the ElectionContract's VOTE/SHARE token balance is exhausted (all tokens distributed to active voters), any new `Vote()` call will fail at the `TransferTokensToVoter()` step due to insufficient balance. This creates a denial-of-service condition where:
- New voters cannot participate in elections
- Existing voters who withdrew cannot re-vote
- The governance system becomes inaccessible to new participants

**Affected Parties:**
- All potential new voters during high participation periods
- The broader governance system that depends on active voting
- Network consensus if election participation is critical

**Severity Justification:**
Medium severity because:
- Requires scale (>1 billion cumulative active votes)
- Temporary condition (resolves as votes expire and are withdrawn)
- No permanent state corruption or fund theft
- Configuration-dependent (risk increases if native supply > election supply)

### Likelihood Explanation

**Reachable Entry Point:**
The `Vote()` function is publicly accessible to any user with sufficient native tokens. [10](#0-9) 

**Feasible Preconditions:**
- Multiple users voting with amounts totaling >1 billion tokens
- Users holding votes for extended lock periods (90-1080 days) [11](#0-10) 
- No upper limit on individual or total voting amounts exists

**Execution Practicality:**
The scenario occurs through normal user behavior—no malicious action required. In a production environment with:
- Native token supply >1 billion (configurable)
- High voter participation rate
- Long lock periods
The cumulative active votes can naturally exceed the VOTE token supply.

**Economic Rationality:**
No additional cost to users—occurs organically as the network grows and participation increases.

### Recommendation

**Immediate Mitigation:**
1. Implement a maximum total active vote limit check in the `Vote()` function:
```
Assert(GetTotalActiveVotes() + input.Amount <= ElectionTokenTotalSupply, 
       "Total active votes would exceed election token capacity");
```

2. Add an emergency reserve mechanism: reserve 10-20% of election tokens that can only be issued through governance proposal.

**Long-term Solution:**
1. Make `ElectionTokenTotalSupply` configurable during initialization, linked to `NativeTokenTotalSupply`:
```
ElectionTokenTotalSupply = Math.Max(NativeTokenTotalSupply, MinimumElectionTokenSupply)
```

2. Implement a governance-controlled emergency issuance function for VOTE/SHARE tokens that can increase supply through multi-sig approval.

3. Add monitoring and alerts when active vote percentage exceeds 80% of election token supply.

**Test Cases:**
- Test voting when ElectionContract VOTE balance approaches zero
- Test concurrent votes totaling >1 billion tokens
- Verify proper error message when insufficient VOTE tokens remain
- Test emergency reserve issuance through governance

### Proof of Concept

**Initial State:**
- ElectionContract holds 1 billion VOTE and 1 billion SHARE tokens
- Multiple users have native tokens available for voting
- Candidates are registered and available

**Exploitation Steps:**
1. User A votes with 500 million tokens, lock period 365 days
   - ElectionContract transfers 500M VOTE + 500M SHARE to User A
   - Remaining: 500M VOTE, 500M SHARE in ElectionContract

2. User B votes with 400 million tokens, lock period 730 days
   - ElectionContract transfers 400M VOTE + 400M SHARE to User B
   - Remaining: 100M VOTE, 100M SHARE in ElectionContract

3. User C votes with 150 million tokens, lock period 365 days
   - ElectionContract attempts to transfer 150M VOTE + 150M SHARE to User C
   - Transfer fails: "Insufficient balance of VOTE. Need balance: 150000000; Current balance: 100000000"

**Expected Result:**
Vote succeeds and User C receives tokens.

**Actual Result:**
Transaction fails with insufficient balance error. User C cannot vote until other users withdraw, creating a DoS condition for new voters.

**Success Condition:**
The vulnerability is confirmed when cumulative active votes equal the election token total supply and subsequent vote attempts fail with balance errors.

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L128-135)
```csharp
            State.TokenContract.Issue.Send(new IssueInput
            {
                Symbol = symbol,
                Amount = EconomicContractConstants.ElectionTokenTotalSupply,
                To = Context.GetContractAddressByName(SmartContractConstants.ElectionContractSystemName),
                Memo = "Issue all election tokens to Election Contract."
            });
        }
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L152-158)
```csharp
        State.TokenContract.Issue.Send(new IssueInput
        {
            Symbol = Context.Variables.NativeSymbol,
            Amount = input.Amount,
            To = input.To,
            Memo = input.Memo
        });
```

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L25-25)
```csharp
    public const long ElectionTokenTotalSupply = 1_000_000_000_00000000;
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L421-467)
```csharp
    public override Hash Vote(VoteMinerInput input)
    {
        // Check candidate information map instead of candidates. 
        var targetInformation = State.CandidateInformationMap[input.CandidatePubkey];
        AssertValidCandidateInformation(targetInformation);

        var electorPubkey = Context.RecoverPublicKey();

        var lockSeconds = (input.EndTimestamp - Context.CurrentBlockTime).Seconds;
        AssertValidLockSeconds(lockSeconds);

        var voteId = GenerateVoteId(input);
        Assert(State.LockTimeMap[voteId] == 0, "Vote already exists.");
        State.LockTimeMap[voteId] = lockSeconds;

        UpdateElectorInformation(electorPubkey, input.Amount, voteId);

        var candidateVotesAmount = UpdateCandidateInformation(input.CandidatePubkey, input.Amount, voteId);

        LockTokensOfVoter(input.Amount, voteId);
        TransferTokensToVoter(input.Amount);
        CallVoteContractVote(input.Amount, input.CandidatePubkey, voteId);
        AddBeneficiaryToVoter(GetVotesWeight(input.Amount, lockSeconds), lockSeconds, voteId);

        var rankingList = State.DataCentersRankingList.Value;
        if (rankingList.DataCenters.ContainsKey(input.CandidatePubkey))
        {
            rankingList.DataCenters[input.CandidatePubkey] =
                rankingList.DataCenters[input.CandidatePubkey].Add(input.Amount);
            State.DataCentersRankingList.Value = rankingList;
        }
        else
        {
            if (rankingList.DataCenters.Count < GetValidationDataCenterCount())
            {
                State.DataCentersRankingList.Value.DataCenters.Add(input.CandidatePubkey,
                    candidateVotesAmount);
                AddBeneficiary(input.CandidatePubkey);
            }
            else
            {
                TryToBecomeAValidationDataCenter(input, candidateVotesAmount, rankingList);
            }
        }

        return voteId;
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L163-166)
```csharp
        tokenInfo.Issued = tokenInfo.Issued.Add(input.Amount);
        tokenInfo.Supply = tokenInfo.Supply.Add(input.Amount);

        Assert(tokenInfo.Issued <= tokenInfo.TotalSupply, "Total supply exceeded");
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L8-8)
```csharp
    public long TotalSupply { get; set; } = 1_000_000_000_00000000;
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L15-16)
```csharp
    public long MaximumLockTime { get; set; } = 1080 * 86400;
    public long MinimumLockTime { get; set; } = 90 * 86400;
```
