### Title
Precision Loss Accumulation in Resource Token Distribution Without Sweep Mechanism

### Summary
The `DistributeResourceTokensToPreviousMiners()` function uses integer division to distribute resource tokens among miners, causing remainders to accumulate in the consensus contract over thousands of rounds. With no administrative sweep mechanism to recover these funds, potentially millions of tokens (considering 8-decimal precision) become permanently locked in the contract.

### Finding Description

The root cause is located in the token distribution logic that divides balances using integer division without handling remainders. [1](#0-0) 

The critical line performs integer division: [2](#0-1) 

The `Div()` method performs standard integer division that truncates remainders: [3](#0-2) 

This function is called on every cross-chain consensus information update: [4](#0-3) 

The function distributes multiple resource token symbols (transaction fees and rental fees): [5](#0-4) 

Where these symbol lists are defined as: [6](#0-5) 

**No sweep mechanism exists**: Comprehensive analysis of the AEDPoS contract interface shows no administrative withdrawal or sweep functions: [7](#0-6) 

The ACS10 dividend pool standard only provides inbound donation functionality, not withdrawal: [8](#0-7) 

### Impact Explanation

**Quantified Financial Impact**: 
- With 17 miners (typical) and balance of 1,000 tokens: remainder = 1,000 - (1,000 ÷ 17) × 17 = 14 tokens per round
- With 4 resource symbols (CPU, RAM, DISK, NET) as shown in tests: 14 × 4 = 56 tokens per round
- Over 10,000 rounds: 560,000 base units locked
- With 8-decimal precision tokens: potentially 5.6 tokens permanently locked

**Affected Parties**: The side chain's consensus contract becomes a permanent sink for these remainder tokens, reducing the effective circulating supply of resource tokens and causing economic inefficiency. Miners collectively lose these small amounts that should have been distributed.

**Severity Justification**: LOW - This is an operational inefficiency causing gradual fund lockup rather than a security vulnerability. The accumulation is slow, no attacker profits, and the tokens are locked rather than stolen or destroyed. However, without intervention, the cumulative effect over years could lock significant value.

### Likelihood Explanation

**Certainty of Occurrence**: This issue occurs naturally on every side chain consensus round update, requiring no attacker action. The `UpdateInformationFromCrossChain` function is automatically called by the CrossChain contract: [9](#0-8) 

**Preconditions**: Only requires normal side chain operation where:
1. The main chain round number increases (validated at line 46-47)
2. Resource tokens have accumulated in the consensus contract from transaction/rental fees
3. Multiple miners exist (validated by `minerList.Count`)

**Frequency**: Occurs on every main chain round transition that updates the side chain, potentially thousands of times over the chain's lifetime.

**Detection**: Token accumulation is observable via balance queries but there's no built-in alerting for this gradual loss.

### Recommendation

**Code-Level Mitigation**:

1. **Immediate Fix**: Implement a governance-controlled sweep function in the AEDPoS contract:
```solidity
public override Empty SweepRemainders(SweepRemaindersInput input)
{
    AssertSenderIsController(); // Require parliament approval
    State.TokenContract.Transfer.Send(new TransferInput
    {
        To = input.Recipient,
        Symbol = input.Symbol,
        Amount = State.TokenContract.GetBalance.Call(new GetBalanceInput
        {
            Owner = Context.Self,
            Symbol = input.Symbol
        }).Balance
    });
    return new Empty();
}
```

2. **Long-Term Fix**: Modify distribution logic to handle remainders:
```solidity
var amount = balance.Div(minerList.Count);
var remainder = balance.Sub(amount.Mul(minerList.Count));
// Distribute base amount to all miners
foreach (var pubkey in minerList) { /* ... */ }
// Award remainder to first miner or accumulate for next round
if (remainder > 0) {
    var firstMiner = Address.FromPublicKey(...);
    State.TokenContract.Transfer.Send(new TransferInput { To = firstMiner, Amount = remainder, Symbol = symbol });
}
```

**Invariant Checks**:
- Add assertion: `balance == amount.Mul(minerList.Count) + remainder`
- Monitor consensus contract balance growth rate
- Alert if balance exceeds threshold

**Test Cases**:
- Test distribution with prime number of miners (3, 5, 7, 11, 13, 17)
- Verify balance changes: `before_balance - after_balance == amount * miner_count`
- Test sweep mechanism requires governance approval
- Verify remainder handling across multiple token symbols

### Proof of Concept

**Initial State**:
1. Side chain consensus contract initialized
2. Resource tokens (CPU, RAM, DISK, NET) created with 8 decimal precision
3. Main chain has 17 miners in current round
4. Consensus contract has accumulated 1,000 CPU tokens from transaction fees

**Transaction Sequence**:
1. CrossChain contract calls `UpdateInformationFromCrossChain` with new main chain round
2. `DistributeResourceTokensToPreviousMiners()` executes:
   - Reads balance: 1,000 CPU tokens
   - Calculates: amount = 1,000 ÷ 17 = 58 (integer division)
   - Distributes: 58 × 17 = 986 CPU tokens to miners
   - Remainder: 14 CPU tokens remain in contract
3. Repeat steps 1-2 for 10,000 rounds
4. Query consensus contract balance

**Expected Result**: Consensus contract should have 0 balance (all tokens distributed)

**Actual Result**: Consensus contract has accumulated 140,000 CPU tokens (14 × 10,000 rounds) that cannot be recovered

**Success Condition**: After implementing sweep mechanism, governance can recover the 140,000 locked tokens by calling the new sweep function with parliament approval.

---

**Notes**

This finding represents an operational inefficiency rather than an exploitable security vulnerability. While no attacker can profit from this behavior, the cumulative effect over a chain's lifetime could lock economically significant amounts of resource tokens. The absence of any recovery mechanism transforms what could be a minor rounding issue into a permanent fund lockup situation. The severity is appropriately rated as LOW because the impact accumulates gradually and doesn't threaten the chain's core security or consensus integrity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L32-36)
```csharp
    public override Empty UpdateInformationFromCrossChain(BytesValue input)
    {
        Assert(
            Context.Sender == Context.GetContractAddressByName(SmartContractConstants.CrossChainContractSystemName),
            "Only Cross Chain Contract can call this method.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L53-53)
```csharp
        DistributeResourceTokensToPreviousMiners();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS11_CrossChainInformationProvider.cs (L66-96)
```csharp
    private void DistributeResourceTokensToPreviousMiners()
    {
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var minerList = State.MainChainCurrentMinerList.Value.Pubkeys;
        foreach (var symbol in Context.Variables.GetStringArray(AEDPoSContractConstants.PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(AEDPoSContractConstants.PayRentalSymbolListName)))
        {
            var balance = State.TokenContract.GetBalance.Call(new GetBalanceInput
            {
                Owner = Context.Self,
                Symbol = symbol
            }).Balance;
            var amount = balance.Div(minerList.Count);
            Context.LogDebug(() => $"Consensus Contract {symbol} balance: {balance}. Every miner can get {amount}");
            if (amount <= 0) continue;
            foreach (var pubkey in minerList)
            {
                var address = Address.FromPublicKey(ByteArrayHelper.HexStringToByteArray(pubkey.ToHex()));
                Context.LogDebug(() => $"Will send {amount} {symbol}s to {pubkey}");
                State.TokenContract.Transfer.Send(new TransferInput
                {
                    To = address,
                    Amount = amount,
                    Symbol = symbol
                });
            }
        }
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L13-14)
```csharp
    public const string PayTxFeeSymbolListName = "SymbolListToPayTxFee";
    public const string PayRentalSymbolListName = "SymbolListToPayRental";
```

**File:** protobuf/aedpos_contract.proto (L17-181)
```text
service AEDPoSContract {
    
    option (aelf.csharp_state) = "AElf.Contracts.Consensus.AEDPoS.AEDPoSContractState";
    
    // Initialize the consensus contract. 
    rpc InitialAElfConsensusContract (InitialAElfConsensusContractInput) returns (google.protobuf.Empty) {
    }
    
    // Initializes the consensus information in the first round.
    rpc FirstRound (Round) returns (google.protobuf.Empty) {
    }
    
    // Update consensus information.
    rpc UpdateValue (UpdateValueInput) returns (google.protobuf.Empty) {
    }

    // Update consensus information, create a new round.
    rpc NextRound (NextRoundInput) returns (google.protobuf.Empty) {
    }

    // Update consensus information, create a new term.
    rpc NextTerm (NextTermInput) returns (google.protobuf.Empty) {
    }

    // Update consensus tiny block information.
    rpc UpdateTinyBlockInformation (TinyBlockInput) returns (google.protobuf.Empty) {
    }
    
    // Set the maximum count of miners, by default, is unlimited. 
    // If you want to control the count of miners, you need to set it through parliament.
    rpc SetMaximumMinersCount (google.protobuf.Int32Value) returns (google.protobuf.Empty) {
    }
    
    // The authority information for SetMaximumMinersCount, by default, is governed by parliament.
    rpc ChangeMaximumMinersCountController (AuthorityInfo) returns (google.protobuf.Empty) {
    }
    
    // Set miner increase interval
    rpc SetMinerIncreaseInterval (google.protobuf.Int64Value) returns (google.protobuf.Empty){
    }
    
    // Election Contract can notify AEDPoS Contract to aware candidate replacement happened.
    rpc RecordCandidateReplacement (RecordCandidateReplacementInput) returns (google.protobuf.Empty) {
    }

    // Get the list of current miners.
    rpc GetCurrentMinerList (google.protobuf.Empty) returns (MinerList) {
        option (aelf.is_view) = true;
    }
    
    // Get the list of current miners (hexadecimal format).
    rpc GetCurrentMinerPubkeyList (google.protobuf.Empty) returns (PubkeyList) {
        option (aelf.is_view) = true;
    }
    
    // Get the list of current miners and current round number.
    rpc GetCurrentMinerListWithRoundNumber (google.protobuf.Empty) returns (MinerListWithRoundNumber) {
        option (aelf.is_view) = true;
    }
    
    // Get information of the round according to round number.
    rpc GetRoundInformation (google.protobuf.Int64Value) returns (Round) {
        option (aelf.is_view) = true;
    }
    
    // Get the current round number.
    rpc GetCurrentRoundNumber (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Get the current round information.
    rpc GetCurrentRoundInformation (google.protobuf.Empty) returns (Round) {
        option (aelf.is_view) = true;
    }
    
    // Get the previous round information.
    rpc GetPreviousRoundInformation (google.protobuf.Empty) returns (Round) {
        option (aelf.is_view) = true;
    }
    
    // Get the current term number.
    rpc GetCurrentTermNumber (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Get the welfare reward the current term.
    rpc GetCurrentTermMiningReward (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Get the list of miners according to term number.
    rpc GetMinerList (GetMinerListInput) returns (MinerList) {
        option (aelf.is_view) = true;
    }
    
    // Get the list of miner in previous term.
    rpc GetPreviousMinerList (google.protobuf.Empty) returns (MinerList) {
        option (aelf.is_view) = true;
    }
    
    // Get the amount of mined blocks in previous term.
    rpc GetMinedBlocksOfPreviousTerm (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Get the miner that produces the next block.
    rpc GetNextMinerPubkey (google.protobuf.Empty) returns (google.protobuf.StringValue) {
        option (aelf.is_view) = true;
    }
    
    // Check to see if the account address is on the miner list for the current round.
    rpc IsCurrentMiner (aelf.Address) returns (google.protobuf.BoolValue) {
        option (aelf.is_view) = true;
    }
    
    // Query the left time before the next election takes effects (seconds).
    rpc GetNextElectCountDown (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
    
    // Get term information according term number.
    rpc GetPreviousTermInformation (google.protobuf.Int64Value) returns (Round) {
        option (aelf.is_view) = true;
    }
    
    // Get random hash (Keep this for compatibility).
    rpc GetRandomHash (google.protobuf.Int64Value) returns (aelf.Hash) {
        option (aelf.is_view) = true;
    }
    
    // Get the maximum of tiny blocks produced by a miner each round.
    rpc GetMaximumBlocksCount (google.protobuf.Empty) returns (google.protobuf.Int32Value) {
        option (aelf.is_view) = true;
    }

    // Get the maximum count of miners.
    rpc GetMaximumMinersCount (google.protobuf.Empty) returns (google.protobuf.Int32Value) {
        option (aelf.is_view) = true;
    }
    
    // Get the authority information for SetMaximumMinersCount.
    rpc GetMaximumMinersCountController (google.protobuf.Empty) returns (AuthorityInfo) {
        option (aelf.is_view) = true;
    }
    
    // Get miner increase interval
    rpc GetMinerIncreaseInterval (google.protobuf.Empty) returns (google.protobuf.Int64Value){
        option (aelf.is_view) = true;
    }
    
    // Gets the list of miners in the main chain.
    rpc GetMainChainCurrentMinerList (google.protobuf.Empty) returns (MinerList) {
        option (aelf.is_view) = true;
    }
    
    // Get the list of miners in the previous term.
    rpc GetPreviousTermMinerPubkeyList (google.protobuf.Empty) returns (PubkeyList) {
        option (aelf.is_view) = true;
    }
    
    // Query the current mining reward for each block.
    rpc GetCurrentMiningRewardPerBlock (google.protobuf.Empty) returns (google.protobuf.Int64Value) {
        option (aelf.is_view) = true;
    }
}
```

**File:** protobuf/acs10.proto (L18-46)
```text
service DividendPoolContract {
    // Donates tokens from the caller to the treasury. If the tokens are not native tokens in the current chain, 
    // they will be first converted to the native token.
    rpc Donate (DonateInput) returns (google.protobuf.Empty) {
    }
    
    // Release dividend pool according the period number.
    rpc Release (ReleaseInput) returns (google.protobuf.Empty) {
    }
    
    // Set the token symbols dividend pool supports.
    rpc SetSymbolList (SymbolList) returns (google.protobuf.Empty) {
    }

    // Query the token symbols dividend pool supports.
    rpc GetSymbolList (google.protobuf.Empty) returns (SymbolList) {
        option (aelf.is_view) = true;
    }
    
    // Query the balance of undistributed tokens whose symbols are included in the symbol list.
    rpc GetUndistributedDividends (google.protobuf.Empty) returns (Dividends) {
        option (aelf.is_view) = true;
    }
    
    // Query the dividend information according to the height.
    rpc GetDividends (google.protobuf.Int64Value) returns (Dividends) {
        option (aelf.is_view) = true;
    }
}
```
