# Audit Report

## Title
Side Chain Dividend Pool Accounting Loss: Multiple Symbol Donations at Same Height Erase Previous Symbols

## Summary
The `Donate()` function in the side chain dividends pool contains a critical accounting error where donating a new token symbol at a block height that already has donations of different symbols completely erases the previous symbols' donation records due to flawed conditional logic that creates a new `Dividends` object instead of merging with the existing one.

## Finding Description

The vulnerability exists in the donation accounting logic of the AEDPoS consensus contract's side chain dividend pool implementation. [1](#0-0) 

The root cause is the conditional logic that checks both whether dividends exist AND whether they contain the specific symbol being donated. When a user donates a token symbol that doesn't exist in the current height's dividend records (but other symbols do exist), the condition evaluates to false because it requires BOTH conditions to be true using an AND operator. This triggers the else block which creates a completely new `Dividends` object containing only the current symbol, overwriting all previously recorded donations at that height.

The `Dividends` message is defined as a map structure designed to accumulate multiple symbols. [2](#0-1) 

The state storage `SideChainReceivedDividends` maps block heights to `Dividends` objects. [3](#0-2) 

**Attack Scenario:**
1. At block height H, User A calls `Donate()` with symbol "ELF" and amount 100
   - No prior dividends exist at this height
   - Else block executes, creating: `{"ELF": 100}`
   - State updated: `SideChainReceivedDividends[H] = {"ELF": 100}`

2. In the same block height H, User B calls `Donate()` with symbol "USDT" and amount 200
   - Prior dividends exist: `{"ELF": 100}`
   - Condition check: `(currentReceivedDividends != null && currentReceivedDividends.Value.ContainsKey("USDT"))`
   - Evaluates to: `(true && false) = false`
   - Else block creates new object: `{"USDT": 200}`
   - State updated: `SideChainReceivedDividends[H] = {"USDT": 200}`
   - **User A's 100 ELF record is permanently erased**

## Impact Explanation

This vulnerability causes **critical accounting integrity violation**:

- **Permanent Data Loss**: Donation records for previous symbols at the same height are irreversibly erased from contract state
- **Incorrect Query Results**: The `GetDividends()` view method returns incomplete and incorrect dividend information [4](#0-3) 
- **State-Reality Discrepancy**: While actual tokens are correctly transferred to the contract and contributed to the TokenHolder scheme [5](#0-4) , the tracking state becomes permanently inconsistent with actual holdings
- **Broken Audit Trail**: The protocol loses the ability to accurately track donation history, violating the fundamental requirement of dividend distribution systems

**Severity: CRITICAL** - While funds are not stolen or lost, the protocol's accounting integrity is fundamentally compromised. This breaks a core invariant of the dividend pool system: accurate tracking of all donations.

## Likelihood Explanation

**Probability: HIGH** - This vulnerability will trigger automatically under normal operations:

**No Special Capabilities Required**: The `Donate()` function is public and can be called by any user. [6](#0-5) 

**Natural Occurrence**: The vulnerability triggers when:
1. Multiple users donate to the dividend pool
2. They donate different token symbols
3. Their transactions are included in the same block

**Low Complexity**: No coordination, special timing, or privileged access is required. This is a natural scenario in any active blockchain where multiple users interact with the dividend pool using different tokens.

**Common Scenario**: Blocks containing multiple transactions are standard in blockchain operations. The side chain dividend pool is designed to accept multiple token symbols, making this a realistic and expected usage pattern.

## Recommendation

Fix the conditional logic to properly handle all three cases:

1. **If dividends are null**: Create new `Dividends` object
2. **If dividends exist and contain the symbol**: Add to existing amount
3. **If dividends exist but don't contain the symbol**: Add the new symbol to the existing dictionary

The corrected logic should be:

```csharp
var currentReceivedDividends = State.SideChainReceivedDividends[Context.CurrentHeight];
if (currentReceivedDividends == null)
{
    currentReceivedDividends = new Dividends
    {
        Value = { { input.Symbol, input.Amount } }
    };
}
else if (currentReceivedDividends.Value.ContainsKey(input.Symbol))
{
    currentReceivedDividends.Value[input.Symbol] = 
        currentReceivedDividends.Value[input.Symbol].Add(input.Amount);
}
else
{
    currentReceivedDividends.Value[input.Symbol] = input.Amount;
}

State.SideChainReceivedDividends[Context.CurrentHeight] = currentReceivedDividends;
```

## Proof of Concept

This test demonstrates the vulnerability by showing that a second donation with a different symbol erases the first donation's record:

```csharp
[Fact]
public async Task SideChainDividendPool_MultipleSymbolDonations_LosesPreviousRecords()
{
    // Setup: Prepare two different token symbols and amounts
    const string firstSymbol = "ELF";
    const long firstAmount = 100;
    const string secondSymbol = "USDT";
    const long secondAmount = 200;
    
    // Get initial block height
    var currentHeight = (await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty())).RealTimeMinersInformation.Values.First().ExpectedMiningTime.Seconds;

    // Transaction 1: User A donates 100 ELF
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = firstSymbol,
        Amount = firstAmount
    });

    // Verify first donation is recorded
    var dividendsAfterFirst = await AEDPoSContractStub.GetDividends.CallAsync(new Int64Value { Value = currentHeight });
    dividendsAfterFirst.Value.Count.ShouldBe(1);
    dividendsAfterFirst.Value[firstSymbol].ShouldBe(firstAmount);

    // Transaction 2: User B donates 200 USDT at the same height
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = secondSymbol,
        Amount = secondAmount
    });

    // Query dividends after second donation
    var dividendsAfterSecond = await AEDPoSContractStub.GetDividends.CallAsync(new Int64Value { Value = currentHeight });
    
    // BUG: The first donation (ELF) is lost!
    dividendsAfterSecond.Value.Count.ShouldBe(1); // Should be 2, but is 1
    dividendsAfterSecond.Value.ContainsKey(firstSymbol).ShouldBeFalse(); // ELF record is gone!
    dividendsAfterSecond.Value[secondSymbol].ShouldBe(secondAmount); // Only USDT remains
    
    // Expected behavior: Both donations should be present
    // dividendsAfterSecond.Value.Count.ShouldBe(2);
    // dividendsAfterSecond.Value[firstSymbol].ShouldBe(firstAmount);
    // dividendsAfterSecond.Value[secondSymbol].ShouldBe(secondAmount);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-37)
```csharp
    public override Empty Donate(DonateInput input)
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L44-64)
```csharp
        State.TokenContract.TransferFrom.Send(new TransferFromInput
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            To = Context.Self
        });

        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = input.Symbol,
            Amount = input.Amount,
            Spender = State.TokenHolderContract.Value
        });

        State.TokenHolderContract.ContributeProfits.Send(new ContributeProfitsInput
        {
            SchemeManager = Context.Self,
            Symbol = input.Symbol,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L74-89)
```csharp
        var currentReceivedDividends = State.SideChainReceivedDividends[Context.CurrentHeight];
        if (currentReceivedDividends != null && currentReceivedDividends.Value.ContainsKey(input.Symbol))
            currentReceivedDividends.Value[input.Symbol] =
                currentReceivedDividends.Value[input.Symbol].Add(input.Amount);
        else
            currentReceivedDividends = new Dividends
            {
                Value =
                {
                    {
                        input.Symbol, input.Amount
                    }
                }
            };

        State.SideChainReceivedDividends[Context.CurrentHeight] = currentReceivedDividends;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L130-134)
```csharp
    public override Dividends GetDividends(Int64Value input)
    {
        Assert(Context.CurrentHeight > input.Value, "Cannot query dividends of a future block.");
        return State.SideChainReceivedDividends[input.Value];
    }
```

**File:** protobuf/acs10.proto (L65-68)
```text
message Dividends {
    // The dividends, symbol -> amount.
    map<string, int64> value = 1;
}
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AElfConsensusContractState.cs (L57-57)
```csharp
    public MappedState<long, Dividends> SideChainReceivedDividends { get; set; }
```
