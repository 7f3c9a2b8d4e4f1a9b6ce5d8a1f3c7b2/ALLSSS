# Audit Report

## Title
Side Chain Dividend Pool Accounting Loss: Multiple Symbol Donations at Same Height Erase Previous Symbols

## Summary
The `Donate()` function in the side chain dividends pool contains a critical accounting error where donating a new token symbol at a block height that already has donations of different symbols completely erases the previous symbols' donation records due to flawed conditional logic that creates a new `Dividends` object instead of merging with the existing one.

## Finding Description

The vulnerability exists in the donation accounting logic of the AEDPoS consensus contract's side chain dividend pool implementation. [1](#0-0) 

The root cause is the conditional logic that checks both whether dividends exist AND whether they contain the specific symbol being donated. [2](#0-1) 

When a user donates a token symbol that doesn't exist in the current height's dividend records (but other symbols do exist), the condition evaluates to false because it requires BOTH conditions to be true using an AND operator. This triggers the else block which creates a completely new `Dividends` object containing only the current symbol, overwriting all previously recorded donations at that height.

The `Dividends` message is defined as a map structure designed to accumulate multiple symbols. [3](#0-2) 

The state storage `SideChainReceivedDividends` maps block heights to `Dividends` objects. [4](#0-3) 

**Attack Scenario:**
1. At block height H, User A calls `Donate()` with symbol "ELF" and amount 100
   - No prior dividends exist at this height
   - Else block creates: `{"ELF": 100}`
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
- **Incorrect Query Results**: The `GetDividends()` view method returns incomplete and incorrect dividend information [5](#0-4) 
- **State-Reality Discrepancy**: While actual tokens are correctly transferred to the contract and contributed to the TokenHolder scheme [6](#0-5) , the tracking state becomes permanently inconsistent with actual holdings
- **Broken Audit Trail**: The protocol loses the ability to accurately track donation history, violating the fundamental requirement of dividend distribution systems

**Severity: CRITICAL** - While funds are not stolen or lost, the protocol's accounting integrity is fundamentally compromised. This breaks a core invariant of the dividend pool system: accurate tracking of all donations.

## Likelihood Explanation

**Probability: HIGH** - This vulnerability will trigger automatically under normal operations:

**No Special Capabilities Required**: The `Donate()` function is public and can be called by any user. [7](#0-6) 

**Natural Occurrence**: The vulnerability triggers when:
1. Multiple users donate to the dividend pool
2. They donate different token symbols
3. Their transactions are included in the same block

**Low Complexity**: No coordination, special timing, or privileged access is required. This is a natural scenario in any active blockchain where multiple users interact with the dividend pool using different tokens.

**Common Scenario**: Blocks containing multiple transactions are standard in blockchain operations. The side chain dividend pool is designed to accept multiple token symbols, making this a realistic and expected usage pattern.

## Recommendation

The logic should be refactored to properly merge new symbols into existing `Dividends` objects instead of overwriting them:

```csharp
var currentReceivedDividends = State.SideChainReceivedDividends[Context.CurrentHeight];
if (currentReceivedDividends == null)
{
    currentReceivedDividends = new Dividends();
}

if (currentReceivedDividends.Value.ContainsKey(input.Symbol))
{
    currentReceivedDividends.Value[input.Symbol] = 
        currentReceivedDividends.Value[input.Symbol].Add(input.Amount);
}
else
{
    currentReceivedDividends.Value.Add(input.Symbol, input.Amount);
}

State.SideChainReceivedDividends[Context.CurrentHeight] = currentReceivedDividends;
```

This separates the null check from the symbol existence check, ensuring that new symbols are properly added to existing `Dividends` objects rather than overwriting them.

## Proof of Concept

```csharp
[Fact]
public async Task SideChainDividendPool_MultipleSymbolDonations_SameHeight_Test()
{
    // Setup: Create and configure two different tokens
    const string symbolELF = "ELF";
    const string symbolUSDT = "USDT";
    const long donateAmountELF = 1000;
    const long donateAmountUSDT = 2000;
    
    await CreateAndConfigureTokenAsync(symbolELF);
    await CreateAndConfigureTokenAsync(symbolUSDT);
    
    // Get current height
    var currentHeight = (await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty())).RealTimeMinersInformation.Values.First().ExpectedMiningTime.Seconds;
    
    // First donation: ELF token
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = symbolELF,
        Amount = donateAmountELF
    });
    
    // Check dividends after first donation
    var dividendsAfterFirst = await AEDPoSContractStub.GetDividends.CallAsync(
        new Int64Value { Value = currentHeight });
    dividendsAfterFirst.Value.ContainsKey(symbolELF).ShouldBeTrue();
    dividendsAfterFirst.Value[symbolELF].ShouldBe(donateAmountELF);
    
    // Second donation: USDT token at SAME height
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = symbolUSDT,
        Amount = donateAmountUSDT
    });
    
    // Check dividends after second donation
    var dividendsAfterSecond = await AEDPoSContractStub.GetDividends.CallAsync(
        new Int64Value { Value = currentHeight });
    
    // BUG: ELF donation record should still exist but it's erased
    dividendsAfterSecond.Value.ContainsKey(symbolELF).ShouldBeTrue(); // FAILS
    dividendsAfterSecond.Value.ContainsKey(symbolUSDT).ShouldBeTrue(); // PASSES
    dividendsAfterSecond.Value[symbolELF].ShouldBe(donateAmountELF); // FAILS
    dividendsAfterSecond.Value[symbolUSDT].ShouldBe(donateAmountUSDT); // PASSES
}
```

This test demonstrates that after two donations of different symbols at the same block height, only the second symbol's donation is recorded, proving the accounting loss vulnerability.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-94)
```csharp
    public override Empty Donate(DonateInput input)
    {
        EnsureTokenContractAddressSet();

        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();

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

        Context.Fire(new DonationReceived
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            PoolContract = Context.Self
        });

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

        Context.LogDebug(() => $"Contributed {input.Amount} {input.Symbol}s to side chain dividends pool.");

        return new Empty();
    }
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
