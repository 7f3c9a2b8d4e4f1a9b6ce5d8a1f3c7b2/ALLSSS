# Audit Report

## Title
Side Chain Donation Tracking Overwrites Multi-Symbol Donations in Same Block

## Summary
The `Donate()` function in the AEDPoS side chain dividends pool contains a critical logic error where donation records are overwritten when multiple different token symbols are donated within the same block. The flawed conditional logic creates a new `Dividends` object instead of adding to the existing one, resulting in permanent loss of previously recorded donations for that block.

## Finding Description

The vulnerability exists in the donation tracking logic of the side chain dividends pool. [1](#0-0) 

The root cause lies in the conditional statement that checks if a record exists AND contains the current symbol. This condition has two negation paths that lead to the else block:

1. `currentReceivedDividends == null` - Correctly creates a new object when no record exists
2. `currentReceivedDividends != null && !ContainsKey(input.Symbol)` - **INCORRECTLY creates a new object, overwriting existing data**

When scenario 2 occurs, the else block creates a completely new `Dividends` object containing only the current donation symbol, then writes it to state, effectively erasing all other symbol donations recorded for that block height.

The `Dividends` message type is intentionally designed as a map structure to support multiple token symbols. [2](#0-1) 

**Concrete Exploit Scenario:**
- Block 1000, Transaction 1: User A donates 1000 ELF → State stores `{ELF: 1000}`
- Block 1000, Transaction 2: User B donates 500 USDT → Condition evaluates to false (record exists but doesn't contain USDT) → Else block executes → State overwrites to `{USDT: 500}` → **ELF donation record is permanently lost**

The `Donate()` method is publicly accessible without special permissions. [3](#0-2) 

The same vulnerability pattern exists in the Treasury contract with an even more restrictive condition that compounds the issue. [4](#0-3) 

## Impact Explanation

**Critical State Corruption:**
- Donation records for entire token symbols are permanently erased from blockchain state
- The `GetDividends` view function returns incorrect historical data [5](#0-4) 
- TokenHolder profit distribution calculations may use corrupted dividend data
- Economic analytics and governance metrics become unreliable

**Direct Financial Impact:**
- Donors lose recognition of their contributions in the permanent record
- Historical queries for donation amounts return incomplete data
- Side chain operators lose accurate tracking for economic decisions

**Severity Justification:** 
This is CRITICAL because:
1. The bug destroys permanent state data
2. It occurs deterministically under normal usage patterns
3. Lost donation records cannot be recovered
4. The corrupted state affects downstream profit calculations
5. No on-chain detection or recovery mechanism exists

## Likelihood Explanation

**Reachable Entry Point:**
The `Donate()` method is a public function implementing the ACS10 standard, accessible to any user with token balance and approval.

**Trivial Preconditions:**
- Any two users call `Donate()` with different token symbols in the same block
- Only requires token balance, approval, and passing `IsTokenAvailableForMethodFee` check
- No special permissions, timing requirements, or complex setup needed

**Execution Practicality:**
- On moderately active side chains, multiple donations per block is expected behavior
- AEDPoS block times (~4 seconds) make concurrent transactions highly probable
- The bug triggers automatically without any malicious intent required
- Normal users performing legitimate donations will unknowingly trigger data loss

**Attack Complexity:** VERY LOW
- No sophisticated manipulation needed
- Occurs naturally through normal protocol usage
- Can be accidentally triggered or deliberately exploited
- No way for users to prevent or detect the issue

**Detection Difficulty:**
- Donation events fire correctly, masking the state corruption [6](#0-5) 
- Data loss only discovered when querying historical records
- No alerts or revert conditions exist

**Probability Assessment:** HIGH - This will occur regularly on any production side chain with multi-token support and moderate transaction volume.

## Recommendation

The fix requires modifying the conditional logic to properly handle the case where a record exists but doesn't contain the current symbol. The corrected logic should add the new symbol to the existing `Dividends` object rather than creating a new one:

**For AEDPoS Side Chain:**
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

**For Treasury Contract:**
Apply similar logic to properly accumulate donations across different symbols within the same block.

## Proof of Concept

```csharp
[Fact]
public async Task MultiSymbol_Donation_Same_Block_Overwrites_Previous_Donations()
{
    // Setup: Ensure we have two different token symbols available
    const long donationAmount1 = 1000_00000000;
    const long donationAmount2 = 500_00000000;
    const string symbol1 = "ELF";
    const string symbol2 = "USDT";
    
    // Get current block height
    var currentHeight = (await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty())).RealTimeMinersInformation.Values.First().ExpectedMiningTime.Seconds;
    
    // Transaction 1: Donate symbol1 in the current block
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = symbol1,
        Amount = donationAmount1
    });
    
    // Transaction 2: Donate symbol2 in the SAME block (before block advances)
    await AEDPoSContractStub.Donate.SendAsync(new DonateInput
    {
        Symbol = symbol2,
        Amount = donationAmount2
    });
    
    // Query the dividends for the current block
    var dividends = await AEDPoSContractStub.GetDividends.CallAsync(new Int64Value { Value = currentHeight });
    
    // BUG: Only symbol2 donation is recorded, symbol1 donation is lost
    dividends.Value.Count.ShouldBe(1); // Should be 2, but bug causes overwrite
    dividends.Value.ContainsKey(symbol2).ShouldBeTrue();
    dividends.Value.ContainsKey(symbol1).ShouldBeFalse(); // LOST!
    dividends.Value[symbol2].ShouldBe(donationAmount2);
    
    // Expected behavior would be:
    // dividends.Value.Count.ShouldBe(2);
    // dividends.Value[symbol1].ShouldBe(donationAmount1);
    // dividends.Value[symbol2].ShouldBe(donationAmount2);
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L37-50)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L66-72)
```csharp
        Context.Fire(new DonationReceived
        {
            From = Context.Sender,
            Symbol = input.Symbol,
            Amount = input.Amount,
            PoolContract = Context.Self
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

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L225-239)
```csharp
            var donatesOfCurrentBlock = State.DonatedDividends[Context.CurrentHeight];
            if (donatesOfCurrentBlock != null && Context.Variables.NativeSymbol == input.Symbol &&
                donatesOfCurrentBlock.Value.ContainsKey(Context.Variables.NativeSymbol))
                donatesOfCurrentBlock.Value[Context.Variables.NativeSymbol] = donatesOfCurrentBlock
                    .Value[Context.Variables.NativeSymbol].Add(input.Amount);
            else
                donatesOfCurrentBlock = new Dividends
                {
                    Value =
                    {
                        { input.Symbol, input.Amount }
                    }
                };

            State.DonatedDividends[Context.CurrentHeight] = donatesOfCurrentBlock;
```
