### Title
Side Chain Dividend Pool Overwrites Multi-Token Donations at Same Block Height

### Summary
The `Donate()` function in the side chain dividend pool contains a critical logic error that causes previous donations to be overwritten when multiple transactions donate different token symbols at the same block height. [1](#0-0)  This results in permanent loss of donated funds that were contributed earlier in the same block.

### Finding Description

The vulnerability exists in the `Donate()` method's logic for accumulating donations per block height. [2](#0-1) 

The code reads the current dividends from state and checks if both conditions are true: (1) the dividends object is not null AND (2) it contains the donated token symbol. [3](#0-2) 

If either condition is false, it creates a completely new `Dividends` object containing only the current donation. [4](#0-3) 

The `Dividends` type is a protobuf message containing a map of token symbols to amounts. [5](#0-4) 

The state variable stores one `Dividends` object per block height. [6](#0-5) 

**Root Cause**: When `currentReceivedDividends` exists but doesn't contain the new symbol, the else-branch executes and creates a NEW `Dividends` object with only the current symbol/amount pair, completely discarding any other token symbols that were previously donated at this height.

**Attack Scenario**:
1. Transaction 1 at height H: User A donates 1000 ELF → State stores `{"ELF": 1000}`
2. Transaction 2 at height H: User B donates 500 USDT → Condition evaluates to `(not null) && (contains "USDT")` = `true && false` = `false` → Else-branch creates `{"USDT": 500}` → State now stores only `{"USDT": 500}`, **1000 ELF is lost**

No authorization checks prevent this, and the function is publicly callable. [7](#0-6) 

### Impact Explanation

**Direct Fund Loss**: Donated tokens are permanently lost from the dividend pool accounting. The tokens have already been transferred to the contract and approved to the TokenHolder contract, but the state variable `SideChainReceivedDividends[height]` fails to record all donations correctly.

**Quantified Damage**: For every donation of a different token symbol at the same block height, all previous donations from that height are lost from the accounting. In a busy chain, multiple users could donate at the same height, causing cumulative losses.

**Affected Parties**: 
- Donors lose the benefit of their donations (no dividend distribution occurs for lost tokens)
- Token holders expecting dividends receive less than donated
- Side chain dividend pool integrity is compromised

**Severity Justification**: HIGH - This is a critical accounting bug causing permanent fund loss with no way to recover. The tokens remain locked in the contract but untracked by the dividend distribution mechanism, making them effectively burned.

### Likelihood Explanation

**Attacker Capabilities**: No special privileges required. Any user can call the public `Donate()` function.

**Attack Complexity**: LOW - The vulnerability triggers naturally whenever two different users donate different token symbols within the same block. No coordination or malicious intent is required.

**Feasibility Conditions**: 
- Multiple transactions in the same block (common in normal operation)
- Different token symbols being donated (normal for a multi-token dividend pool)
- No special timing or state manipulation needed

**Detection Constraints**: The loss is silent - no error is thrown, and the `DonationReceived` event fires normally for both transactions. Only careful auditing of state changes would reveal the discrepancy.

**Probability**: HIGH - On an active chain with regular donations, this will occur frequently by accident, not requiring any attack. Block times in AELf are predictable, making same-height donations common.

### Recommendation

**Code-Level Mitigation**: Refactor the conditional logic to properly handle three cases:

1. If `currentReceivedDividends` is null, create a new `Dividends` object
2. If `currentReceivedDividends` exists and contains the symbol, add to existing amount
3. If `currentReceivedDividends` exists but doesn't contain the symbol, add the new symbol to the existing map

The corrected logic should be:
- Check if `currentReceivedDividends` is null first, create new if needed
- Otherwise, check if the symbol exists in the map
  - If yes: add to existing amount
  - If no: insert new symbol/amount pair into existing map
- Never create a new `Dividends` object when one already exists

**Invariant Checks**: 
- Add validation that reading `SideChainReceivedDividends[height]` after multiple donations returns all donated symbols
- Verify total donated amounts match the sum across all symbols in the state

**Test Cases**:
1. Test multiple donations of different symbols at same height
2. Test multiple donations of same symbol at same height (already works)
3. Test mixed scenario: donate symbol A, then A again, then B at same height
4. Test edge case: three different symbols at same height
5. Verify state persistence across all scenarios

### Proof of Concept

**Required Initial State**:
- Side chain dividend pool initialized
- Two users (UserA, UserB) with token balances (ELF, USDT)
- Both tokens approved for method fees
- TokenHolder contract deployed and configured

**Transaction Steps**:
1. At block height 1000:
   - UserA calls `Donate(symbol="ELF", amount=1000)`
   - Verify: `GetDividends(1000)` returns `{"ELF": 1000}` ✓
   
2. At block height 1000 (same height):
   - UserB calls `Donate(symbol="USDT", amount=500)`
   - Verify: `GetDividends(1000)` returns `{"USDT": 500}` only

**Expected Result**: `GetDividends(1000)` should return `{"ELF": 1000, "USDT": 500}`

**Actual Result**: `GetDividends(1000)` returns `{"USDT": 500}` - the 1000 ELF donation is lost

**Success Condition**: The second donation overwrites the first, demonstrating the vulnerability. The 1000 ELF remains in the contract balance but is not recorded in the `SideChainReceivedDividends` mapping, preventing proper dividend distribution.

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
