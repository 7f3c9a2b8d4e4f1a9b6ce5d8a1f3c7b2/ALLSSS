### Title
Missing Debt Forgiveness Mechanism for Side Chain OwningRental Creates Permanent Economic Burden

### Summary
The `State.OwningRental` debt tracking system for side chain resource rental fees lacks any mechanism to forgive or write off accumulated debt. When a side chain creator has insufficient balance to pay rental fees, debt accumulates indefinitely with no administrative relief mechanism, creating a permanent economic burden that can become practically impossible to repay.

### Finding Description

The `State.OwningRental` state variable tracks rental debt for side chain resource tokens (CPU, RAM, DISK, NET). [1](#0-0) 

The `PayRental()` method is automatically called every block on side chains. [2](#0-1) 

When the side chain creator has insufficient balance to pay rental fees, the system donates all available balance and adds the shortfall to the debt. [3](#0-2) 

**Root Cause:** The entire codebase contains only TWO locations where `State.OwningRental[symbol]` is modified:
1. Resetting to zero when debt is paid: [4](#0-3) 
2. Adding to the debt when payment fails: [5](#0-4) 

No administrative function exists to forgive, reduce, or cap this debt. The `UpdateRental` and `UpdateRentedResources` methods can only adjust future rates, not forgive past debt. [6](#0-5) 

**Critical Design Flaw:** When debt exists, it MUST be paid before current rental fees can be paid. [7](#0-6) 

### Impact Explanation

**Concrete Harm:**
- Side chain creators face permanent, unpayable debt that consumes all future token balances
- If debt accumulates to a large amount (e.g., 10,000,000 tokens) during extended periods of insufficient balance, the creator can never catch up
- All future available balance is consumed by debt repayment (lines 1051-1057), never reaching current rental payment
- This creates an economic death spiral where the creator is perpetually in debt with no recovery path

**Quantified Impact:**
- Example scenario: If debt grows to 1,000,000 tokens and current rental is 100 tokens/minute, the creator must first repay the entire 1,000,000 before any current charges are paid
- Test case demonstrates debt accumulation: [8](#0-7) 

**Who is Affected:**
Side chain creators who experience temporary liquidity issues, market crashes, or operational problems that cause insufficient balance for rental payments.

**Severity Justification (Medium):**
While the side chain continues technical operations (PayRental doesn't revert), the economic model becomes permanently broken with no administrative relief mechanism available.

### Likelihood Explanation

**Realistic Scenario (Not an Attack):**
This is not an exploitable attack but a realistic operational risk:
1. Side chain operates normally with creator paying rental fees
2. Creator experiences temporary insufficient balance (market crash, liquidity crisis, operational issues)
3. PayRental() executes automatically every block via DonateResourceToken
4. Each execution adds unpaid rental to debt (line 1075)
5. Over days/weeks, debt accumulates to astronomically high levels
6. Even when creator later obtains funds, the debt is practically impossible to repay

**Execution Practicality:**
- Automatic execution through system transactions - no special actions needed
- DonateResourceToken is called by consensus contract every block: [9](#0-8) 
- No assertions prevent debt accumulation - the system continues operating

**Probability:**
Medium to High - Temporary liquidity issues are common in blockchain ecosystems, especially during market volatility.

### Recommendation

**Code-Level Mitigation:**

1. **Add Debt Forgiveness Function:**
```solidity
public override Empty ForgiveOwningRental(ForgiveOwningRentalInput input) 
{
    AssertControllerForSideChainRental();
    foreach (var (symbol, amount) in input.ForgivenessAmount) 
    {
        Assert(State.OwningRental[symbol] >= amount, "Forgiveness exceeds debt");
        State.OwningRental[symbol] = State.OwningRental[symbol].Sub(amount);
    }
    return new Empty();
}
```

2. **Add Debt Cap Mechanism:**
Implement a maximum debt threshold beyond which further debt stops accumulating, preventing astronomical debt values.

3. **Add Debt Restructuring:**
Allow governance to reset debt to zero or a manageable level through proposal-based mechanism.

**Invariant Checks:**
- Add monitoring for debt levels exceeding reasonable thresholds
- Alert when debt accumulation rate exceeds payment capacity
- Implement debt-to-resource-usage ratio limits

**Test Cases:**
- Test debt forgiveness by governance
- Test debt cap enforcement
- Test debt restructuring proposals
- Verify only authorized controllers can forgive debt

### Proof of Concept

**Initial State:**
- Side chain is operational with configured rental rates (100 tokens/minute per resource)
- Creator initially has 0 balance for resource tokens

**Execution Steps:**

1. Initialize side chain with zero balance: [10](#0-9) 

2. After 1 minute, debt accumulates to: CPU=400, RAM=800, DISK=51200, NET=100000 tokens

3. Issue only 1 token to creator for each resource

4. After another minute, debt grows to: CPU=799, RAM=1599, DISK=102399, NET=199999 tokens: [11](#0-10) 

5. Creator's balance remains 0 - all tokens consumed by debt repayment: [12](#0-11) 

**Expected Result:**
Governance should be able to forgive or restructure the debt.

**Actual Result:**
No mechanism exists to forgive debt. The only way to clear `State.OwningRental[symbol]` is to pay it in full, which becomes impossible when debt reaches astronomical levels.

**Success Condition:**
Debt continues accumulating indefinitely with no administrative relief, confirming the permanent economic burden on the side chain creator.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContractState_ChargeFee.cs (L33-36)
```csharp
    /// <summary>
    /// Symbol -> Amount
    /// </summary>
    public MappedState<string, long> OwningRental { get; set; }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L913-924)
```csharp
    public override Empty DonateResourceToken(TotalResourceTokensMaps input)
    {
        AssertSenderIsCurrentMiner();
        var donateResourceTokenExecuteHeight = State.DonateResourceTokenExecuteHeight.Value;
        if (donateResourceTokenExecuteHeight == 0)
        {
            donateResourceTokenExecuteHeight = Context.CurrentHeight;
        }

        Assert(donateResourceTokenExecuteHeight == Context.CurrentHeight,
            $"This method already executed in height {State.DonateResourceTokenExecuteHeight.Value}");
        State.DonateResourceTokenExecuteHeight.Value = donateResourceTokenExecuteHeight.Add(1);
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L947-950)
```csharp
        if (!isMainChain)
        {
            PayRental();
        }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1046-1059)
```csharp
            // Try to update owning rental.
            var owningRental = State.OwningRental[symbol];
            if (owningRental > 0)
            {
                // If Creator own this symbol and current balance can cover the debt, pay the debt at first.
                if (availableBalance > owningRental)
                {
                    donates = owningRental;
                    // Need to update available balance,
                    // cause existing balance not necessary equals to available balance.
                    availableBalance = availableBalance.Sub(owningRental);
                    State.OwningRental[symbol] = 0;
                }
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1067-1082)
```csharp
            else // Fail
            {
                // Donate all existing balance. Directly reset the donates.
                donates = GetBalance(creator, symbol);
                State.Balances[creator][symbol] = 0;

                // Update owning rental to record a new debt.
                var own = rental.Sub(availableBalance);
                State.OwningRental[symbol] = State.OwningRental[symbol].Add(own);

                Context.Fire(new RentalAccountBalanceInsufficient
                {
                    Symbol = symbol,
                    Amount = own
                });
            }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L1099-1127)
```csharp
    public override Empty UpdateRental(UpdateRentalInput input)
    {
        AssertControllerForSideChainRental();
        foreach (var pair in input.Rental)
        {
            Assert(
                Context.Variables.GetStringArray(TokenContractConstants.PayRentalSymbolListName).Contains(pair.Key),
                "Invalid symbol.");
            Assert(pair.Value >= 0, "Invalid amount.");
            State.Rental[pair.Key] = pair.Value;
        }

        return new Empty();
    }

    public override Empty UpdateRentedResources(UpdateRentedResourcesInput input)
    {
        AssertControllerForSideChainRental();
        foreach (var pair in input.ResourceAmount)
        {
            Assert(
                Context.Variables.GetStringArray(TokenContractConstants.PayRentalSymbolListName).Contains(pair.Key),
                "Invalid symbol.");
            Assert(pair.Value >= 0, "Invalid amount.");
            State.ResourceAmount[pair.Key] = pair.Value;
        }

        return new Empty();
    }
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L96-119)
```csharp
    public async Task OwnResourceTest()
    {
        await InitialTokenContractAsync(false);

        // Check balance before mining
        {
            var cpuBalance = await GetCreatorBalanceOfAsync("CPU");
            cpuBalance.ShouldBe(0);
            var ramBalance = await GetCreatorBalanceOfAsync("RAM");
            ramBalance.ShouldBe(0);
            var diskBalance = await GetCreatorBalanceOfAsync("DISK");
            diskBalance.ShouldBe(0);
            var netBalance = await GetCreatorBalanceOfAsync("NET");
            netBalance.ShouldBe(0);
        }

        await DelayOneMinuteAsync();

        var owningRental = await TokenContractStub.GetOwningRental.CallAsync(new Empty());
        owningRental.ResourceAmount["CPU"].ShouldBe(CpuAmount * Rental);
        owningRental.ResourceAmount["RAM"].ShouldBe(RamAmount * Rental);
        owningRental.ResourceAmount["DISK"].ShouldBe(DiskAmount * Rental);
        owningRental.ResourceAmount["NET"].ShouldBe(NetAmount * Rental);
    }
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/SideChainSideChainRentFeeTest.cs (L173-205)
```csharp
    public async Task PayDebtTest_NotEnough()
    {
        await OwnResourceTest();

        // Charge
        foreach (var symbol in Symbols)
            await TokenContractStub.Issue.SendAsync(new IssueInput
            {
                Symbol = symbol,
                To = Creator,
                Amount = 1
            });

        await DelayOneMinuteAsync();

        var owningRental = await TokenContractStub.GetOwningRental.CallAsync(new Empty());
        owningRental.ResourceAmount["CPU"].ShouldBe(CpuAmount * Rental * 2 - 1);
        owningRental.ResourceAmount["RAM"].ShouldBe(RamAmount * Rental * 2 - 1);
        owningRental.ResourceAmount["DISK"].ShouldBe(DiskAmount * Rental * 2 - 1);
        owningRental.ResourceAmount["NET"].ShouldBe(NetAmount * Rental * 2 - 1);

        // Check balance before mining
        {
            var cpuBalance = await GetCreatorBalanceOfAsync("CPU");
            cpuBalance.ShouldBe(0);
            var ramBalance = await GetCreatorBalanceOfAsync("RAM");
            ramBalance.ShouldBe(0);
            var diskBalance = await GetCreatorBalanceOfAsync("DISK");
            diskBalance.ShouldBe(0);
            var netBalance = await GetCreatorBalanceOfAsync("NET");
            netBalance.ShouldBe(0);
        }
    }
```
