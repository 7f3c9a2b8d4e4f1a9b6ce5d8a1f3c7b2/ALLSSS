### Title
Virtual Balance Mismatch Causes Liquidity Fragmentation and Trading Denial in Token Converter

### Summary
The `NativeTokenToResourceBalance` constant sets a 10 million token virtual balance for native token deposit connectors, which is used in Bancor pricing calculations but does not represent actual tokens held by the TokenConverter contract. When deposit balances are low, the Bancor formula calculates payouts based on this inflated effective balance (virtual + actual), causing transactions to fail when the calculated payout exceeds the contract's real token holdings, creating liquidity fragmentation and preventing legitimate users from selling resource tokens.

### Finding Description
The root cause lies in how the TokenConverter contract uses virtual balances for pricing calculations versus actual token availability for transfers. [1](#0-0) 

During initialization, each native token deposit connector is configured with this 10M virtual balance: [2](#0-1) 

The `GetSelfBalance` method combines virtual balance with actual deposit balance for pricing: [3](#0-2) 

When users sell resource tokens, the Bancor formula uses this combined effective balance to calculate the payout: [4](#0-3) 

However, the actual transfer must come from the contract's real token holdings: [5](#0-4) 

The contract's actual native token balance comes solely from Buy operations that deposit into `DepositBalance`: [6](#0-5) 

Fees are split 50/50 between Treasury donation and burning, with none remaining in the converter: [7](#0-6) 

**Mathematical Condition for Failure:**
Using the simplified Bancor formula when connector weights are equal: [8](#0-7) 

Return = `toBalance * paidAmount / (fromBalance + paidAmount)` where `toBalance = virtualBalance + depositBalance`

For the return to exceed the actual deposit balance:
- `(virtualBalance + depositBalance) * sellAmount / (resourceBalance + sellAmount) > depositBalance`
- Simplifies to: `sellAmount > (depositBalance * resourceBalance) / virtualBalance`

With `virtualBalance = 10M`, if `depositBalance = 100k` and `resourceBalance = 490M`:
- Threshold: `sellAmount > 100k * 490M / 10M = 4.9M tokens`

Selling more than 4.9M resource tokens would calculate a payout exceeding the 100k actual deposit, causing the transfer to fail.

### Impact Explanation
**Operational Impact - Denial of Service:**
- Legitimate users cannot sell resource tokens when deposit balances are insufficient relative to virtual balances
- Transactions fail unexpectedly despite pricing indicating they should succeed
- Creates liquidity fragmentation across multiple resource pairs (CPU, RAM, NET, DISK, READ, WRITE, STORAGE, TRAFFIC)
- Each resource connector has its own 10M virtual balance, amplifying the fragmentation when total native token supply is much larger than 10M per connector

**Severity Justification:**
- No fund theft occurs (transactions revert rather than allowing over-withdrawal)
- Affects system availability and usability rather than fund security
- Impact is more severe early in the system lifecycle when deposit balances are low
- Users' resource tokens become effectively frozen until sufficient deposits accumulate
- Medium severity is appropriate: significant operational disruption without direct fund loss

### Likelihood Explanation
**High Likelihood in Realistic Scenarios:**

**Reachable Entry Point:** The `Sell` method is publicly accessible: [9](#0-8) 

**Feasible Preconditions:**
1. Connectors can be enabled with zero initial deposit when all resource tokens are in the contract: [10](#0-9) 

2. Early system stage where limited buying has occurred (deposit balance << 10M virtual)
3. User has acquired resource tokens through previous Buy operations or initial distribution
4. Total native token supply is significantly larger than 10M, making individual connector deposits proportionally smaller

**Execution Practicality:**
- No special privileges required - any token holder can attempt to sell
- The SafeMath `Sub` operation uses checked arithmetic that will throw on underflow: [11](#0-10) 
- Transaction simply reverts, preventing the user from selling

**Economic Rationality:**
- Natural system state, not an attack - occurs during normal operation when deposits haven't accumulated
- More likely when multiple resource types fragment the limited deposits
- Users have rational incentive to sell but are blocked by insufficient backing

### Recommendation
**Immediate Mitigation:**
1. Add a pre-flight balance check in the `Sell` method before Bancor calculation to ensure sufficient deposit balance exists
2. Consider reducing virtual balance values to be more proportional to expected deposit accumulation rates
3. Implement a minimum deposit requirement during `EnableConnector` to ensure adequate initial liquidity

**Code-Level Changes:**
Before line 168 in `TokenConverterContract.cs`, add:
```csharp
var maxAvailableNative = State.DepositBalance[toConnector.Symbol];
Assert(maxAvailableNative > 0, "Insufficient liquidity in deposit connector");
```

After calculating `amountToReceive` at line 172, add:
```csharp
Assert(amountToReceive <= State.DepositBalance[toConnector.Symbol], 
    "Calculated payout exceeds available deposit balance");
```

**Invariant Checks:**
- `amountToReceive <= DepositBalance[connector]` must hold for all Sell operations
- Virtual balance should not exceed expected maximum deposit accumulation
- Consider dynamic virtual balance adjustment based on actual deposit levels

**Test Cases:**
1. Test selling when deposit balance is minimal (< 1% of virtual balance)
2. Test selling amounts that would exceed deposit balance
3. Test multiple resource pairs with fragmented deposits
4. Verify graceful failure with clear error messages

### Proof of Concept
**Initial State:**
- Resource token (e.g., CPU) created with 500M total supply, all issued to TokenConverter [12](#0-11) 

- Native token connector initialized with 10M virtual balance, 0 deposit balance
- Resource token connector initialized with 100k virtual balance

**Transaction Sequence:**

1. **Enable Connectors:** Call `EnableConnector` for CPU resource token
   - `GetNeededDeposit` returns 0 (all tokens in contract)
   - Deposit balance = 0, system is now active

2. **Limited Initial Buying:** User1 buys 10M CPU tokens
   - Pays approximately 200k native tokens (calculated via Bancor)
   - Deposit balance increases to ~200k
   - Contract now has 490M CPU, 200k native tokens

3. **Attempted Large Sale:** User2 (who previously acquired 50M CPU tokens through multiple small purchases) attempts to sell 50M CPU
   - Bancor calculates based on effective balances:
     - Native effective: 10M virtual + 200k deposit = 10.2M
     - Resource effective: 100k virtual + 490M real = 490.1M
   - Calculated return: `10.2M * 50M / (490.1M + 50M) ≈ 944k native tokens`
   - Contract attempts to transfer 944k native tokens
   - **Transfer fails** - contract only has 200k native tokens
   - Transaction reverts with transfer failure

**Expected vs Actual Result:**
- Expected: User can sell 50M CPU based on pricing formula showing adequate liquidity
- Actual: Transaction fails due to insufficient actual tokens despite pricing suggesting otherwise
- Success Condition (for vulnerability): Transaction reverts when `amountToReceive > depositBalance`, confirming virtual balance inflates pricing beyond actual liquidity

**Notes:**
This vulnerability manifests naturally during normal system operation rather than requiring a deliberate attack. The mismatch between virtual balance used for pricing and actual deposit balance available for withdrawal creates a structural liquidity issue that becomes more severe when:
- The system is in early stages with low accumulated deposits
- Native token supply is much larger than 10M per connector (as mentioned in the vulnerability description)
- Multiple resource types fragment available liquidity across independent connector pairs

### Citations

**File:** contract/AElf.Contracts.Economic/EconomicContractConstants.cs (L20-20)
```csharp
    public const long NativeTokenToResourceBalance = 10_000_000_00000000;
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L96-102)
```csharp
            State.TokenContract.Issue.Send(new IssueInput
            {
                Symbol = resourceTokenSymbol,
                Amount = EconomicContractConstants.ResourceTokenTotalSupply,
                To = tokenConverter,
                Memo = "Initialize for resource trade"
            });
```

**File:** contract/AElf.Contracts.Economic/EconomicContract.cs (L240-249)
```csharp
            var nativeTokenConnector = new Connector
            {
                Symbol = EconomicContractConstants.NativeTokenPrefix.Append(resourceTokenSymbol),
                IsPurchaseEnabled = true,
                IsVirtualBalanceEnabled = true,
                Weight = "0.005",
                VirtualBalance = EconomicContractConstants.NativeTokenToResourceBalance,
                RelatedSymbol = resourceTokenSymbol,
                IsDepositAccount = true
            };
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L133-141)
```csharp
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = amountToPay
            });
        State.DepositBalance[fromConnector.Symbol] = State.DepositBalance[fromConnector.Symbol].Add(amountToPay);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-165)
```csharp
    public override Empty Sell(SellInput input)
    {
        var fromConnector = State.Connectors[input.Symbol];
        Assert(fromConnector != null, "[Sell]Can't find from connector.");
        Assert(fromConnector.IsPurchaseEnabled, "can't purchase");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L168-172)
```csharp
        var amountToReceive = BancorHelper.GetReturnFromPaid(
            GetSelfBalance(fromConnector), GetWeight(fromConnector),
            GetSelfBalance(toConnector), GetWeight(toConnector),
            input.Amount
        );
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-194)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L214-258)
```csharp
    private void HandleFee(long fee)
    {
        var donateFee = fee.Div(2);
        var burnFee = fee.Sub(donateFee);

        // Donate 0.5% fees to Treasury
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = donateFee
            });
        if (State.DividendPoolContract.Value == null)
            State.DividendPoolContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TreasuryContractSystemName);
        State.TokenContract.Approve.Send(new ApproveInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            Spender = State.DividendPoolContract.Value,
            Amount = donateFee
        });
        State.DividendPoolContract.Donate.Send(new DonateInput
        {
            Symbol = State.BaseTokenSymbol.Value,
            Amount = donateFee
        });

        // Transfer to self contract then burn
        State.TokenContract.TransferFrom.Send(
            new TransferFromInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                From = Context.Sender,
                To = Context.Self,
                Amount = burnFee
            });
        State.TokenContract.Burn.Send(
            new BurnInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                Amount = burnFee
            });
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L374-390)
```csharp
    private long GetSelfBalance(Connector connector)
    {
        long realBalance;
        if (connector.IsDepositAccount)
            realBalance = State.DepositBalance[connector.Symbol];
        else
            realBalance = State.TokenContract.GetBalance.Call(
                new GetBalanceInput
                {
                    Owner = Context.Self,
                    Symbol = connector.Symbol
                }).Balance;

        if (connector.IsVirtualBalanceEnabled) return connector.VirtualBalance.Add(realBalance);

        return realBalance;
    }
```

**File:** contract/AElf.Contracts.TokenConverter/BancorHelper.cs (L47-49)
```csharp
        if (wf == wt)
            // if both weights are the same, the formula can be reduced
            return (long)(bt / (bf + a) * a);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConvert_Views.cs (L73-84)
```csharp
        var amountOutOfTokenConvert = tokenInfo.TotalSupply - balance - input.AmountToTokenConvert;
        long needDeposit = 0;
        if (amountOutOfTokenConvert > 0)
        {
            var fb = fromConnector.VirtualBalance;
            var tb = toConnector.IsVirtualBalanceEnabled
                ? toConnector.VirtualBalance.Add(tokenInfo.TotalSupply)
                : tokenInfo.TotalSupply;
            needDeposit =
                BancorHelper.GetAmountToPayFromReturn(fb, GetWeight(fromConnector),
                    tb, GetWeight(toConnector), amountOutOfTokenConvert);
        }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L92-97)
```csharp
    public static long Sub(this long a, long b)
    {
        checked
        {
            return a - b;
        }
```
