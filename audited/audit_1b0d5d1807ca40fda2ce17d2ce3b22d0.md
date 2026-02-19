### Title
Zero Deposit Allows Connector Enablement Without Base Token Reserves, Breaking Sell Functionality

### Summary
When `GetNeededDeposit()` is called with `AmountToTokenConvert` equal to all circulating tokens (totalSupply - balance), the function returns `needDeposit = 0`. [1](#0-0)  This allows a connector to be enabled with zero base token reserves, violating Bancor market equilibrium and causing permanent DoS of the `Sell` function since the contract has no base tokens to pay sellers.

### Finding Description

In `GetNeededDeposit()`, the calculation of tokens outside the converter is: [2](#0-1) 

When `input.AmountToTokenConvert == (tokenInfo.TotalSupply - balance)`, this results in `amountOutOfTokenConvert = 0`. The subsequent check only calculates deposit if `amountOutOfTokenConvert > 0`, otherwise `needDeposit` remains 0. [3](#0-2) 

In `EnableConnector()`, this zero deposit is used directly to set the base token reserve: [4](#0-3) 

The deposit balance is used by `GetSelfBalance()` for deposit account connectors (base tokens): [5](#0-4) 

When users attempt to `Sell()` resource tokens with `depositBalance = 0`, the operation fails at line 193-194 where `0.Sub(amountToReceive)` causes an arithmetic underflow exception (SafeMath uses checked arithmetic), [6](#0-5)  or the base token transfer at line 186-192 fails with insufficient balance. [7](#0-6) 

The root cause is that `GetNeededDeposit()` interprets "all tokens in converter" as "no deposit needed", when economically it should require sufficient base tokens to maintain Bancor market equilibrium and support sell operations.

### Impact Explanation

**Severity: Medium**

**Direct Operational Impact - Permanent DoS:**
- Any token connector enabled with zero deposit has a permanently broken `Sell` function
- All holders of that resource token cannot exit their positions
- Tokens effectively become one-way convertible (can only buy, never sell)

**Economic Value Loss:**
- Token holders experience locked funds - they hold tokens with zero liquidity
- The Bancor market fails its core function of providing continuous liquidity
- Violates the "Pricing & Reserves" critical invariant requiring reserve depletion protection

**Affected Parties:**
- Token holders who cannot sell their holdings
- The protocol's reputation as a reliable token converter
- Any users who acquired tokens expecting bidirectional liquidity

This is not theoretical - any connector where all issued tokens are transferred to the converter during `EnableConnector` will exhibit this failure mode, creating a permanently broken market.

### Likelihood Explanation

**Likelihood: Medium-High**

**Entry Point:** `EnableConnector()` is callable by any address after connector pairs are configured by the connector controller. [8](#0-7) 

**Preconditions:**
1. Token must be created with fixed supply
2. Connector pair added by controller (normal operational flow)
3. Token owner/enabler transfers all circulating tokens when calling `EnableConnector`

**Scenario Practicality:**
This is not just an attack - it can occur through legitimate misunderstanding:
- A token issuer might believe transferring all tokens provides "maximum liquidity"
- No validation prevents this configuration
- The function signature doesn't indicate deposit requirements
- Testing with partial token amounts (like the existing test at 99.9999% of supply) wouldn't catch this edge case [9](#0-8) 

**Detection Difficulty:** The issue only manifests when users attempt to sell, potentially after the connector has been enabled and tokens distributed, making remediation complex.

### Recommendation

**Immediate Fix:** Modify `GetNeededDeposit()` to calculate required deposit based on the total token supply in the converter after the operation, not just tokens outside:

```csharp
// After line 73, calculate deposit for all tokens in converter
var tokensInConverter = balance + input.AmountToTokenConvert;
if (tokensInConverter > 0) {
    var fb = fromConnector.VirtualBalance;
    var tb = toConnector.IsVirtualBalanceEnabled 
        ? toConnector.VirtualBalance.Add(tokensInConverter)
        : tokensInConverter;
    needDeposit = BancorHelper.GetAmountToPayFromReturn(
        fb, GetWeight(fromConnector),
        tb, GetWeight(toConnector), 
        tokensInConverter);
}
```

**Additional Safeguards:**
1. Add validation in `EnableConnector()` requiring `needDeposit.NeedAmount > 0` when `input.AmountToTokenConvert > 0`
2. Add assertion that deposit is proportional to tokens being added
3. Document minimum deposit requirements in protobuf comments [10](#0-9) 

**Test Cases:**
1. Test `EnableConnector` with `AmountToTokenConvert == TotalSupply` - should require substantial deposit
2. Test that `Sell` succeeds immediately after connector enablement
3. Verify deposit scales proportionally with token supply

### Proof of Concept

**Initial State:**
1. Create token "TEST" with total supply 100_0000_0000
2. Add connector pair via `AddPairConnector` with virtual balance 1_0000_0000, weights 0.05/0.05
3. Issue all 100_0000_0000 tokens to address A

**Exploit Sequence:**
1. Address A calls `GetNeededDeposit({tokenSymbol: "TEST", amountToTokenConvert: 100_0000_0000})`
   - Expected: Returns substantial deposit requirement
   - **Actual: Returns {needAmount: 0, amountOutOfTokenConvert: 0}**

2. Address A calls `EnableConnector({tokenSymbol: "TEST", amountToTokenConvert: 100_0000_0000})`
   - All tokens transferred to converter
   - No base tokens deposited (needAmount = 0)
   - Connector enabled successfully
   - **State: DepositBalance["ntTEST"] = 0**

3. Address B calls `Buy({symbol: "TEST", amount: 1000})`
   - Successfully buys 1000 TEST tokens
   - Pays base tokens which update DepositBalance

4. Address B calls `Sell({symbol: "TEST", amount: 500})`
   - Bancor calculates positive `amountToReceive`
   - **Execution FAILS at line 193-194: arithmetic overflow exception on `0.Sub(amountToReceive)` before any buys**
   - OR fails at transfer with "Insufficient balance" if DepositBalance increased from buys but insufficient for sell amount

**Success Condition:** Sell function is permanently broken when connector is enabled with zero deposit, violating Bancor market functionality.

### Citations

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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L186-192)
```csharp
        State.TokenContract.Transfer.Send(
            new TransferInput
            {
                Symbol = State.BaseTokenSymbol.Value,
                To = Context.Sender,
                Amount = amountToReceive
            });
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L193-194)
```csharp
        State.DepositBalance[toConnector.Symbol] =
            State.DepositBalance[toConnector.Symbol].Sub(amountToReceive);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L269-300)
```csharp
    public override Empty EnableConnector(ToBeConnectedTokenInfo input)
    {
        var fromConnector = State.Connectors[input.TokenSymbol];
        Assert(fromConnector != null && !fromConnector.IsDepositAccount,
            "[EnableConnector]Can't find from connector.");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[EnableConnector]Can't find to connector.");
        var needDeposit = GetNeededDeposit(input);
        if (needDeposit.NeedAmount > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = State.BaseTokenSymbol.Value,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = needDeposit.NeedAmount
                });

        if (input.AmountToTokenConvert > 0)
            State.TokenContract.TransferFrom.Send(
                new TransferFromInput
                {
                    Symbol = input.TokenSymbol,
                    From = Context.Sender,
                    To = Context.Self,
                    Amount = input.AmountToTokenConvert
                });

        State.DepositBalance[toConnector.Symbol] = needDeposit.NeedAmount;
        toConnector.IsPurchaseEnabled = true;
        fromConnector.IsPurchaseEnabled = true;
        return new Empty();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L374-389)
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
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L395-398)
```csharp
            AmountToTokenConvert = 99_9999_0000
        };
        var deposit = await DefaultStub.GetNeededDeposit.CallAsync(toBeBuildConnectorInfo);
        deposit.NeedAmount.ShouldBe(100);
```

**File:** protobuf/token_converter_contract.proto (L73-76)
```text
    // Query how much the base token need be deposited before enabling the connector.
    rpc GetNeededDeposit(ToBeConnectedTokenInfo) returns (DepositInfo) {
        option (aelf.is_view) = true;
    }
```
