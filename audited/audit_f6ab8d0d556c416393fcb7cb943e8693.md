### Title
Duplicate Token Symbols in SetMethodFee Cause Users to Pay Inflated Transaction Fees

### Summary
The `SetMethodFee()` function across all ACS1-implementing contracts does not validate for duplicate token symbols in the `input.Fees` collection. When duplicate symbols exist, the fee charging logic in `GetBaseFeeDictionary` groups by symbol and sums all amounts, causing users to pay the cumulative total rather than a single fee. This can result in users paying 2x, 3x, or more in transaction fees than intended.

### Finding Description

The vulnerability exists in the `SetMethodFee()` implementation where governance can set method fees with duplicate token symbols without validation. [1](#0-0) 

The function only validates each fee entry individually via `AssertValidToken` but never checks if the same symbol appears multiple times in `input.Fees`. The raw `MethodFees` object is stored directly in state without deduplication. [2](#0-1) 

When fees are charged, the `GetBaseFeeDictionary` method processes the stored `MethodFees` by grouping entries by symbol and summing their `BasicFee` amounts: [3](#0-2) 

This means if `input.Fees` contains `{Symbol: "ELF", BasicFee: 1000}` twice, the dictionary will contain `{"ELF": 2000}`, and users will be charged 2000 instead of 1000.

An existing test case explicitly confirms this behavior: [4](#0-3) 

The test demonstrates that when the same `NativeTokenSymbol` appears twice with `BasicFee = 1000` each, the user is charged `basicMethodFee.Add(basicMethodFee)` (2000 total).

All other ACS1 implementations follow the identical pattern with no duplicate validation: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Direct Financial Loss**: Users pay inflated transaction fees proportional to the number of duplicate symbols. If a token appears N times, users pay N times the intended fee.

**Affected Parties**: All users calling methods with fees configured through duplicate symbols. This affects every contract implementing ACS1 (Parliament, Association, Treasury, Economic, Election, Token, etc.).

**Quantified Impact**: If governance sets fees as `[{ELF: 1000}, {ELF: 1000}, {ELF: 500}]`, users expect to pay 1000 ELF but actually pay 2500 ELF - a 150% overcharge.

**Severity Justification (Medium)**: 
- Requires governance action (not directly exploitable by arbitrary users)
- Causes direct fund loss to innocent users
- Could occur through human error in governance proposals
- No upper bound on overcharge multiplier

### Likelihood Explanation

**Attacker Capabilities**: An attacker needs the ability to propose and pass governance proposals through Parliament (or other governance contracts). Alternatively, this could occur through honest human error when configuring fees.

**Attack Complexity**: Low - simply include duplicate symbols in a `MethodFees` proposal:
```
MethodFees {
  MethodName = "Transfer",
  Fees = [
    {Symbol: "ELF", BasicFee: 1000},
    {Symbol: "ELF", BasicFee: 1000}  // Duplicate
  ]
}
```

**Feasibility Conditions**: 
1. Governance proposal creation and voting access
2. No automated validation tools to detect duplicates
3. Manual review may miss subtle duplicates in large fee configurations

**Detection Constraints**: The duplicate symbols are stored in contract state and visible on-chain, but there's no mechanism to reject or alert on duplicates. The test case confirms this is "working as coded" rather than a known issue.

**Probability**: Medium - while governance is typically careful, complex fee configurations across multiple tokens make accidental duplicates realistic. Malicious proposals could intentionally hide duplicates among many legitimate fee entries.

### Recommendation

Add duplicate symbol validation in `SetMethodFee()` implementations across all ACS1 contracts:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    var symbolSet = new HashSet<string>();
    foreach (var methodFee in input.Fees)
    {
        AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        Assert(symbolSet.Add(methodFee.Symbol), 
            $"Duplicate token symbol '{methodFee.Symbol}' in method fees.");
    }
    
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to set method fee.");
    State.TransactionFees[input.MethodName] = input;
    
    return new Empty();
}
```

**Invariant to enforce**: Each token symbol must appear at most once in the `Fees` collection for any given method.

**Test cases to add**:
1. Reject `SetMethodFee` when duplicate symbols exist
2. Verify error message clearly identifies the duplicate symbol
3. Test with multiple duplicates (A, A, B, B)
4. Test case-sensitivity if applicable

Apply this fix to all contracts implementing ACS1: AEDPoS, Parliament, Association, Referendum, Genesis, Treasury, Economic, Election, Token, Vote, TokenConverter, TokenHolder, CrossChain, Configuration, and Profit contracts.

### Proof of Concept

**Initial State**:
- Parliament governance has authority over method fee controller
- Token "ELF" exists and is available for method fees
- User has balance of 10000 ELF

**Exploitation Steps**:

1. Parliament creates proposal to set method fees:
```
Proposal: SetMethodFee({
  MethodName: "Transfer",
  Fees: [
    {Symbol: "ELF", BasicFee: 1000},
    {Symbol: "ELF", BasicFee: 1000}
  ]
})
```

2. Proposal passes through governance voting and is executed

3. User calls `Transfer` method expecting to pay 1000 ELF fee

4. `ChargeTransactionFees` is called by pre-execution plugin

5. `GetBaseFeeDictionary` processes the fees: groups by "ELF" and sums to 2000

6. User's balance is reduced by 2000 ELF instead of expected 1000 ELF

**Expected Result**: User pays 1000 ELF (or proposal is rejected due to duplicate)

**Actual Result**: User pays 2000 ELF (100% overcharge)

**Success Condition**: User balance after transaction is 8000 ELF (10000 - 2000) instead of 9000 ELF (10000 - 1000), confirmed by the existing test case at line 103. [7](#0-6)

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L13-23)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);

        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS1_TransactionFeeProvider.cs (L90-96)
```csharp
    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        EnsureTokenContractAddressSet();
        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fees.cs (L322-327)
```csharp
    private Dictionary<string, long> GetBaseFeeDictionary(MethodFees methodFees)
    {
        return methodFees.Fees.Where(f => !string.IsNullOrEmpty(f.Symbol))
            .GroupBy(f => f.Symbol, f => f.BasicFee)
            .ToDictionary(g => g.Key, g => g.Sum());
    }
```

**File:** test/AElf.Kernel.SmartContract.ExecutionPluginForMethodFee.Tests/ExecutePluginTransactionDirectlyTest.cs (L66-104)
```csharp
    public async Task Set_Repeat_Token_Test()
    {
        await IssueTokenToDefaultSenderAsync(NativeTokenSymbol, 100000_00000000);
        await SetPrimaryTokenSymbolAsync();
        var address = DefaultSender;
        var methodName = nameof(TokenContractContainer.TokenContractStub.Transfer);
        var basicMethodFee = 1000;
        var methodFee = new MethodFees
        {
            MethodName = methodName,
            Fees =
            {
                new MethodFee
                {
                    Symbol = NativeTokenSymbol,
                    BasicFee = basicMethodFee
                },
                new MethodFee
                {
                    Symbol = NativeTokenSymbol,
                    BasicFee = basicMethodFee
                }
            }
        };
        var sizeFee = 0;
        await TokenContractImplStub.SetMethodFee.SendAsync(methodFee);
        var beforeChargeBalance = await GetBalanceAsync(address, NativeTokenSymbol);
        var chargeTransactionFeesInput = new ChargeTransactionFeesInput
        {
            MethodName = methodName,
            ContractAddress = TokenContractAddress,
            TransactionSizeFee = sizeFee,
        };

        var chargeFeeRet = await TokenContractStub.ChargeTransactionFees.SendAsync(chargeTransactionFeesInput);
        chargeFeeRet.Output.Success.ShouldBeTrue();
        var afterChargeBalance = await GetBalanceAsync(address, NativeTokenSymbol);
        beforeChargeBalance.Sub(afterChargeBalance).ShouldBe(basicMethodFee.Add(basicMethodFee));
    }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-18)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
        State.TransactionFees[input.MethodName] = input;

        return new Empty();
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-21)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
        return new Empty();
```
