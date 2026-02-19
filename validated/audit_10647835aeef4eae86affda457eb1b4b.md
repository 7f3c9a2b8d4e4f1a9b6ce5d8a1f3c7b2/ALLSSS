# Audit Report

## Title
Fee Tokens Permanently Locked in TokenConverter When Base Token Not Available for Method Fees

## Summary
The TokenConverter contract's `HandleFee()` function transfers half the fee (donateFee) to itself before calling Treasury's `Donate()` method. However, when the base token is not burnable (`IsBurnable = false`), Treasury's `Donate()` returns early with success without transferring the tokens, causing permanent fund loss in the TokenConverter contract with no recovery mechanism.

## Finding Description

The vulnerability occurs in the fee handling flow between TokenConverter and Treasury contracts:

In TokenConverter's `HandleFee()` method, the function first transfers donateFee from the user to the TokenConverter contract itself, then approves the Treasury to spend it, and finally calls `Donate()` via an inline transaction. [1](#0-0) 

The critical issue lies in Treasury's `Donate()` implementation, which contains an early return path when `IsTokenAvailableForMethodFee` returns false. [2](#0-1) 

The `IsTokenAvailableForMethodFee` check specifically verifies if the token has `IsBurnable = true`. [3](#0-2) 

When this check fails, `Donate()` returns `Empty` successfully without executing the subsequent `TransferFrom` call that would move tokens from TokenConverter to Treasury. [4](#0-3) 

Since inline transactions in AElf only rollback on exceptions (not on successful returns), the tokens transferred earlier remain in the TokenConverter contract permanently.

The root cause is that TokenConverter's `Initialize()` function sets the base token without validating that it has `IsBurnable = true`. [5](#0-4) 

Furthermore, no recovery or withdrawal function exists in the TokenConverter contract to reclaim these locked tokens. The contract only has `Buy`, `Sell`, and administrative functions, none of which can extract stuck tokens.

## Impact Explanation

**High Severity** - Permanent, unrecoverable fund loss affecting all users:

1. **Direct Financial Loss:** Every `Buy()` or `Sell()` transaction calculates a fee where half is designated as donateFee. When the base token is non-burnable, this portion accumulates permanently in the TokenConverter contract with each transaction.

2. **No Recovery Mechanism:** The TokenConverter contract lacks any withdrawal, recovery, or claim function. Tokens transferred to the contract cannot be extracted except through the specific Buy/Sell mechanics which operate on different token pools.

3. **Cumulative Impact:** The loss compounds with each swap transaction, creating an ever-growing sink of locked funds.

4. **Protocol Treasury Loss:** The intended donations to the Treasury never arrive, breaking the protocol's economic model for fee distribution.

5. **User Detriment:** Users pay full fees but only receive partial benefit (the burn portion works, the donation portion is lost).

## Likelihood Explanation

**Low-Medium Likelihood:**

**Preconditions:**
- TokenConverter must be initialized with a base token where `IsBurnable = false`
- This configuration becomes permanent as the `IsBurnable` property cannot be changed after token creation

**Feasibility:**
- The standard native token (ELF) has `IsBurnable = true` by default, making mainchain deployments safe
- However, custom side-chain deployments or test environments may use different tokens
- No validation prevents this misconfiguration during initialization

**Triggering:**
- Once misconfigured, the vulnerability triggers automatically on every fee-bearing Buy/Sell transaction
- No special privileges or attack coordination required
- The issue persists for the lifetime of the contract deployment

**Probability Assessment:**
Low-Medium because while standard deployments are secure, the lack of validation creates operational risk during:
- Custom side-chain deployments with non-standard tokens
- Contract migrations or upgrades with parameter changes
- Testing environments that transition to production

## Recommendation

Add validation in the `Initialize()` method to verify the base token is burnable:

```csharp
public override Empty Initialize(InitializeInput input)
{
    Assert(IsValidBaseSymbol(input.BaseTokenSymbol), $"Base token symbol is invalid. {input.BaseTokenSymbol}");
    Assert(State.TokenContract.Value == null, "Already initialized.");
    State.TokenContract.Value =
        Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
    
    var baseSymbol = !string.IsNullOrEmpty(input.BaseTokenSymbol)
        ? input.BaseTokenSymbol
        : Context.Variables.NativeSymbol;
    
    // ADD THIS VALIDATION
    var isTokenBurnable = State.TokenContract.IsTokenAvailableForMethodFee.Call(
        new StringValue { Value = baseSymbol }).Value;
    Assert(isTokenBurnable, 
        "Base token must be burnable (IsBurnable = true) to support fee donation mechanism.");
    
    State.BaseTokenSymbol.Value = baseSymbol;
    // ... rest of initialization
}
```

Additionally, consider adding an emergency recovery function controlled by the connector controller to extract stuck tokens if this issue has already occurred in deployed instances.

## Proof of Concept

```csharp
[Fact]
public async Task FeeLockVulnerability_NonBurnableBaseToken_Test()
{
    // Setup: Create a non-burnable token
    await ExecuteProposalForParliamentTransaction(TokenContractAddress, 
        nameof(TokenContractStub.Create),
        new CreateInput
        {
            Symbol = "NBELF",
            Decimals = 2,
            IsBurnable = false,  // Non-burnable token
            TokenName = "non-burnable token",
            TotalSupply = 1000_000_000L,
            Issuer = DefaultSender,
            Owner = DefaultSender
        });
    
    // Issue tokens to test user
    await TokenContractStub.Issue.SendAsync(new IssueInput
    {
        Symbol = "NBELF",
        Amount = 1_000_000L,
        To = DefaultSender
    });
    
    // Initialize TokenConverter with non-burnable base token
    await InitializeTreasuryContractAsync();
    await DefaultStub.Initialize.SendAsync(new InitializeInput
    {
        BaseTokenSymbol = "NBELF",
        FeeRate = "0.005",
        Connectors = { /* connector config */ }
    });
    
    // Get initial balance of TokenConverter
    var initialConverterBalance = await GetBalanceAsync("NBELF", TokenConverterContractAddress);
    
    // Execute a Buy transaction that triggers HandleFee
    await TokenContractStub.Approve.SendAsync(new ApproveInput
    {
        Symbol = "NBELF",
        Spender = TokenConverterContractAddress,
        Amount = 10_000L
    });
    
    await DefaultStub.Buy.SendAsync(new BuyInput
    {
        Symbol = "SOMETOKEN",
        Amount = 100L,
        PayLimit = 10_000L
    });
    
    // Verify: Tokens are locked in TokenConverter
    var finalConverterBalance = await GetBalanceAsync("NBELF", TokenConverterContractAddress);
    var lockedAmount = finalConverterBalance - initialConverterBalance;
    
    // The donateFee should be stuck in TokenConverter
    lockedAmount.ShouldBeGreaterThan(0);
    
    // Verify: No way to recover these tokens (no withdrawal function exists)
    // Verify: Treasury didn't receive the donation
    var treasuryBalance = await GetBalanceAsync("NBELF", TreasuryContractAddress);
    treasuryBalance.ShouldBe(0);
}
```

## Notes

This vulnerability demonstrates a critical integration issue between TokenConverter and Treasury contracts where the lack of input validation in TokenConverter's initialization creates an attack surface for permanent fund loss. The issue is particularly insidious because:

1. It requires misconfiguration during deployment (not a runtime attack)
2. Once deployed, it cannot be fixed without contract upgrade
3. The loss accumulates silently with every transaction
4. Standard mainchain deployments are safe, but side-chain deployments are at risk

The fix is straightforward - add validation during initialization to prevent non-burnable tokens from being used as the base token.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L27-55)
```csharp
    public override Empty Initialize(InitializeInput input)
    {
        Assert(IsValidBaseSymbol(input.BaseTokenSymbol), $"Base token symbol is invalid. {input.BaseTokenSymbol}");
        Assert(State.TokenContract.Value == null, "Already initialized.");
        State.TokenContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);
        State.BaseTokenSymbol.Value = !string.IsNullOrEmpty(input.BaseTokenSymbol)
            ? input.BaseTokenSymbol
            : Context.Variables.NativeSymbol;
        var feeRate = AssertedDecimal(input.FeeRate);
        Assert(IsBetweenZeroAndOne(feeRate), "Fee rate has to be a decimal between 0 and 1.");
        State.FeeRate.Value = feeRate.ToString(CultureInfo.InvariantCulture);
        foreach (var connector in input.Connectors)
        {
            if (connector.IsDepositAccount)
            {
                Assert(!string.IsNullOrEmpty(connector.Symbol), "Invalid connector symbol.");
                AssertValidConnectorWeight(connector);
            }
            else
            {
                Assert(IsValidSymbol(connector.Symbol), "Invalid symbol.");
                AssertValidConnectorWeight(connector);
            }

            State.Connectors[connector.Symbol] = connector;
        }

        return new Empty();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L214-241)
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
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L181-182)
```csharp
        if (!State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = input.Symbol }).Value)
            return new Empty();
```

**File:** contract/AElf.Contracts.Treasury/TreasuryContract.cs (L194-202)
```csharp
        if (Context.Sender != Context.Self)
            State.TokenContract.TransferFrom.Send(new TransferFromInput
            {
                From = Context.Sender,
                To = Context.Self,
                Symbol = input.Symbol,
                Amount = input.Amount,
                Memo = "Donate to treasury."
            });
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Views.cs (L252-257)
```csharp
    private bool IsTokenAvailableForMethodFee(string symbol)
    {
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null) throw new AssertionException("Token is not found.");
        return tokenInfo.IsBurnable;
    }
```
