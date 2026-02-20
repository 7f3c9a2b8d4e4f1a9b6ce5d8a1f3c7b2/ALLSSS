# Audit Report

## Title
Integer Overflow in Withdraw Function Causes Permanent Token Lock Denial of Service

## Summary
The `Withdraw` function in TokenHolderContract contains a critical vulnerability where unvalidated `MinimumLockMinutes` values trigger arithmetic overflow exceptions, permanently preventing users from withdrawing locked tokens. Any user who registers for profits under schemes with extreme lock durations will experience complete and irreversible fund loss.

## Finding Description

The TokenHolderContract allows permissionless scheme creation without validating the `MinimumLockMinutes` parameter. The `CreateScheme` function directly stores user-provided values into contract state without bounds checking: [1](#0-0) 

When users lock tokens via `RegisterForProfits`, they can specify any scheme manager address, including malicious schemes: [2](#0-1) 

The withdrawal mechanism fails when the overflow-vulnerable timestamp comparison executes: [3](#0-2) 

The `AddMinutes` extension method converts minutes to seconds by multiplying by 60: [4](#0-3) 

The SafeMath `Mul` implementation uses C# checked arithmetic that throws `OverflowException`: [5](#0-4) 

**Attack Execution:**
1. Attacker calls `CreateScheme` with `MinimumLockMinutes = 9223372036854775807` (Int64.MaxValue)
2. Victim calls `RegisterForProfits` specifying the attacker's address as scheme manager
3. Tokens are locked via MultiToken contract with no immediate indication of vulnerability
4. When victim attempts withdrawal, calculation `9223372036854775807 × 60 = 553402322211286548420` exceeds Int64.MaxValue
5. `OverflowException` thrown, transaction reverts permanently
6. No alternative unlock mechanism exists - tokens are irrecoverably trapped

**Security Guarantees Broken:**
- Users cannot reclaim their legitimately locked tokens after any time period
- The core invariant that "locked tokens become withdrawable after MinimumLockMinutes" is violated
- Token supply becomes permanently imbalanced as locked funds are inaccessible

**Contrast with Election Contract:**

The Election contract properly implements min/max validation to prevent such scenarios: [6](#0-5) 

The protobuf schema defines `minimum_lock_minutes` as `int64` without protocol-level constraints: [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

**Direct Financial Impact:**
- 100% permanent loss of all tokens locked under affected schemes
- No recovery mechanism exists in the contract - the only unlock path is through `Withdraw`, which will always fail [8](#0-7) 

**Affected Users:**
- Any user calling `RegisterForProfits` for schemes with overflow-inducing `MinimumLockMinutes` values
- Both malicious honeypot schemes and accidental misconfigurations cause identical permanent lockup
- User-specified lock amounts in `RegisterForProfits` can represent substantial token holdings

**Systemic Impact:**
- Breaks fundamental token holder profit distribution guarantees
- Creates permanent supply imbalance (locked tokens become ghost balance)
- Undermines trust in TokenHolder contract mechanisms

The existing test suite contains no boundary value validation, leaving this vulnerability undetected: [9](#0-8) 

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- No privileged roles required - `CreateScheme` is publicly callable by any address
- Single transaction to create malicious scheme
- No complex setup, timing requirements, or chain state manipulation needed

**Exploitation Feasibility:**
The permissionless nature of scheme creation enables trivial exploitation: [10](#0-9) 

**Real-World Scenarios:**

*Malicious Attack:*
- Attacker creates honeypot scheme advertising attractive yields
- Victims lock tokens expecting profit distributions  
- Withdrawal attempts fail deterministically with overflow exception
- Irreversible fund trap created with minimal effort

*Accidental Misconfiguration:*
- Developer sets `Int64.MaxValue` intending "effectively infinite" lock period
- Tests with small values don't expose overflow condition
- Production deployment breaks all withdrawals for legitimate users

**Detection Difficulty:**
Victims cannot identify the vulnerability before locking tokens - the overflow only manifests during withdrawal attempts when funds are already trapped.

## Recommendation

Implement input validation in `CreateScheme` to enforce maximum bounds on `MinimumLockMinutes`:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation to prevent overflow in AddMinutes(MinimumLockMinutes)
    const long maxSafeMinutes = long.MaxValue / 60; // 153722867280912930
    Assert(input.MinimumLockMinutes >= 0, "MinimumLockMinutes cannot be negative.");
    Assert(input.MinimumLockMinutes <= maxSafeMinutes, 
        $"MinimumLockMinutes exceeds maximum safe value of {maxSafeMinutes}.");
    
    // ... rest of function
}
```

Alternatively, follow the Election contract pattern with explicit min/max bounds: [6](#0-5) 

## Proof of Concept

```csharp
[Fact]
public async Task Withdraw_WithMaxLockMinutes_CausesOverflow()
{
    // Create scheme with Int64.MaxValue lock minutes
    await TokenHolderContractStub.CreateScheme.SendAsync(
        new CreateTokenHolderProfitSchemeInput
        {
            Symbol = "ELF",
            MinimumLockMinutes = long.MaxValue // 9223372036854775807
        });
    
    // User locks tokens
    await TokenHolderContractStub.RegisterForProfits.SendAsync(
        new RegisterForProfitsInput
        {
            Amount = 1000L,
            SchemeManager = Starter
        });
    
    // Attempt withdrawal - will throw OverflowException
    var withdrawResult = await TokenHolderContractStub.Withdraw
        .SendWithExceptionAsync(Starter);
    
    // Verify withdrawal fails with overflow
    withdrawResult.TransactionResult.Status
        .ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.TransactionResult.Error
        .ShouldContain("Arithmetic operation resulted in an overflow");
}
```

## Notes

This vulnerability represents a complete breakdown of the TokenHolder withdrawal mechanism. The attack requires no privileges and creates permanent fund loss with deterministic reliability. The contrast with the Election contract's proper validation demonstrates this is a correctable design oversight rather than an unavoidable platform limitation. Immediate remediation is critical to prevent exploitation.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-25)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L149-167)
```csharp
    public override Empty RegisterForProfits(RegisterForProfitsInput input)
    {
        Assert(State.LockIds[input.SchemeManager][Context.Sender] == null, "Already registered.");
        var scheme = GetValidScheme(input.SchemeManager);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = Context.GenerateId(Context.Self,
            ByteArrayHelper.ConcatArrays(input.SchemeManager.ToByteArray(), Context.Sender.ToByteArray()));
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
        State.LockIds[input.SchemeManager][Context.Sender] = lockId;
        State.LockTimestamp[lockId] = Context.CurrentBlockTime;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L230-236)
```csharp
        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });
```

**File:** src/AElf.CSharp.Core/Extension/TimestampExtensions.cs (L39-42)
```csharp
    public static Timestamp AddMinutes(this Timestamp timestamp, long minutes)
    {
        return timestamp + new Duration { Seconds = minutes.Mul(60) };
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L79-85)
```csharp
    public static long Mul(this long a, long b)
    {
        checked
        {
            return a * b;
        }
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L320-326)
```csharp
    private void AssertValidLockSeconds(long lockSeconds)
    {
        Assert(lockSeconds >= State.MinimumLockTime.Value,
            $"Invalid lock time. At least {State.MinimumLockTime.Value.Div(60).Div(60).Div(24)} days");
        Assert(lockSeconds <= State.MaximumLockTime.Value,
            $"Invalid lock time. At most {State.MaximumLockTime.Value.Div(60).Div(60).Div(24)} days");
    }
```

**File:** protobuf/token_holder_contract.proto (L63-70)
```text
message CreateTokenHolderProfitSchemeInput {
    // The token symbol.
    string symbol = 1;
    // Minimum lock time for holding token.
    int64 minimum_lock_minutes = 2;
    // Threshold setting for releasing dividends.
    map<string, int64> auto_distribute_threshold = 3;
}
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L433-459)
```csharp
    [Fact]
    public async Task Withdraw_Test()
    {
        var amount = 1000L;
        var nativeTokenSymbol = TokenHolderContractTestConstants.NativeTokenSymbol;
        await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = nativeTokenSymbol
        });
        await TokenHolderContractStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
        {
            Amount = amount,
            SchemeManager = Starter
        });
        var beforeUnLockBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Symbol = nativeTokenSymbol,
            Owner = Starter
        })).Balance;
        await TokenHolderContractStub.Withdraw.SendAsync(Starter);
        var afterUnLockBalance = (await TokenContractStub.GetBalance.CallAsync(new GetBalanceInput
        {
            Symbol = nativeTokenSymbol,
            Owner = Starter
        })).Balance;
        afterUnLockBalance.ShouldBe(beforeUnLockBalance.Add(amount));
    }
```
