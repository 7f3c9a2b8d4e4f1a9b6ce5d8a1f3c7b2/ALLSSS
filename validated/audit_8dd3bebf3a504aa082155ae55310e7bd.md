# Audit Report

## Title
Missing Input Validation Allows Zero or Negative Lock Periods, Enabling Immediate Token Withdrawal

## Summary
The `CreateScheme()` function in TokenHolderContract lacks validation for the `MinimumLockMinutes` parameter, allowing schemes to be created with zero or negative lock periods. This completely bypasses the token lock mechanism, enabling users to withdraw locked tokens immediately after registration, defeating the core purpose of incentivizing long-term token commitment for profit distribution.

## Finding Description

The TokenHolderContract's `CreateScheme()` function accepts the `MinimumLockMinutes` parameter without any validation and directly stores it in the contract state: [1](#0-0) 

The protobuf schema defines `minimum_lock_minutes` as `int64`, which permits negative values: [2](#0-1) 

The lock period enforcement occurs in the `Withdraw()` function through a timestamp comparison: [3](#0-2) 

The `AddMinutes()` extension method performs simple arithmetic without input validation, directly adding the minutes value (converted to seconds) to the timestamp: [4](#0-3) 

**Root Cause Analysis:**

When `MinimumLockMinutes = 0`, the expression returns the original lock timestamp, making the check `LockTimestamp < CurrentBlockTime` true in the very next block, allowing immediate withdrawal.

When `MinimumLockMinutes` is negative (e.g., -100), the method returns a timestamp in the past, making the unlock condition immediately satisfied.

No validation exists to prevent scheme creators from setting exploitable lock periods.

## Impact Explanation

**Direct Security Impact:**
- Complete bypass of the token lock mechanism that is fundamental to the TokenHolder contract's security model
- Users can register for profit distribution, claim benefits, and immediately withdraw without any time commitment
- Economic incentive structures relying on locked token commitments are undermined

**Affected Systems:**
- All profit distribution schemes created via TokenHolder that expect long-term token commitment
- Side chain consensus dividend pools in AEDPoS that compute lock periods dynamically: [5](#0-4) 

- Any protocol relying on TokenHolder's time-lock guarantees for economic security

**Production Risk:**
The AEDPoS contract computes `MinimumLockMinutes = periodSeconds.Div(60)`. If `periodSeconds < 60`, integer division produces zero, creating an exploitable scheme in production systems.

**Severity Justification (High):**
This represents a critical failure of a core security mechanism. The ability to bypass lock periods enables gaming of dividend systems, reward misallocation, and breaks the fundamental economic model of requiring long-term token commitment for profit participation.

## Likelihood Explanation

**Attacker Capabilities:**
- Any user can call the public `CreateScheme()` method to create their own profit distribution scheme
- No special permissions or privileges required
- Attack requires a single transaction with a crafted parameter value

**Attack Complexity:**
- Trivial: Set `MinimumLockMinutes = 0` or any negative value in the CreateScheme input
- No complex state manipulation required
- No timing requirements or race conditions
- Immediately exploitable upon scheme creation

**Real-World Probability:**
- High likelihood through either malicious configuration or accidental misconfiguration
- The existing test suite inadvertently demonstrates this vulnerability by successfully withdrawing from a scheme with no lock period specified: [6](#0-5) 

- Production systems computing lock periods dynamically risk creating zero-period schemes through integer arithmetic

**Economic Rationality:**
There is zero cost for an attacker to set an exploitable parameter value, making exploitation economically rational for anyone seeking to game profit distribution systems.

## Recommendation

Add input validation to the `CreateScheme()` function to enforce a minimum lock period. The fix should:

1. Add validation in `CreateScheme()` to reject zero or negative `MinimumLockMinutes`:
```csharp
Assert(input.MinimumLockMinutes > 0, "Minimum lock period must be positive.");
```

2. Consider adding a reasonable minimum threshold (e.g., 1 day = 1440 minutes) to prevent abuse through very short lock periods.

3. In AEDPoS side chain initialization, ensure `periodSeconds` is always >= 60 seconds, or explicitly validate the computed `MinimumLockMinutes` before calling `CreateScheme()`.

## Proof of Concept

The existing test suite demonstrates this vulnerability. The `Withdraw_Test()` creates a scheme without specifying `MinimumLockMinutes` (defaulting to 0), registers for profits, and immediately withdraws without any time delay. The test passes, confirming immediate withdrawal is possible: [6](#0-5) 

To explicitly exploit this:
1. Call `CreateScheme` with `MinimumLockMinutes = 0`
2. Call `RegisterForProfits` to lock tokens and become a beneficiary
3. Immediately call `Withdraw` in the next block
4. Tokens are unlocked without any waiting period

## Notes

This vulnerability affects the core economic security model of the TokenHolder contract. The lock period is not an optional feature but a fundamental mechanism to ensure long-term commitment in exchange for profit distribution rights. The absence of input validation creates a critical bypass that undermines the entire system's incentive structure.

The production deployment risk in AEDPoS side chains is particularly concerning, as integer division arithmetic could inadvertently create exploitable schemes without malicious intent.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
```

**File:** protobuf/token_holder_contract.proto (L67-67)
```text
    int64 minimum_lock_minutes = 2;
```

**File:** src/AElf.CSharp.Core/Extension/TimestampExtensions.cs (L39-42)
```csharp
    public static Timestamp AddMinutes(this Timestamp timestamp, long minutes)
    {
        return timestamp + new Duration { Seconds = minutes.Mul(60) };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SideChainDividendsPool.cs (L28-32)
```csharp
        State.TokenHolderContract.CreateScheme.Send(new CreateTokenHolderProfitSchemeInput
        {
            Symbol = AEDPoSContractConstants.SideChainShareProfitsTokenSymbol,
            MinimumLockMinutes = periodSeconds.Div(60)
        });
```

**File:** test/AElf.Contracts.TokenHolder.Tests/TokenHolderTests.cs (L434-459)
```csharp
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
