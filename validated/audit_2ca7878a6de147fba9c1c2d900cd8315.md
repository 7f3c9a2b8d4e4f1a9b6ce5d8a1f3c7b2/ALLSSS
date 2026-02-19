# Audit Report

## Title
Missing Input Validation Allows Zero or Negative Lock Periods, Enabling Immediate Token Withdrawal

## Summary
The `CreateScheme()` function in TokenHolderContract lacks validation for the `MinimumLockMinutes` parameter, allowing schemes to be created with zero or negative lock periods. This completely bypasses the token lock mechanism, enabling users to withdraw locked tokens immediately after registration, defeating the core purpose of incentivizing long-term token commitment for profit distribution.

## Finding Description

The TokenHolderContract's `CreateScheme()` function accepts the `MinimumLockMinutes` parameter without any validation and directly stores it in the contract state. [1](#0-0) 

The protobuf schema defines `minimum_lock_minutes` as `int64`, which permits negative values: [2](#0-1) 

The lock period enforcement occurs in the `Withdraw()` function through a timestamp comparison that checks if the lock timestamp plus the minimum lock minutes is less than the current block time: [3](#0-2) 

The `AddMinutes()` extension method performs simple arithmetic without input validation, directly adding the minutes value (converted to seconds) to the timestamp: [4](#0-3) 

**Root Cause Analysis:**
When `MinimumLockMinutes = 0`, the expression `State.LockTimestamp[lockId].AddMinutes(0)` returns the original lock timestamp, making the check `LockTimestamp < CurrentBlockTime` true in the very next block, allowing withdrawal immediately.

When `MinimumLockMinutes` is negative (e.g., -100), `State.LockTimestamp[lockId].AddMinutes(-100)` returns a timestamp 100 minutes in the past, making the unlock condition immediately satisfied and allowing instant withdrawal.

No validation exists to prevent scheme creators from setting exploitable lock periods.

## Impact Explanation

**Direct Security Impact:**
- Complete bypass of the token lock mechanism that is fundamental to the TokenHolder contract's security model
- Users can register for profit distribution, claim benefits, and immediately withdraw without any time commitment
- Economic incentive structures relying on locked token commitments are undermined

**Affected Systems:**
- All profit distribution schemes created via TokenHolder that expect long-term token commitment
- Side chain consensus dividend pools in AEDPoS that compute lock periods dynamically [5](#0-4) 
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
- The existing test suite inadvertently demonstrates this vulnerability by successfully withdrawing from a scheme with no lock period specified [6](#0-5) 
- Production systems computing lock periods dynamically risk creating zero-period schemes through integer arithmetic

**Economic Rationality:**
There is zero cost for an attacker to set an exploitable parameter value, making exploitation economically rational for anyone seeking to game profit distribution systems.

## Recommendation

Add validation in the `CreateScheme()` function to ensure `MinimumLockMinutes` is strictly positive:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    Assert(input.MinimumLockMinutes > 0, "Minimum lock minutes must be positive.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
    {
        Manager = Context.Sender,
        IsReleaseAllBalanceEveryTimeByDefault = true,
        CanRemoveBeneficiaryDirectly = true
    });

    State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
    {
        Symbol = input.Symbol,
        MinimumLockMinutes = input.MinimumLockMinutes,
        AutoDistributeThreshold = { input.AutoDistributeThreshold }
    };

    return new Empty();
}
```

Additionally, audit all callsites that compute `MinimumLockMinutes` dynamically to ensure they never produce zero or negative values.

## Proof of Concept

The existing test suite demonstrates this vulnerability. The `Withdraw_Test` creates a scheme without specifying `MinimumLockMinutes` (defaulting to 0), registers for profits, and immediately withdraws successfully: [6](#0-5) 

The test passes, proving that tokens can be withdrawn immediately when `MinimumLockMinutes` is zero, completely bypassing the intended lock mechanism.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
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

        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L211-245)
```csharp
    public override Empty Withdraw(Address input)
    {
        var scheme = GetValidScheme(input);
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        var lockId = State.LockIds[input][Context.Sender];
        Assert(lockId != null, "Sender didn't register for profits.");
        var amount = State.TokenContract.GetLockedAmount.Call(new GetLockedAmountInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Symbol = scheme.Symbol
        }).Amount;

        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");

        State.TokenContract.Unlock.Send(new UnlockInput
        {
            Address = Context.Sender,
            LockId = lockId,
            Amount = amount,
            Symbol = scheme.Symbol
        });

        State.LockIds[input].Remove(Context.Sender);
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = Context.Sender
        });
        return new Empty();
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
