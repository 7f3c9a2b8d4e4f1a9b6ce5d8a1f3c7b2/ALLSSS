# Audit Report

## Title
Integer Overflow in Withdraw Function Causes Permanent Token Lock Denial of Service

## Summary
The `Withdraw` function in TokenHolderContract lacks input validation on `MinimumLockMinutes` values during scheme creation, allowing attackers to create profit schemes with extreme lock durations that trigger arithmetic overflow exceptions during withdrawal attempts. This permanently prevents users from withdrawing their locked tokens, resulting in complete fund loss for all scheme participants.

## Finding Description

The vulnerability exists across two critical locations in the TokenHolderContract:

**Missing Input Validation on Scheme Creation:**

The `CreateScheme` function is permissionless and accepts `MinimumLockMinutes` without any bounds checking, directly storing the unvalidated value into contract state [1](#0-0) 

**Overflow-Vulnerable Withdrawal Check:**

The `Withdraw` function performs a timestamp comparison that triggers an arithmetic overflow when `MinimumLockMinutes` contains extreme values [2](#0-1) 

**Root Cause Chain:**

The `AddMinutes` extension method multiplies the minutes parameter by 60 using the `Mul` SafeMath function to convert to seconds [3](#0-2) 

The `Mul` function uses C# checked arithmetic blocks that throw `OverflowException` when multiplication exceeds `Int64.MaxValue` [4](#0-3) 

**Attack Execution Flow:**

1. Attacker creates a scheme with `MinimumLockMinutes = Int64.MaxValue` (no authorization required)
2. Victims call `RegisterForProfits`, locking their tokens via the MultiToken contract [5](#0-4) 
3. When victims attempt withdrawal, the calculation `Int64.MaxValue * 60` exceeds the maximum int64 value (9,223,372,036,854,775,807)
4. The `Mul` operation throws `OverflowException`, causing transaction revert
5. Tokens remain locked with no alternative recovery mechanism

**Contrast with Election Contract:**

Unlike TokenHolderContract, the Election contract properly validates lock times with both minimum and maximum bounds to prevent such overflow scenarios [6](#0-5) 

The protobuf schema defines `minimum_lock_minutes` as `int64`, explicitly allowing values up to `Int64.MaxValue` without protocol-level constraints [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

**Direct Financial Impact:**
- 100% permanent loss of access to locked tokens for all users registered under malicious schemes
- No emergency withdrawal or admin recovery mechanism exists in the contract
- The locked amount is user-specified in `RegisterForProfits` and can represent substantial holdings

**Affected Users:**
- Any user who calls `RegisterForProfits` for schemes configured with overflow-inducing `MinimumLockMinutes` values
- Both maliciously created schemes and accidentally misconfigured legitimate schemes cause identical fund lockup

**Systemic Impact:**
- Breaks the fundamental guarantee that users can reclaim their tokens after the lock period
- Undermines trust in TokenHolder profit distribution mechanisms
- Creates permanent imbalance in token supply (locked tokens become inaccessible forever)

The vulnerability represents a complete availability failure for the withdrawal function, which is classified as HIGH severity under standard smart contract security frameworks when it results in permanent fund loss.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- No privileged roles required - `CreateScheme` is publicly callable by any address
- Single transaction to create malicious scheme with `MinimumLockMinutes = Int64.MaxValue`
- No complex timing requirements, race conditions, or multi-step setup needed

**Exploitation Scenarios:**

*Malicious Attack (HIGH probability):*
- Attacker creates honeypot scheme advertising attractive profit distributions
- Markets the scheme through social channels to attract deposits
- Victims lock tokens expecting profits
- When attempting withdrawal, all transactions fail permanently
- Attacker has created irreversible fund trap

*Accidental Misconfiguration (MEDIUM probability):*
- Developer intends to set "effectively infinite" lock period using `Int64.MaxValue`
- Tests with small values don't catch the overflow condition
- Production deployment with extreme value breaks all withdrawals
- Existing test suite contains no validation for boundary values [8](#0-7) 

**Real-World Feasibility:**
- No blockchain state manipulation required
- Works deterministically on any chain where TokenHolderContract is deployed
- Victims cannot detect the vulnerability until attempting withdrawal (after their tokens are already locked)

## Recommendation

Implement input validation in `CreateScheme` to restrict `MinimumLockMinutes` to safe ranges:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation similar to Election contract
    const long MaxSafeLockMinutes = 525600 * 10; // 10 years in minutes
    Assert(input.MinimumLockMinutes >= 0, "Lock time cannot be negative.");
    Assert(input.MinimumLockMinutes <= MaxSafeLockMinutes, 
        $"Lock time exceeds maximum of {MaxSafeLockMinutes} minutes.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);
    // ... rest of existing code
}
```

Additional defensive measures:
- Add overflow handling in `Withdraw` with more informative error messages
- Update protobuf schema documentation to specify recommended maximum values
- Implement contract upgrade to fix existing vulnerable deployments

## Proof of Concept

```csharp
[Fact]
public async Task Withdraw_With_Overflow_MinimumLockMinutes_Test()
{
    // Attacker creates malicious scheme with Int64.MaxValue lock time
    var attackerScheme = GetTokenHolderContractTester(UserKeyPairs[0]);
    await attackerScheme.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = long.MaxValue // 9223372036854775807
    });

    var attackerAddress = Address.FromPublicKey(UserKeyPairs[0].PublicKey);
    
    // Victim registers and locks tokens
    var victimStub = GetTokenHolderContractTester(UserKeyPairs[1]);
    await victimStub.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        Amount = 1000,
        SchemeManager = attackerAddress
    });

    // Attempt withdrawal - this will throw OverflowException
    var withdrawResult = await victimStub.Withdraw.SendWithExceptionAsync(attackerAddress);
    
    // Verify the transaction fails due to overflow
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    // Tokens remain locked indefinitely - victim cannot recover funds
}
```

This test demonstrates that when `MinimumLockMinutes` is set to `Int64.MaxValue`, the `Withdraw` function will always fail with an overflow exception, permanently locking the victim's tokens.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L159-165)
```csharp
        State.TokenContract.Lock.Send(new LockInput
        {
            LockId = lockId,
            Symbol = scheme.Symbol,
            Address = Context.Sender,
            Amount = input.Amount
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L227-228)
```csharp
        Assert(State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes) < Context.CurrentBlockTime,
            "Cannot withdraw.");
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
