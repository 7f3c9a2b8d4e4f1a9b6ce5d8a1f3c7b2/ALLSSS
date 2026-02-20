# Audit Report

## Title
Integer Overflow in TokenHolder Withdraw Function Enables Permanent Token Lock via Malicious MinimumLockMinutes

## Summary
The TokenHolderContract contains a critical vulnerability where the `CreateScheme()` function accepts unbounded `MinimumLockMinutes` values without validation. When users register for profits and later attempt to withdraw, excessively large values cause integer overflow in checked arithmetic operations, throwing an `OverflowException` that permanently locks user funds with no recovery mechanism.

## Finding Description

The vulnerability stems from missing input validation in the `CreateScheme()` function, which directly stores user-provided `MinimumLockMinutes` values without bounds checking. [1](#0-0) 

When users call `RegisterForProfits()`, their tokens are locked in a virtual address controlled by the TokenHolderContract. [2](#0-1) 

The critical failure occurs in the `Withdraw()` function's time validation, which calls `AddMinutes()` on the stored `MinimumLockMinutes` value. [3](#0-2) 

The `AddMinutes()` extension method internally multiplies the minutes value by 60 to convert to seconds, using SafeMath's checked arithmetic. [4](#0-3) 

The `Mul()` operation uses a checked block that throws `OverflowException` on overflow rather than wrapping. [5](#0-4) 

**Attack Execution Path:**
1. Attacker creates scheme with `MinimumLockMinutes = Int64.MaxValue` or any value > 153,722,867,280,912,930
2. Victim registers for profits, locking tokens 
3. On withdrawal attempt, `Int64.MaxValue * 60` overflows in checked context
4. Transaction reverts with `OverflowException`
5. Tokens remain permanently locked

**Why Direct Unlock Fails:**
The Token contract's `Unlock()` function computes virtual addresses as `Hash(Context.Sender || userAddress || lockId)`. [6](#0-5) 

When TokenHolderContract locks tokens, the virtual address is `Hash(TokenHolderContract || userAddress || lockId)`. If users call `Unlock()` directly, it computes `Hash(userAddress || userAddress || lockId)` - a different address, making direct unlock impossible.

**Why RemoveBeneficiary Doesn't Help:**
The scheme manager's `RemoveBeneficiary()` function only removes beneficiaries from the profit scheme but never calls Token.Unlock(). [7](#0-6) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes permanent, complete loss of all tokens locked in malicious schemes:

- **100% Fund Loss**: Users lose entire locked amount with zero recovery
- **Permanence**: No time-based expiry or admin intervention possible
- **No Bypass**: Virtual address mechanism prevents direct unlock, RemoveBeneficiary doesn't unlock tokens
- **Breaks Core Invariant**: Users should always be able to withdraw after the stated lock period

The impact affects any user who registers for profits in a scheme with overflow-inducing `MinimumLockMinutes` values. While the attacker doesn't directly steal funds, they achieve permanent denial of user assets.

## Likelihood Explanation

**Probability: MEDIUM-HIGH**

**Attacker Capabilities:**
- `CreateScheme()` is publicly accessible with no authorization checks
- No special privileges or governance approvals required
- Single transaction to set malicious parameter

**Attack Complexity: LOW**
- Set one parameter to extreme value
- No complex sequencing or timing requirements
- No oracle manipulation or governance attacks needed

**Feasibility Factors:**
- Requires users to voluntarily register for profits in attacker's scheme
- Parameters are queryable via `GetScheme()` view function, but users unlikely to validate before registration [8](#0-7) 

- Extreme values like Int64.MaxValue (~292 million years) may appear as display bugs rather than malicious parameters
- No contract-level validation or warnings during scheme creation

**Real-World Feasibility:**
In DeFi contexts, users frequently participate in new yield farming schemes without exhaustive parameter auditing. The malicious parameter is difficult to detect and could be disguised among otherwise legitimate scheme settings.

## Recommendation

Implement strict validation in `CreateScheme()` to enforce reasonable bounds on `MinimumLockMinutes`:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation to prevent overflow
    const long MaxAllowedLockMinutes = 153722867280912930; // ~292 million years, safely below overflow threshold
    const long ReasonableMaxLockMinutes = 525600 * 10; // 10 years in minutes
    
    Assert(input.MinimumLockMinutes >= 0, "Lock minutes cannot be negative.");
    Assert(input.MinimumLockMinutes <= ReasonableMaxLockMinutes, 
        $"Lock minutes exceeds reasonable maximum of {ReasonableMaxLockMinutes}.");
    
    // ... rest of existing code
}
```

Consider additional protections:
- Add emergency unlock mechanism for scheme managers
- Implement maximum lock duration governance parameter
- Add overflow-safe time arithmetic that saturates instead of throwing

## Proof of Concept

```csharp
[Fact]
public async Task PermanentLock_Via_IntegerOverflow_Test()
{
    // 1. Attacker creates malicious scheme with overflow-inducing MinimumLockMinutes
    var attackerAddress = Address.FromPublicKey(AttackerKeyPair.PublicKey);
    var victimAddress = Address.FromPublicKey(VictimKeyPair.PublicKey);
    
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = long.MaxValue // This should be validated but isn't
    });
    
    // 2. Victim registers for profits, locking 1000 ELF
    await TokenHolderContractStubByVictim.RegisterForProfits.SendAsync(new RegisterForProfitsInput
    {
        SchemeManager = attackerAddress,
        Amount = 1000_00000000 // 1000 ELF
    });
    
    // Verify tokens are locked
    var lockedAmount = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = victimAddress,
        Symbol = "ELF",
        LockId = ComputeLockId(attackerAddress, victimAddress)
    });
    lockedAmount.Amount.ShouldBe(1000_00000000);
    
    // 3. Victim attempts withdrawal - this will throw OverflowException
    var withdrawResult = await TokenHolderContractStubByVictim.Withdraw.SendWithExceptionAsync(attackerAddress);
    
    // Transaction reverts due to overflow in AddMinutes(long.MaxValue)
    withdrawResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    withdrawResult.TransactionResult.Error.ShouldContain("Overflow"); // or similar error message
    
    // 4. Tokens remain permanently locked - verify funds are still inaccessible
    var stillLocked = await TokenContractStub.GetLockedAmount.CallAsync(new GetLockedAmountInput
    {
        Address = victimAddress,
        Symbol = "ELF",
        LockId = ComputeLockId(attackerAddress, victimAddress)
    });
    stillLocked.Amount.ShouldBe(1000_00000000); // Funds still locked, unrecoverable
}
```

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L70-84)
```csharp
    public override Empty RemoveBeneficiary(RemoveTokenHolderBeneficiaryInput input)
    {
        var scheme = GetValidScheme(Context.Sender);

        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
        var lockedAmount = detail.Shares;
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Actions.cs (L234-235)
```csharp
        var fromVirtualAddress = HashHelper.ComputeFrom(Context.Sender.Value.Concat(input.Address.Value)
            .Concat(input.LockId.Value).ToArray());
```

**File:** protobuf/token_holder_contract.proto (L53-55)
```text
    rpc GetScheme (aelf.Address) returns (TokenHolderProfitScheme) {
        option (aelf.is_view) = true;
    }
```
