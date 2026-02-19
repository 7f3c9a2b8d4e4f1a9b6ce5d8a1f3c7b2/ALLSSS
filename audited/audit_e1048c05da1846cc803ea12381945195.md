### Title
Integer Overflow in TokenHolder Withdraw Function Enables Permanent Token Lock via Malicious MinimumLockMinutes

### Summary
The `Withdraw()` function in TokenHolderContract performs unchecked arithmetic on user-controlled `MinimumLockMinutes` values, which when set to extremely large values (e.g., Int64.MaxValue) causes an `OverflowException` during the lock time validation check. While overflow protection exists via checked arithmetic, this throws an exception that permanently prevents users from withdrawing their locked tokens, enabling a malicious scheme manager to create a honeypot that traps user funds indefinitely.

### Finding Description

The vulnerability exists in the `Withdraw()` function's time validation logic: [1](#0-0) 

When `AddMinutes` is called, it internally performs `minutes.Mul(60)`: [2](#0-1) 

The `Mul` operation uses checked arithmetic for overflow detection: [3](#0-2) 

However, the `MinimumLockMinutes` value is set during scheme creation without any validation on its maximum value: [4](#0-3) 

The `MinimumLockMinutes` field is defined as `int64` with no bounds specified: [5](#0-4) 

**Root Cause**: When a scheme manager creates a scheme with `MinimumLockMinutes` set to any value where `value * 60 > Int64.MaxValue` (e.g., values >= 153,722,867,280,912,931), the multiplication in `AddMinutes` will overflow. The checked arithmetic throws an `OverflowException`, causing the entire `Withdraw` transaction to fail.

**Why Protections Fail**: While the checked block in `SafeMath.Mul` prevents silent overflow, it makes the vulnerability exploitable by transforming a potential calculation error into a guaranteed DoS condition. There is no input validation in `CreateScheme` to prevent extreme values.

### Impact Explanation

**Direct Fund Impact**: 
- Users who register for profits in a malicious scheme lock their tokens via the Token contract
- When attempting withdrawal, the overflow exception prevents the unlock operation from executing
- Tokens remain permanently locked with no recovery mechanism
- Each affected user loses 100% of their locked token amount

**Affected Parties**:
- Any user who calls `RegisterForProfits` on a scheme with malicious `MinimumLockMinutes`
- The scheme manager does not gain direct access to funds but achieves permanent user fund denial

**Severity Justification**: HIGH
- Permanent, irrecoverable loss of user funds
- No authorization required to create malicious schemes
- Simple single-parameter exploitation
- No time-based recovery possible

### Likelihood Explanation

**Attacker Capabilities**:
- Any address can call `CreateScheme` to become a scheme manager
- No special privileges or governance approval required
- Single transaction to set malicious parameter

**Attack Complexity**: LOW
- Set `MinimumLockMinutes = Int64.MaxValue` (or any value >= 153,722,867,280,912,931)
- Wait for users to call `RegisterForProfits` on the malicious scheme
- Users' funds are automatically trapped when they attempt withdrawal

**Feasibility Conditions**:
- Attack requires users to voluntarily register for profits in the attacker's scheme
- Users may not scrutinize the `MinimumLockMinutes` value before registration
- Scheme could appear legitimate with attractive profit-sharing terms

**Detection Constraints**:
- Malicious value is visible in scheme data but requires users to query and validate it
- No automatic warnings or validation errors during scheme creation
- Exploited schemes would show pattern of failed withdrawal transactions

**Probability**: HIGH - Attack is straightforward, requires no special conditions, and users have limited ability to detect malicious parameters before registration.

### Recommendation

**Immediate Fix**: Add validation in `CreateScheme` to enforce maximum bounds on `MinimumLockMinutes`:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add validation to prevent overflow in AddMinutes calculation
    // Max safe value: (Int64.MaxValue / 60) - 1 to account for timestamp addition
    const long MaxSafeMinutes = 153722867280912930; // (2^63 - 1) / 60 - 1
    Assert(input.MinimumLockMinutes >= 0 && input.MinimumLockMinutes <= MaxSafeMinutes, 
           "MinimumLockMinutes out of valid range.");
    
    // ... rest of existing code
}
```

**Additional Safeguards**:
1. Consider reasonable business logic limits (e.g., max 5 years = 2,628,000 minutes)
2. Add try-catch around the AddMinutes operation in Withdraw with appropriate error message
3. Add pre-registration validation in `RegisterForProfits` to warn users of extreme lock times
4. Implement scheme audit/flagging mechanism for suspicious parameters

**Test Cases**:
- Test CreateScheme with MinimumLockMinutes = Int64.MaxValue (should reject)
- Test CreateScheme with MinimumLockMinutes = (Int64.MaxValue / 60) (should reject)  
- Test successful withdraw after lock period with maximum allowed MinimumLockMinutes
- Test that overflow protection doesn't affect legitimate lock periods

### Proof of Concept

**Initial State**:
- Attacker address: `AttackerAddr`
- Victim address: `VictimAddr`
- Token symbol: `TEST`
- Victim has 1000 TEST tokens

**Attack Sequence**:

1. **Attacker creates malicious scheme**:
   ```
   Call: CreateScheme({
       symbol: "TEST",
       minimum_lock_minutes: 9223372036854775807, // Int64.MaxValue
       auto_distribute_threshold: {}
   })
   Sender: AttackerAddr
   ```

2. **Victim registers for profits** (locks tokens):
   ```
   Call: RegisterForProfits({
       scheme_manager: AttackerAddr,
       amount: 1000
   })
   Sender: VictimAddr
   ```
   - Tokens are locked via Token contract
   - Lock timestamp recorded

3. **Victim attempts withdrawal** (at any point in future):
   ```
   Call: Withdraw(AttackerAddr)
   Sender: VictimAddr
   ```

**Expected Result**: Withdrawal succeeds after minimum lock period

**Actual Result**: 
- Transaction fails with `OverflowException`
- Error occurs at: `State.LockTimestamp[lockId].AddMinutes(scheme.MinimumLockMinutes)`
- Computation: `Int64.MaxValue * 60` exceeds Int64.MaxValue
- Checked arithmetic throws exception
- Tokens remain permanently locked

**Success Condition**: Victim cannot withdraw tokens under any circumstances; attacker has created permanent lock condition using only scheme creation privileges.

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
