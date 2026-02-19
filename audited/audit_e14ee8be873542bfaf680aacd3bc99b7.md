### Title
Hardcoded Election Lock Amount Causes DoS or Incorrect Economic Security When Native Token Decimals Differ from 8

### Summary
The `LockTokenForElection` constant is hardcoded to `100_000_00000000` assuming 8 decimal places, but native token decimals are configurable from 0 to 18. When a chain is initialized with native token decimals different from 8, the election announcement system will either fail completely (DoS) or lock incorrect amounts, breaking the intended economic security model.

### Finding Description

The Election contract uses a hardcoded constant `LockTokenForElection = 100_000_00000000` [1](#0-0)  which assumes the native token has exactly 8 decimal places.

However, the native token decimals are configurable during chain initialization through `InitialEconomicSystemInput.NativeTokenDecimals` [2](#0-1) , which accepts any value from 0 to 18 [3](#0-2) . The production initialization reads this from configurable `EconomicOptions.Decimals` [4](#0-3) , which defaults to 8 but can be changed [5](#0-4) .

Test code demonstrates this is feasible, showing native token creation with 2 decimals [6](#0-5) .

The hardcoded constant is used directly in two critical locations without any decimal adjustment:

1. **LockCandidateNativeToken**: Transfers exactly `LockTokenForElection` amount from the candidate [7](#0-6) 

2. **QuitElection**: Refunds exactly `LockTokenForElection` amount back to the candidate [8](#0-7) 

The MultiToken contract performs no decimal-specific validation beyond checking that amounts are positive [9](#0-8) . It does not verify that token amounts align with the token's configured decimal precision.

### Impact Explanation

**Scenario 1 - Native token with fewer decimals (e.g., 2 decimals):**
- Intended lock: 100,000 tokens
- Actual interpretation: `100_000_00000000` with 2 decimals = 1,000,000,000,000 tokens (1 trillion)
- With typical total supply of 1,000,000,000 tokens (1 billion) [10](#0-9) , the `TransferFrom` will fail due to insufficient balance
- **Impact**: Complete DoS of election system - no candidate can announce election
- **Severity**: Critical - breaks core governance functionality

**Scenario 2 - Native token with more decimals (e.g., 10 decimals):**
- Intended lock: 100,000 tokens  
- Actual interpretation: `100_000_00000000` with 10 decimals = 10,000 tokens
- **Impact**: Lock amount is 10x too small, reducing economic barrier to becoming a candidate by 90%
- **Severity**: High - undermines election economic security model

**Scenario 3 - Native token with 6 decimals:**
- Intended lock: 100,000 tokens
- Actual interpretation: `100_000_00000000` with 6 decimals = 100,000,000 tokens (100 million)
- **Impact**: Lock amount is 1,000x too large - likely DoS unless candidates have enormous balances
- **Severity**: Critical - effectively blocks all election participation

The refund mechanism in `QuitElection` has the same hardcoded amount, so if a candidate somehow manages to lock tokens (in scenarios where it doesn't immediately fail), they will receive back the same incorrect amount, maintaining the precision error.

### Likelihood Explanation

**Entry Points**: The vulnerability is triggered through public methods `AnnounceElection` [11](#0-10)  and `AnnounceElectionFor` [12](#0-11) , both callable by any user.

**Preconditions**: 
1. Chain must be initialized with native token decimals ≠ 8
2. This is feasible as decimals are configurable via `EconomicOptions` or `InitialEconomicSystemInput`
3. Side chains or custom deployments may choose different decimals for various reasons (existing token compatibility, precision requirements, etc.)

**Feasibility**: The test codebase already demonstrates native token with 2 decimals [6](#0-5) , proving this configuration is valid and can occur in practice.

**No Existing Validation**: The token creation process validates only that decimals are between 0-18 [13](#0-12) . There is no check enforcing that the native token specifically must have 8 decimals, and no validation in the Election contract that the native token decimals match the assumed precision.

**Probability**: Medium-High. While the default configuration uses 8 decimals, any chain deployment that modifies this configuration (legitimately or otherwise) will encounter this issue immediately upon first election announcement attempt.

### Recommendation

**Immediate Fix**: Replace the hardcoded constant with a dynamic calculation based on the native token's actual decimals:

```csharp
private long GetLockTokenAmount()
{
    var tokenInfo = State.TokenContract.GetTokenInfo.Call(new GetTokenInfoInput
    {
        Symbol = Context.Variables.NativeSymbol
    });
    
    // Calculate 100,000 tokens with correct decimal precision
    return 100_000L * (long)Math.Pow(10, tokenInfo.Decimals);
}
```

Use this method instead of the constant in both `LockCandidateNativeToken` and `QuitElection`.

**Additional Validations**:
1. Add initialization check in Election contract to verify native token decimals are within acceptable range (e.g., 2-18)
2. Store the expected lock amount during initialization based on native token decimals
3. Add unit tests covering native tokens with decimals 0, 2, 6, 8, 10, and 18

**Invariant to Enforce**: Lock amount must equal `100,000 * 10^(native_token_decimals)` to maintain consistent economic security regardless of decimal configuration.

### Proof of Concept

**Initial State**:
- Side chain initialized with native token having 2 decimals (as shown in test code)
- Total supply: 1,000,000,000 (1 billion with 2 decimals = 10 million tokens in user representation)
- Candidate has balance: 1,100,000,000 (11 million tokens in user representation)

**Transaction Steps**:
1. Candidate calls `AnnounceElection` with admin address
2. Contract executes `LockCandidateNativeToken()`
3. Contract calls `TransferFrom` with amount = `100_000_00000000`
4. With 2 decimals, this represents 1,000,000,000,000 tokens (1 trillion)

**Expected Result** (if working correctly):
- Lock 100,000 tokens (represented as 10,000,000 with 2 decimals)
- Candidate balance reduced by 10,000,000

**Actual Result**:
- `TransferFrom` fails with "Insufficient balance" error
- Transaction reverts
- No candidate can announce election
- Election system is completely non-functional

**Success Condition for Exploit**: Any attempt to announce election on a chain with native token decimals ≠ 8 will either fail (DoS) or lock incorrect amounts (economic security violation).

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContractConstants.cs (L5-5)
```csharp
    public const long LockTokenForElection = 100_000_00000000;
```

**File:** protobuf/economic_contract.proto (L35-35)
```text
    int32 native_token_decimals = 4;
```

**File:** contract/AElf.Contracts.MultiToken/TokenContractConstants.cs (L6-6)
```csharp
    public const int MaxDecimals = 18;
```

**File:** src/AElf.EconomicSystem/EconomicContractInitializationProvider.cs (L40-40)
```csharp
                    NativeTokenDecimals = _economicOptions.Decimals,
```

**File:** src/AElf.OS.Core/EconomicOptions.cs (L9-9)
```csharp
    public int Decimals { get; set; } = 8;
```

**File:** test/AElf.Contracts.TestBase/ContractTester.cs (L769-769)
```csharp
            Decimals = 2,
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L93-93)
```csharp
    public override Empty AnnounceElection(Address input)
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L121-121)
```csharp
    public override Empty AnnounceElectionFor(AnnounceElectionForInput input)
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L192-192)
```csharp
            Amount = ElectionContractConstants.LockTokenForElection,
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L247-247)
```csharp
            Amount = ElectionContractConstants.LockTokenForElection,
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L81-86)
```csharp
    private void AssertValidSymbolAndAmount(string symbol, long amount)
    {
        Assert(!string.IsNullOrEmpty(symbol) && IsValidSymbol(symbol),
            "Invalid symbol.");
        Assert(amount > 0, "Invalid amount.");
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L276-277)
```csharp
               && input.Decimals >= 0
               && input.Decimals <= TokenContractConstants.MaxDecimals, "Invalid input.");
```

**File:** test/AElf.Contracts.Election.Tests/ElectionContractTestConstants.cs (L6-6)
```csharp
    public const long NativeTokenTotalSupply = 1_000_000_000_00000000;
```
