### Title
Authorization Check After Expensive Validation Loop Enables Resource Exhaustion DOS

### Summary
The `SetMethodFee` function performs expensive validation on all input fee entries before checking caller authorization, allowing unauthorized attackers to force the contract to consume excessive execution resources. An attacker can submit transactions with thousands of token symbols, causing the foreach loop to execute costly operations (regex validation, state reads, token info checks) before the authorization check rejects them at line 18.

### Finding Description

**Code Location:** [1](#0-0) 

**Root Cause:**
The authorization check occurs after the validation loop. The execution flow is:

1. Line 15: `foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(...)` - processes ALL input entries
2. Line 17-18: Authorization check - verifies caller is the method fee controller

Each loop iteration calls `AssertValidFeeToken` which performs: [2](#0-1) 

This includes:
- `AssertValidSymbolAndAmount`: regex pattern matching validation [3](#0-2) 

- `GetTokenInfo`: state read operation [4](#0-3) 

- Token burnable check

**Why Protections Fail:**
The `input.Fees` field is a protobuf repeated field with no runtime size validation: [5](#0-4) 

AElf's `ArrayValidator` only validates hardcoded arrays in contract code during deployment, not input parameters at runtime: [6](#0-5) 

The transaction size limit (5MB) allows thousands of `MethodFee` entries to be included in a single transaction.

### Impact Explanation

**Operational DOS Impact:**
- Unauthorized callers force execution of expensive operations (regex validation × N, state reads × N) before being rejected
- Each malicious transaction consumes significant execution call threshold budget (up to 15,000 calls) before failing authorization
- Repeated attacks waste blockchain computational resources and could delay or prevent legitimate governance operations
- While AElf's `ExecutionCallThreshold` (15,000) eventually aborts the transaction, the attacker can repeatedly submit such transactions

**Who Is Affected:**
- The MultiToken contract's governance functionality
- Legitimate method fee controller trying to update fees
- Network validators processing these wasteful transactions

**Severity Justification:**
Medium severity because:
- Does not result in fund theft or critical invariant violations
- Impact bounded by execution limits and transaction fees attacker must pay
- Causes resource waste and operational disruption rather than direct financial loss
- Simple fix available by reordering checks

### Likelihood Explanation

**Attacker Capabilities:**
Any user can call the public `SetMethodFee` function without authorization. No special privileges required to trigger the vulnerability.

**Attack Complexity:**
Low - attacker simply needs to:
1. Craft a `MethodFees` message with thousands of `MethodFee` entries (each with arbitrary symbol strings)
2. Submit transaction calling `SetMethodFee` with this payload
3. Transaction size limit (5MB) allows 100,000+ minimal entries

**Feasibility Conditions:**
- Function is publicly accessible
- No input size validation exists
- Authorization check happens after expensive loop
- Attacker pays transaction fees but causes disproportionate resource consumption

**Economic Rationality:**
While the attacker must pay transaction fees for failed transactions, the cost-to-impact ratio favors the attacker if the goal is resource exhaustion or preventing legitimate governance actions.

### Recommendation

**Immediate Fix:**
Move the authorization check before the validation loop:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    // Check authorization FIRST
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
           "Unauthorized to set method fee.");
    
    // Then validate input
    foreach (var symbolToAmount in input.Fees) 
        AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Additional Hardening:**
Add input size validation to prevent excessive entries even for authorized callers:

```csharp
Assert(input.Fees.Count <= 100, "Too many fee entries.");
```

**Test Cases:**
1. Verify unauthorized caller is rejected BEFORE any validation occurs
2. Test with maximum allowed fee entries from authorized caller
3. Test that exceeding entry limit is rejected for any caller
4. Verify gas/execution costs remain bounded

### Proof of Concept

**Initial State:**
- MultiToken contract deployed with method fee controller set
- Attacker has any valid account (no special privileges)

**Attack Steps:**
1. Attacker creates `MethodFees` input with 10,000+ entries:
   ```
   MethodFees {
     method_name: "Transfer",
     fees: [
       { symbol: "TOKEN1", basic_fee: 1000000 },
       { symbol: "TOKEN2", basic_fee: 1000000 },
       ... (repeat 10,000 times with different symbols)
       { symbol: "TOKEN10000", basic_fee: 1000000 }
     ]
   }
   ```

2. Attacker submits transaction: `SetMethodFee(input)`

3. Contract execution:
   - Enters foreach loop at line 15
   - Processes thousands of entries, each calling:
     - Regex validation
     - State reads for GetTokenInfo
     - Burnable checks
   - Consumes execution call threshold
   - Finally reaches line 18 and rejects due to unauthorized caller

**Expected Result:**
Transaction should fail immediately at authorization check

**Actual Result:**
Transaction consumes extensive resources processing all 10,000 entries before failing authorization, wasting execution budget that could have been prevented by early authorization check

**Success Condition:**
Execution call threshold consumed significantly (potentially reaching 15,000 limit) despite unauthorized caller being eventually rejected

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L13-22)
```csharp
    public override Empty SetMethodFee(MethodFees input)
    {
        foreach (var symbolToAmount in input.Fees) AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);

        RequiredMethodFeeControllerSet();
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");

        State.TransactionFees[input.MethodName] = input;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_ACS1_MethodFeeProvider.cs (L123-132)
```csharp
    private void AssertValidFeeToken(string symbol, long amount)
    {
        AssertValidSymbolAndAmount(symbol, amount);
        var tokenInfo = GetTokenInfo(symbol);
        if (tokenInfo == null)
        {
            throw new AssertionException("Token is not found");
        }
        Assert(tokenInfo.IsBurnable, $"Token {symbol} cannot set as method fee.");
    }
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

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Helper.cs (L405-416)
```csharp
    private TokenInfo GetTokenInfo(string symbolOrAlias)
    {
        var tokenInfo = State.TokenInfos[symbolOrAlias];
        if (tokenInfo != null) return tokenInfo;
        var actualTokenSymbol = State.SymbolAliasMap[symbolOrAlias];
        if (!string.IsNullOrEmpty(actualTokenSymbol))
        {
            tokenInfo = State.TokenInfos[actualTokenSymbol];
        }

        return tokenInfo;
    }
```

**File:** protobuf/acs1.proto (L40-46)
```text
message MethodFees {
    // The name of the method to be charged.
    string method_name = 1;
    // List of fees to be charged.
    repeated MethodFee fees = 2;
    bool is_size_fee_free = 3;// Optional based on the implementation of SetMethodFee method.
}
```

**File:** src/AElf.CSharp.CodeOps/Validators/Method/ArrayValidator.cs (L59-63)
```csharp
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode != OpCodes.Newarr)
                continue;

```
