### Title
Pre-Authorization Resource Exhaustion in SetMethodFee Across All ACS1 Implementations

### Summary
The `SetMethodFee` function in all ACS1-implementing system contracts performs expensive validation operations on an unbounded `input.Fees` array before checking caller authorization. An attacker can submit transactions with thousands of fee entries (limited only by the 5MB transaction size limit), forcing the network to perform extensive state reads and computation before the authorization check rejects the transaction. This affects 15+ critical system contracts including MultiToken, Parliament, Association, and Election contracts.

### Finding Description

The vulnerability exists in the `SetMethodFee` implementation where validation occurs before authorization: [1](#0-0) 

**Root Cause:** The foreach loop at line 15 iterates through all entries in `input.Fees` and calls `AssertValidFeeToken` for each entry, which performs:
- Symbol validation via regex matching
- Token information retrieval through state reads (`GetTokenInfo`)
- Burnable token verification [2](#0-1) [3](#0-2) 

Each `GetTokenInfo` call performs 1-2 state reads. Only after ALL validations complete does the authorization check occur at line 18.

**Why Protections Fail:**

1. **No Array Size Limit:** The `fees` field is defined as an unbounded repeated field in the protobuf specification: [4](#0-3) 

2. **No Runtime Input Validation:** The compile-time ArrayValidator only checks hardcoded arrays in contract code, not runtime input parameters: [5](#0-4) 

3. **Large Transaction Size Allowed:** The transaction pool accepts transactions up to 5MB: [6](#0-5) 

With each MethodFee entry consuming approximately 23-50 bytes (symbol string + int64 + protobuf overhead), an attacker can include 100,000+ entries in a single transaction.

**Systemic Issue:** This identical vulnerability pattern exists across ALL ACS1 implementations: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Operational DoS Impact:**
- Unauthorized users can force network validators to perform 100,000+ state reads and validation operations per transaction
- Each malicious transaction consumes significant block space (up to 5MB) and computation resources
- Multiple such transactions can exhaust network capacity, delaying legitimate transactions
- Validators must process the entire validation loop before rejecting the transaction

**Affected Components:**
All critical system contracts implementing ACS1 are vulnerable, including:
- MultiToken (core token operations)
- Parliament (governance)
- Association (multi-sig governance)
- Referendum (referendum governance)
- Election (validator elections)
- Consensus (AEDPoS consensus)
- CrossChain (cross-chain operations)
- Treasury, Profit, TokenConverter, TokenHolder, Vote, Configuration, Economic, NFT contracts

**Severity Justification:**
Medium severity due to:
- Easy exploitation requiring no special permissions
- Affects multiple critical system contracts
- Can cause network-wide resource exhaustion
- Authorization check fails to prevent resource waste
- However, attacker pays transaction fees and cannot permanently disable the network

### Likelihood Explanation

**Highly Exploitable:**

1. **Reachable Entry Point:** `SetMethodFee` is a public RPC method defined in the ACS1 standard: [9](#0-8) 

2. **No Preconditions:** Any user can submit transactions calling this method without any special permissions or setup

3. **Low Complexity:** Attack requires only:
   - Constructing a MethodFees message with a large Fees array
   - Submitting the transaction to any network node
   - No need to bypass authentication or satisfy complex conditions

4. **Economic Feasibility:** While the attacker pays transaction fees based on transaction size, they can cause disproportionate resource consumption. The cost-to-damage ratio favors the attacker as validators must perform expensive operations (state reads, validation) before rejection.

5. **Detection Difficulty:** Malicious transactions appear as normal failed authorization attempts in logs, making sustained attacks harder to detect and mitigate.

### Recommendation

**Immediate Fix:**
Move the authorization check to occur BEFORE the validation loop in all ACS1 implementations:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    
    foreach (var symbolToAmount in input.Fees) 
        AssertValidFeeToken(symbolToAmount.Symbol, symbolToAmount.BasicFee);
    
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Additional Protections:**
1. Add a maximum array size check (e.g., limit Fees array to 10-20 entries):
```csharp
Assert(input.Fees.Count <= 20, "Too many fee entries.");
```

2. Update all affected contracts:
   - TokenContract_ACS1_MethodFeeProvider.cs
   - ParliamentContract_ACS1_TransactionFeeProvider.cs
   - AssociationContract_ACS1_TransactionFeeProvider.cs
   - ReferendumContract_ACS1_TransactionFeeProvider.cs
   - ElectionContract_ACS1_TransactionFeeProvider.cs
   - And 10+ other ACS1 implementations

3. Add regression tests verifying:
   - Authorization check occurs before expensive operations
   - Large arrays are rejected with appropriate error messages
   - Resource consumption is bounded for unauthorized callers

### Proof of Concept

**Attack Sequence:**

1. **Initial State:** Attacker has a funded account with sufficient balance for transaction fees

2. **Craft Malicious Transaction:**
   - Create a MethodFees message with MethodName = "Transfer"
   - Populate Fees array with 100,000 entries:
     - Each entry: `{ Symbol: "ELF", BasicFee: 1 }`
   - Transaction size: ~2.3-5 MB

3. **Submit Transaction:**
   - Call `TokenContract.SetMethodFee(maliciousMethodFees)`
   - Transaction is broadcast to network

4. **Expected Result (Vulnerable):**
   - Validators receive the transaction
   - Contract execution begins
   - Foreach loop iterates 100,000 times
   - Each iteration performs:
     - Symbol validation (100,000 regex checks)
     - GetTokenInfo state reads (100,000-200,000 state reads)
     - IsBurnable checks
   - After all 100,000 validations complete, authorization check at line 18 finally fails
   - Transaction status: Failed with "Unauthorized to set method fee"
   - Network resources consumed: Significant (state reads, CPU time, block space)

5. **Actual Result (After Fix):**
   - Authorization check occurs immediately at line 14
   - Transaction fails instantly with "Unauthorized to set method fee"
   - No validation loop executes
   - Minimal resource consumption

**Success Condition:** 
The attack succeeds if the network performs expensive validation operations (100,000+ state reads) before rejecting an unauthorized transaction, demonstrating that resource exhaustion occurs pre-authorization.

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

**File:** protobuf/acs1.proto (L19-23)
```text
service MethodFeeProviderContract {
    
    // Set the method fees for the specified method. Note that this will override all fees of the method.
    rpc SetMethodFee (MethodFees) returns (google.protobuf.Empty) {
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

**File:** src/AElf.CSharp.CodeOps/Validators/Method/ArrayValidator.cs (L49-106)
```csharp
    public IEnumerable<ValidationResult> Validate(MethodDefinition method, CancellationToken ct)
    {
        if (ct.IsCancellationRequested)
            throw new ContractAuditTimeoutException();
            
        if (!method.HasBody)
            return Enumerable.Empty<ValidationResult>();
            
        var errors = new List<ValidationResult>();
            
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode != OpCodes.Newarr)
                continue;

            var typ = ((TypeReference) instruction.Operand).FullName;

            ArrayValidationResult error = null;
            if (AllowedTypes.TryGetLimit(typ, out var limit))
            {
                if (TryGetArraySize(instruction, out var arrayDimension))
                {
                    if (limit.By == LimitBy.Count)
                    {
                        if (arrayDimension > limit.Count)
                            error = new ArrayValidationResult($"Array size can not be larger than {limit.Count} elements. ({arrayDimension} x {typ})");
                    }
                    else
                    {
                        try
                        {
                            var totalSize = arrayDimension.Mul(limit.ElementSize);

                            if (totalSize > AllowedTotalSize)
                                error = new ArrayValidationResult($"Array size can not be larger than {AllowedTotalSize} bytes. ({arrayDimension} x {typ})");
                        }
                        catch (OverflowException)
                        {
                            error = new ArrayValidationResult($"Array size is too large that causes overflow when estimating memory usage.");
                        }
                    }
                }
                else
                {
                    error = new ArrayValidationResult($"Array size could not be identified for {typ}." + GetIlCodesPartial(instruction));
                }
            }
            else
            {
                error = new ArrayValidationResult($"Array of {typ} type is not allowed.");
            }
                
            if (error != null)
                errors.Add(error.WithInfo(method.Name, method.DeclaringType.Namespace, method.DeclaringType.Name, null));
        }

        return errors;
    }
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L7-7)
```csharp

```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L10-19)
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

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L10-19)
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
