### Title
Missing Extensibility Mechanism for New Fee Types Causes Initialization Deadlock

### Summary
The `InitialCoefficients()` function can only be called once and hardcodes initialization for exactly five fee types (READ, STORAGE, WRITE, TRAFFIC, TX). If the protocol is extended with additional fee types, there is no mechanism to initialize their coefficients, causing fee calculation to fail with `InvalidOperationException` and resulting in a denial-of-service for transactions using the new fee types. [1](#0-0) 

### Finding Description

The root cause is a three-part initialization deadlock:

**1. Single Initialization Constraint**
The `InitialCoefficients()` method contains an assertion that prevents re-initialization, ensuring it can only be called once during contract deployment. [2](#0-1) 

**2. Hardcoded Fee Type Initialization**
Lines 112-121 explicitly initialize only five fee types using conditional checks. Any new fee type added to the `FeeTypeEnum` will not be included in this initialization. [3](#0-2) 

The `FeeTypeEnum` currently defines exactly these five types: [4](#0-3) 

**3. Update Mechanism Blocks New Additions**
The `UpdateCoefficients()` method, which is the only way to modify coefficients post-initialization, explicitly requires that the fee type already exists. It asserts failure if attempting to add a new fee type. [5](#0-4) 

**4. Failure Point During Fee Calculation**
When a transaction attempts to use a fee type without initialized coefficients, the `TokenFeeProviderBase.CalculateFeeAsync` method throws an `InvalidOperationException`, blocking transaction execution. [6](#0-5) 

### Impact Explanation

**Operational DoS of Fee Calculation:**
- Any transaction requiring the new fee type cannot calculate fees and will fail with `InvalidOperationException`
- Contracts implementing new resource token types or fee mechanisms become unusable
- Protocol upgrades introducing new fee dimensions (e.g., COMPUTE, MEMORY, BANDWIDTH) are blocked
- No workaround exists without redeploying the entire token contract, requiring migration of all token state

**Who is Affected:**
- All users attempting transactions that require the new fee type
- Developers deploying contracts that depend on new resource token types
- The protocol's ability to evolve its fee model

**Severity Justification (Medium):**
- Does not directly cause fund theft or unauthorized access
- Requires protocol-level decision to add new fee types (not exploitable by malicious actors)
- However, creates complete operational failure for legitimate protocol evolution
- No recovery path without major state migration

### Likelihood Explanation

**Preconditions:**
1. Protocol governance decides to add a new fee type to `FeeTypeEnum` (e.g., COMPUTE token for CPU-intensive operations)
2. Contract code is updated via the Genesis contract upgrade mechanism
3. New fee provider implementation is deployed

**Execution Path:**
1. Contract upgrade succeeds, new code is deployed
2. System attempts to initialize coefficients for the new fee type
3. `InitialCoefficients()` cannot be called (already initialized assertion fails)
4. `UpdateCoefficients()` cannot add the type (non-existent fee type assertion fails)
5. First transaction using the new fee type triggers `CalculateFeeAsync`
6. Missing coefficient causes exception, transaction fails

**Probability:**
- **Medium likelihood** - depends on whether protocol evolution includes new fee types
- Current design supports 4 resource tokens (READ, STORAGE, WRITE, TRAFFIC) plus TX fees
- Future resource types (COMPUTE, BANDWIDTH, MEMORY) are plausible protocol enhancements
- ACS8 standard could be extended to support additional resource dimensions [7](#0-6) 

### Recommendation

**Add a mechanism to register new fee types post-initialization:**

1. **Create AddNewFeeType Method:**
   - Add a new public method `AddFeeTypeCoefficients(CalculateFeeCoefficients coefficients)`
   - Validate that the fee type doesn't already exist
   - Apply coefficient validation (AssertCoefficientsValid, AssertPieceUpperBoundsIsInOrder)
   - Add to `State.AllCalculateFeeCoefficients.Value`
   - Require developer fee controller authorization

2. **Modify UpdateCoefficients Logic:**
   - Remove or soften the assertion at line 42
   - Allow adding new fee types if they don't exist (with proper validation)
   - Distinguish between "add" and "update" operations

3. **Add Governance Protection:**
   - Require proposal/approval from fee controller organizations
   - Emit event when new fee type is added
   - Include fee type metadata validation

4. **Example Implementation:**
```csharp
public override Empty AddFeeTypeCoefficients(CalculateFeeCoefficients input)
{
    Assert(input != null, "Invalid coefficient input.");
    AssertDeveloperFeeController();
    
    var currentAll = State.AllCalculateFeeCoefficients.Value;
    var existing = currentAll.Value.SingleOrDefault(x => x.FeeTokenType == input.FeeTokenType);
    Assert(existing == null, "Fee type already exists, use UpdateCoefficients instead.");
    
    foreach (var piece in input.PieceCoefficientsList)
        AssertCoefficientsValid(piece);
    AssertPieceUpperBoundsIsInOrder(input.PieceCoefficientsList);
    
    currentAll.Value.Add(input);
    State.AllCalculateFeeCoefficients.Value = currentAll;
    
    Context.Fire(new FeeTypeAdded { Coefficients = input });
    return new Empty();
}
```

### Proof of Concept

**Initial State:**
- Token contract deployed with `InitialCoefficients()` called
- 5 fee types initialized: READ(0), STORAGE(1), WRITE(2), TRAFFIC(3), TX(4)

**Extension Scenario:**
1. Protocol team decides to add COMPUTE fee type
2. Update `FeeTypeEnum` in protobuf: `COMPUTE = 5;`
3. Implement `ComputeFeeProvider` class extending `TokenFeeProviderBase`
4. Deploy updated contract via Genesis contract upgrade
5. System attempts to call `InitialCoefficients()` or `UpdateCoefficients()` to add COMPUTE coefficients

**Expected Result:**
- COMPUTE fee type coefficients should be initialized and available for fee calculation

**Actual Result:**
- `InitialCoefficients()` fails: "Coefficient already initialized" assertion at line 110
- `UpdateCoefficients()` fails: "Specific fee type not existed before" assertion at line 42
- Transaction using COMPUTE fee type fails: "Function not found" exception at TokenFeeProviderBase line 31
- System enters unrecoverable state for COMPUTE-based transactions

**Success Condition:**
Fee calculation succeeds for all fee types including newly added COMPUTE type, demonstrating the design flaw prevents legitimate protocol evolution.

### Citations

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L40-42)
```csharp
        var currentCoefficients = currentAllCoefficients.Value.SingleOrDefault(x =>
            x.FeeTokenType == feeType);
        Assert(currentCoefficients != null, "Specific fee type not existed before.");
```

**File:** contract/AElf.Contracts.MultiToken/TokenContract_Fee_Calculate_Coefficient.cs (L108-130)
```csharp
    public override Empty InitialCoefficients(Empty input)
    {
        Assert(State.AllCalculateFeeCoefficients.Value == null, "Coefficient already initialized");
        var allCalculateFeeCoefficients = new AllCalculateFeeCoefficients();
        if (allCalculateFeeCoefficients.Value.All(x => x.FeeTokenType != (int)FeeTypeEnum.Read))
            allCalculateFeeCoefficients.Value.Add(GetReadFeeInitialCoefficient());
        if (allCalculateFeeCoefficients.Value.All(x => x.FeeTokenType != (int)FeeTypeEnum.Storage))
            allCalculateFeeCoefficients.Value.Add(GetStorageFeeInitialCoefficient());
        if (allCalculateFeeCoefficients.Value.All(x => x.FeeTokenType != (int)FeeTypeEnum.Write))
            allCalculateFeeCoefficients.Value.Add(GetWriteFeeInitialCoefficient());
        if (allCalculateFeeCoefficients.Value.All(x => x.FeeTokenType != (int)FeeTypeEnum.Traffic))
            allCalculateFeeCoefficients.Value.Add(GetTrafficFeeInitialCoefficient());
        if (allCalculateFeeCoefficients.Value.All(x => x.FeeTokenType != (int)FeeTypeEnum.Tx))
            allCalculateFeeCoefficients.Value.Add(GetTxFeeInitialCoefficient());
        State.AllCalculateFeeCoefficients.Value = allCalculateFeeCoefficients;

        Context.Fire(new CalculateFeeAlgorithmUpdated
        {
            AllTypeFeeCoefficients = allCalculateFeeCoefficients
        });

        return new Empty();
    }
```

**File:** protobuf/token_contract.proto (L598-604)
```text
enum FeeTypeEnum {
    READ = 0;
    STORAGE = 1;
    WRITE = 2;
    TRAFFIC = 3;
    TX = 4;
}
```

**File:** src/AElf.Kernel.FeeCalculation/Infrastructure/TokenFeeProviderBase.cs (L28-32)
```csharp
        if (!functionDictionary.ContainsKey(targetKey))
        {
            var currentKeys = string.Join(" ", functionDictionary.Keys);
            throw new InvalidOperationException($"Function not found. Current keys: {currentKeys}");
        }
```

**File:** protobuf/acs8.proto (L1-10)
```text
/**
 * AElf Standards ACS8(Transaction Resource Token Fee Standard)
 *
 * ACS8 has some similarities to ACS1, both of them are charge transaction fee standard.
 * The difference is that ACS1 charges the user a transaction fee, ACS8 charges the called contract, 
 * and the transaction fee charged by ACS8 is the specified four tokens: WRITE, READ, STORAGE, TRAFFIC.
 * In another word, if a contract declares that it inherits from ACS8, each transaction in this contract will 
 * charge four kinds of resource token.
 */
syntax = "proto3";
```
