### Title
Authorization Check After Unbounded Loop Enables Resource Exhaustion DoS in SetMethodFee

### Summary
The `SetMethodFee` method in 14 ACS1-compliant system contracts (including Configuration) performs authorization checks AFTER executing an unbounded foreach loop that makes cross-contract calls for each element in the user-supplied `input.Fees` array. Attackers can submit transactions with large fee arrays to force miners/validators to execute thousands of expensive cross-contract calls before the transaction is rejected, enabling resource exhaustion DoS attacks across critical system contracts.

### Finding Description

The vulnerability exists in the `SetMethodFee` method implementation pattern used across all ACS1 transaction fee provider contracts. In the Configuration contract specifically: [1](#0-0) 

The critical flow is:
1. Line 13: The foreach loop iterates over `input.Fees` calling `AssertValidToken()` for each entry
2. Line 15-17: Authorization check happens AFTER the loop completes

Each `AssertValidToken()` invocation makes a cross-contract call: [2](#0-1) 

The `input.Fees` array is defined as unbounded in the protobuf specification: [3](#0-2) 

**Root Cause**: The authorization check verifying `Context.Sender == State.MethodFeeController.Value.OwnerAddress` occurs after all expensive operations, violating the "fail-fast" security principle.

**Why Existing Protections Fail**:
- The `ExecutionCallThreshold` (15,000) provides an upper bound but still allows ~14,999 cross-contract calls before transaction abort [4](#0-3) 
- Transaction fees are paid by the attacker but don't prevent the resource consumption that affects miners/validators
- No size limit exists on the `fees` array before the loop executes

**Widespread Impact**: This exact pattern exists in 14 system contracts: [5](#0-4) [6](#0-5) 

Similar implementations exist in: Consensus (AEDPoS), CrossChain, Economic, Election, Genesis, MultiToken, TokenConverter, TokenHolder, Profit, Referendum, Treasury, and Vote contracts.

### Impact Explanation

**Operational DoS Impact**:
- **Miner/Validator Resource Exhaustion**: Miners must execute up to ~14,999 cross-contract calls per malicious transaction before discovering it's unauthorized, consuming significant computational resources
- **Network Congestion**: Multiple attackers can simultaneously submit such transactions to all 14 vulnerable contracts, multiplicatively amplifying the attack (14 × ~15,000 = ~210,000 potential cross-contract calls per coordinated attack round)
- **Block Space Consumption**: Large failing transactions occupy block space that could be used for legitimate transactions
- **Cross-Contract Cascade**: Each call to `TokenContract.IsTokenAvailableForMethodFee` forces the TokenContract to execute validation logic, potentially creating cascading resource consumption

**Affected Components**:
- All 14 system contracts implementing ACS1 (governance, consensus, token, treasury, cross-chain, voting)
- Miners/validators processing these transactions
- Legitimate users experiencing transaction delays during attacks

**Severity Justification (Medium)**:
- Does not directly steal funds or break consensus invariants
- Operational impact limited by ExecutionCallThreshold and transaction fees
- Requires continuous attack effort to maintain DoS effect
- However, affects critical infrastructure contracts and creates disproportionate resource consumption relative to attacker cost

### Likelihood Explanation

**Attacker Capabilities**: 
- No special permissions required - any blockchain user can call `SetMethodFee`
- Attack requires only crafting a `MethodFees` input with a large `fees` array
- No need to bypass authentication or exploit complex state transitions

**Attack Complexity**: LOW
- Single transaction submission per attack attempt
- Simple input structure: `MethodFees { method_name: "x", fees: [{ symbol: "ELF", basic_fee: 0 }, ... repeat 14999 times] }`
- Can be automated and coordinated across multiple contracts

**Feasibility Conditions**:
- ✓ Public entry point accessible to all users
- ✓ No rate limiting on `SetMethodFee` calls before authorization check
- ✓ Authorization check consistently placed after expensive loop across all 14 contracts
- ✓ ExecutionCallThreshold high enough (15,000) to allow significant damage before abort

**Economic Rationality**:
- Attacker pays transaction fees (ACS1 method fees + size fees + resource fees)
- However, cost/damage ratio may be favorable:
  - Single malicious transaction forces ~14,999 cross-contract executions
  - Coordinated attack across 14 contracts = ~210,000 forced contract calls
  - Network-wide impact from relatively modest attacker expenditure

**Detection/Operational Constraints**:
- Failed `SetMethodFee` transactions would appear in logs with "Unauthorized to set method fee" errors
- Pattern of large failing transactions could trigger monitoring alerts
- However, damage occurs during execution before failure is detected

### Recommendation

**Immediate Fix**: Move authorization check before the expensive foreach loop in all affected contracts.

For Configuration contract (and similarly for all 14 ACS1 implementations):

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    // CHECK AUTHORIZATION FIRST
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
    
    // THEN perform expensive operations
    foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Additional Protections**:
1. Add explicit size limit on `input.Fees` array (e.g., maximum 100 fee entries):
```csharp
Assert(input.Fees.Count <= 100, "Too many fees specified.");
```

2. Add integration tests verifying authorization check occurs before expensive operations:
```csharp
[Fact]
public async Task SetMethodFee_Should_Check_Authorization_Before_Loop()
{
    // Arrange: Create unauthorized sender with large fees array
    var largeFeesInput = new MethodFees { 
        MethodName = "Test",
        Fees = { /* 10000 entries */ }
    };
    
    // Act & Assert: Should fail quickly without executing loop
    var result = await ConfigurationStub.SetMethodFee.SendAsync(largeFeesInput);
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Unauthorized");
    // Verify minimal resource consumption via transaction trace
}
```

3. Consider implementing rate limiting or cooldown periods for `SetMethodFee` calls in governance

### Proof of Concept

**Initial State**:
- Configuration contract deployed with default MethodFeeController (Parliament default organization)
- Attacker address is NOT the MethodFeeController owner

**Attack Sequence**:

```
Step 1: Attacker crafts malicious input
---------------------------------------
MethodFees maliciousInput = new MethodFees {
    MethodName = "SetConfiguration",
    Fees = {
        new MethodFee { Symbol = "ELF", BasicFee = 0 },
        new MethodFee { Symbol = "WRITE", BasicFee = 0 },
        ... repeat for 14,999 total entries ...
    }
};

Step 2: Attacker submits transaction
-------------------------------------
ConfigurationContract.SetMethodFee(maliciousInput)

Step 3: Contract execution path
--------------------------------
→ foreach loop executes (line 13)
  → Iteration 1: AssertValidToken("ELF", 0)
    → Cross-contract call: TokenContract.IsTokenAvailableForMethodFee("ELF")
  → Iteration 2: AssertValidToken("WRITE", 0)  
    → Cross-contract call: TokenContract.IsTokenAvailableForMethodFee("WRITE")
  → ... continues for up to 14,999 iterations ...
  → ExecutionCallThreshold reached: RuntimeCallThresholdExceededException
  OR all iterations complete

→ RequiredMethodFeeControllerSet() executes (line 15)
→ Authorization check executes (line 17)
  → Assert fails: "Unauthorized to set method fee."

Step 4: Transaction result
---------------------------
Status: Failed
Error: "Unauthorized to set method fee." OR "Contract call threshold 15000 exceeded."
```

**Expected vs Actual Result**:
- **Expected (secure)**: Authorization check fails immediately, minimal resource consumption
- **Actual (vulnerable)**: Up to ~14,999 cross-contract calls execute before authorization failure, significant miner/validator resource exhaustion

**Success Condition for Attacker**: 
- Transaction eventually fails (expected)
- BUT: Forced miners to execute thousands of expensive cross-contract calls
- Network resources consumed disproportionately to attacker's transaction fee cost
- Repeatable attack vector affecting 14 critical system contracts

**Notes**

This vulnerability represents a systemic design flaw in the ACS1 implementation pattern rather than an isolated bug. The authorization-after-expensive-operations anti-pattern is consistently replicated across all major AElf system contracts, indicating a need for:

1. **Pattern Review**: Audit all ACS1 implementations for similar authorization ordering issues
2. **Development Guidelines**: Establish coding standards requiring authorization checks before expensive operations (especially loops with user-controlled bounds)
3. **Protobuf Constraints**: Consider adding size limits to `repeated` fields in critical protobuf messages
4. **Execution Monitoring**: Implement runtime monitoring for transactions approaching ExecutionCallThreshold to detect potential DoS attempts

While the ExecutionCallThreshold provides eventual transaction termination, it's calibrated for legitimate use cases and allows sufficient iterations for meaningful resource exhaustion attacks. The vulnerability is mitigated but not eliminated by existing protections.

### Citations

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L11-21)
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

**File:** contract/AElf.Contracts.Configuration/ConfigurationContract_ACS1_TransactionFeeProvider.cs (L79-88)
```csharp
    private void AssertValidToken(string symbol, long amount)
    {
        Assert(amount >= 0, "Invalid amount.");
        if (State.TokenContract.Value == null)
            State.TokenContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.TokenContractSystemName);

        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
            $"Token {symbol} cannot set as method fee.");
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

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
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
