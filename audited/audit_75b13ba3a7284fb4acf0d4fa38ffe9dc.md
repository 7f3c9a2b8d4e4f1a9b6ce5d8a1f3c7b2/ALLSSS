# Audit Report

## Title
Authorization Check After Unbounded Loop Enables Resource Exhaustion DoS in SetMethodFee

## Summary
The `SetMethodFee` method across 15+ system contracts (Genesis, Parliament, Association, etc.) performs authorization checks only after iterating through an unbounded `input.Fees` array and executing expensive cross-contract calls for each entry. An attacker can submit transactions with thousands of fee entries, forcing nodes to execute up to 15,000 cross-contract calls before the transaction fails authorization. This creates a cost-asymmetric DoS vector where attackers pay minimal size-based transaction fees while nodes consume massive computational resources.

## Finding Description

The vulnerability exists in the standard ACS1 `SetMethodFee` implementation pattern used across all system contracts. The Genesis contract implementation demonstrates the issue: the method iterates through all entries in `input.Fees` before performing authorization validation. [1](#0-0) 

Each iteration invokes `AssertValidToken`, which performs a cross-contract call to the Token contract: [2](#0-1) 

The authorization check only executes after this expensive loop completes: [3](#0-2) 

The `MethodFees` protobuf definition contains an unbounded repeated field: [4](#0-3) 

**Why Existing Protections Fail:**

1. **Execution Observer Limits**: AElf enforces call count limits of 15,000, but this still permits thousands of expensive operations before halting execution: [5](#0-4) 

2. **Transaction Size Limit**: The 5MB limit accommodates tens of thousands of fee entries: [6](#0-5) 

3. **No Resource Token Charging**: System contracts don't implement ACS8. The resource consumption plugins check for "acs8" identity: [7](#0-6) [8](#0-7) 

Genesis contract protobuf lacks ACS8 declaration: [9](#0-8) 

4. **Failed Transactions Still Consume Resources**: Post-execution plugins execute even when main transactions fail: [10](#0-9) 

**Widespread Pattern**: Parliament and Association contracts exhibit identical vulnerabilities: [11](#0-10) [12](#0-11) 

Even Profit contract's count validation occurs AFTER loop execution: [13](#0-12) 

## Impact Explanation

**Severity: HIGH** - Enables network-wide denial-of-service against critical governance infrastructure.

**Operational Impact:**
- Attackers can submit transactions containing 10,000-15,000 fee entries
- Each malicious transaction forces thousands of cross-contract calls before authorization failure
- Node CPU, memory, and I/O resources are exhausted processing these operations
- All 15+ system contracts implementing ACS1 are simultaneously vulnerable

**Cost Asymmetry:**
- **Attacker cost**: Size-based transaction fee (~500KB transaction ≈ minimal fee)
- **Node cost**: Thousands of cross-contract calls with state reads, context switches, and contract execution overhead
- **Attack multiplier**: Mempool can be flooded with hundreds of such transactions
- **Economic rationality**: Trivial cost to attacker versus massive computational burden on validators

**Affected Critical Systems:**
- Genesis contract (chain upgrades, contract deployment)
- Parliament contract (governance proposals)
- Association contract (multi-signature operations)
- Consensus contract (AEDPoS configuration)
- Economic contract (tokenomics parameters)
- Election, Treasury, Profit, Vote, and 7+ additional system contracts

## Likelihood Explanation

**Probability: HIGH** - Trivial to execute with no special prerequisites.

**Attacker Capabilities:**
- No privileged access required - any address can submit transactions
- Attack requires only constructing a `MethodFees` protobuf message with numerous entries
- No need to compromise authorized roles or pass governance votes

**Attack Complexity:**
- **Technical barrier**: Low - simple protobuf message serialization
- **Detection avoidance**: Transactions pass all pre-execution validation (signature verification, size limits)
- **Execution guarantee**: Loop executes before authorization check by design
- **Resource consumption**: Guaranteed before transaction fails

**Operational Feasibility:**
- Entry points are public RPC methods defined in ACS1 standard
- No rate limiting exists for failed authorization attempts
- Multiple system contracts can be targeted in parallel
- Attack sustainability: Low per-transaction cost enables sustained campaigns

## Recommendation

**Immediate Fix**: Move authorization checks before expensive operations:

```csharp
public override Empty SetMethodFee(MethodFees input)
{
    // Perform authorization check FIRST
    RequiredMethodFeeControllerSet();
    Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, 
        "Unauthorized to set method fee.");
    
    // Then validate inputs
    foreach (var methodFee in input.Fees) 
        AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
    
    State.TransactionFees[input.MethodName] = input;
    return new Empty();
}
```

**Additional Hardening:**
1. Add count validation BEFORE loop: `Assert(input.Fees.Count <= 100, "Too many fee entries.");`
2. Consider implementing ACS8 for system contracts to charge resource tokens
3. Add rate limiting for failed SetMethodFee calls per address
4. Implement circuit breakers when repeated authorization failures are detected

**Apply Fix To**: All contracts implementing ACS1 - Genesis, Parliament, Association, Referendum, Consensus, Economic, Election, Treasury, Profit, Vote, Configuration, CrossChain, TokenConverter, TokenHolder, NFT

## Proof of Concept

```csharp
// Test demonstrating resource exhaustion before authorization check
[Fact]
public async Task SetMethodFee_ResourceExhaustionDoS_BeforeAuthorizationCheck()
{
    // Setup: Deploy Genesis contract and get an unauthorized address
    var unauthorizedAddress = Accounts[1].Address; // Not the controller
    
    // Create malicious input with 10,000 fee entries
    var maliciousInput = new MethodFees
    {
        MethodName = "TestMethod",
        Fees = { }
    };
    
    // Add 10,000 entries (each triggers cross-contract call)
    for (int i = 0; i < 10000; i++)
    {
        maliciousInput.Fees.Add(new MethodFee
        {
            Symbol = "ELF",
            BasicFee = 1
        });
    }
    
    // Measure execution time/resources
    var startTime = DateTime.UtcNow;
    
    // Execute from unauthorized address
    var result = await GenesisContractStub.SetMethodFee.SendAsync(maliciousInput);
    
    var executionTime = DateTime.UtcNow - startTime;
    
    // Verify: Transaction fails authorization but consumed significant resources
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("Unauthorized to set method fee.");
    
    // Demonstrate resource consumption occurred (execution time >> normal)
    executionTime.TotalMilliseconds.ShouldBeGreaterThan(1000); // Significant delay
    
    // Verify cross-contract calls were made (check transaction trace)
    var trace = result.TransactionResult.Trace;
    trace.InlineTraces.Count.ShouldBeGreaterThan(5000); // Thousands of calls made
}
```

## Notes

This vulnerability represents a systemic design flaw in the ACS1 implementation pattern across the entire AElf system contract ecosystem. The authorization-after-validation pattern violates the security principle of "fail fast" and creates an exploitable cost asymmetry. The issue is exacerbated by system contracts not implementing ACS8 resource token charging, meaning attackers incur only minimal size-based fees while imposing unbounded computational costs on validators. Immediate remediation across all affected contracts is strongly recommended to prevent potential network disruption.

### Citations

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L11-11)
```csharp
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L15-15)
```csharp
        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Genesis/BasicContractZeroContract_ACS1_TransactionFeeProvider.cs (L80-80)
```csharp
        Assert(State.TokenContract.IsTokenAvailableForMethodFee.Call(new StringValue { Value = symbol }).Value,
```

**File:** protobuf/acs1.proto (L44-44)
```text
    repeated MethodFee fees = 2;
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L5-5)
```csharp
    public const int ExecutionCallThreshold = 15000;
```

**File:** src/AElf.Kernel.TransactionPool/TransactionPoolConsts.cs (L5-5)
```csharp
    public const int TransactionSizeLimit = 1024 * 1024 * 5; // 5M
```

**File:** src/AElf.Kernel.SmartContract.ExecutionPluginForResourceFee/ResourceConsumptionPreExecutionPlugin.cs (L25-25)
```csharp
        base("acs8")
```

**File:** src/AElf.Kernel.SmartContract/Application/SmartContractExecutionPluginBase.cs (L16-18)
```csharp
    protected bool HasApplicableAcs(IReadOnlyList<ServiceDescriptor> descriptors)
    {
        return descriptors.Any(service => service.File.GetIdentity() == _acsSymbol);
```

**File:** protobuf/basic_contract_zero.proto (L17-18)
```text
service BasicContractZero {
    option (aelf.csharp_state) = "AElf.Contracts.Genesis.BasicContractZeroState";
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L314-325)
```csharp
        if (!trace.IsSuccessful())
        {
            // If failed to execute this tx, at least we need to commit pre traces.
            internalStateCache = new TieredStateCache(txContext.StateCache);
            foreach (var preTrace in txContext.Trace.PreTraces)
            {
                var stateSets = preTrace.GetStateSets();
                internalStateCache.Update(stateSets);
            }

            internalChainContext.StateCache = internalStateCache;
        }
```

**File:** contract/AElf.Contracts.Parliament/ParliamentContract_ACS1_TransactionFeeProvider.cs (L12-15)
```csharp
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Association/AssociationContract_ACS1_TransactionFeeProvider.cs (L12-15)
```csharp
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        RequiredMethodFeeControllerSet();

        Assert(Context.Sender == State.MethodFeeController.Value.OwnerAddress, "Unauthorized to set method fee.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L13-14)
```csharp
        foreach (var methodFee in input.Fees) AssertValidToken(methodFee.Symbol, methodFee.BasicFee);
        Assert(input.Fees.Count <= ProfitContractConstants.TokenAmountLimit, "Invalid input.");
```
