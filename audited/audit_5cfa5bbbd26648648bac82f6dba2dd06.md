### Title
Missing Authorization Check in MigrateConnectorTokens Allows Anyone to Trigger Critical Connector Migration

### Summary
The `MigrateConnectorTokens()` function lacks authorization validation, allowing any user to trigger the migration of connector tokens from the old naming convention to the new one. This breaks the established authorization pattern where all connector management operations require connector controller approval, potentially causing disruption to the token conversion system and loss of funds.

### Finding Description

The `MigrateConnectorTokens()` function is missing the required authorization check that should restrict access to only the connector controller. [1](#0-0) 

While all other connector management functions properly enforce authorization by calling `AssertPerformedByConnectorController()`: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The authorization helper method `AssertPerformedByConnectorController()` checks if the sender is the connector controller's owner address and defaults to the Parliament organization if not set: [6](#0-5) 

The `MigrateConnectorTokens()` function is exposed as a public RPC method without any access restrictions: [7](#0-6) 

Test cases demonstrate that the function can be called by any user without authorization checks, with only a duplicate migration check in place: [8](#0-7) [9](#0-8) 

In contrast, other connector management functions have proper authorization tests that verify unauthorized calls are rejected: [10](#0-9) [11](#0-10) 

### Impact Explanation

**Direct Operational Impact - DoS and State Corruption:**

The migration function modifies critical state that directly affects the Buy and Sell operations. When `MigrateConnectorTokens()` is called, it:

1. Updates the `RelatedSymbol` field of resource connectors to point to new connector token symbols
2. Creates new connector entries with renamed symbols in the state mapping
3. Migrates deposit balances to new keys

The Buy and Sell functions rely on these `RelatedSymbol` relationships to find connector pairs for Bancor pricing calculations: [12](#0-11) [13](#0-12) 

**Concrete Harm Scenarios:**

1. **Premature Migration**: An attacker can trigger migration before the system is ready, breaking active trading pairs and causing Buy/Sell operations to fail
2. **Deposit Balance Inconsistency**: The deposit balance accounting becomes corrupted as balances are migrated to new keys while old references may still exist
3. **DoS of Token Conversion**: Users cannot buy or sell tokens after unauthorized migration disrupts connector relationships
4. **Potential Fund Loss**: If migration occurs during active trading, the mismatch between actual token balances and deposit balance records could lead to locked funds

**Affected Parties:**
- All users attempting to buy or sell tokens through the TokenConverter
- The protocol itself loses functionality and trustworthiness
- Token holders may have funds locked in broken connector states

**Severity Justification:** This is CRITICAL because:
- It requires zero preconditions or privileges to exploit
- It directly impacts core protocol functionality (token conversion)
- It can cause loss of funds through deposit balance corruption
- The authorization gap violates the fundamental invariant that only authorized controllers should manage connectors

### Likelihood Explanation

**Attacker Capabilities Required:** 
- None. Any account can send a transaction to the public `MigrateConnectorTokens()` method.

**Attack Complexity:**
- Trivial. Single transaction call with empty input parameter.

**Feasibility Conditions:**
- The function is always callable as a public RPC method with no preconditions
- No special state requirements or timing constraints
- No economic cost beyond transaction fees (negligible)

**Detection/Operational Constraints:**
- The vulnerability is exploitable immediately upon deployment
- No detection mechanisms exist since the function lacks access control
- The only barrier is the duplicate migration check, which only prevents calling with the new prefix pattern twice, but does NOT prevent the first unauthorized call

**Probability Assessment:**
- **CERTAIN** - The vulnerability is directly exploitable by any user at any time
- The test suite proves the function works without authorization
- No compensating controls exist in the contract design

### Recommendation

**Immediate Fix:**

Add the authorization check at the beginning of `MigrateConnectorTokens()` function:

```csharp
public override Empty MigrateConnectorTokens(Empty input)
{
    AssertPerformedByConnectorController(); // ADD THIS LINE
    foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayTxFeeSymbolListName)
                 .Union(Context.Variables.GetStringArray(PayRentalSymbolListName)))
    {
        // ... rest of function
    }
}
```

**Invariant Checks to Add:**

1. Enforce that `MigrateConnectorTokens()` can only be called by the connector controller
2. Add comprehensive authorization tests similar to existing connector management tests
3. Consider adding a migration state flag to ensure migration can only happen once per deployment lifecycle

**Test Cases to Prevent Regression:**

Add test case `MigrateConnectorTokens_Without_Authority_Test`:
```csharp
[Fact]
public async Task MigrateConnectorTokens_Without_Authority_Test()
{
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    var migrateResult = await DefaultStub.MigrateConnectorTokens.SendWithExceptionAsync(new Empty());
    migrateResult.TransactionResult.Error.ShouldContain("Only manager can perform this action.");
}
```

Add test case `MigrateConnectorTokens_With_Authority_Test`:
```csharp
[Fact]
public async Task MigrateConnectorTokens_With_Authority_Test()
{
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    await ExecuteProposalForParliamentTransaction(
        TokenConverterContractAddress,
        nameof(TokenConverterContractImplContainer.TokenConverterContractImplStub.MigrateConnectorTokens),
        new Empty());
    
    // Verify migration succeeded
    var connector = await DefaultStub.GetPairConnector.CallAsync(new TokenSymbol { Symbol = WriteSymbol });
    connector.DepositConnector.Symbol.ShouldStartWith("(NT)");
}
```

### Proof of Concept

**Required Initial State:**
- TokenConverter contract deployed and initialized
- At least one connector pair created and enabled for a resource token (e.g., WRITE)
- Active deposit balances in the system

**Exploitation Steps:**

1. **Attacker calls MigrateConnectorTokens without authorization:**
   ```
   Transaction: TokenConverterContract.MigrateConnectorTokens(Empty)
   Sender: Any arbitrary account (no privileges required)
   ```

2. **Function executes without authorization check:**
   - Iterates through all resource tokens in PayTxFeeSymbolListName and PayRentalSymbolListName
   - Modifies `Connectors[resourceTokenSymbol].RelatedSymbol` to new naming convention
   - Creates new connector entries with renamed symbols
   - Migrates deposit balances to new keys

3. **Subsequent Buy/Sell operations fail or behave incorrectly:**
   - Buy transactions may fail to find the correct connector pair
   - Sell transactions may use wrong pricing due to broken RelatedSymbol references
   - Deposit balance accounting becomes inconsistent

**Expected vs Actual Result:**

**Expected:** Transaction should FAIL with "Only manager can perform this action." error

**Actual:** Transaction SUCCEEDS and migrates all connector tokens, regardless of caller identity

**Success Condition for Exploit:**
- The migration completes without any authorization error
- Connector state is modified by an unauthorized user
- Core token conversion functionality is disrupted

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-60)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-81)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L112-119)
```csharp
    public override Empty Buy(BuyInput input)
    {
        var toConnector = State.Connectors[input.Symbol];
        Assert(toConnector != null, "[Buy]Can't find to connector.");
        Assert(toConnector.IsPurchaseEnabled, "can't purchase");
        Assert(!string.IsNullOrEmpty(toConnector.RelatedSymbol), "can't find related symbol'");
        var fromConnector = State.Connectors[toConnector.RelatedSymbol];
        Assert(fromConnector != null, "[Buy]Can't find from connector.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L161-167)
```csharp
    public override Empty Sell(SellInput input)
    {
        var fromConnector = State.Connectors[input.Symbol];
        Assert(fromConnector != null, "[Sell]Can't find from connector.");
        Assert(fromConnector.IsPurchaseEnabled, "can't purchase");
        var toConnector = State.Connectors[fromConnector.RelatedSymbol];
        Assert(toConnector != null, "[Sell]Can't find to connector.");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L260-262)
```csharp
    public override Empty SetFeeRate(StringValue input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L303-305)
```csharp
    public override Empty ChangeConnectorController(AuthorityInfo input)
    {
        AssertPerformedByConnectorController();
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L311-342)
```csharp
    public override Empty MigrateConnectorTokens(Empty input)
    {
        foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayTxFeeSymbolListName)
                     .Union(Context.Variables.GetStringArray(PayRentalSymbolListName)))
        {
            var newConnectorTokenSymbol = NewNtTokenPrefix.Append(resourceTokenSymbol);

            if (State.Connectors[resourceTokenSymbol] == null)
            {
                continue;
            }

            var oldConnectorTokenSymbol = State.Connectors[resourceTokenSymbol].RelatedSymbol;

            Assert(!oldConnectorTokenSymbol.StartsWith(NewNtTokenPrefix), "Already migrated.");

            // Migrate

            State.Connectors[resourceTokenSymbol].RelatedSymbol = newConnectorTokenSymbol;

            if (State.Connectors[oldConnectorTokenSymbol] != null)
            {
                var connector = State.Connectors[oldConnectorTokenSymbol];
                connector.Symbol = newConnectorTokenSymbol;
                State.Connectors[newConnectorTokenSymbol] = connector;
            }

            State.DepositBalance[newConnectorTokenSymbol] = State.DepositBalance[oldConnectorTokenSymbol];
        }

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L397-403)
```csharp
    private void AssertPerformedByConnectorController()
    {
        if (State.ConnectorController.Value == null) State.ConnectorController.Value = GetDefaultConnectorController();

        Assert(Context.Sender == State.ConnectorController.Value.OwnerAddress,
            "Only manager can perform this action.");
    }
```

**File:** protobuf/token_converter_contract.proto (L55-56)
```text
    rpc MigrateConnectorTokens (google.protobuf.Empty) returns (google.protobuf.Empty) {
    }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/ConnectorTokenMigrateTest.cs (L14-21)
```csharp
    public async Task CanBuyResourceTokenAfterMigration()
    {
        await CreateWriteToken();
        await InitializeTreasuryContractAsync();
        await InitializeTokenConverterContract();
        await PrepareToBuyAndSell();

        await DefaultStub.MigrateConnectorTokens.SendAsync(new Empty());
```

**File:** test/AElf.Contracts.TokenConverter.Tests/ConnectorTokenMigrateTest.cs (L143-153)
```csharp
    public async Task MigrateTwiceTest()
    {
        await CreateWriteToken();
        await InitializeTreasuryContractAsync();
        await InitializeTokenConverterContract();
        await PrepareToBuyAndSell();

        await DefaultStub.MigrateConnectorTokens.SendAsync(new Empty());
        var result = await DefaultStub.MigrateConnectorTokens.SendWithExceptionAsync(new Empty());
        result.TransactionResult.Error.ShouldContain("Already migrated.");
    }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L116-125)
```csharp
    public async Task AddPairConnector_Without_Authority_Test()
    {
        var tokenSymbol = "NETT";
        var pairConnector = GetLegalPairConnectorParam(tokenSymbol);
        var addConnectorWithoutAuthorityRet =
            await DefaultStub.AddPairConnector.SendWithExceptionAsync(
                pairConnector);
        addConnectorWithoutAuthorityRet.TransactionResult.Error.ShouldContain(
            "Only manager can perform this action.");
    }
```

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L146-159)
```csharp
    public async Task UpdateConnector_Without_Authority_Test()
    {
        var tokenSymbol = "CWJ";
        await AddPairConnectorAsync(tokenSymbol);
        var updateConnector = new Connector
        {
            Symbol = tokenSymbol,
            Weight = "0.3"
        };
        var updateRet =
            await DefaultStub.UpdateConnector.SendWithExceptionAsync(
                updateConnector);
        updateRet.TransactionResult.Error.ShouldContain("Only manager can perform this action.");
    }
```
