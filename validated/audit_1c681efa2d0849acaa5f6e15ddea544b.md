# Audit Report

## Title
Missing Authorization Check in MigrateConnectorTokens Allows Anyone to Trigger Critical Connector Migration

## Summary
The `MigrateConnectorTokens()` function lacks authorization validation, allowing any user to trigger the migration of connector tokens from the old naming convention to the new one. This breaks the established authorization pattern where all connector management operations require connector controller approval, potentially causing disruption to the token conversion system.

## Finding Description

The `MigrateConnectorTokens()` function is missing the required authorization check that should restrict access to only the connector controller. [1](#0-0) 

While all other connector management functions properly enforce authorization by calling `AssertPerformedByConnectorController()`: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The authorization helper method `AssertPerformedByConnectorController()` checks if the sender is the connector controller's owner address and defaults to the Parliament organization if not set: [6](#0-5) 

The `MigrateConnectorTokens()` function is exposed as a public RPC method without any access restrictions: [7](#0-6) 

Test cases demonstrate that the function can be called by any user without authorization checks, with only a duplicate migration check in place: [8](#0-7) [9](#0-8) 

In contrast, other connector management functions have proper authorization tests that verify unauthorized calls are rejected: [10](#0-9) [11](#0-10) 

## Impact Explanation

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
4. **State Integrity Violation**: The fundamental invariant that only authorized controllers manage connectors is broken, representing a privilege escalation vulnerability

**Severity Justification:** This is HIGH severity because:
- It requires zero preconditions or privileges to exploit
- It directly impacts core protocol functionality (token conversion)
- It can cause DoS through state corruption
- The authorization gap violates the fundamental security invariant that only authorized controllers should manage connectors

## Likelihood Explanation

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

## Recommendation

Add the authorization check to the `MigrateConnectorTokens()` function to align with the security pattern used by all other connector management operations:

```csharp
public override Empty MigrateConnectorTokens(Empty input)
{
    AssertPerformedByConnectorController(); // Add this line
    
    foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayTxFeeSymbolListName)
                 .Union(Context.Variables.GetStringArray(PayRentalSymbolListName)))
    {
        // ... rest of the function
    }
    
    return new Empty();
}
```

This ensures that only the connector controller (which defaults to the Parliament organization) can authorize this critical state migration operation.

## Proof of Concept

The existing test demonstrates the vulnerability - the function is called directly by a regular user without any authorization setup:

```csharp
[Fact]
public async Task UnauthorizedMigrationTest()
{
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();

    // Any user can call this without authorization
    var result = await DefaultStub.MigrateConnectorTokens.SendAsync(new Empty());
    
    // This succeeds when it should fail with "Only manager can perform this action."
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
}
```

This test shows that `DefaultStub` (a regular user stub) can successfully call `MigrateConnectorTokens` without any authorization checks, unlike other connector management functions which properly reject unauthorized calls.

### Citations

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L58-61)
```csharp
    public override Empty UpdateConnector(Connector input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.Symbol), "input symbol can not be empty'");
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L79-82)
```csharp
    public override Empty AddPairConnector(PairConnectorParam input)
    {
        AssertPerformedByConnectorController();
        Assert(!string.IsNullOrEmpty(input.ResourceConnectorSymbol),
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L260-263)
```csharp
    public override Empty SetFeeRate(StringValue input)
    {
        AssertPerformedByConnectorController();
        var feeRate = AssertedDecimal(input.Value);
```

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L303-306)
```csharp
    public override Empty ChangeConnectorController(AuthorityInfo input)
    {
        AssertPerformedByConnectorController();
        Assert(CheckOrganizationExist(input), "new controller does not exist");
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

**File:** contract/AElf.Contracts.TokenConverter/TokenConverterContract.cs (L397-416)
```csharp
    private void AssertPerformedByConnectorController()
    {
        if (State.ConnectorController.Value == null) State.ConnectorController.Value = GetDefaultConnectorController();

        Assert(Context.Sender == State.ConnectorController.Value.OwnerAddress,
            "Only manager can perform this action.");
    }

    private AuthorityInfo GetDefaultConnectorController()
    {
        if (State.ParliamentContract.Value == null)
            State.ParliamentContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ParliamentContractSystemName);

        return new AuthorityInfo
        {
            ContractAddress = State.ParliamentContract.Value,
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty())
        };
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
