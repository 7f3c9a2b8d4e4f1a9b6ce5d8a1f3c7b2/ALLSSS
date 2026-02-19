# Audit Report

## Title
Missing Authorization Check in MigrateConnectorTokens Allows Unauthorized Connector State Migration

## Summary
The `MigrateConnectorTokens()` function lacks the required authorization check that all other connector management operations enforce, allowing any user to trigger a one-time connector token naming migration. This breaks the established authorization pattern where connector controller approval is required for all connector management operations.

## Finding Description

The `MigrateConnectorTokens()` function is missing the authorization check that restricts access to the connector controller. [1](#0-0) 

All other connector management functions enforce authorization by calling `AssertPerformedByConnectorController()`: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

The authorization helper validates that the sender is the connector controller's owner address: [6](#0-5) 

The function is exposed as a public RPC method: [7](#0-6) 

Test cases demonstrate the function can be called without authorization, with only a duplicate migration check: [8](#0-7) [9](#0-8) 

In contrast, other connector management functions have authorization tests verifying unauthorized calls are rejected: [10](#0-9) [11](#0-10) 

## Impact Explanation

This vulnerability allows unauthorized modification of connector state, breaking the fundamental security invariant that only the connector controller (defaulting to Parliament governance) should manage connector configurations.

The migration operation modifies critical connector state including `RelatedSymbol` fields and deposit balance mappings. [12](#0-11) 

While test evidence shows that Buy and Sell operations continue functioning correctly after migration [13](#0-12) [14](#0-13) , the unauthorized access represents an operational security risk where:

1. **Premature Migration**: An attacker could trigger migration before governance intends, disrupting planned operational timelines
2. **Governance Bypass**: Violates the authorization pattern that requires Parliament approval for connector management
3. **Operational Disruption**: Unexpected state changes could interfere with monitoring, tooling, or planned maintenance windows

The impact is primarily **unauthorized configuration change** rather than direct fund loss, as the migration itself is functionally correct when executed.

## Likelihood Explanation

The likelihood is **CERTAIN** because:
- Any account can call the public RPC method with no authorization required
- No special preconditions, state requirements, or economic costs beyond transaction fees
- The vulnerability is directly exploitable via a single transaction
- No compensating controls exist in the contract design

The only protection is a duplicate migration check preventing the operation from being called twice with the new prefix pattern. [15](#0-14) 

## Recommendation

Add the authorization check at the beginning of the `MigrateConnectorTokens` function to match the pattern used by all other connector management operations:

```csharp
public override Empty MigrateConnectorTokens(Empty input)
{
    AssertPerformedByConnectorController();  // Add this line
    
    foreach (var resourceTokenSymbol in Context.Variables.GetStringArray(PayTxFeeSymbolListName)
                 .Union(Context.Variables.GetStringArray(PayRentalSymbolListName)))
    {
        // ... rest of the function
    }
    
    return new Empty();
}
```

Additionally, add an authorization test case following the pattern of other connector management tests to verify unauthorized calls are properly rejected.

## Proof of Concept

```csharp
[Fact]
public async Task MigrateConnectorTokens_Without_Authority_Should_Fail()
{
    await CreateWriteToken();
    await InitializeTreasuryContractAsync();
    await InitializeTokenConverterContract();
    await PrepareToBuyAndSell();
    
    // Attempt to call MigrateConnectorTokens without authorization
    // This should fail with "Only manager can perform this action." but currently succeeds
    var result = await DefaultStub.MigrateConnectorTokens.SendAsync(new Empty());
    
    // Currently this succeeds (vulnerability)
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // After fix, this should fail:
    // result.TransactionResult.Error.ShouldContain("Only manager can perform this action.");
}
```

## Notes

This vulnerability represents a **MEDIUM to HIGH severity access control bypass** rather than a critical fund-loss issue. The missing authorization check violates the consistent authorization pattern enforced across all other connector management operations. While the migration operation itself functions correctly (as proven by tests), allowing unauthorized actors to trigger it breaks the governance model's security guarantees.

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

**File:** test/AElf.Contracts.TokenConverter.Tests/ConnectorTokenMigrateTest.cs (L37-44)
```csharp
        var buyResult = (await DefaultStub.Buy.SendAsync(
            new BuyInput
            {
                Symbol = WriteConnector.Symbol,
                Amount = 1000L,
                PayLimit = amountToPay + fee + 10L
            })).TransactionResult;
        buyResult.Status.ShouldBe(TransactionResultStatus.Mined);
```

**File:** test/AElf.Contracts.TokenConverter.Tests/ConnectorTokenMigrateTest.cs (L112-118)
```csharp
        var sellResult = (await DefaultStub.Sell.SendAsync(new SellInput
        {
            Symbol = WriteConnector.Symbol,
            Amount = 1000L,
            ReceiveLimit = amountToReceive - fee - 10L
        })).TransactionResult;
        sellResult.Status.ShouldBe(TransactionResultStatus.Mined);
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

**File:** test/AElf.Contracts.TokenConverter.Tests/TokenConvertConnectorTest.cs (L240-251)
```csharp
    public async Task SetFeeRate_Test()
    {
        //not controller
        {
            var setFeeRateRet =
                await DefaultStub.SetFeeRate.SendWithExceptionAsync(
                    new StringValue
                    {
                        Value = "0.5"
                    });
            setFeeRateRet.TransactionResult.Error.ShouldContain("Only manager can perform this action.");
        }
```
