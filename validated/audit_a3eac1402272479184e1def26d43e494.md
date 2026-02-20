# Audit Report

## Title
Unbounded Scheme Creation Leading to State Bloat and DoS in TokenHolder Contract

## Summary
The `CreateScheme` function in TokenHolderContract allows any caller to repeatedly create unlimited profit schemes without validation. Each invocation creates a new `Scheme` object in ProfitContract with permanent storage, causing unbounded state growth and enabling state bloat attacks that degrade node performance through accumulated storage and increasingly large query responses.

## Finding Description

The `CreateScheme` method in TokenHolderContract unconditionally delegates to ProfitContract without checking if the caller already has an existing scheme. [1](#0-0) 

When TokenHolderContract calls `State.ProfitContract.CreateScheme.Send()` with no `Token` parameter, the ProfitContract generates scheme IDs using a count-based mechanism where `createdSchemeCount` is derived from the current size of `State.ManagingSchemeIds[manager].SchemeIds.Count`. [2](#0-1) 

This count-based generation ensures each invocation produces a unique scheme ID (hash of count 0, 1, 2, 3...), and each scheme is permanently stored in `State.SchemeInfos[schemeId]` while its ID is appended to the `State.ManagingSchemeIds[manager].SchemeIds` array. [3](#0-2) 

The ProfitContract's test suite explicitly validates that creating multiple schemes from the same manager is supported functionality ("Of course it's okay for an address to create many profit schemes"), confirming this execution path is valid and intentional for ProfitContract itself. [4](#0-3) 

However, TokenHolderContract only tracks a single scheme per address in `State.TokenHolderProfitSchemes[Context.Sender]`, which gets overwritten on each call. This design mismatch means repeated calls create orphaned schemes in ProfitContract that consume permanent storage but serve no purpose for TokenHolder functionality.

## Impact Explanation

**State Database Bloat**: Each scheme creation stores a complete `Scheme` object (containing virtual address, manager, scheme ID, current period, total shares, profit receiving due period count, delay distribute period count, and other fields) in permanent contract state. [5](#0-4) 

Additionally, each 32-byte scheme ID is permanently appended to the `ManagingSchemeIds` array with no cleanup mechanism, causing unbounded linear growth. [6](#0-5) 

**DoS of Query Operations**: The `GetManagingSchemeIds` view method returns the complete array of all scheme IDs for a given manager. [7](#0-6)  As schemes accumulate into the hundreds or thousands, this query returns increasingly large responses, degrading node performance and potentially causing RPC timeouts or memory exhaustion.

**Operational Degradation**: Over time, the accumulated state bloat increases disk usage, slows state reads, and impacts overall node synchronization and query performance.

**Severity Assessment**: Medium - While there is no direct fund loss or critical system failure, the unbounded nature of the vulnerability allows sustained operational degradation. Transaction fees provide economic barriers but do not prevent determined attackers with sufficient resources from causing significant infrastructure impact.

## Likelihood Explanation

**No Authorization Required**: The `CreateScheme` method is a public function with no authorization checks, role requirements, or preconditions. [8](#0-7)  Any address can invoke this method repeatedly.

**Simple Execution**: The attack requires only repeated invocations of a single public method with valid input parameters. No complex state setup, timing constraints, or coordinated actions are needed.

**Economic Barriers**: The contract implements ACS1 transaction fee standards, [9](#0-8)  meaning fees can be configured via governance. However, if fees are set low relative to attacker resources, or if the attacker has substantial funding, they can create hundreds or thousands of schemes across multiple blocks to bypass per-block gas limits.

**Probability**: Medium - The attack is trivial to execute technically but requires sustained transaction fee expenditure. The cost scales linearly with the number of schemes created, making it economically feasible for well-funded attackers but providing some deterrence.

## Recommendation

Add a validation check in `TokenHolderContract.CreateScheme` to prevent duplicate scheme creation:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Check if scheme already exists for this sender
    var existingScheme = State.TokenHolderProfitSchemes[Context.Sender];
    Assert(existingScheme == null || existingScheme.Symbol == null, 
           "Scheme already exists for this address.");
    
    if (State.ProfitContract.Value == null)
        State.ProfitContract.Value =
            Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

    State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
    {
        Manager = Context.Sender,
        IsReleaseAllBalanceEveryTimeByDefault = true,
        CanRemoveBeneficiaryDirectly = true
    });

    State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
    {
        Symbol = input.Symbol,
        MinimumLockMinutes = input.MinimumLockMinutes,
        AutoDistributeThreshold = { input.AutoDistributeThreshold }
    };

    return new Empty();
}
```

This prevents repeated scheme creation while preserving the intended one-scheme-per-address design of TokenHolderContract.

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_UnboundedCreation_StateBloa()
{
    const int createTimes = 100;
    
    // Attacker repeatedly calls CreateScheme
    for (var i = 0; i < createTimes; i++)
    {
        var result = await TokenHolderContractStub.CreateScheme.SendAsync(
            new CreateTokenHolderProfitSchemeInput
            {
                Symbol = "ELF"
            });
        result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    }
    
    // Verify all schemes were created in ProfitContract
    var managingSchemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    
    // State bloat: 100+ schemes stored permanently
    managingSchemeIds.SchemeIds.Count.ShouldBe(createTimes);
    
    // Only last scheme tracked by TokenHolder (99 orphaned)
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    tokenHolderScheme.Symbol.ShouldBe("ELF");
    
    // Query DoS: GetManagingSchemeIds returns large array
    // With thousands of schemes, this causes performance degradation
}
```

## Notes

The vulnerability exists at the integration layer between TokenHolderContract and ProfitContract. ProfitContract is designed to support multiple schemes per manager (as evidenced by its test suite), but TokenHolderContract's design assumes one scheme per address. This architectural mismatch, combined with the lack of duplicate checking, enables the state bloat attack. The transaction fee mechanism (ACS1) provides economic disincentive but is governance-configurable and may not be set high enough to prevent well-funded attackers.

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-35)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
    {
        if (State.ProfitContract.Value == null)
            State.ProfitContract.Value =
                Context.GetContractAddressByName(SmartContractConstants.ProfitContractSystemName);

        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });

        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };

        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-72)
```csharp
        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
        State.SchemeInfos[schemeId] = scheme;

        var schemeIds = State.ManagingSchemeIds[scheme.Manager];
        if (schemeIds == null)
            schemeIds = new CreatedSchemeIds
            {
                SchemeIds = { schemeId }
            };
        else
            schemeIds.SchemeIds.Add(schemeId);

        State.ManagingSchemeIds[scheme.Manager] = schemeIds;

```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L938-954)
```csharp
    private Scheme GetNewScheme(CreateSchemeInput input, Hash schemeId, Address manager)
    {
        var scheme = new Scheme
        {
            SchemeId = schemeId,
            // The address of general ledger for current profit scheme.
            VirtualAddress = Context.ConvertVirtualAddressToContractAddress(schemeId),
            Manager = manager,
            ProfitReceivingDuePeriodCount = input.ProfitReceivingDuePeriodCount,
            CurrentPeriod = 1,
            IsReleaseAllBalanceEveryTimeByDefault = input.IsReleaseAllBalanceEveryTimeByDefault,
            DelayDistributePeriodCount = input.DelayDistributePeriodCount,
            CanRemoveBeneficiaryDirectly = input.CanRemoveBeneficiaryDirectly
        };

        return scheme;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L964-971)
```csharp
    private Hash GenerateSchemeId(CreateSchemeInput createSchemeInput)
    {
        var manager = createSchemeInput.Manager ?? Context.Sender;
        if (createSchemeInput.Token != null)
            return Context.GenerateId(Context.Self, createSchemeInput.Token);
        var createdSchemeCount = State.ManagingSchemeIds[manager]?.SchemeIds.Count ?? 0;
        return Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false));
    }
```

**File:** test/AElf.Contracts.Profit.Tests/ProfitTests.cs (L14-40)
```csharp
    /// <summary>
    /// Of course it's okay for an address to creator many profit schemes.
    /// </summary>
    /// <returns></returns>
    [Fact]
    public async Task ProfitContract_CreateManyProfitItems_Test()
    {
        const int createTimes = 5;

        var creator = Creators[0];
        var creatorAddress = Address.FromPublicKey(CreatorKeyPair[0].PublicKey);

        for (var i = 0; i < createTimes; i++)
        {
            var executionResult = await creator.CreateScheme.SendAsync(new CreateSchemeInput
            {
            });
            executionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
        }

        var createdSchemeIds = await creator.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
        {
            Manager = creatorAddress
        });

        createdSchemeIds.SchemeIds.Count.ShouldBe(createTimes);
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract_ACS1_TransactionFeeProvider.cs (L11-20)
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
