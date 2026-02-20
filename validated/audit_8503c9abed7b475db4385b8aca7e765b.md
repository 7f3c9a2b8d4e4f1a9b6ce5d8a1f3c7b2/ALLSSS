# Audit Report

## Title
Unbounded Scheme Creation Leading to State Bloat and DoS in TokenHolder Contract

## Summary
The `CreateScheme` method in TokenHolderContract allows any caller to repeatedly create unlimited profit schemes without validation, causing each invocation to create a new scheme in ProfitContract with permanent storage. This results in unbounded state growth and potential denial-of-service when TokenHolder operations query the accumulated scheme IDs.

## Finding Description

The `CreateScheme` method lacks validation to prevent duplicate scheme creation and unconditionally calls ProfitContract to create new schemes. [1](#0-0) 

When TokenHolderContract calls `State.ProfitContract.CreateScheme.Send()` without setting a `Token` field, ProfitContract generates unique scheme IDs using `Context.GenerateId(Context.Self, createdSchemeCount.ToBytes(false))` where `createdSchemeCount` equals the current array size, ensuring each invocation creates a distinct scheme. [2](#0-1) 

Each created scheme is permanently stored in `State.SchemeInfos[schemeId]` and the scheme ID is appended to `State.ManagingSchemeIds[manager].SchemeIds` without any cleanup mechanism. [3](#0-2) 

The duplicate check at line 59 only prevents creating the same scheme ID twice, but since each call generates a new unique ID based on the incrementing count, this protection never triggers. [4](#0-3) 

When TokenHolderContract methods need the scheme ID, they call `GetManagingSchemeIds` and take only the first result via `FirstOrDefault()`, meaning all subsequently created schemes become orphaned but remain in permanent storage. [5](#0-4) 

## Impact Explanation

**State Database Bloat**: Each scheme creates a `Scheme` object in permanent storage containing virtual address, manager, scheme ID, current period, total shares, and configuration fields. The scheme ID is also permanently appended to the `ManagingSchemeIds` array with no upper bound.

**Denial of Service**: Critical TokenHolder operations (AddBeneficiary, RemoveBeneficiary, ContributeProfits, RegisterForProfits, Withdraw, ClaimProfits) all call `UpdateTokenHolderProfitScheme`, which executes a cross-contract call to `GetManagingSchemeIds`. [6](#0-5) 

As the scheme array grows to hundreds or thousands of entries, this cross-contract call during transaction execution consumes excessive gas, potentially exceeding block gas limits and causing legitimate operations to fail. This DoS affects all TokenHolder functionality for the targeted manager address.

**Severity**: Medium to High - While transaction fees provide an economic barrier, a determined attacker with sufficient funds can render TokenHolder functionality unusable for their own address or grief the system with sustained state bloat.

## Likelihood Explanation

**No Authorization Required**: The `CreateScheme` method is publicly accessible as an override of the proto-defined interface with no authorization checks in the implementation.

**Economic Feasibility**: Transaction fees via ACS1 provide the only cost barrier. [7](#0-6) 

If fees are set low or an attacker has sufficient funds, they can create hundreds or thousands of schemes by spreading transactions across multiple blocks to bypass per-block gas limits. The attack cost scales linearly while the impact compounds with each additional scheme.

**Probability**: Medium - Simple to execute via repeated transaction submission, limited primarily by economic costs rather than technical barriers.

## Recommendation

Add a validation check in `TokenHolderContract.CreateScheme` to prevent creating multiple schemes for the same manager:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Check if scheme already exists
    var existingScheme = State.TokenHolderProfitSchemes[Context.Sender];
    Assert(existingScheme == null || existingScheme.SchemeId == null, 
        "Scheme already exists for this manager.");
    
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

Alternatively, implement a scheme limit per manager in ProfitContract or add a cleanup mechanism for orphaned schemes.

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_Unbounded_StateBlat_Test()
{
    // Create multiple schemes from the same manager
    const int schemeCount = 100;
    
    for (int i = 0; i < schemeCount; i++)
    {
        await TokenHolderContractStub.CreateScheme.SendAsync(
            new CreateTokenHolderProfitSchemeInput
            {
                Symbol = "ELF",
                MinimumLockMinutes = 1
            });
    }
    
    // Verify all schemes were created in ProfitContract
    var managingSchemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = Starter });
    
    // Should have 100+ schemes (including any from setup)
    managingSchemeIds.SchemeIds.Count.ShouldBeGreaterThanOrEqualTo(schemeCount);
    
    // But TokenHolderContract only references the first one
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(Starter);
    await TokenHolderContractStub.ContributeProfits.SendAsync(new ContributeProfitsInput
    {
        SchemeManager = Starter,
        Symbol = "ELF",
        Amount = 1
    });
    
    // Verify only the first scheme is updated, others are orphaned
    var firstScheme = await ProfitContractStub.GetScheme.CallAsync(
        managingSchemeIds.SchemeIds.First());
    var lastScheme = await ProfitContractStub.GetScheme.CallAsync(
        managingSchemeIds.SchemeIds.Last());
    
    // First scheme has contributions, last scheme is empty (orphaned)
    var firstBalance = (await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput 
        { 
            Owner = firstScheme.VirtualAddress, 
            Symbol = "ELF" 
        })).Balance;
    var lastBalance = (await TokenContractStub.GetBalance.CallAsync(
        new GetBalanceInput 
        { 
            Owner = lastScheme.VirtualAddress, 
            Symbol = "ELF" 
        })).Balance;
    
    firstBalance.ShouldBeGreaterThan(0);
    lastBalance.ShouldBe(0); // Orphaned scheme never receives contributions
    
    // Demonstrate state bloat: array has grown unboundedly
    managingSchemeIds.SchemeIds.Count.ShouldBe(schemeCount);
}
```

## Notes

This vulnerability represents a design flaw where TokenHolderContract's local state management is inconsistent with ProfitContract's scheme storage model. The overwriting behavior in TokenHolderContract (line 27) combined with the append-only behavior in ProfitContract creates orphaned schemes that accumulate indefinitely. The economic barrier of transaction fees provides only partial mitigation, as a sufficiently funded attacker can still cause significant operational degradation.

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

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L286-299)
```csharp
    private void UpdateTokenHolderProfitScheme(ref TokenHolderProfitScheme scheme, Address manager,
        bool updateSchemePeriod)
    {
        if (scheme.SchemeId != null && !updateSchemePeriod) return;
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
        Assert(originSchemeId != null, "Origin scheme not found.");
        var originScheme = State.ProfitContract.GetScheme.Call(originSchemeId);
        scheme.SchemeId = originScheme.SchemeId;
        scheme.Period = originScheme.CurrentPeriod;
        State.TokenHolderProfitSchemes[Context.Sender] = scheme;
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L56-71)
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
