# Audit Report

## Title
Authorization Bypass in CreateScheme Allows Attacker to Pollute Victim's Manager Scheme List Causing Bounded DoS

## Summary
The `CreateScheme` function in the Profit contract lacks authorization checks when accepting the `input.Manager` parameter, allowing any caller to designate an arbitrary address as the scheme manager without that address's consent. This enables an attacker to pollute a victim's managing scheme list up to the state size limit (~4000 schemes, 128KB), causing bounded DoS when querying `GetManagingSchemeIds` and violating the authorization invariant that users control their own manager role assignments.

## Finding Description

The root cause lies in the `CreateScheme` function's handling of the manager parameter. [1](#0-0)  The function directly assigns `input.Manager ?? Context.Sender` as the scheme manager without verifying that the caller (`Context.Sender`) is authorized to assign that specific manager address.

The vulnerable execution path proceeds as follows:
1. Attacker calls `CreateScheme` with `input.Manager` set to victim's address
2. The scheme is created with the victim as the manager [2](#0-1) 
3. The scheme ID is added to `State.ManagingSchemeIds[victim]` without any authorization check [3](#0-2) 

The function only validates the `ProfitReceivingDuePeriodCount` parameter and scheme uniqueness, performing no authorization check on the manager field assignment [4](#0-3) 

This design is inconsistent with all other manager-gated operations in the contract. Operations like `AddSubScheme` [5](#0-4) , `RemoveSubScheme` [6](#0-5) , `AddBeneficiary` [7](#0-6) , and `ResetManager` [8](#0-7)  all properly verify that `Context.Sender == scheme.Manager` before allowing management operations.

The attack is bounded by the state size limit of 128KB [9](#0-8) . Since each Hash is 32 bytes, this allows approximately 4096 schemes maximum per manager address before state writes fail (with protobuf overhead, closer to ~4000 in practice).

The `GetManagingSchemeIds` view method returns the entire list without pagination [10](#0-9) , meaning a victim's query can return up to ~4000 unwanted scheme IDs in a single 128KB response.

## Impact Explanation

**Authorization Violation**: The primary impact is a clear authorization bypass. The victim becomes the actual manager of schemes they never created or authorized. All manager-restricted operations will succeed if the victim calls them on these attacker-created schemes, meaning the victim has been forced into an unwanted management role with associated responsibilities.

**Bounded DoS Impact**: 
- The victim's `GetManagingSchemeIds` query returns up to ~4000 unwanted scheme IDs (128KB of data)
- Clients and applications processing this data experience degraded performance with memory and CPU overhead
- The victim's legitimate scheme management interface becomes polluted with attacker-created schemes
- Applications displaying scheme lists must process and render thousands of entries

**No Mitigation Available**: The victim cannot remove these unwanted schemes from their manager list. While they can use `ResetManager` to transfer management to another address, the pollution already occurred and the schemes existed in their list during the attack period.

**Severity Justification**: This qualifies as Medium severity due to:
1. Clear authorization bypass - fundamental security invariant violated
2. Bounded but significant DoS (128KB response, ~4000 schemes)
3. Practical exploitability with reasonable cost
4. Operational degradation rather than direct fund loss
5. No impact on consensus, cross-chain integrity, or protocol-level guarantees

## Likelihood Explanation

**Attacker Capabilities**: Any address with sufficient ELF tokens for transaction fees can execute this attack. No special permissions or trusted roles are required.

**Attack Complexity**: The attack is simple - repeatedly call `CreateScheme` with the victim's address as manager. Each call costs 10 ELF in transaction fees [11](#0-10) .

**Economic Feasibility**: 
- Maximum impact attack costs ~40,000 ELF (4000 schemes × 10 ELF)
- Smaller-scale attacks (100-500 schemes) cost 1,000-5,000 ELF and still cause noticeable degradation
- No rate limiting or scheme creation caps per manager exist

**Detection**: The attack is publicly visible on-chain, but the victim cannot prevent or reverse it once executed.

## Recommendation

Add an authorization check in the `CreateScheme` function to ensure that if a custom manager is specified, the caller must be authorized to assign that role. The recommended fix is:

```csharp
public override Hash CreateScheme(CreateSchemeInput input)
{
    ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);
    
    // Add authorization check when manager is specified
    if (input.Manager != null && input.Manager != Context.Sender)
    {
        Assert(false, "Cannot assign another address as manager without their consent.");
    }
    
    var manager = input.Manager ?? Context.Sender;
    // ... rest of the function
}
```

This ensures that only the transaction sender can become the manager, maintaining the authorization invariant that users control their own role assignments.

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_AuthorizationBypass_Test()
{
    var attacker = Creators[0];
    var victim = Creators[1];
    var victimAddress = Address.FromPublicKey(CreatorKeyPair[1].PublicKey);
    
    // Attacker creates a scheme with victim as manager
    var result = await attacker.CreateScheme.SendAsync(new CreateSchemeInput
    {
        Manager = victimAddress,
        ProfitReceivingDuePeriodCount = 100
    });
    
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);
    
    // Verify victim has unwanted scheme in their managing list
    var victimSchemes = await attacker.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = victimAddress });
    
    victimSchemes.SchemeIds.Count.ShouldBe(1);
    
    // Verify victim is the manager of the scheme they didn't create
    var scheme = await attacker.GetScheme.CallAsync(victimSchemes.SchemeIds[0]);
    scheme.Manager.ShouldBe(victimAddress);
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L48-60)
```csharp
        if (input.ProfitReceivingDuePeriodCount == 0)
            input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
        else
            Assert(
                input.ProfitReceivingDuePeriodCount > 0 &&
                input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
                "Invalid profit receiving due period count.");

        var schemeId = GenerateSchemeId(input);
        var manager = input.Manager ?? Context.Sender;
        var scheme = GetNewScheme(input, schemeId, manager);
        Assert(State.SchemeInfos[schemeId] == null, "Already exists.");
        State.SchemeInfos[schemeId] = scheme;
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L62-71)
```csharp
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

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L99-99)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can add sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L139-139)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only manager can remove sub-scheme.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L729-729)
```csharp
        Assert(Context.Sender == scheme.Manager, "Only scheme manager can reset manager.");
```

**File:** src/AElf.Kernel.SmartContract/SmartContractConstants.cs (L9-9)
```csharp
    public const int StateSizeLimit = 128 * 1024;
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L12-15)
```csharp
    public override CreatedSchemeIds GetManagingSchemeIds(GetManagingSchemeIdsInput input)
    {
        return State.ManagingSchemeIds[input.Manager];
    }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L47-47)
```csharp
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
```
