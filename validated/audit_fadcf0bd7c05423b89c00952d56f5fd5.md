# Audit Report

## Title
Authorization Bypass in CreateScheme Allows Attacker to Pollute Victim's Manager Scheme List Causing Bounded DoS

## Summary
The `CreateScheme` function in the Profit contract lacks authorization checks when setting an arbitrary address as the scheme manager. Any attacker can create schemes designating a victim as the manager without consent, polluting the victim's managing scheme list up to the state size limit of approximately 4000 schemes (128KB). This causes bounded DoS when querying `GetManagingSchemeIds`, degrading performance for victims and clients processing their scheme data.

## Finding Description
The vulnerability exists in the `CreateScheme` function where it accepts an arbitrary `input.Manager` parameter and assigns it as the scheme manager without verifying that the caller has authorization to do so. [1](#0-0) 

The function uses `input.Manager ?? Context.Sender`, accepting any address provided by the caller. There is no assertion like `Assert(manager == Context.Sender, ...)` to verify authorization.

The scheme ID is then added to the manager's list without any permission check: [2](#0-1) 

**Attack Execution Path:**
1. Attacker calls `CreateScheme` with `input.Manager` set to victim's address
2. The scheme is created with victim as manager without consent verification
3. The scheme ID is added to `State.ManagingSchemeIds[victim]` 
4. Attacker repeats this up to the state size limit

**Why Existing Protections Fail:**
The function only validates `ProfitReceivingDuePeriodCount` and scheme uniqueness: [3](#0-2) 

No authorization check exists on the manager field assignment.

**State Size Bound:**
The attack is bounded by AElf's state size limit of 128KB: [4](#0-3) 

Each Hash is 32 bytes, allowing approximately 4096 schemes maximum per manager address before state writes fail.

**Unbounded View Method:**
The `GetManagingSchemeIds` view method returns the entire list without pagination: [5](#0-4) 

This forces clients to process up to 128KB of data when querying a victim's schemes.

## Impact Explanation
**Operational DoS Impact:**
- Victim's `GetManagingSchemeIds` query returns up to ~4000 unwanted scheme IDs (128KB of data)
- Clients/nodes processing this data experience degraded performance with memory and CPU overhead
- The victim's legitimate scheme management interface becomes polluted with attacker-created schemes
- Applications displaying scheme lists must process and render thousands of malicious entries

**Authorization Violation:**
- Victims become managers of schemes they never created or authorized
- This violates the expected security invariant that users control their own manager role assignments

**Affected Parties:**
- Targeted manager addresses (victims)
- Clients/applications querying victim's schemes
- Blockchain nodes serving large responses

**Severity: Medium** due to:
1. Clear authorization bypass requiring no victim consent
2. Bounded but significant DoS (128KB, ~4000 schemes)
3. Practical exploitability with reasonable cost
4. Operational degradation rather than direct fund loss

## Likelihood Explanation
**Attacker Capabilities:**
- Any address with sufficient ELF tokens for transaction fees
- No special permissions or trusted role required

**Attack Complexity:**
Simple attack requiring only repeated calls to a public method. The transaction fee is 10 ELF per CreateScheme call: [6](#0-5) 

**Feasibility:**
- Maximum attack cost: ~40,000 ELF to create 4000 schemes
- Smaller-scale attacks (100-500 schemes) cost 1,000-5,000 ELF and still cause noticeable degradation
- No rate limiting or scheme creation caps per manager exist
- Economically feasible for motivated attackers (competitors, griefers)

**Detection/Mitigation:**
- Attack is publicly visible on-chain
- Victim cannot easily remove unwanted schemes from their list (would require calling `ResetManager` up to 4000 times at their own gas cost)
- No built-in protection or reversal mechanism

## Recommendation
Add an authorization check in the `CreateScheme` function to ensure that when a custom manager is specified, the caller must be that manager:

```csharp
public override Hash CreateScheme(CreateSchemeInput input)
{
    ValidateContractState(State.TokenContract, SmartContractConstants.TokenContractSystemName);

    if (input.ProfitReceivingDuePeriodCount == 0)
        input.ProfitReceivingDuePeriodCount = ProfitContractConstants.DefaultProfitReceivingDuePeriodCount;
    else
        Assert(
            input.ProfitReceivingDuePeriodCount > 0 &&
            input.ProfitReceivingDuePeriodCount <= ProfitContractConstants.MaximumProfitReceivingDuePeriodCount,
            "Invalid profit receiving due period count.");

    var schemeId = GenerateSchemeId(input);
    var manager = input.Manager ?? Context.Sender;
    
    // ADD THIS CHECK:
    Assert(manager == Context.Sender, "Only the manager themselves can create a scheme with that manager address.");
    
    var scheme = GetNewScheme(input, schemeId, manager);
    // ... rest of the function
}
```

Alternatively, always use `Context.Sender` as the manager and remove the `input.Manager` parameter functionality entirely, then provide a separate `ResetManager` function for transferring management (which already exists and has proper authorization).

## Proof of Concept

```csharp
[Fact]
public async Task ProfitContract_CreateScheme_AuthorizationBypass_Test()
{
    // Setup: Two users - attacker and victim
    var attacker = Creators[0];
    var victim = Creators[1];
    var victimAddress = Address.FromPublicKey(CreatorKeyPair[1].PublicKey);

    // Initial state: victim has no schemes
    var initialSchemes = await attacker.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = victimAddress
    });
    Assert.Empty(initialSchemes.SchemeIds);

    // Attack: Attacker creates scheme with victim as manager (without victim's consent)
    var executionResult = await attacker.CreateScheme.SendAsync(new CreateSchemeInput
    {
        Manager = victimAddress  // Setting victim as manager without their authorization
    });
    executionResult.TransactionResult.Status.ShouldBe(TransactionResultStatus.Mined);

    // Verify: Victim now has a scheme in their manager list that they never created
    var finalSchemes = await attacker.GetManagingSchemeIds.CallAsync(new GetManagingSchemeIdsInput
    {
        Manager = victimAddress
    });
    
    // Vulnerability confirmed: Victim's scheme list is polluted
    Assert.Single(finalSchemes.SchemeIds);
    
    // The victim is now the manager of this scheme despite never creating or authorizing it
    var scheme = await attacker.GetScheme.CallAsync(finalSchemes.SchemeIds[0]);
    Assert.Equal(victimAddress, scheme.Manager);
}
```

## Notes
While the `ResetManager` function theoretically allows victims to transfer unwanted schemes to another address, this is not a viable mitigation because:
1. It requires the victim to actively monitor and detect the attack
2. The victim must call `ResetManager` once for each unwanted scheme (up to 4000 times)
3. Each call costs gas fees, imposing financial burden on the victim
4. New schemes can be added while the victim is cleaning up
5. This defensive action itself represents a DoS impact on the victim's time and resources

The protocol definition in the protobuf shows that the manager parameter is documented as optional with "the default is the creator": [7](#0-6) 

This suggests the intended behavior is for callers to manage their own schemes by default, making the authorization bypass a clear violation of expected security properties.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L48-59)
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

**File:** contract/AElf.Contracts.Profit/ProfitContract_ACS1_TransactionFeeProvider.cs (L42-49)
```csharp
            case nameof(CreateScheme):
                return new MethodFees
                {
                    Fees =
                    {
                        new MethodFee { Symbol = Context.Variables.NativeSymbol, BasicFee = 10_00000000 }
                    }
                };
```

**File:** protobuf/profit_contract.proto (L127-128)
```text
    // The manager of this scheme, the default is the creator.
    aelf.Address manager = 4;
```
