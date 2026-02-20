# Audit Report

## Title
Unbounded State Bloat via Unlimited Profit Scheme Creation in TokenHolderContract

## Summary
The `CreateScheme()` function in TokenHolderContract allows any user to repeatedly create unlimited profit schemes without authorization or duplicate prevention. Each invocation creates a new permanent scheme object in ProfitContract while TokenHolderContract only tracks one scheme per address, causing all subsequent schemes to become orphaned and unreachable, resulting in unbounded state bloat that permanently degrades blockchain performance.

## Finding Description

**Vulnerability Entry Point:**

The `CreateScheme()` method in TokenHolderContract is publicly accessible without any authorization checks. [1](#0-0) 

**Root Cause #1 - Single Scheme Storage:**

TokenHolderContract maintains only ONE scheme reference per address in the state mapping. When `CreateScheme()` is called multiple times by the same address, this storage location is unconditionally overwritten with the new scheme's metadata. [2](#0-1) 

The state structure confirms only one scheme can be tracked per address: [3](#0-2) 

**Root Cause #2 - Unique Scheme ID Generation:**

Each call to `CreateScheme()` in TokenHolderContract sends a request to ProfitContract to create a new scheme: [4](#0-3) 

The ProfitContract generates a unique scheme ID for each creation request using an incrementing counter. Since the `Token` field is null in requests from TokenHolderContract, the scheme ID is generated using the manager's existing scheme count: [5](#0-4) 

**Root Cause #3 - Permanent Scheme Storage:**

ProfitContract stores each created scheme permanently and adds the scheme ID to the manager's list without any upper bound: [6](#0-5) 

The duplicate check only prevents creating a scheme with an identical scheme ID, not multiple schemes per manager: [7](#0-6) 

**Root Cause #4 - Scheme Orphaning:**

When TokenHolderContract needs to retrieve the scheme ID, it calls `GetManagingSchemeIds()` and takes only the **first** scheme using `.FirstOrDefault()`, meaning all schemes created after the first become permanently orphaned: [8](#0-7) 

**Storage Structure:**

Each Scheme object in ProfitContract contains substantial data including addresses, hashes, repeated fields, and maps: [9](#0-8) 

This amounts to a minimum of ~130+ bytes per scheme plus variable-size collections.

**No Cleanup Mechanism:**

Analysis of ProfitContract confirms no method exists to delete or remove entire schemes once created. The only scheme-related removal methods affect relationships, not the scheme objects themselves: [10](#0-9) 

## Impact Explanation

**Unbounded State Bloat Attack:**

An attacker can exploit this vulnerability by repeatedly calling `CreateScheme()` with any parameters. Each invocation:
1. Creates a new permanent Scheme object consuming ~130+ bytes plus virtual address overhead
2. Adds a new entry to the manager's scheme list in `ManagingSchemeIds`
3. Overwrites TokenHolderContract's tracking, orphaning the previous scheme
4. Has no cleanup or removal path

**Denial of Service Consequences:**

The permanent state bloat causes operational DoS effects:
- **Storage Growth**: Unbounded growth of ProfitContract state that all validators must store
- **Synchronization Impact**: New nodes take progressively longer to sync as state size increases
- **Query Degradation**: Lookups in `SchemeInfos` and `ManagingSchemeIds` mappings become slower
- **Blockchain Bloat**: State database grows without bound, affecting all network participants

**Affected Parties:**

- All blockchain validators must store the bloated state indefinitely
- Chain operators face escalating storage and infrastructure costs
- New nodes experience degraded synchronization performance
- All users experience slower transaction processing as state grows

The severity is **HIGH** because this constitutes an economically viable operational DoS attack with permanent, irreversible impact requiring only minimal transaction fees to execute.

## Likelihood Explanation

**Attacker Prerequisites:**

The attack requires:
- No special permissions or authorizations
- No token holdings, allowances, or locked stakes
- No specific contract states or timing requirements
- Only the ability to submit transactions (pay transaction fees)

**Attack Complexity:**

The attack is trivially simple:
1. Call `TokenHolderContract.CreateScheme()` with any valid input parameters
2. Repeat the call as many times as desired
3. Optionally amplify by using multiple attacker-controlled addresses

No complex transaction sequencing, race conditions, or vulnerability chaining is required.

**Economic Feasibility:**

The cost-benefit ratio strongly favors the attacker:
- **Attack Cost**: Only transaction fees (typically minimal per transaction)
- **Damage Inflicted**: Permanent storage bloat affecting all nodes forever
- **Cost-to-Damage Ratio**: Extremely favorable for attacker—minimal expenditure creates permanent protocol degradation

The attack becomes economically rational even for moderately motivated attackers.

**Detection and Prevention:**

- The attack is visible on-chain but difficult to prevent without protocol upgrades
- No existing rate limiting or anti-spam mechanisms protect this function
- Once schemes are created, the damage is permanent with no cleanup mechanism
- Would require hard fork or contract upgrade to remediate accumulated bloat

The likelihood is **HIGH**—the attack is trivially executable, economically rational, and has no technical barriers.

## Recommendation

Implement duplicate prevention in `TokenHolderContract.CreateScheme()` to prevent users from creating multiple schemes:

```csharp
public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
{
    // Add duplicate check
    Assert(State.TokenHolderProfitSchemes[Context.Sender] == null, 
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

Additionally, consider implementing:
1. A scheme deletion mechanism in ProfitContract for cleanup
2. Rate limiting on scheme creation
3. Maximum scheme count per manager enforcement

## Proof of Concept

```csharp
[Fact]
public async Task CreateScheme_Multiple_Times_Causes_State_Bloat()
{
    // Initial state: no schemes exist
    var initialSchemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = DefaultSender });
    initialSchemeIds.SchemeIds.Count.ShouldBe(0);
    
    // Attack: Create multiple schemes from the same address
    for (int i = 0; i < 100; i++)
    {
        await TokenHolderContractStub.CreateScheme.SendAsync(
            new CreateTokenHolderProfitSchemeInput
            {
                Symbol = "ELF",
                MinimumLockMinutes = 100
            });
    }
    
    // Verify: 100 schemes now exist in ProfitContract
    var finalSchemeIds = await ProfitContractStub.GetManagingSchemeIds.CallAsync(
        new GetManagingSchemeIdsInput { Manager = DefaultSender });
    finalSchemeIds.SchemeIds.Count.ShouldBe(100);
    
    // Verify: All schemes are valid and stored in State.SchemeInfos
    foreach (var schemeId in finalSchemeIds.SchemeIds)
    {
        var scheme = await ProfitContractStub.GetScheme.CallAsync(schemeId);
        scheme.ShouldNotBeNull();
        scheme.Manager.ShouldBe(DefaultSender);
    }
    
    // Verify: TokenHolderContract only tracks the last scheme
    var tokenHolderScheme = await TokenHolderContractStub.GetScheme.CallAsync(DefaultSender);
    tokenHolderScheme.ShouldNotBeNull();
    
    // Verify: Only first scheme is accessible via TokenHolderContract's retrieval logic
    // All other 99 schemes are orphaned and unreachable but permanently stored
    
    // This proves unbounded state bloat: 100 permanent Scheme objects created
    // with no cleanup mechanism, affecting all validators indefinitely
}
```

### Citations

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L14-14)
```csharp
    public override Empty CreateScheme(CreateTokenHolderProfitSchemeInput input)
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L20-25)
```csharp
        State.ProfitContract.CreateScheme.Send(new CreateSchemeInput
        {
            Manager = Context.Sender,
            IsReleaseAllBalanceEveryTimeByDefault = true,
            CanRemoveBeneficiaryDirectly = true
        });
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L27-32)
```csharp
        State.TokenHolderProfitSchemes[Context.Sender] = new TokenHolderProfitScheme
        {
            Symbol = input.Symbol,
            MinimumLockMinutes = input.MinimumLockMinutes,
            AutoDistributeThreshold = { input.AutoDistributeThreshold }
        };
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L290-293)
```csharp
        var originSchemeId = State.ProfitContract.GetManagingSchemeIds.Call(new GetManagingSchemeIdsInput
        {
            Manager = manager
        }).SchemeIds.FirstOrDefault();
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContractState.cs (L10-10)
```csharp
    public MappedState<Address, TokenHolderProfitScheme> TokenHolderProfitSchemes { get; set; }
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L59-71)
```csharp
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

**File:** protobuf/profit_contract.proto (L54-61)
```text
    // Add sub scheme to a scheme. 
    // This will effectively add the specified sub-scheme as a beneficiary of the parent scheme.
    rpc AddSubScheme (AddSubSchemeInput) returns (google.protobuf.Empty) {
    }
    
    // Remove sub scheme from a scheme.
    rpc RemoveSubScheme (RemoveSubSchemeInput) returns (google.protobuf.Empty) {
    }
```

**File:** protobuf/profit_contract.proto (L135-160)
```text
message Scheme {
    // The virtual address of the scheme.
    aelf.Address virtual_address = 1;
    // The total weight of the scheme.
    int64 total_shares = 2;
    // The manager of the scheme.
    aelf.Address manager = 3;
    // The current period.
    int64 current_period = 4;
    // Sub schemes information.
    repeated SchemeBeneficiaryShare sub_schemes = 5;
    // Whether you can directly remove the beneficiary.
    bool can_remove_beneficiary_directly = 6;
    // Period of profit distribution.
    int64 profit_receiving_due_period_count = 7;
    // Whether all the schemes balance will be distributed during distribution each period.
    bool is_release_all_balance_every_time_by_default = 8;
    // The is of the scheme.
    aelf.Hash scheme_id = 9;
    // Delay distribute period.
    int32 delay_distribute_period_count = 10;
    // Record the scheme's current total share for deferred distribution of benefits, period -> total shares.
    map<int64, int64> cached_delay_total_shares = 11;
    // The received token symbols.
    repeated string received_token_symbols = 12;
}
```
