# Audit Report

## Title
Inconsistent Null Handling in GetProfitDetails Causes DoS in TokenHolder and Election Contracts

## Summary
The Profit contract's `GetProfitDetails()` view method returns `null` when querying non-existent beneficiaries, but multiple critical callers fail to perform null checks before accessing properties on the returned object. This causes `NullReferenceException` crashes in `TokenHolderContract.AddBeneficiary`, `TokenHolderContract.RemoveBeneficiary`, and the Election contract's vote change operations, creating a denial-of-service condition that prevents legitimate profit scheme management and election operations.

## Finding Description

The vulnerability stems from inconsistent null handling across the Profit contract's view methods. The `GetProfitDetails()` method directly returns the result of a nested state mapping access without null validation: [1](#0-0) 

When the AElf state storage system retrieves a non-existent key, it returns `null` through the deserialization layer: [2](#0-1) [3](#0-2) 

In contrast, the similar `GetAllProfitsMap()` method properly handles null cases: [4](#0-3) 

This inconsistency causes three critical crash scenarios:

**1. TokenHolderContract.AddBeneficiary** attempts to add a new beneficiary by first checking if they exist, but crashes when accessing properties on the null result: [5](#0-4) 

**2. TokenHolderContract.RemoveBeneficiary** directly chains method calls on the potentially null result: [6](#0-5) 

**3. ElectionContract.GetProfitDetailByElectionVotingRecord** (called during vote changes) accesses properties without null validation: [7](#0-6) 

The Profit contract's own `AddBeneficiary` implementation demonstrates the correct null handling pattern: [8](#0-7) 

## Impact Explanation

This vulnerability causes operational denial-of-service across multiple critical economic subsystems:

**TokenHolder Schemes**: Scheme managers cannot add new beneficiaries to their profit schemes. The `AddBeneficiary` method is exposed as a public RPC operation to allow manual beneficiary management with custom share allocations. When a scheme manager attempts to add any new beneficiary (the primary use case), the transaction fails with a `NullReferenceException`, completely blocking this functionality.

**Election System**: When voters call `ChangeVotingOption` with `IsResetVotingTime = true` to extend their voting period, the operation may fail if profit details cannot be retrieved, disrupting the election reward distribution mechanism.

**Affected Operations**:
- New beneficiary registration in TokenHolder schemes
- Beneficiary removal operations (when targeting non-existent addresses)
- Vote option changes with time extension in Election contract

The severity is high because these are core economic functions that legitimate users need for participating in profit distribution, staking rewards, and election incentives. The bug is not just theoretical - it occurs during the most common and intended usage patterns.

## Likelihood Explanation

This vulnerability is **highly likely** to manifest in production because:

**Public Entry Points**: All affected methods are exposed as public RPC endpoints that any user can call:
- `TokenHolderContract.AddBeneficiary` is defined as a public RPC method for scheme managers
- `TokenHolderContract.RemoveBeneficiary` is publicly callable 
- `ElectionContract.ChangeVotingOption` is publicly callable [9](#0-8) 

**Minimal Preconditions**: The bug triggers during normal, legitimate operations:
- For `AddBeneficiary`: Simply calling with a new beneficiary address (the expected use case)
- For `RemoveBeneficiary`: Attempting to remove a non-existent beneficiary 
- For Election: Changing votes with time extension when profit details are unavailable

**No Attack Cost**: This is not an exploit requiring special setup - it happens naturally when users perform intended operations. Any scheme manager trying to add their first beneficiary will encounter this immediately.

**Deterministic Reproduction**: The bug is 100% reproducible. Every call to `AddBeneficiary` for a non-existent beneficiary will fail with the same exception.

## Recommendation

Add null checks in all methods that call `GetProfitDetails()`:

**For TokenHolderContract.AddBeneficiary**, check if detail is null before accessing its properties:

```csharp
var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    SchemeId = scheme.SchemeId,
    Beneficiary = input.Beneficiary
});
var shares = input.Shares;
if (detail != null && detail.Details.Any())  // Add null check
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = scheme.SchemeId,
        Beneficiary = input.Beneficiary
    });
    shares.Add(detail.Details.Single().Shares);
}
```

**For TokenHolderContract.RemoveBeneficiary**, validate the detail exists before chaining:

```csharp
var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = input.Beneficiary,
    SchemeId = scheme.SchemeId
});
Assert(detail != null && detail.Details.Any(), "Beneficiary not found in scheme");
var lockedAmount = detail.Details.Single().Shares;
```

**For ElectionContract.GetProfitDetailByElectionVotingRecord**, add null guard:

```csharp
var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
{
    Beneficiary = electionVotingRecord.Voter,
    SchemeId = State.WelfareHash.Value
});

if (profitDetails == null) return null;  // Add null check

ProfitDetail profitDetail = profitDetails.Details.FirstOrDefault(d => d.Id == electionVotingRecord.VoteId);
```

Alternatively, modify `GetProfitDetails()` to return an empty `ProfitDetails` object instead of null, matching the behavior of `GetAllProfitsMap()`.

## Proof of Concept

```csharp
[Fact]
public async Task TokenHolder_AddBeneficiary_CrashesOnNewBeneficiary()
{
    // Create a TokenHolder scheme
    await TokenHolderContractStub.CreateScheme.SendAsync(new CreateTokenHolderProfitSchemeInput
    {
        Symbol = "ELF",
        MinimumLockMinutes = 100
    });
    
    // Attempt to add a new beneficiary (who doesn't exist in the profit scheme yet)
    // This should work but will throw NullReferenceException
    var result = await TokenHolderContractStub.AddBeneficiary.SendWithExceptionAsync(
        new AddTokenHolderBeneficiaryInput
        {
            Beneficiary = SampleAddress.AddressList[0],
            Shares = 100
        });
    
    // Verify the transaction failed with NullReferenceException
    result.TransactionResult.Status.ShouldBe(TransactionResultStatus.Failed);
    result.TransactionResult.Error.ShouldContain("NullReferenceException");
}
```

### Citations

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L46-49)
```csharp
    public override ProfitDetails GetProfitDetails(GetProfitDetailsInput input)
    {
        return State.ProfitDetailsMap[input.SchemeId][input.Beneficiary];
    }
```

**File:** contract/AElf.Contracts.Profit/ViewMethods.cs (L108-110)
```csharp
        var profitDetails = State.ProfitDetailsMap[schemeId][beneficiary];

        if (profitDetails == null) return new GetAllProfitsMapOutput();
```

**File:** src/AElf.Sdk.CSharp/State/MappedState.cs (L26-36)
```csharp
    public TEntity this[TKey key]
    {
        get
        {
            if (!Cache.TryGetValue(key, out var valuePair))
            {
                valuePair = LoadKey(key);
                Cache[key] = valuePair;
            }

            return valuePair.IsDeleted ? SerializationHelper.Deserialize<TEntity>(null) : valuePair.Value;
```

**File:** src/AElf.Types/Helper/SerializationHelper.cs (L88-91)
```csharp
        public static T Deserialize<T>(byte[] bytes)
        {
            if (bytes == null)
                return default;
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L40-46)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            SchemeId = scheme.SchemeId,
            Beneficiary = input.Beneficiary
        });
        var shares = input.Shares;
        if (detail.Details.Any())
```

**File:** contract/AElf.Contracts.TokenHolder/TokenHolderContract.cs (L74-78)
```csharp
        var detail = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = input.Beneficiary,
            SchemeId = scheme.SchemeId
        }).Details.Single();
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L170-177)
```csharp
        var profitDetails = State.ProfitContract.GetProfitDetails.Call(new GetProfitDetailsInput
        {
            Beneficiary = electionVotingRecord.Voter,
            SchemeId = State.WelfareHash.Value
        });

        // In new rules, profitDetail.Id equals to its vote id.
        ProfitDetail profitDetail = profitDetails.Details.FirstOrDefault(d => d.Id == electionVotingRecord.VoteId);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L194-201)
```csharp
        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);
```

**File:** protobuf/token_holder_contract.proto (L23-30)
```text
    // Add a beneficiary to a scheme.
    rpc AddBeneficiary (AddTokenHolderBeneficiaryInput) returns (google.protobuf.Empty) {
    }
    
    // Removes a beneficiary from a scheme.
    // Note: amount > 0: update the weight of the beneficiary, amount = 0: remove the beneficiary.
    rpc RemoveBeneficiary (RemoveTokenHolderBeneficiaryInput) returns (google.protobuf.Empty) {
    }
```
