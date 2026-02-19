### Title
Unbounded ProfitDetails Growth Causes Denial of Service in Profit Claiming

### Summary
The `AddBeneficiary` method in the Profit contract allows unlimited `ProfitDetail` entries to be added for the same beneficiary with different `ProfitDetailId` values, causing unbounded growth of the `ProfitDetailsMap[schemeId][beneficiary].Details` list. When beneficiaries attempt to claim profits, the contract must iterate through all accumulated details, leading to gas exhaustion and permanent denial of service for profit claims when the list grows to thousands of entries.

### Finding Description

The root cause is in the `AddBeneficiary` method where each call with a different `ProfitDetailId` appends a new `ProfitDetail` to the beneficiary's details list without any size limit or deduplication check: [1](#0-0) 

The `ProfitDetailsMap` state variable stores a repeated list of `ProfitDetail` objects per beneficiary: [2](#0-1) [3](#0-2) 

**Why Existing Protections Fail:**

1. The cleanup logic only removes very old details that meet strict conditions (already claimed AND expired AND beyond receiving period): [4](#0-3) 

2. The `ProfitReceivingLimitForEachTime` constant only limits how many details are **processed** per claim (10), not the total list size: [5](#0-4) 

3. When claiming profits, the contract must iterate through **all** details to filter available ones, regardless of the processing limit: [6](#0-5) 

**Attack Vectors:**

1. **Malicious Scheme Manager**: A scheme manager (or TokenHolder contract) can repeatedly call `AddBeneficiary` with the same beneficiary but different `ProfitDetailId` values, as only manager authorization is checked: [7](#0-6) 

2. **Election Contract Voting**: The Election contract adds a new detail for each vote with a unique `voteId`: [8](#0-7) 

When votes are withdrawn, the removal does NOT specify the `ProfitDetailId`, so only expired details are removed: [9](#0-8) 

This causes active vote details to accumulate indefinitely for frequent voters.

### Impact Explanation

**Operational DoS Impact:**

When a beneficiary with thousands of accumulated `ProfitDetail` entries attempts to claim profits, the LINQ filtering operation in `ClaimProfits` must iterate through the entire list. With 10,000 details, this gas-intensive iteration will exceed block gas limits, making profit claims impossible.

**Who is Affected:**
- Election contract users who vote frequently (100+ times) will accumulate hundreds of details and face claim DoS
- Any beneficiary targeted by a malicious scheme manager will be unable to claim from that scheme
- System-wide welfare distribution can be disrupted

**Severity: HIGH**
- Permanent denial of service for legitimate profit claims
- No fund recovery path once gas limits are exceeded
- Affects core reward distribution mechanism across Election and TokenHolder systems

### Likelihood Explanation

**Likelihood: HIGH**

**Attacker Capabilities:**
- Any user can create their own scheme (becomes manager) via the public `CreateScheme` method
- Scheme managers have authority to call `AddBeneficiary` repeatedly with different IDs
- No cost barrier: adding beneficiaries is only limited by transaction fees

**Attack Complexity: LOW**
- Single transaction loop calling `AddBeneficiary` 10,000 times with different `ProfitDetailId` values
- No special permissions beyond scheme creation
- Can target any address preemptively

**Natural Occurrence: HIGH**
- Election contract naturally creates this scenario through normal voting behavior
- Users voting 100+ times over months will accumulate 100+ details
- Details persist until `EndPeriod + ProfitReceivingDuePeriodCount` (10+ periods beyond expiration)

**Detection/Constraints:**
- Attack is difficult to detect until victim attempts to claim
- No automatic cleanup mechanism exists
- Gas costs for attacker are minimal compared to impact

### Recommendation

**Immediate Mitigation:**

1. Add a maximum limit on `ProfitDetails.Details` list size per beneficiary:

```csharp
public override Empty AddBeneficiary(AddBeneficiaryInput input)
{
    // ... existing validation ...
    
    var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
    if (currentProfitDetails != null)
    {
        Assert(currentProfitDetails.Details.Count < MAX_PROFIT_DETAILS_PER_BENEFICIARY, 
            "Maximum profit details limit exceeded.");
    }
    
    // ... rest of method ...
}
```

Recommended `MAX_PROFIT_DETAILS_PER_BENEFICIARY` = 100.

2. Implement aggressive cleanup in `AddBeneficiary` to remove any details where `EndPeriod < CurrentPeriod` (expired), not just those beyond receiving period.

3. Fix the Election contract's `RemoveBeneficiaryOfVoter` to pass the specific `voteId` when removing:

```csharp
private void RemoveBeneficiaryOfVoter(Hash voteId, Address voterAddress = null)
{
    State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
    {
        SchemeId = State.WelfareHash.Value,
        Beneficiary = voterAddress ?? Context.Sender,
        ProfitDetailId = voteId  // Add this field
    });
}
```

4. Add pagination to `ClaimProfits` to prevent single-transaction gas exhaustion while processing large detail lists.

**Test Cases:**
- Test claiming with 1000+ details to verify gas limits
- Test that cleanup properly removes expired details
- Test Election voting/withdrawal cycle maintains bounded detail count

### Proof of Concept

**Initial State:**
- Attacker calls `CreateScheme` to create a scheme with themselves as manager
- Victim address exists but has not interacted with the scheme

**Exploitation Steps:**

1. Attacker executes loop 10,000 times:
   ```
   For i = 1 to 10,000:
     Call AddBeneficiary(
       schemeId: attackerSchemeId,
       beneficiary: victimAddress,
       shares: 1,
       profitDetailId: Hash(i)
     )
   ```

2. State after attack:
   - `ProfitDetailsMap[attackerSchemeId][victimAddress].Details.Count = 10,000`

3. Victim attempts to claim:
   ```
   Call ClaimProfits(
     schemeId: attackerSchemeId,
     beneficiary: victimAddress
   )
   ```

**Expected vs Actual Result:**

Expected: Victim successfully claims their profit shares

Actual: Transaction fails with out-of-gas error when the LINQ query `profitDetails.Details.Where(...)` attempts to iterate through 10,000 entries

**Success Condition:**
The attack succeeds when victim's `ClaimProfits` transaction consistently fails due to gas exhaustion, demonstrating permanent DoS of profit claiming functionality.

### Citations

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L171-174)
```csharp
        Assert(
            Context.Sender == scheme.Manager || Context.Sender ==
            Context.GetContractAddressByName(SmartContractConstants.TokenHolderContractSystemName),
            "Only manager can add beneficiary.");
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L186-201)
```csharp
        var profitDetail = new ProfitDetail
        {
            StartPeriod = scheme.CurrentPeriod.Add(scheme.DelayDistributePeriodCount),
            EndPeriod = input.EndPeriod,
            Shares = input.BeneficiaryShare.Shares,
            Id = input.ProfitDetailId
        };

        var currentProfitDetails = State.ProfitDetailsMap[schemeId][input.BeneficiaryShare.Beneficiary];
        if (currentProfitDetails == null)
            currentProfitDetails = new ProfitDetails
            {
                Details = { profitDetail }
            };
        else
            currentProfitDetails.Details.Add(profitDetail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L204-207)
```csharp
        var oldProfitDetails = currentProfitDetails.Details.Where(
            d => d.EndPeriod != long.MaxValue && d.LastProfitPeriod >= d.EndPeriod &&
                 d.EndPeriod.Add(scheme.ProfitReceivingDuePeriodCount) < scheme.CurrentPeriod).ToList();
        foreach (var detail in oldProfitDetails) currentProfitDetails.Details.Remove(detail);
```

**File:** contract/AElf.Contracts.Profit/ProfitContract.cs (L765-767)
```csharp
        var availableDetails = profitDetails.Details.Where(d =>
            d.LastProfitPeriod == 0 ? d.EndPeriod >= d.StartPeriod : d.EndPeriod >= d.LastProfitPeriod).ToList();
        var profitableDetails = availableDetails.Where(d => d.LastProfitPeriod < scheme.CurrentPeriod).ToList();
```

**File:** contract/AElf.Contracts.Profit/ProfitContractState.cs (L13-13)
```csharp
    public MappedState<Hash, Address, ProfitDetails> ProfitDetailsMap { get; set; }
```

**File:** protobuf/profit_contract.proto (L233-236)
```text
message ProfitDetails {
    // The profit information.
    repeated ProfitDetail details = 1;
}
```

**File:** contract/AElf.Contracts.Profit/ProfitContractConstants.cs (L5-5)
```csharp
    public const int ProfitReceivingLimitForEachTime = 10;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L304-311)
```csharp
    private void RemoveBeneficiaryOfVoter(Address voterAddress = null)
    {
        State.ProfitContract.RemoveBeneficiary.Send(new RemoveBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            Beneficiary = voterAddress ?? Context.Sender
        });
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Elector.cs (L369-382)
```csharp
    private void AddBeneficiaryToVoter(long votesWeight, long lockSeconds, Hash voteId)
    {
        State.ProfitContract.AddBeneficiary.Send(new AddBeneficiaryInput
        {
            SchemeId = State.WelfareHash.Value,
            BeneficiaryShare = new BeneficiaryShare
            {
                Beneficiary = Context.Sender,
                Shares = votesWeight
            },
            EndPeriod = GetEndPeriod(lockSeconds),
            // one vote, one profit detail, so voteId equals to profitDetailId
            ProfitDetailId = voteId
        });
```
