### Title
Insufficient Validation in SetMinerIncreaseInterval Allows Zero or Negative Values Leading to Consensus Failure

### Summary
The `SetMinerIncreaseInterval` function lacks proper validation to prevent zero or negative values, only checking that the new value is less than or equal to the current value. [1](#0-0)  If set to zero, division by zero exceptions occur in miner count calculations, causing immediate consensus failure. If set to negative, the system produces invalid negative miner counts that corrupt the election and subsidy mechanisms, leading to complete consensus breakdown.

### Finding Description

The vulnerability exists in the `SetMinerIncreaseInterval` method which only validates that `input.Value <= State.MinerIncreaseInterval.Value` without ensuring the value remains positive. [2](#0-1) 

The `State.MinerIncreaseInterval` field is defined as `int64` in the protobuf specification, which is a signed integer allowing negative values. [3](#0-2)  During initialization, the value is assigned without validation. [4](#0-3) 

The `MinerIncreaseInterval` value is used as a divisor in two critical functions. In `GetAutoIncreasedMinersCount()`, elapsed time is divided by this interval to calculate auto-increased miner count. [5](#0-4)  The same division operation occurs in `GetMinersCount()`. [6](#0-5) 

The `Div` extension method performs standard division without overflow checking. [7](#0-6)  When the divisor is zero, a `DivideByZeroException` is thrown. When the divisor is negative and the dividend (elapsed time) is positive, the result is negative, causing the formula to subtract from `SupposedMinersCount` (which is 17). [8](#0-7) 

The calculated miner count flows to the Election contract via `UpdateMinersCount`, which has no validation on the input value and directly stores it. [9](#0-8)  The Election contract then uses this value in `GetValidationDataCenterCount()`, multiplying it by 5. [10](#0-9)  This propagates the corruption through the subsidy synchronization logic. [11](#0-10) 

### Impact Explanation

**Case 1 - Zero Value:** If `MinerIncreaseInterval` is set to 0, any call to `GetAutoIncreasedMinersCount()` or `GetMinersCount()` triggers a `DivideByZeroException`, causing the consensus contract to crash. This halts block production as miners cannot calculate the required miner count for round generation. The blockchain becomes non-functional until the contract state is manually recovered.

**Case 2 - Negative Value:** If set to a negative value (e.g., -31536000), the calculation produces negative miner counts. For example, with 100 million seconds elapsed: (100000000 / -31536000) * 2 = -6.34, so 17 + (-6.34) = approximately 10 miners if cast positive, but could produce negative values in edge cases. These invalid values corrupt the Election contract's data center calculations, causing incorrect subsidy distributions and potentially breaking the entire election mechanism that determines which candidates become validators.

The severity is **CRITICAL** because it causes complete consensus failure - a denial of service at the protocol level affecting all chain participants. Block production stops, transactions cannot be processed, and the economic system freezes.

### Likelihood Explanation

The attack requires governance control via the `MaximumMinersCountController`, which defaults to the Parliament contract's default organization. [12](#0-11)  An attacker must either compromise governance or exploit the weak validation to pass a malicious proposal.

The validation only checks that new values are less than or equal to current values, suggesting the intent was to only allow decreasing intervals. However, this design fails to prevent zero or negative values. Once `MinerIncreaseInterval` reaches a positive value like 1, a subsequent call can set it to 0, then -1, then any negative value, as each satisfies `input.Value <= current_value`.

The attack could occur through:
1. **Malicious governance:** Compromised Parliament majority intentionally sets harmful value
2. **Honest mistake:** Governance members accidentally approve a proposal with typo or wrong sign
3. **Social engineering:** Attacker tricks governance into approving harmful proposal disguised as optimization

The complexity is LOW - only requires a single governance proposal with a zero or negative integer value. The default `MinerIncreaseInterval` is 31,536,000 (one year), and the validation allows any value ≤ this, including 0 and negative values. [13](#0-12) 

Existing tests only verify permission checks and normal decreasing values, not boundary conditions. [14](#0-13) 

### Recommendation

**Immediate Fix:**
Add positive value validation in `SetMinerIncreaseInterval`:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value > 0, "Miner increase interval must be positive.");
    Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

**Additional Protections:**
1. Add validation in `InitialAElfConsensusContract` to ensure initial value is positive
2. Add validation in `UpdateMinersCount` to reject non-positive miner counts
3. Add defensive checks in `GetAutoIncreasedMinersCount()` before division

**Test Cases to Add:**
1. Test `SetMinerIncreaseInterval` with value 0 - should fail with "must be positive" error
2. Test `SetMinerIncreaseInterval` with negative value - should fail with "must be positive" error
3. Test initialization with zero/negative `MinerIncreaseInterval` - should fail
4. Test miner count calculation behavior at boundaries to ensure no integer overflow

### Proof of Concept

**Initial State:**
- `State.MinerIncreaseInterval.Value = 31536000` (default 1 year)
- `State.BlockchainStartTimestamp` set, consensus is running normally
- Parliament governance is active with default organization

**Attack Sequence:**

**Step 1:** Attacker (or compromised governance) creates Parliament proposal to set `MinerIncreaseInterval` to 0:
```
CreateProposal(
    ToAddress: ConsensusContract,
    MethodName: "SetMinerIncreaseInterval",
    Params: Int64Value { Value = 0 }
)
```

**Step 2:** Validation passes because `0 <= 31536000` is true (no positivity check exists)

**Step 3:** Proposal gets approved and executed by Parliament, setting `State.MinerIncreaseInterval.Value = 0`

**Step 4:** Next miner attempts to produce block and calls internal consensus functions that invoke `GetAutoIncreasedMinersCount()`

**Expected Result:** Normal miner count calculation continues

**Actual Result:** `DivideByZeroException` is thrown at the division operation, consensus contract crashes, block production halts, blockchain stops functioning

**Success Condition:** Blockchain cannot produce new blocks, requiring emergency intervention to restore chain functionality. The attack achieves complete protocol denial of service with a single governance action exploiting insufficient validation.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L31-43)
```csharp
    private void RequiredMaximumMinersCountControllerSet()
    {
        if (State.MaximumMinersCountController.Value != null) return;
        EnsureParliamentContractAddressSet();

        var defaultAuthority = new AuthorityInfo
        {
            OwnerAddress = State.ParliamentContract.GetDefaultOrganizationAddress.Call(new Empty()),
            ContractAddress = State.ParliamentContract.Value
        };

        State.MaximumMinersCountController.Value = defaultAuthority;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L56-64)
```csharp
    public override Empty SetMinerIncreaseInterval(Int64Value input)
    {
        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set miner increase interval.");
        Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
        State.MinerIncreaseInterval.Value = input.Value;
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L88-95)
```csharp
    private int GetAutoIncreasedMinersCount()
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        return AEDPoSContractConstants.SupposedMinersCount.Add(
            (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
            .Div(State.MinerIncreaseInterval.Value).Mul(2));
    }
```

**File:** protobuf/aedpos_contract.proto (L191-191)
```text
    int64 miner_increase_interval = 4;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L31-31)
```csharp
        State.MinerIncreaseInterval.Value = input.MinerIncreaseInterval;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L388-390)
```csharp
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L149-160)
```csharp
    public override Empty UpdateMinersCount(UpdateMinersCountInput input)
    {
        Context.LogDebug(() =>
            $"Consensus Contract Address: {Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName)}");
        Context.LogDebug(() => $"Sender Address: {Context.Sender}");
        Assert(
            Context.GetContractAddressByName(SmartContractConstants.ConsensusContractSystemName) == Context.Sender,
            "Only consensus contract can update miners count.");
        State.MinersCount.Value = input.MinersCount;
        SyncSubsidyInfoAfterReduceMiner();
        return new Empty();
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L359-377)
```csharp
    private void SyncSubsidyInfoAfterReduceMiner()
    {
        var rankingList = State.DataCentersRankingList.Value;
        if (rankingList == null)
            return;
        var validDataCenterCount = GetValidationDataCenterCount();
        if (rankingList.DataCenters.Count <= validDataCenterCount) return;
        Context.LogDebug(() => "sync DataCenter after reduce bp");
        var diffCount = rankingList.DataCenters.Count.Sub(validDataCenterCount);
        var toRemoveList = rankingList.DataCenters.OrderBy(x => x.Value)
            .Take(diffCount).ToList();
        foreach (var kv in toRemoveList)
        {
            rankingList.DataCenters.Remove(kv.Key);
            RemoveBeneficiary(kv.Key);
        }

        State.DataCentersRankingList.Value = rankingList;
    }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L406-409)
```csharp
    private int GetValidationDataCenterCount()
    {
        return GetMinersCount(new Empty()).Value.Mul(5);
    }
```

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L13-13)
```csharp
    public long MinerIncreaseInterval { get; set; } = 31536000;
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L121-144)
```csharp
        var transactionResult = await ParliamentReachAnAgreementWithExceptionAsync(new CreateProposalInput
        {
            ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            ContractMethodName = nameof(ConsensusStub.SetMinerIncreaseInterval),
            Params = new Int64Value
            {
                Value = minerIncreaseInterval.Value + 1
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = defaultOrganizationAddress
        });
        transactionResult.Error.ShouldContain("Invalid interval");
        var newMinerIncreaseInterval = minerIncreaseInterval.Value - 1;
        await ParliamentReachAnAgreementAsync(new CreateProposalInput
        {
            ToAddress = ContractAddresses[ConsensusSmartContractAddressNameProvider.Name],
            ContractMethodName = nameof(ConsensusStub.SetMinerIncreaseInterval),
            Params = new Int64Value
            {
                Value = newMinerIncreaseInterval
            }.ToByteString(),
            ExpiredTime = TimestampHelper.GetUtcNow().AddDays(1),
            OrganizationAddress = defaultOrganizationAddress
        });
```
