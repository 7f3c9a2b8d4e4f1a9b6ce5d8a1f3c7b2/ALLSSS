### Title
Division by Zero Vulnerability in SetMinerIncreaseInterval Causes Permanent Consensus DoS

### Summary
The `SetMinerIncreaseInterval()` function allows setting `State.MinerIncreaseInterval.Value` to zero due to insufficient validation, which causes a `DivideByZeroException` in critical consensus operations. This vulnerability results in permanent blockchain halt as the value cannot be recovered once set to zero, and consensus term transitions become impossible.

### Finding Description

**Root Cause:**
The `SetMinerIncreaseInterval()` function only validates that the new value must be less than or equal to the current value, but fails to enforce that it must be greater than zero. [1](#0-0) 

The assertion on line 61 checks `input.Value <= State.MinerIncreaseInterval.Value`, which allows zero to pass when the current value is positive (default is 31,536,000 seconds). [2](#0-1) 

**Division by Zero Locations:**

1. In `GetAutoIncreasedMinersCount()`, line 94 performs division by `State.MinerIncreaseInterval.Value`: [3](#0-2) 

2. In `GetMinersCount()`, line 390 also performs the same division: [4](#0-3) 

**Execution Path:**
The `GetMinersCount()` function is called during critical consensus operations when processing term transitions: [5](#0-4) [6](#0-5) 

**Exception Behavior:**
The SafeMath `.Div()` extension method performs simple division that throws `DivideByZeroException` when the divisor is zero: [7](#0-6) [8](#0-7) 

### Impact Explanation

**Consensus Halt:**
Once `MinerIncreaseInterval` is set to zero, any call to `GetMinersCount()` during consensus term transitions will throw `DivideByZeroException`, causing the transaction to revert. This prevents the blockchain from transitioning to new terms, effectively halting block production.

**Irreversible State:**
The assertion logic only permits decreasing values (`input.Value <= State.MinerIncreaseInterval.Value`). Once set to zero, the value cannot be increased back to a positive number, making this a permanent DoS with no recovery mechanism through the same function.

**Affected Operations:**
- `GetMaximumMinersCount()` - public view method becomes unusable
- `ProcessNextTerm()` - consensus term transitions fail
- `UpdateMinersCountToElectionContract()` - miner count synchronization breaks
- All miners lose ability to produce blocks once the current term ends

**Severity:** Critical - Results in complete blockchain halt with no built-in recovery mechanism.

### Likelihood Explanation

**Required Permissions:**
Execution requires the `MaximumMinersCountController` (by default, the Parliament contract's default organization) to call `SetMinerIncreaseInterval()` with a zero value. [9](#0-8) 

**Attack Complexity:**
- **Low Complexity:** Single transaction through Parliament governance
- **Accidental Trigger:** Could occur through misconfiguration or parameter error
- **Malicious Trigger:** Compromised governance or malicious proposal
- **No Economic Barrier:** No cost beyond governance proposal fees

**Feasibility:**
The attack is fully executable under normal AElf contract semantics. Test evidence shows the function accepts decreasing values without lower bound validation: [10](#0-9) 

**Detection:**
The vulnerability would manifest immediately upon the next term transition, but by then the damage is irreversible through the same function.

### Recommendation

**Immediate Fix:**
Add validation to enforce `MinerIncreaseInterval` must always be positive:

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

**Additional Safeguards:**
1. Add minimum interval constant (e.g., 1 day) to prevent excessively small values that could cause overflow
2. Consider allowing controlled increases with governance approval, not just decreases
3. Add emergency recovery mechanism that bypasses the constraint under specific conditions

**Regression Prevention:**
Add test cases covering:
- Attempting to set `MinerIncreaseInterval` to zero (should fail)
- Attempting to set negative values (should fail)
- Verifying `GetMaximumMinersCount()` and consensus operations after interval changes
- Testing recovery scenarios if value reaches unsafe levels

### Proof of Concept

**Initial State:**
- `State.MinerIncreaseInterval.Value = 31536000` (default: 1 year in seconds)
- Blockchain operating normally with term transitions

**Attack Steps:**
1. Parliament governance creates proposal to call `SetMinerIncreaseInterval(0)`
2. Proposal passes approval threshold and gets released
3. Transaction executes successfully:
   - Line 61 assertion passes: `0 <= 31536000` ✓
   - Line 62 sets: `State.MinerIncreaseInterval.Value = 0` ✓

**Expected vs Actual Result:**
- **Expected:** Interval configuration updated, blockchain continues operating
- **Actual:** Configuration succeeds, but blockchain becomes unusable

**Failure Manifestation:**
4. Any subsequent call to `GetMaximumMinersCount()` throws `DivideByZeroException`
5. Next term transition attempts to call `GetMinersCount()` via `UpdateMinersCountToElectionContract()`
6. Division by zero exception occurs at line 390 or 94
7. Term transition transaction reverts
8. Blockchain cannot produce blocks beyond current term
9. Recovery impossible through `SetMinerIncreaseInterval()` due to constraint enforcement

**Success Condition:** 
Blockchain permanently halted at term boundary with no recovery mechanism available through the compromised function.

### Citations

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

**File:** src/AElf.Kernel.Consensus.AEDPoS/ConsensusOptions.cs (L13-13)
```csharp
    public long MinerIncreaseInterval { get; set; } = 31536000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L381-391)
```csharp
    private int GetMinersCount(Round input)
    {
        if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;

        if (!TryToGetRoundInformation(1, out _)) return 0;
        return Math.Min(input.RealTimeMinersInformation.Count < AEDPoSContractConstants.SupposedMinersCount
            ? AEDPoSContractConstants.SupposedMinersCount
            : AEDPoSContractConstants.SupposedMinersCount.Add(
                (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
                .Div(State.MinerIncreaseInterval.Value).Mul(2)), State.MaximumMinersCount.Value);
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L120-136)
```csharp
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_NextTerm.cs (L53-61)
```csharp
    private void UpdateMinersCountToElectionContract(Round input)
    {
        var minersCount = GetMinersCount(input);
        if (minersCount != 0 && State.ElectionContract.Value != null)
            State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
            {
                MinersCount = minersCount
            });
    }
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L87-90)
```csharp
    public static long Div(this long a, long b)
    {
        return a / b;
    }
```

**File:** test/AElf.Sdk.CSharp.Tests/SafeMathTests.cs (L50-51)
```csharp
        Should.Throw<DivideByZeroException>(() => { number1.Div(0); });
        Should.Throw<DivideByZeroException>(() => { number2.Div(0); });
```

**File:** test/AElf.Contracts.AEDPoSExtension.Demo.Tests/MaximumMinersCountTests.cs (L133-146)
```csharp
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
        minerIncreaseInterval = await ConsensusStub.GetMinerIncreaseInterval.CallAsync(new Empty());
        minerIncreaseInterval.Value.ShouldBe(newMinerIncreaseInterval);
```
