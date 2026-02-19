### Title
Division-by-Zero Consensus Halt via Unchecked MinerIncreaseInterval

### Summary
The `SetMinerIncreaseInterval()` function fails to validate that the input value is positive, allowing governance to set `MinerIncreaseInterval` to zero or negative values. This causes a division-by-zero exception during consensus round transitions, permanently halting block production and rendering the blockchain non-functional.

### Finding Description
The vulnerability exists in the `SetMinerIncreaseInterval()` function which only validates that the new value is less than or equal to the current value, but fails to ensure it is positive: [1](#0-0) 

The function accepts `Int64Value` input and only performs the check `input.Value <= State.MinerIncreaseInterval.Value` before setting the state. There is no validation preventing `input.Value` from being 0 or negative.

This invalid value then causes division-by-zero exceptions in two critical locations:

**Location 1** - `GetAutoIncreasedMinersCount()`: [2](#0-1) 

**Location 2** - `GetMinersCount(Round input)`: [3](#0-2) 

Both perform `.Div(State.MinerIncreaseInterval.Value)` without checking for zero. The `Div()` extension method directly uses the division operator which throws `DivideByZeroException` when the divisor is zero: [4](#0-3) 

The test suite confirms this behavior: [5](#0-4) 

The critical failure path occurs during normal consensus operation. The `GetMinersCount(Round input)` function is called in `ProcessNextRound`: [6](#0-5) 

And also during term transitions: [7](#0-6) 

Authorization is controlled by `MaximumMinersCountController` which defaults to the Parliament contract's default organization: [8](#0-7) 

### Impact Explanation
**Consensus System Halt (Critical)**

When `MinerIncreaseInterval` is set to zero, the next consensus round transition will encounter a division-by-zero exception and fail. This causes:

1. **Immediate blockchain halt**: Block production stops completely as miners cannot successfully execute `ProcessNextRound` or term transitions
2. **Permanent DoS**: The blockchain becomes permanently non-functional until manual intervention (chain rollback or hard fork) occurs
3. **Protocol-wide impact**: All network participants are affected - no transactions can be processed, no blocks produced
4. **Economic damage**: Complete loss of chain liveness disrupts all dApps, token transfers, cross-chain operations, and governance functions

The severity is **CRITICAL** because it represents a total system failure with complete loss of blockchain functionality.

### Likelihood Explanation
**High Likelihood**

The vulnerability can be triggered through standard governance mechanisms without requiring any exploit or malicious behavior:

**Attacker Capabilities Required:**
- Control or influence over Parliament default organization (requires 2/3 miner approval for proposals)
- Ability to create and pass a governance proposal

**Attack Complexity:**
- Low - single governance proposal with a single parameter
- No special timing, state manipulation, or multi-step coordination required

**Execution Path:**
1. Create Parliament proposal calling `SetMinerIncreaseInterval(0)`
2. Obtain 2/3 miner approval (standard governance process)
3. Execute the approved proposal
4. Wait for next consensus round transition
5. Blockchain halts with division-by-zero exception

**Feasibility Conditions:**
- Governance mechanism working normally
- Standard proposal approval process
- No technical barriers or race conditions

While this requires governance control, it represents a realistic scenario because:
- Governance proposals can contain configuration errors or malicious parameters
- The test suite shows decreasing the interval is a valid operation, making zero a "boundary case" someone might test
- No warning or safeguard prevents this configuration [9](#0-8) 

The likelihood is rated **HIGH** due to the low complexity and realistic governance-based execution path.

### Recommendation

**Immediate Fix:**

Add positive value validation in `SetMinerIncreaseInterval()`:

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

**Defense in Depth:**

Add validation checks in the division operations as well:

```csharp
private int GetAutoIncreasedMinersCount()
{
    if (State.BlockchainStartTimestamp.Value == null) return AEDPoSContractConstants.SupposedMinersCount;
    
    Assert(State.MinerIncreaseInterval.Value > 0, "Invalid miner increase interval configuration.");
    
    return AEDPoSContractConstants.SupposedMinersCount.Add(
        (int)(Context.CurrentBlockTime - State.BlockchainStartTimestamp.Value).Seconds
        .Div(State.MinerIncreaseInterval.Value).Mul(2));
}
```

**Test Cases:**

Add regression tests to verify:
1. `SetMinerIncreaseInterval(0)` is rejected with appropriate error
2. `SetMinerIncreaseInterval(-1)` is rejected with appropriate error  
3. `SetMinerIncreaseInterval(1)` succeeds as minimum valid value
4. Existing functionality with positive values continues to work

### Proof of Concept

**Initial State:**
- Blockchain initialized with `MinerIncreaseInterval = 240` (default test value)
- Parliament contract initialized
- Normal consensus operation with miners producing blocks

**Attack Steps:**

1. **Create malicious governance proposal:**
   ```
   Parliament.CreateProposal({
     ToAddress: ConsensusContract,
     Method: "SetMinerIncreaseInterval",
     Params: Int64Value { Value: 0 },
     OrganizationAddress: DefaultParliamentOrg
   })
   ```

2. **Obtain 2/3 miner approval:**
   - Miners approve proposal (either maliciously or through error)
   - Proposal reaches approval threshold

3. **Execute proposal:**
   ```
   Parliament.Release(proposalId)
   ```
   - Transaction succeeds
   - `State.MinerIncreaseInterval.Value` now equals 0

4. **Wait for next consensus round:**
   - Miner attempts to call `NextRound` or round naturally transitions
   - `ProcessNextRound()` executes
   - Calls `GetMinersCount(nextRound)` at line 128
   - Division operation `.Div(State.MinerIncreaseInterval.Value)` attempts `.Div(0)`
   - `DivideByZeroException` is thrown

**Expected Result:**
- Proposal should be rejected with "Miner increase interval must be positive" error

**Actual Result:**
- Proposal executes successfully
- Consensus system halts on next round transition with division-by-zero exception
- Blockchain stops producing blocks permanently

**Success Condition for Exploit:**
- `State.MinerIncreaseInterval.Value == 0` after proposal execution
- Next consensus operation throws `DivideByZeroException`
- No new blocks are produced

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L128-134)
```csharp
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
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
