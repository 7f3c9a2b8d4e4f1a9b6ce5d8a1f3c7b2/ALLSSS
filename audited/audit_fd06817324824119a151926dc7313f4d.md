### Title
Missing Minimum Bound Check in SetMinerIncreaseInterval Enables Consensus DoS via Rapid Miner Count Inflation

### Summary
The `SetMinerIncreaseInterval` function lacks a minimum bound check, allowing the `MinerIncreaseInterval` to be reduced to extremely small values (e.g., 1 second) through governance. This causes `GetAutoIncreasedMinersCount` to inflate the miner count at 2 miners per second, rapidly overwhelming consensus with thousands of miners within hours, effectively freezing the network.

### Finding Description

**Root Cause Location:**

The vulnerability exists in the `SetMinerIncreaseInterval` method which only validates that the new interval is less than or equal to the current value, but imposes no minimum bound: [1](#0-0) 

The validation at line 61 only prevents *increasing* the interval, but allows unlimited *decreasing*. Starting from the default value of 31,536,000 seconds (1 year), the interval can be progressively reduced to 1 second through governance proposals.

**Miner Count Calculation:**

The `GetAutoIncreasedMinersCount` function calculates the miner count using: [2](#0-1) 

Formula: `17 + (elapsed_seconds / MinerIncreaseInterval) * 2`

When `MinerIncreaseInterval = 1`, this becomes `17 + elapsed_seconds * 2`, adding 2 miners per second.

**Consensus Integration:**

This inflated count propagates to the Election contract during round/term transitions: [3](#0-2) 

The Election contract then uses this count to select validators: [4](#0-3) 

At line 81, `GetVictories` attempts to select `State.MinersCount.Value` top candidates, which with the inflated count would try to select thousands or millions of validators.

**Cap Ineffectiveness:**

While the result is theoretically capped by `MaximumMinersCount`: [5](#0-4) 

This cap is set to `int.MaxValue` (2,147,483,647), providing no practical protection.

### Impact Explanation

**Consensus Breakdown Timeline:**
- **After 1 hour:** 17 + (3,600 × 2) = 7,217 miners
- **After 1 day:** 17 + (86,400 × 2) = 172,817 miners  
- **After 1 week:** 17 + (604,800 × 2) = 1,209,617 miners

**Concrete Harm:**

1. **Round Duration Explosion:** With 7,217 miners and 4-second time slots, a single consensus round would take ~8 hours instead of minutes, making the network unusable.

2. **Computational Overload:** Round generation complexity scales with miner count. The `GenerateNextRoundInformation` method must process all miners, causing memory exhaustion and CPU overload.

3. **Network Paralysis:** Nodes cannot keep up with consensus operations, leading to massive missed blocks, stalled chain progression, and complete network freeze.

4. **Election System Failure:** `GetVictories` attempting to select 100,000+ validators from a limited candidate pool breaks the election mechanism.

**Affected Parties:** All network participants—validators become unable to produce blocks, users cannot submit transactions, and the entire blockchain halts.

**Severity Justification:** HIGH - Complete consensus failure and network-wide DoS with permanent damage accumulating every second after deployment.

### Likelihood Explanation

**Attacker Capabilities:**
- Requires Parliament organization approval to call `SetMinerIncreaseInterval`
- Parliament is the default governance mechanism, not a "compromised trusted role" scenario
- A governance proposal to "improve miner growth responsiveness" could pass without malicious intent

**Attack Complexity:**
1. Submit Parliament proposal to reduce `MinerIncreaseInterval` to a small value (e.g., 1 or 10 seconds)
2. Proposal passes through normal governance (feasible if framed as network optimization)
3. Interval change takes effect immediately upon execution
4. Miner count automatically inflates based on elapsed blockchain time
5. Damage accumulates continuously—7,217 miners after just 1 hour

**Feasibility Conditions:**
- No technical barriers—exploit uses standard governance flow
- No special permissions beyond Parliament approval required
- Attack is irreversible once interval is reduced (can only decrease, never increase per line 61 constraint)
- Damage is cumulative and permanent

**Detection Constraints:**
- Initial interval reduction appears benign
- Consensus degradation manifests gradually as miner count grows
- By the time symptoms appear (hours later), network may already be unrecoverable

**Probability:** MEDIUM-HIGH - While requiring governance approval, the change could be approved legitimately without understanding consequences, or through social engineering of governance participants.

### Recommendation

**Immediate Fix - Add Minimum Bound:**

In `SetMinerIncreaseInterval`, add a minimum interval check:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
    
    // ADD THIS CHECK:
    const long MinimumMinerIncreaseInterval = 86400; // 1 day minimum
    Assert(input.Value >= MinimumMinerIncreaseInterval, 
        "Miner increase interval cannot be less than 1 day");
    
    State.MinerIncreaseInterval.Value = input.Value;
    return new Empty();
}
```

**Additional Safeguards:**

1. **Cap Effective Miner Count:** In `GetMinersCount`, add reasonable upper bound (e.g., 1000 miners):
   ```csharp
   const int MaxReasonableMinersCount = 1000;
   return Math.Min(..., Math.Min(State.MaximumMinersCount.Value, MaxReasonableMinersCount));
   ```

2. **Rate Limit Interval Changes:** Prevent rapid successive reductions by enforcing cooldown period between changes.

3. **Validation Tests:** Add test cases verifying:
   - Interval cannot be set below minimum threshold
   - Miner count never exceeds reasonable operational limits
   - Consensus remains functional under maximum allowed miner count

### Proof of Concept

**Initial State:**
- Blockchain running with default `MinerIncreaseInterval = 31,536,000` seconds
- Current miner count = 17 (SupposedMinersCount)
- Blockchain has been running for 24 hours

**Attack Steps:**

1. **T=0:** Parliament submits proposal calling `SetMinerIncreaseInterval(1)` with justification "Enable more dynamic miner growth"

2. **T=governance_delay:** Proposal passes and executes, setting `State.MinerIncreaseInterval.Value = 1`

3. **T=governance_delay + 1 hour (3,600 seconds):**
   - `GetAutoIncreasedMinersCount()` calculates: 
   - Previous 24 hours = 86,400 seconds elapsed total
   - New count = 17 + (86,400 / 1) × 2 = 172,817 miners
   - `UpdateMinersCountToElectionContract` sends this to Election contract at next term

4. **T=next_term_change:**
   - `GetVictories` attempts to select top 172,817 candidates
   - Round generation tries to allocate 172,817 time slots
   - Round duration becomes ~8 days (172,817 × 4 seconds / 60 / 60 / 24)
   - Network freezes—no blocks produced, consensus halted

**Expected Result:** Normal consensus operation with 17-30 miners

**Actual Result:** Consensus completely halted with 172,817+ miners overwhelming the system

**Success Condition:** Network becomes unresponsive, block production stops, and the blockchain cannot progress due to excessive validator count.

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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L52-84)
```csharp
    private List<ByteString> GetVictories(List<string> currentMiners)
    {
        var validCandidates = GetValidCandidates();

        List<ByteString> victories;

        Context.LogDebug(() => $"Valid candidates: {validCandidates.Count} / {State.MinersCount.Value}");

        var diff = State.MinersCount.Value - validCandidates.Count;
        // Valid candidates not enough.
        if (diff > 0)
        {
            victories =
                new List<ByteString>(validCandidates.Select(v => ByteStringHelper.FromHexString(v)));
            var backups = currentMiners.Where(k => !validCandidates.Contains(k)).ToList();
            if (State.InitialMiners.Value != null)
                backups.AddRange(
                    State.InitialMiners.Value.Value.Select(k => k.ToHex()).Where(k => !backups.Contains(k)));

            victories.AddRange(backups.OrderBy(p => p)
                .Take(Math.Min(diff, currentMiners.Count))
                // ReSharper disable once ConvertClosureToMethodGroup
                .Select(v => ByteStringHelper.FromHexString(v)));
            Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
            return victories;
        }

        victories = validCandidates.Select(k => State.CandidateVotes[k])
            .OrderByDescending(v => v.ObtainedActiveVotedVotesAmount).Select(v => v.Pubkey)
            .Take(State.MinersCount.Value).ToList();
        Context.LogDebug(() => string.Join("\n", victories.Select(v => v.ToHex().Substring(0, 10)).ToList()));
        return victories;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract.cs (L52-52)
```csharp
        State.MaximumMinersCount.Value = int.MaxValue;
```
