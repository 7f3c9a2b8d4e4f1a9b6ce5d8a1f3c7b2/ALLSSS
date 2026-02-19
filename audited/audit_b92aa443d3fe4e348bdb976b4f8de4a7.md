### Title
State Inconsistency Between Consensus and Election Contracts Causes Incorrect Miner Selection During Term Transitions

### Summary
When `SetMinerIncreaseInterval()` is called to decrease the miner increase interval, it updates the consensus contract's state but fails to synchronize the Election contract's `MinersCount` value. This creates a state inconsistency that causes `GetVictories()` to select the wrong number of miners during the next term transition, potentially excluding legitimate candidates or including too many, lasting for the entire term duration until corrected.

### Finding Description

The vulnerability exists in the interaction between two functions in the consensus contract and their effect on the Election contract's state. [1](#0-0) 

`SetMinerIncreaseInterval()` updates `State.MinerIncreaseInterval.Value` but does not call `UpdateMinersCount` on the Election contract. This contrasts with `SetMaximumMinersCount()`: [2](#0-1) 

The consensus contract's `GetMinersCount()` function calculates the effective miners count using both `State.MinerIncreaseInterval.Value` and `State.MaximumMinersCount.Value`: [3](#0-2) 

However, during term transitions, the Election contract's `GetVictories()` method uses its own stored `State.MinersCount.Value` to determine how many miners to select: [4](#0-3) 

The term transition flow calls `GetVictories()` before updating the Election contract's miners count: [5](#0-4) [6](#0-5) 

The Election contract's `MinersCount` is only updated AFTER the term has started: [7](#0-6) 

**Root Cause**: `SetMinerIncreaseInterval()` modifies a parameter that affects `GetAutoIncreasedMinersCount()` calculations but fails to propagate this change to the Election contract, creating a critical state inconsistency.

### Impact Explanation

**Consensus Integrity Impact**: 
- The term begins with an incorrect number of miners (e.g., 7 instead of 11 if the interval is halved)
- Top-voted candidates may be excluded from mining and rewards for the entire term
- Network decentralization is reduced if too few miners are selected
- Stakeholders who voted for excluded candidates receive no mining rewards for that term

**Duration**: The issue persists for the full term duration (potentially days to weeks) until the next term transition occurs.

**Affected Parties**:
- Excluded candidate miners lose mining opportunities and rewards
- Token holders who voted for excluded candidates lose expected returns
- Network security is compromised with reduced miner diversity

**Severity**: Medium - This violates the "Consensus & Cross-Chain" critical invariant requiring "miner schedule integrity" and causes "invalid round transitions" with incorrect miner sets.

### Likelihood Explanation

**Attacker Capabilities**: Requires governance authority (MaximumMinersCountController), typically the Parliament organization. This is not an arbitrary attacker but a legitimate governance action.

**Attack Complexity**: Low - This occurs through normal governance operations:
1. Governance proposes and approves reducing `MinerIncreaseInterval` to allow faster miner growth
2. The proposal is executed via `SetMinerIncreaseInterval()`
3. A term transition naturally occurs before the inconsistency is resolved

**Feasibility Conditions**:
- The interval must be decreased (line 61 only allows `input.Value <= State.MinerIncreaseInterval.Value`)
- A term transition must occur before the next round's `ProcessNextRound` (which doesn't regularly update MinersCount)
- No manual call to `SetMaximumMinersCount()` occurs between the interval change and term transition

**Operational Constraints**: This is not a malicious attack but an unintended consequence of valid governance actions. The timing window exists naturally between configuration changes and term transitions.

**Probability**: Medium - Governance changes to miner parameters are infrequent but realistic for protocol evolution. The vulnerability triggers automatically when the timing aligns.

### Recommendation

**Code-Level Mitigation**:
Add a call to update the Election contract's miners count in `SetMinerIncreaseInterval()`:

```csharp
public override Empty SetMinerIncreaseInterval(Int64Value input)
{
    RequiredMaximumMinersCountControllerSet();
    Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
        "No permission to set miner increase interval.");
    Assert(input.Value <= State.MinerIncreaseInterval.Value, "Invalid interval");
    State.MinerIncreaseInterval.Value = input.Value;
    
    // Add synchronization with Election contract
    TryToGetCurrentRoundInformation(out var round);
    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
    {
        MinersCount = GetMinersCount(round)
    });
    
    return new Empty();
}
```

**Invariant Checks**:
- Ensure `Election.MinersCount` always matches the consensus contract's calculated `GetMinersCount()` before term transitions
- Add assertion in `GenerateFirstRoundOfNextTerm()` to verify consistency

**Test Cases**:
1. Call `SetMinerIncreaseInterval()` with decreased interval, then trigger term transition immediately - verify correct miner count
2. Call `SetMaximumMinersCount()` then `SetMinerIncreaseInterval()` in sequence - verify Election contract reflects both changes
3. Verify that term transitions always use the current calculated miners count, not a stale cached value

### Proof of Concept

**Required Initial State**:
- Blockchain age: 150,000 seconds
- `MinerIncreaseInterval`: 100,000 seconds  
- `MaximumMinersCount`: 50
- Calculated auto-increased count: 5 + (150,000 / 100,000) * 2 = 7 miners
- `Election.MinersCount`: 7

**Transaction Steps**:

1. Governance executes `SetMinerIncreaseInterval(50000)`:
   - `State.MinerIncreaseInterval.Value` = 50,000
   - New calculated count: 5 + (150,000 / 50,000) * 2 = 11 miners
   - `Election.MinersCount` remains 7 (NOT updated)

2. Before next round update, a miner triggers term transition:
   - `GetConsensusExtraDataForNextTerm()` calls `GenerateFirstRoundOfNextTerm()`
   - `TryToGetVictories()` calls `Election.GetVictories()`
   - `GetVictories()` uses `State.MinersCount.Value` = 7
   - Returns only top 7 candidates by votes

3. `ProcessNextTerm()` executes:
   - New term starts with 7 miners (incorrect)
   - Line 176: `UpdateMinersCountToElectionContract()` updates to 11 (too late)
   - Miner list already set with 7 miners for entire term

**Expected Result**: Term should start with 11 miners based on new interval

**Actual Result**: Term starts with 7 miners, using stale Election contract state

**Success Condition**: The term's `RealTimeMinersInformation` contains only 7 entries instead of expected 11, verifiable by querying `GetCurrentMinerList()` after term transition.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-29)
```csharp
    public override Empty SetMaximumMinersCount(Int32Value input)
    {
        EnsureElectionContractAddressSet();

        Assert(input.Value > 0, "Invalid max miners count.");

        RequiredMaximumMinersCountControllerSet();
        Assert(Context.Sender == State.MaximumMinersCountController.Value.OwnerAddress,
            "No permission to set max miners count.");

        TryToGetCurrentRoundInformation(out var round);

        State.MaximumMinersCount.Value = input.Value;
        State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
        {
            MinersCount = GetMinersCount(round)
        });

        return new Empty();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L223-242)
```csharp
    private Round GenerateFirstRoundOfNextTerm(string senderPubkey, int miningInterval)
    {
        Round newRound;
        TryToGetCurrentRoundInformation(out var currentRound);

        if (TryToGetVictories(out var victories))
        {
            Context.LogDebug(() => "Got victories successfully.");
            newRound = victories.GenerateFirstRoundOfNewTerm(miningInterval, Context.CurrentBlockTime,
                currentRound);
        }
        else
        {
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L266-283)
```csharp
    private bool TryToGetVictories(out MinerList victories)
    {
        if (!State.IsMainChain.Value)
        {
            victories = null;
            return false;
        }

        var victoriesPublicKeys = State.ElectionContract.GetVictories.Call(new Empty());
        Context.LogDebug(() =>
            "Got victories from Election Contract:\n" +
            $"{string.Join("\n", victoriesPublicKeys.Value.Select(s => s.ToHex().Substring(0, 20)))}");
        victories = new MinerList
        {
            Pubkeys = { victoriesPublicKeys.Value }
        };
        return victories.Pubkeys.Any();
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-177)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

```
