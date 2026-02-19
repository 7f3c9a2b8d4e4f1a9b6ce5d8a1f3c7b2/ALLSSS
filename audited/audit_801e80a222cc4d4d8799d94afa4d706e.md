### Title
Duplicate Initial Miner Entries Cause Consensus DoS During Evil Miner Replacement

### Summary
The `State.InitialMiners` list can contain duplicate entries due to lack of deduplication during initialization and incomplete removal during pubkey replacement. When `GetMinerReplacementInformation()` selects initial miners as backup alternatives, duplicates can be returned, causing the Consensus contract to crash with an `ArgumentException` when attempting to add the same pubkey twice to the round's miner map, resulting in denial of service.

### Finding Description

**Root Cause:**

`State.InitialMiners` is initialized directly from the input without deduplication: [1](#0-0) 

During pubkey replacement, the `Remove()` method only removes the **first occurrence** of a duplicate: [2](#0-1) 

If `State.InitialMiners` contains `[A, A, B]` and `A` is replaced with `A'`, only the first `A` is removed, resulting in `[A, B, A']` - a stale entry remains.

**Exploitation Path:**

When `GetMinerReplacementInformation()` needs to replace evil miners but doesn't find enough non-initial-miner candidates, it falls back to selecting initial miners as alternatives: [3](#0-2) 

If `State.InitialMiners.Value.Value` contains duplicates like `[A', A', B]`, the `Select().Where().Where().Take(n)` chain does **not** deduplicate. It can return `[A', A']` in `selectedInitialMiners`.

This duplicate list is returned in `AlternativeCandidatePubkeys`: [4](#0-3) 

The Consensus contract iterates through both lists in parallel and calls `Add()` on the protobuf map: [5](#0-4) 

The map field `real_time_miners_information` is defined as a protobuf map: [6](#0-5) 

When the same pubkey is added twice, the second `Add()` throws `ArgumentException` (duplicate key), crashing consensus round generation.

### Impact Explanation

**Concrete Impact:**
- **Operational DoS**: Consensus contract cannot generate new rounds when evil miner replacement is triggered
- **Chain Halt**: Block production stops until the issue is manually resolved through governance or emergency response
- **Scope**: Affects entire blockchain - all nodes experience the same failure

**Severity Justification:**
- Critical infrastructure failure (consensus mechanism)
- Requires manual intervention to recover
- Can occur during normal operations (evil miner detection and replacement)
- Affects all network participants

### Likelihood Explanation

**Feasibility:**
- **Precondition 1**: Initial configuration contains duplicate miner pubkeys (operational error)
- **Precondition 2**: OR pubkey replacement creates unremoved stale entries due to pre-existing duplicates
- **Trigger**: Evil miner detection combined with insufficient non-initial-miner candidates

**Probability Assessment:**
- Configuration errors are realistic in complex deployments
- The `Remove()` single-occurrence issue is deterministic once duplicates exist
- Evil miner detection is a designed feature that will trigger periodically
- **Medium likelihood**: Requires either configuration error OR edge case in replacement chain, but consequences are automatic once triggered

**Detection:**
- Not easily detectable until the DoS occurs
- No validation prevents duplicate insertion
- No monitoring alerts for duplicate initial miners

### Recommendation

**Immediate Fixes:**

1. **Add deduplication during initialization:**
```csharp
// In InitialElectionContract
State.InitialMiners.Value = new PubkeyList
{
    Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)).Distinct() }
};
```

2. **Remove all occurrences during replacement:**
```csharp
// In ReplaceCandidatePubkey
var initialMiners = State.InitialMiners.Value;
if (initialMiners.Value.Contains(oldPubkeyBytes))
{
    // Remove ALL occurrences
    while (initialMiners.Value.Remove(oldPubkeyBytes)) { }
    initialMiners.Value.Add(newPubkeyBytes);
    State.InitialMiners.Value = initialMiners;
}
```

3. **Add duplicate check in GetMinerReplacementInformation:**
```csharp
// Before returning
alternativeCandidates = alternativeCandidates.Distinct().ToList();
```

**Invariant Checks:**
- Assert `State.InitialMiners` has no duplicates after initialization
- Assert `alternativeCandidates` has no duplicates before returning
- Add unit test with duplicate initial miner configuration

### Proof of Concept

**Initial State:**
- `State.InitialMiners = ["A'", "A'", "B"]` (duplicate `A'` from configuration error or incomplete replacement)
- `A'` is not banned
- `B` is a current miner
- Current miner list: `["Evil1", "Evil2", "B"]`
- `Evil1` and `Evil2` are marked as evil/banned

**Execution Steps:**

1. Consensus contract calls `GetMinerReplacementInformation` with `CurrentMinerList = ["Evil1", "Evil2", "B"]`

2. `GetEvilMinersPubkeys` returns `["Evil1", "Evil2"]` (both are banned)

3. First filter (lines 368-380) finds no non-initial-miner candidates from snapshot (or excludes them all)
   - Result: `alternativeCandidates = []`

4. Second filter calculates `diff = 2 - 0 = 2`

5. Lines 385-391 execute:
   - `State.InitialMiners.Value.Value.Select(k => k.ToHex())` → `["A'", "A'", "B"]`
   - `.Where(k => !State.BannedPubkeyMap[k])` → `["A'", "A'", "B"]` (none banned)
   - `.Where(k => !input.CurrentMinerList.Contains(k))` → `["A'", "A'"]` (`B` filtered out)
   - `.Take(2)` → `["A'", "A'"]`
   
6. Returns: `AlternativeCandidatePubkeys = ["A'", "A'"]`, `EvilMinerPubkeys = ["Evil1", "Evil2"]`

7. Consensus contract (lines 311-339):
   - **i=0**: `Remove("Evil1")`, `Add("A'", minerInRound)` ✓ Success
   - **i=1**: `Remove("Evil2")`, `Add("A'", minerInRound)` ✗ **CRASH**

**Expected vs Actual:**
- Expected: Successful miner replacement, new round generated
- Actual: `ArgumentException: An item with the same key has already been added` at line 338
- Consensus round generation fails, chain halts

### Citations

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L34-38)
```csharp
        State.InitialMiners.Value = new PubkeyList
        {
            // ReSharper disable once ConvertClosureToMethodGroup
            Value = { input.MinerList.Select(m => ByteStringHelper.FromHexString(m)) }
        };
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L220-226)
```csharp
        var initialMiners = State.InitialMiners.Value;
        if (initialMiners.Value.Contains(oldPubkeyBytes))
        {
            initialMiners.Value.Remove(oldPubkeyBytes);
            initialMiners.Value.Add(newPubkeyBytes);
            State.InitialMiners.Value = initialMiners;
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L385-391)
```csharp
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-339)
```csharp
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];

                    // Update history information of evil node.
                    UpdateCandidateInformation(evilMinerPubkey,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
                        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);

                    Context.Fire(new MinerReplaced
                    {
                        NewMinerPubkey = alternativeCandidatePubkey
                    });

                    // Transfer evil node's consensus information to the chosen backup.
                    var evilMinerInformation = currentRound.RealTimeMinersInformation[evilMinerPubkey];
                    var minerInRound = new MinerInRound
                    {
                        Pubkey = alternativeCandidatePubkey,
                        ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
                        Order = evilMinerInformation.Order,
                        PreviousInValue = Hash.Empty,
                        IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
                    };

                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
                }
```

**File:** protobuf/aedpos_contract.proto (L247-247)
```text
    map<string, MinerInRound> real_time_miners_information = 2;
```
