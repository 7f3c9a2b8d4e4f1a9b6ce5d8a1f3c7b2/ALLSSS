# Audit Report

## Title
Banned Pubkey Can Be Included in Election Snapshot via Replacement Chain, Allowing Banned Miners to Re-Enter Consensus

## Summary
The `GetPreviousTermSnapshotWithNewestPubkey()` function in the Election contract fails to verify whether the newest pubkey in a replacement chain is itself banned before including it in the election snapshot. This allows banned miners to bypass the ban mechanism and re-enter the active consensus miner set through the miner replacement mechanism.

## Finding Description

The vulnerability exists in the election snapshot replacement logic. When a banned candidate is identified in a term snapshot, the system retrieves the newest pubkey in the replacement chain but does not verify if that newest pubkey is also banned. [1](#0-0) 

The vulnerable logic at lines 151-154 checks only if the newest pubkey is null, identical to the banned candidate, or already exists in the snapshot. It does NOT call `IsPubkeyBanned()` to verify the newest pubkey's ban status.

The `IsPubkeyBanned()` helper function exists and is used elsewhere in the codebase: [2](#0-1) 

The replacement chain is maintained through mappings that track initial to newest pubkey transitions: [3](#0-2) 

When pubkeys are replaced, the old pubkey is banned: [4](#0-3) 

If a newest pubkey in the chain is subsequently marked as evil, it also gets banned: [5](#0-4) 

The corrupted snapshot from `GetPreviousTermSnapshotWithNewestPubkey()` is consumed by `GetMinerReplacementInformation()`: [6](#0-5) 

Critically, when selecting alternative candidates from the snapshot (lines 368-377), there is NO banned pubkey filtering applied. Note that when initial miners are added as alternatives, a banned check IS performed: [7](#0-6) 

This inconsistency reveals the missing validation. The consensus contract receives these alternatives and directly adds them to the active miner set without any additional banned checks: [8](#0-7) 

At line 338, the alternative candidate (which could be banned) is directly added to `currentRound.RealTimeMinersInformation`, making them an active miner.

## Impact Explanation

**Consensus Integrity Compromise**: The fundamental invariant that banned miners cannot participate in consensus is violated. Miners are banned for malicious behavior (evil node detection) or through governance action. Allowing them to re-enter consensus through replacement chains completely undermines this security mechanism.

**Reward Misallocation**: Banned miners who re-enter consensus will continue earning mining rewards (block production rewards, subsidy distributions) that should not be allocated to them. This represents direct fund impact through improper reward distribution.

**Security Degradation**: Miners are typically banned for detected malicious behavior or severe underperformance. Allowing them back into the active consensus set enables continued attacks or network performance degradation.

**Governance Bypass**: The ban enforcement mechanism is a critical governance control callable by the consensus contract or emergency response organization. This vulnerability makes that governance mechanism ineffective when miners establish replacement chains.

## Likelihood Explanation

**Reachable Entry Point**: The vulnerability is triggered automatically during normal consensus operations when the consensus contract calls `GetMinerReplacementInformation()` during round generation. This happens on the main chain within the same term when evil miners are detected.

**Feasible Preconditions**: 
- Replacement chains (A→B→C) are a standard, legitimate feature where miners replace their pubkeys
- Any miner in the chain can later be marked as evil/banned through normal consensus evil node detection
- No special permissions or attack complexity required

**Execution Practicality**: The exploit occurs passively once the conditions exist. When the consensus contract detects evil miners and queries for replacements, banned pubkeys in replacement chains are automatically included in the alternatives without any active attack needed.

**Economic Rationality**: An attacker controlling multiple pubkeys can establish a replacement chain at minimal cost (standard replacement fees). Intermediate pubkeys can operate normally while the final pubkey engages in malicious behavior. After being banned, the replacement chain mechanism allows re-entry into consensus.

## Recommendation

Add a banned pubkey check when retrieving the newest pubkey in the replacement chain. Modify `GetPreviousTermSnapshotWithNewestPubkey()` to verify the newest pubkey is not banned:

```csharp
foreach (var bannedCandidate in bannedCandidates)
{
    var newestPubkey = GetNewestPubkey(bannedCandidate);
    // Add banned check for the newest pubkey
    if (newestPubkey == null || newestPubkey == bannedCandidate ||
        snapshot.ElectionResult.ContainsKey(newestPubkey) ||
        IsPubkeyBanned(newestPubkey)) continue;  // ADD THIS CHECK
    
    var electionResult = snapshot.ElectionResult[bannedCandidate];
    snapshot.ElectionResult.Add(newestPubkey, electionResult);
    if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) 
        snapshot.ElectionResult.Remove(bannedCandidate);
}
```

Additionally, add a defensive banned check in `GetMinerReplacementInformation()` when selecting alternative candidates from the snapshot:

```csharp
var maybeNextCandidates = latestSnapshot.ElectionResult
    // Except initial miners.
    .Where(cs =>
        !State.InitialMiners.Value.Value.Contains(
            ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
    // Except current miners.
    .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
    // ADD: Except banned pubkeys
    .Where(cs => !State.BannedPubkeyMap[cs.Key])
    .OrderByDescending(s => s.Value).ToList();
```

## Proof of Concept

The vulnerability can be demonstrated through the following sequence:

1. **Setup Replacement Chain**: Miner A legitimately replaces to pubkey B via `ReplaceCandidatePubkey`. Pubkey A is banned and `InitialToNewestPubkeyMap[A] = B`.

2. **Second Replacement**: Miner B replaces to pubkey C. Pubkey B is banned and `InitialToNewestPubkeyMap[A] = C`.

3. **Ban Newest Pubkey**: Pubkey C is detected as evil and banned via `UpdateCandidateInformation` with `IsEvilNode = true`. Now `State.BannedPubkeyMap[C] = true`.

4. **Trigger Vulnerability**: During next round generation, consensus contract calls `GetMinerReplacementInformation`:
   - `GetPreviousTermSnapshotWithNewestPubkey()` is called
   - Finds A is banned in snapshot
   - Calls `GetNewestPubkey(A)` → returns C
   - Checks: C != null ✓, C != A ✓, C not in snapshot ✓
   - **Missing check**: Does NOT verify `IsPubkeyBanned(C)`
   - Adds C to snapshot with A's voting power

5. **Banned Miner Re-Enters**: 
   - `GetMinerReplacementInformation` selects C as alternative candidate
   - Consensus contract adds C to `currentRound.RealTimeMinersInformation`
   - Banned miner C is now an active consensus miner

The test would verify that after step 5, pubkey C (which has `State.BannedPubkeyMap[C] = true`) appears in the active miner list returned by the consensus contract, proving banned miners can bypass the ban mechanism through replacement chains.

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L145-157)
```csharp
        var bannedCandidates = snapshot.ElectionResult.Keys.Where(IsPubkeyBanned).ToList();
        Context.LogDebug(() => $"Banned candidates count: {bannedCandidates.Count}");
        if (!bannedCandidates.Any()) return snapshot;
        Context.LogDebug(() => "Getting snapshot and there's miner replaced during current term.");
        foreach (var bannedCandidate in bannedCandidates)
        {
            var newestPubkey = GetNewestPubkey(bannedCandidate);
            // If newest pubkey not exists or same as old pubkey (which is banned), skip.
            if (newestPubkey == null || newestPubkey == bannedCandidate ||
                snapshot.ElectionResult.ContainsKey(newestPubkey)) continue;
            var electionResult = snapshot.ElectionResult[bannedCandidate];
            snapshot.ElectionResult.Add(newestPubkey, electionResult);
            if (snapshot.ElectionResult.ContainsKey(bannedCandidate)) snapshot.ElectionResult.Remove(bannedCandidate);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L363-377)
```csharp
        var latestSnapshot = GetPreviousTermSnapshotWithNewestPubkey();
        // Check out election snapshot.
        if (latestSnapshot != null && latestSnapshot.ElectionResult.Any())
        {
            Context.LogDebug(() => $"Previous term snapshot:\n{latestSnapshot}");
            var maybeNextCandidates = latestSnapshot.ElectionResult
                // Except initial miners.
                .Where(cs =>
                    !State.InitialMiners.Value.Value.Contains(
                        ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
                // Except current miners.
                .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
                .OrderByDescending(s => s.Value).ToList();
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L387-391)
```csharp
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Candidate.cs (L61-64)
```csharp
    private bool IsPubkeyBanned(string pubkey)
    {
        return State.BannedPubkeyMap[pubkey];
    }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L246-246)
```csharp
        State.BannedPubkeyMap[input.OldPubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L280-291)
```csharp
    private void PerformReplacement(string oldPubkey, string newPubkey)
    {
        State.CandidateReplacementMap[newPubkey] = oldPubkey;

        // Initial pubkey is:
        // - miner pubkey of the first round (aka. Initial Miner), or
        // - the pubkey announced election

        var initialPubkey = State.InitialPubkeyMap[oldPubkey] ?? oldPubkey;
        State.InitialPubkeyMap[newPubkey] = initialPubkey;

        State.InitialToNewestPubkeyMap[initialPubkey] = newPubkey;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-338)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

            Context.LogDebug(() => $"Got miner replacement information:\n{minerReplacementInformation}");

            if (minerReplacementInformation.AlternativeCandidatePubkeys.Count > 0)
            {
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
```
