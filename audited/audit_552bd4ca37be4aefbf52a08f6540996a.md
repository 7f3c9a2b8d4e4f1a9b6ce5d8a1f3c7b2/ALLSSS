# Audit Report

## Title
Banned Candidates Can Be Selected as Miner Replacements Due to Missing Ban Status Check

## Summary
The `GetMinerReplacementInformation()` function in the Election contract fails to verify if alternative candidates from the previous term snapshot are currently banned before selecting them as miner replacements. This allows banned candidates to bypass the ban mechanism and be reintroduced into the active miner set, undermining consensus integrity.

## Finding Description
The vulnerability exists in the alternative candidate selection logic within `GetMinerReplacementInformation()`. When selecting replacement candidates from the previous term's election snapshot, the code filters out initial miners and current miners but completely omits checking the banned status of candidates. [1](#0-0) 

The filtering logic only excludes candidates who are initial miners or currently active miners, but does not check `State.BannedPubkeyMap[cs.Key]` to filter out banned candidates.

This is inconsistent with the fallback logic for selecting initial miners as alternatives, where banned status IS explicitly checked: [2](#0-1) 

The root cause lies in how `GetPreviousTermSnapshotWithNewestPubkey()` handles banned candidates. While it identifies banned candidates in the snapshot, it only replaces them if a replacement pubkey exists: [3](#0-2) 

When a banned candidate has no replacement (i.e., `newestPubkey == bannedCandidate`), the code continues without removing the banned candidate from the snapshot. These banned candidates then flow through to the selection logic where they are not filtered out.

Candidates are banned via `UpdateCandidateInformation()` when marked as evil nodes: [4](#0-3) 

The consensus contract directly adds the returned alternative candidates to the active miner set without additional validation: [5](#0-4) 

## Impact Explanation
This vulnerability has **critical impact** on consensus integrity:

1. **Consensus Integrity Violation**: Banned candidates are directly added to `currentRound.RealTimeMinersInformation`, allowing them to participate in block production despite being banned for malicious behavior.

2. **Ban Mechanism Circumvention**: The entire purpose of the ban system is defeated. Nodes identified as evil through `UpdateCandidateInformation(IsEvilNode=true)` can immediately return to the active miner set through the replacement mechanism.

3. **Protocol Trust Degradation**: If malicious nodes that were banned can rejoin the miner set, it undermines the security model and trust in the consensus mechanism. The ban is meant to be permanent, but this vulnerability provides an unintended path back into the active set.

The impact is not theoretical - the consensus contract directly uses the returned alternative candidates without any additional validation, as shown in the cited code.

## Likelihood Explanation
This vulnerability has **high likelihood** of occurrence because:

**Reachable Entry Point**: `GetMinerReplacementInformation()` is a public view method called by the consensus contract during normal miner replacement operations within the same term. [6](#0-5) 

**Feasible Preconditions**: The vulnerability triggers naturally when:
1. A candidate exists in the previous term's election results
2. That candidate is banned during the current term via `UpdateCandidateInformation(IsEvilNode=true)`
3. The candidate is not an initial miner and not currently in the miner list  
4. The candidate has no replacement pubkey (has not called `ReplaceCandidatePubkey`)
5. An evil miner needs to be replaced

**Execution Practicality**: This scenario occurs during normal blockchain operations without requiring any attacker action. Miners can be banned at any time during a term for malicious behavior, and the snapshot from the previous term would still contain their pre-ban voting results.

**No Attack Required**: This is a pure logic bug that manifests during legitimate protocol operations, making it extremely likely to occur in practice.

## Recommendation
Add a banned status check when filtering snapshot candidates for alternative selection. The fix should be applied at the same location where initial miners and current miners are filtered:

```csharp
var maybeNextCandidates = latestSnapshot.ElectionResult
    // Except initial miners.
    .Where(cs =>
        !State.InitialMiners.Value.Value.Contains(
            ByteString.CopyFrom(ByteArrayHelper.HexStringToByteArray(cs.Key))))
    // Except current miners.
    .Where(cs => !input.CurrentMinerList.Contains(cs.Key))
    // Except banned candidates.
    .Where(cs => !State.BannedPubkeyMap[cs.Key])
    .OrderByDescending(s => s.Value).ToList();
```

This ensures consistency with the initial miner selection logic and prevents banned candidates from being returned as alternatives.

Alternatively, `GetPreviousTermSnapshotWithNewestPubkey()` could be modified to explicitly remove banned candidates that have no replacement rather than skipping them.

## Proof of Concept
```csharp
[Fact]
public async Task BannedCandidateCanBeSelectedAsAlternative_Test()
{
    // Setup: Create a candidate that will be in previous term snapshot
    var bannedCandidate = "BANNED_PUBKEY_HEX";
    
    // Step 1: Previous term - candidate has high votes and is in snapshot
    // (Simulate term N ending with candidate in election results)
    
    // Step 2: Current term starts - candidate is NOT in initial miners
    
    // Step 3: Ban the candidate during current term
    await ElectionContractStub.UpdateCandidateInformation.SendAsync(
        new UpdateCandidateInformationInput
        {
            Pubkey = bannedCandidate,
            IsEvilNode = true
        });
    
    // Verify candidate is banned
    var isBanned = await ElectionContractStub.State.BannedPubkeyMap[bannedCandidate];
    Assert.True(isBanned);
    
    // Step 4: Trigger miner replacement by calling GetMinerReplacementInformation
    var currentMiners = new List<string> { "MINER1", "MINER2", "EVIL_MINER" };
    var result = await ElectionContractStub.GetMinerReplacementInformation.CallAsync(
        new GetMinerReplacementInformationInput
        {
            CurrentMinerList = { currentMiners }
        });
    
    // Vulnerability: Banned candidate appears in alternative list
    Assert.Contains(bannedCandidate, result.AlternativeCandidatePubkeys);
    
    // This demonstrates the banned candidate can be returned as a valid alternative
    // and would be added to the active miner set by the consensus contract
}
```

### Citations

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L145-158)
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
        }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L368-377)
```csharp
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L337-338)
```csharp
                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
```
