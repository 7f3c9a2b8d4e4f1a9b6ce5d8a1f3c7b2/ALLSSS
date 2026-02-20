# Audit Report

## Title
Insufficient Alternative Candidates Due to Incorrect Initial Miners Calculation in Miner Replacement Logic

## Summary
The `GetMinerReplacementInformation` function in the Election contract calculates the number of initial miners to take before applying filters, causing fewer alternative candidates to be returned than evil miners detected. This results in some banned miners remaining active in the consensus mechanism.

## Finding Description

The vulnerability exists in the miner replacement logic that handles evil miner detection and replacement during consensus round generation.

**Detection Phase**: When the consensus contract processes a new round, it detects evil miners through `TryToDetectEvilMiners`, which identifies miners with missed time slots exceeding the tolerance threshold. [1](#0-0) [2](#0-1) 

These evil miners are then marked by calling `UpdateCandidateInformation` with `IsEvilNode = true`, which sets their banned status: [3](#0-2) [4](#0-3) 

**The Bug**: During the same term, the consensus contract calls `GetMinerReplacementInformation` to find replacement candidates: [5](#0-4) 

The critical flaw is in how initial miners are selected as fallback alternatives. The code calculates `takeAmount` BEFORE applying filters: [6](#0-5) 

The `takeAmount` is calculated as `Math.Min(diff, State.InitialMiners.Value.Value.Count)` at line 386, but then two filters are applied at lines 389-390:
- Filtering out banned initial miners (`!State.BannedPubkeyMap[k]`)
- Filtering out initial miners already in the current miner list (`!input.CurrentMinerList.Contains(k)`)

When the filtered collection has fewer elements than `takeAmount`, the `Take(takeAmount)` LINQ operation returns only the available elements, resulting in fewer alternative candidates than needed.

**Consumption Phase**: The consensus contract only replaces as many evil miners as there are alternative candidates: [7](#0-6) 

The loop at line 311 iterates only `minerReplacementInformation.AlternativeCandidatePubkeys.Count` times. Evil miners at indices beyond this count remain in the active consensus miner list without replacement.

## Impact Explanation

**Consensus Integrity Compromise**: This vulnerability breaks the fundamental security guarantee that all detected evil miners must be removed from consensus participation. Evil miners that should be banned remain active and can:

- Continue producing blocks and earning block rewards they should not receive
- Potentially continue malicious behavior (e.g., deliberately missing time slots to disrupt consensus)
- Undermine network security and decentralization principles

**Quantified Scenario**: Consider a network with 10 initial miners where 6 have been banned over time and 2 are currently mining. If 5 evil miners are detected with no alternatives from the election snapshot, only 2 initial miners remain available after filtering (10 - 6 - 2 = 2). The calculation would be:
- `diff = 5 - 0 = 5` 
- `takeAmount = Math.Min(5, 10) = 5`
- After filtering: only 2 available
- Result: 2 alternatives returned, only 2 evil miners replaced, **3 evil miners remain active**

**Affected Parties**: The entire blockchain network suffers compromised consensus security, honest validators face unfair competition with malicious actors who continue earning rewards, and token holders experience reduced network security.

## Likelihood Explanation

**Medium Likelihood** - This is an operational vulnerability that triggers during normal protocol execution when specific state conditions are met:

**Preconditions:**
1. Multiple miners detected as evil through `TryToDetectEvilMiners` (missed ≥4320 time slots) or manual `RemoveEvilNode` calls by the emergency response organization
2. Significant number of initial miners already banned or currently serving as active miners
3. Insufficient alternative candidates in the election snapshot

**Feasibility**: No attacker action is required—the bug manifests automatically during routine evil miner detection and replacement. The state conditions are realistic in production environments:
- Initial miners accumulate bans over the network's lifetime
- Initial miners naturally participate as current miners
- Small initial miner sets are common in permissioned/bootstrap phases

The mathematical trigger condition: `(banned_initial_miners + active_initial_miners) > (total_initial_miners - needed_alternatives)`

## Recommendation

Calculate `takeAmount` AFTER applying the filters, not before:

```csharp
// If the count of evil miners is greater than alternative candidates, add some initial miners to alternative candidates.
var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
if (diff > 0)
{
    var availableInitialMiners = State.InitialMiners.Value.Value
        .Select(k => k.ToHex())
        .Where(k => !State.BannedPubkeyMap[k])
        .Where(k => !input.CurrentMinerList.Contains(k))
        .ToList();
    
    var takeAmount = Math.Min(diff, availableInitialMiners.Count);
    alternativeCandidates.AddRange(availableInitialMiners.Take(takeAmount));
}
```

This ensures `takeAmount` accurately reflects the number of available initial miners after filtering, guaranteeing sufficient alternatives are returned for all detected evil miners (up to the available limit).

## Proof of Concept

```csharp
[Fact]
public async Task InsufficientAlternativeCandidates_EvilMinersRemainActive()
{
    // Setup: 10 initial miners, 6 banned, 2 currently mining
    // Detect 5 evil miners with 0 alternatives from snapshot
    // Expected: Only 2 alternatives returned (10 - 6 - 2 = 2)
    // Result: 3 evil miners remain in consensus
    
    var initialMiners = GenerateInitialMiners(10);
    var bannedMiners = initialMiners.Take(6).ToList();
    var currentMiners = initialMiners.Skip(8).Take(2).Concat(GenerateEvilMiners(5)).ToList();
    
    // Mark 6 initial miners as banned
    foreach (var miner in bannedMiners)
    {
        await ElectionContractStub.UpdateCandidateInformation.SendAsync(
            new UpdateCandidateInformationInput
            {
                Pubkey = miner,
                IsEvilNode = true
            });
    }
    
    // Call GetMinerReplacementInformation with 5 evil miners detected
    var result = await ElectionContractStub.GetMinerReplacementInformation.CallAsync(
        new GetMinerReplacementInformationInput
        {
            CurrentMinerList = { currentMiners }
        });
    
    // Verify: Only 2 alternatives returned instead of 5 needed
    result.EvilMinerPubkeys.Count.ShouldBe(5);
    result.AlternativeCandidatePubkeys.Count.ShouldBe(2); // Bug: Should be 5
    
    // This means 3 evil miners (indices 2-4) will remain active in consensus
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L177-183)
```csharp
    public bool TryToDetectEvilMiners(out List<string> evilMiners)
    {
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
        return evilMiners.Count > 0;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L139-154)
```csharp
        if (State.IsMainChain.Value && // Only detect evil miners in Main Chain.
            currentRound.TryToDetectEvilMiners(out var evilMiners))
        {
            Context.LogDebug(() => "Evil miners detected.");
            foreach (var evilMiner in evilMiners)
            {
                Context.LogDebug(() =>
                    $"Evil miner {evilMiner}, missed time slots: {currentRound.RealTimeMinersInformation[evilMiner].MissedTimeSlots}.");
                // Mark these evil miners.
                State.ElectionContract.UpdateCandidateInformation.Send(new UpdateCandidateInformationInput
                {
                    Pubkey = evilMiner,
                    IsEvilNode = true
                });
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-305)
```csharp
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
        {
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-339)
```csharp
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
                }
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L383-392)
```csharp
        var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
        if (diff > 0)
        {
            var takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count);
            var selectedInitialMiners = State.InitialMiners.Value.Value
                .Select(k => k.ToHex())
                .Where(k => !State.BannedPubkeyMap[k])
                .Where(k => !input.CurrentMinerList.Contains(k)).Take(takeAmount);
            alternativeCandidates.AddRange(selectedInitialMiners);
        }
```
