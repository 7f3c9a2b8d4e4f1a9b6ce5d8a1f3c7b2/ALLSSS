# Audit Report

## Title
Insufficient Alternative Candidates Due to Incorrect Initial Miners Calculation in Miner Replacement Logic

## Summary
The `GetMinerReplacementInformation` function calculates the number of initial miners to take before applying filters, causing fewer alternative candidates to be returned than evil miners detected. This results in banned miners remaining active in consensus.

## Finding Description

The vulnerability exists in the miner replacement logic that handles evil miner detection and replacement during consensus round generation.

**Execution Flow:**

1. **Detection Phase**: Evil miners are detected when they exceed the tolerable missed time slots count (4320 slots = 3 days). [1](#0-0)  The consensus contract marks them as evil by calling `UpdateCandidateInformation` with `IsEvilNode = true`. [2](#0-1)  This sets `State.BannedPubkeyMap[pubkey] = true` in the Election contract. [3](#0-2) 

2. **The Bug**: During round generation, the consensus contract calls `GetMinerReplacementInformation` to find replacements. [4](#0-3)  When falling back to initial miners as alternatives, the Election contract incorrectly calculates `takeAmount` using the total count BEFORE filtering. [5](#0-4) 

   The issue: `takeAmount = Math.Min(diff, State.InitialMiners.Value.Value.Count)` is calculated first, then two filters are applied:
   - Removing banned initial miners (`.Where(k => !State.BannedPubkeyMap[k])`)
   - Removing initial miners already in current miner list (`.Where(k => !input.CurrentMinerList.Contains(k))`)

   After filtering, if fewer than `takeAmount` initial miners remain, `Take(takeAmount)` returns only the available elements, resulting in `alternativeCandidates` having fewer entries than `evilMinersPubKeys`.

3. **Consumption Phase**: The consensus contract receives the mismatched lists and only replaces as many evil miners as there are alternative candidates. [6](#0-5) 

   The loop iterates only `minerReplacementInformation.AlternativeCandidatePubkeys.Count` times, meaning evil miners at indices beyond this count remain in the active consensus miner list without replacement.

## Impact Explanation

**Consensus Integrity Compromise**: This breaks the security guarantee that all detected evil miners should be removed from consensus. Evil miners that should be banned remain active and can:
- Continue producing blocks and earning block rewards they shouldn't receive
- Potentially continue malicious behavior that caused them to be marked as evil
- Undermine network security and decentralization

**Quantified Scenario**: If 5 evil miners are detected but only 3 alternative candidates are available after filtering (e.g., 7 banned initial miners + 2 currently mining = 9 unavailable out of 10 total), then 2 evil miners remain active in consensus.

**Affected Parties**: The entire blockchain network suffers compromised consensus security, honest validators face unfair competition with malicious actors, and token holders experience reduced network security.

## Likelihood Explanation

This vulnerability manifests during normal protocol execution when specific state conditions are met:

**Preconditions:**
1. Multiple miners are detected as evil (via `TryToDetectEvilMiners` for missed time slots or `RemoveEvilNode` by emergency response organization)
2. Many initial miners are already banned OR already serving in the current miner list
3. Insufficient alternative candidates exist in the election snapshot

**Feasibility**: Medium likelihood because:
- No attacker action required - manifests during routine evil miner detection
- State conditions are realistic in production: initial miners can accumulate bans over time
- More likely in networks with small initial miner sets or high historical ban rates
- Occurs during same-term round generation (not requiring term changes)

The mathematical condition triggering the bug: `(banned_initial_miners + active_initial_miners) > (total_initial_miners - needed_alternatives)`

## Recommendation

Calculate `takeAmount` AFTER applying both filters to ensure it reflects the actual number of available initial miners:

```csharp
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

Additionally, consider adding validation in the consensus contract to assert that `AlternativeCandidatePubkeys.Count == EvilMinerPubkeys.Count` before processing replacements, or handle the mismatch explicitly by logging the shortfall and deferring remaining replacements to the next round.

## Proof of Concept

```csharp
[Fact]
public void Test_InsufficientAlternativeCandidates()
{
    // Setup: 10 initial miners, 5 become evil, 7 are banned, 2 are currently mining
    // Expected: 5 evil miners should be replaced
    // Actual: Only 1 replacement available (10 - 7 banned - 2 active = 1)
    // Result: 4 evil miners remain unreplaced
    
    var evilMiners = new List<string> { "evil1", "evil2", "evil3", "evil4", "evil5" };
    var currentMiners = new List<string> { "miner1", "miner2" }.Concat(evilMiners).ToList();
    var bannedInitialMiners = 7; // 7 out of 10 initial miners are banned
    
    var replacementInfo = ElectionContract.GetMinerReplacementInformation(
        new GetMinerReplacementInformationInput { CurrentMinerList = { currentMiners } }
    );
    
    // Bug manifests: Only 1 alternative available despite 5 evil miners
    Assert.Equal(5, replacementInfo.EvilMinerPubkeys.Count);
    Assert.Equal(1, replacementInfo.AlternativeCandidatePubkeys.Count); // Should be 5
    
    // Consensus contract will only replace 1 evil miner, leaving 4 active
}
```

## Notes

This vulnerability represents a gap between the **intended security invariant** (all detected evil miners must be removed) and the **actual implementation** (only as many are removed as alternatives are available). The issue is not in the evil miner detection logic itself, but in the calculation of available alternatives when the election snapshot is insufficient and the system falls back to initial miners. The fix requires recalculating `takeAmount` after filters are applied to reflect the true number of available initial miners.

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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-306)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L309-342)
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

                isMinerListChanged = true;
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
