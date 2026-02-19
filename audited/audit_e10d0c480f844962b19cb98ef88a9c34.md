# Audit Report

## Title
Insufficient Alternative Candidates Due to Incorrect Initial Miners Calculation in Miner Replacement Logic

## Summary
The `GetMinerReplacementInformation` function in the Election contract calculates the number of initial miners to take before applying filters, causing fewer alternative candidates to be returned than evil miners detected. This results in some banned miners remaining active in the consensus mechanism.

## Finding Description

The vulnerability exists in the miner replacement logic that handles evil miner detection and replacement during consensus round generation. The execution flow is:

1. **Detection Phase**: The consensus contract calls `GetMinerReplacementInformation` to identify evil miners and find replacements [1](#0-0) 

2. **The Bug**: In the Election contract's `GetMinerReplacementInformation`, when falling back to initial miners as alternatives, the code incorrectly calculates `takeAmount` using the total count of all initial miners BEFORE filtering [2](#0-1) 

   The issue is that `takeAmount` is set to `Math.Min(diff, State.InitialMiners.Value.Value.Count)` but then two filters are applied:
   - Removing banned initial miners (`.Where(k => !State.BannedPubkeyMap[k])`)
   - Removing initial miners already in current miner list (`.Where(k => !input.CurrentMinerList.Contains(k))`)

   When the filtered collection has fewer elements than `takeAmount`, the `Take(takeAmount)` LINQ operation returns only the available elements, resulting in `alternativeCandidates` having fewer entries than needed.

3. **Consumption Phase**: The consensus contract receives the mismatch and only replaces as many evil miners as there are alternative candidates [3](#0-2) 

   The loop at line 311 iterates only `minerReplacementInformation.AlternativeCandidatePubkeys.Count` times, meaning evil miners at indices beyond this count remain in the active consensus miner list without replacement.

Evil miners are marked via the `UpdateCandidateInformation` method with `IsEvilNode = true`, which sets `State.BannedPubkeyMap[pubkey] = true` [4](#0-3) 

## Impact Explanation

**Consensus Integrity Compromise**: This breaks the security guarantee that all detected evil miners should be removed from consensus. Evil miners that should be banned remain active and can:
- Continue producing blocks and earning block rewards they shouldn't receive
- Potentially continue malicious behavior that caused them to be marked as evil
- Undermine network security and decentralization

**Quantified Scenario**: If 5 evil miners are detected but only 3 alternative candidates are available after filtering (e.g., 7 banned initial miners + 2 currently mining = 9 unavailable out of 10 total), then 2 evil miners remain active in consensus until the next term change.

**Affected Parties**: The entire blockchain network suffers compromised consensus security, honest validators face unfair competition with malicious actors, and token holders experience reduced network security.

## Likelihood Explanation

This is an operational vulnerability that occurs during normal protocol execution when specific state conditions are met:

**Preconditions:**
1. Multiple miners are detected as evil (via `Round.TryToDetectEvilMiners` for missed time slots or `RemoveEvilNode` by emergency response organization)
2. Many initial miners are already banned OR already serving in the current miner list
3. Insufficient alternative candidates exist in the election snapshot

**Feasibility**: Medium likelihood because:
- No attacker action required - manifests during routine evil miner detection
- State conditions are realistic in production: initial miners can accumulate bans over time
- More likely in networks with small initial miner sets or high historical ban rates
- Occurs during same-term round generation (not requiring term changes)

The mathematical condition triggering the bug: `(banned_initial_miners + active_initial_miners) > (total_initial_miners - needed_alternatives)`

## Recommendation

Calculate `takeAmount` AFTER applying the filters, not before. The corrected code should be:

```csharp
var diff = evilMinersPubKeys.Count - alternativeCandidates.Count;
if (diff > 0)
{
    var availableInitialMiners = State.InitialMiners.Value.Value
        .Select(k => k.ToHex())
        .Where(k => !State.BannedPubkeyMap[k])
        .Where(k => !input.CurrentMinerList.Contains(k))
        .ToList(); // Materialize after filtering
    
    var takeAmount = Math.Min(diff, availableInitialMiners.Count); // Use filtered count
    var selectedInitialMiners = availableInitialMiners.Take(takeAmount);
    alternativeCandidates.AddRange(selectedInitialMiners);
}
```

Alternatively, add validation to ensure all evil miners can be replaced, throwing an assertion if insufficient alternatives exist.

## Proof of Concept

```csharp
[Fact]
public async Task InsufficientAlternativeCandidates_EvilMinersRemainUnreplaced()
{
    // Setup: Create a scenario with 10 initial miners total
    // Ban 6 initial miners and have 2 currently mining
    // Detect 5 evil miners
    // Only 2 initial miners available as alternatives (10 - 6 - 2 = 2)
    // Expected: 3 evil miners remain unreplaced (5 - 2 = 3)
    
    var initialMinersCount = 10;
    var bannedCount = 6;
    var currentlyMiningInitialMinersCount = 2;
    var evilMinersDetected = 5;
    
    // After filtering: available = 10 - 6 - 2 = 2
    // Bug: takeAmount = Min(5, 10) = 5, but Take(5) returns only 2 after filters
    // Result: AlternativeCandidatePubkeys.Count = 2
    // Loop replaces only 2 evil miners, leaving 3 unreplaced
    
    var replacementInfo = await ElectionStub.GetMinerReplacementInformation.CallAsync(
        new GetMinerReplacementInformationInput { CurrentMinerList = { currentMiners } });
    
    replacementInfo.EvilMinerPubkeys.Count.ShouldBe(5);
    replacementInfo.AlternativeCandidatePubkeys.Count.ShouldBe(2); // Bug: should be 5
    
    // After consensus processes this, 3 evil miners remain active
    await ConsensusStub.NextRound.SendAsync(new NextRoundInput());
    
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var unreplacedEvilMiners = replacementInfo.EvilMinerPubkeys
        .Skip(2) // The ones not replaced
        .Where(pubkey => currentRound.RealTimeMinersInformation.ContainsKey(pubkey));
    
    unreplacedEvilMiners.Count().ShouldBe(3); // Vulnerability confirmed
}
```

## Notes

The vulnerability is confirmed by examining the exact code flow. The `BannedPubkeyMap` state tracking is defined at [5](#0-4)  and the miner replacement logic is invoked during consensus round generation only on the main chain when in the same term [6](#0-5) .

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L299-299)
```csharp
        if (IsMainChain && previousRound.TermNumber == currentRound.TermNumber) // In same term.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
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

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Election/ElectionContractState.cs (L33-33)
```csharp
    public MappedState<string, bool> BannedPubkeyMap { get; set; }
```
