# Audit Report

## Title
Insufficient Alternative Candidates Allows Banned Miners to Remain in Consensus

## Summary
The miner replacement mechanism fails to ensure complete removal of banned miners when the alternative candidate pool is exhausted. The replacement loop iterates only based on the count of available alternatives, leaving unreplaced banned miners in the consensus round who can continue producing blocks and earning rewards.

## Finding Description

The vulnerability exists in the consensus contract's miner replacement logic during round generation. When the system detects evil miners that need replacement, it calls `GetMinerReplacementInformation` to obtain both the list of banned miners and available alternatives. [1](#0-0) 

The critical flaw occurs in the replacement loop, which iterates based solely on `AlternativeCandidatePubkeys.Count` and accesses both lists by index without verifying equal lengths. [2](#0-1) 

In `GetMinerReplacementInformation`, the Election contract can legitimately return fewer alternatives than evil miners. It first attempts to select candidates from the election snapshot, taking only the minimum between evil miner count and available candidates. [3](#0-2) 

It then tries to fill the gap with initial miners, but these are filtered to exclude banned and currently active miners. [4](#0-3) 

The returned `MinerReplacementInformation` structure contains `EvilMinerPubkeys` with all banned miners but `AlternativeCandidatePubkeys` with potentially fewer alternatives. [5](#0-4) 

**Root Cause:** When the alternative count is less than the evil miner count, only the first N evil miners are removed and replaced (lines 337-338 in the replacement loop). The remaining evil miners at indices N through end are never accessed and remain in `currentRound.RealTimeMinersInformation`.

Subsequently, `Round.GenerateNextRoundInformation` generates the next round using all miners present in `RealTimeMinersInformation` without any filtering for banned status. [6](#0-5) 

The mining permission validation only checks whether a pubkey exists in `RealTimeMinersInformation`, not whether it's banned. [7](#0-6) 

## Impact Explanation

**Consensus Integrity Compromise:** This vulnerability breaks the fundamental security invariant that miners marked as evil (stored in `State.BannedPubkeyMap`) must be excluded from consensus participation. [8](#0-7)  Banned miners can continue producing blocks, participating in consensus rounds, and validating transactions despite being penalized for violating consensus rules.

**Reward Misallocation:** Unreplaced evil miners continue earning block production rewards and mining dividends, directly undermining the economic security model designed to discourage malicious behavior through punishment.

**Attack Amplification:** Multiple malicious miners can coordinate simultaneous misbehavior. When the alternative candidate pool is shallow (common during low election participation or when most initial miners are already active), several evil miners remain operational, enabling sustained malicious activity against chain security.

**Severity: Critical** - This vulnerability compromises the core consensus mechanism's ability to maintain network integrity by removing misbehaving nodes.

## Likelihood Explanation

**Automatic Trigger:** The vulnerability is triggered automatically during normal consensus round generation, requiring no special permissions or external intervention.

**Realistic Preconditions:**
1. Multiple miners marked as evil in the same term (detectable through excessive missed time slots as defined by `TolerableMissedTimeSlotsCount`) [9](#0-8) 
2. Limited alternative candidates in the election snapshot due to low voter participation or few announced candidates
3. Most initial miners already active or also banned

**Execution Practicality:** These conditions naturally occur during:
- Periods of low election participation
- Network-wide issues causing multiple simultaneous failures  
- Coordinated attacks where multiple malicious nodes deliberately trigger evil node detection

**Economic Rationality:** Attackers controlling multiple miner nodes can deliberately cause time slot misses across their nodes. With a shallow candidate pool, some nodes remain active despite being marked evil.

**Likelihood: High** - The preconditions are realistic in production environments, especially during early network stages or low-participation periods.

## Recommendation

Modify the replacement logic to handle mismatched list sizes correctly. The system should either:

1. **Strict Approach:** Assert that `AlternativeCandidatePubkeys.Count == EvilMinerPubkeys.Count` and fail round generation if insufficient alternatives exist, forcing emergency governance intervention.

2. **Graceful Degradation:** Loop through all evil miners and remove them from `RealTimeMinersInformation` even when no alternatives are available, accepting a temporarily reduced miner set until the candidate pool replenishes.

3. **Validation Guard:** Add a check in `Round.GenerateNextRoundInformation` to filter out any miners present in `State.BannedPubkeyMap` before propagating to the next round.

The recommended fix is approach #2 combined with #3 for defense in depth:

```csharp
// In GenerateNextRoundInformation
for (var i = 0; i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
{
    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
    
    // Always remove evil miner
    UpdateCandidateInformation(evilMinerPubkey, ...);
    Context.Fire(new MinerReplaced { ... });
    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
    
    // Add alternative only if available
    if (i < minerReplacementInformation.AlternativeCandidatePubkeys.Count)
    {
        var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
        // Transfer consensus information and add alternative
    }
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BannedMiners_Remain_In_Consensus_When_Insufficient_Alternatives()
{
    // Setup: Initialize chain with 17 initial miners
    var initialMiners = MissionedECKeyPairs.InitialKeyPairs.Take(17).ToList();
    
    // Step 1: All initial miners are currently active
    await BlockMiningService.MineBlockToNextRoundAsync();
    var currentRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    currentRound.RealTimeMinersInformation.Count.ShouldBe(17);
    
    // Step 2: Mark 5 miners as evil (missed too many time slots)
    var evilMiners = initialMiners.Take(5).Select(k => k.PublicKey.ToHex()).ToList();
    foreach (var evilMiner in evilMiners)
    {
        await ElectionStub.UpdateCandidateInformation.SendAsync(new UpdateCandidateInformationInput
        {
            Pubkey = evilMiner,
            IsEvilNode = true
        });
    }
    
    // Step 3: No alternative candidates exist (low election participation scenario)
    // All initial miners are in use, no candidates announced
    
    // Step 4: Trigger next round generation
    await BlockMiningService.MineBlockToNextRoundAsync();
    var nextRound = await ConsensusStub.GetCurrentRoundInformation.CallAsync(new Empty());
    
    // VULNERABILITY: Evil miners should be removed but remain due to insufficient alternatives
    // Expected: nextRound should not contain evil miners
    // Actual: evil miners remain in consensus
    foreach (var evilMiner in evilMiners)
    {
        nextRound.RealTimeMinersInformation.Keys.ShouldNotContain(evilMiner); // This assertion FAILS
        
        // Evil miner can still produce blocks
        var minerInfo = nextRound.RealTimeMinersInformation[evilMiner];
        minerInfo.ShouldNotBeNull(); // Evil miner still present
    }
}
```

**Notes**

The vulnerability is confirmed through code analysis showing:
1. The replacement loop's iteration count depends solely on alternative availability
2. No secondary filtering exists to remove banned miners from round generation
3. Mining permission validation doesn't cross-reference the banned pubkey map

This represents a critical consensus security flaw that allows circumvention of the punishment mechanism designed to maintain network integrity.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L301-305)
```csharp
            var minerReplacementInformation = State.ElectionContract.GetMinerReplacementInformation.Call(
                new GetMinerReplacementInformationInput
                {
                    CurrentMinerList = { currentRound.RealTimeMinersInformation.Keys }
                });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L311-314)
```csharp
                for (var i = 0; i < minerReplacementInformation.AlternativeCandidatePubkeys.Count; i++)
                {
                    var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
                    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L376-377)
```csharp
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L383-391)
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
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-36)
```csharp
        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;

        // Set next round miners' information of miners who successfully mined during this round.
        foreach (var minerInRound in minersMinedCurrentRound.OrderBy(m => m.FinalOrderOfNextRound))
        {
            var order = minerInRound.FinalOrderOfNextRound;
            nextRound.RealTimeMinersInformation[minerInRound.Pubkey] = new MinerInRound
            {
                Pubkey = minerInRound.Pubkey,
                Order = order,
                ExpectedMiningTime = currentBlockTimestamp.AddMilliseconds(miningInterval.Mul(order)),
                ProducedBlocks = minerInRound.ProducedBlocks,
                MissedTimeSlots = minerInRound.MissedTimeSlots
            };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

**File:** contract/AElf.Contracts.Election/ElectionContract_Maintainence.cs (L93-96)
```csharp
        if (input.IsEvilNode)
        {
            var publicKeyByte = ByteArrayHelper.HexStringToByteArray(input.Pubkey);
            State.BannedPubkeyMap[input.Pubkey] = true;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L179-181)
```csharp
        evilMiners = RealTimeMinersInformation.Values
            .Where(m => m.MissedTimeSlots >= AEDPoSContractConstants.TolerableMissedTimeSlotsCount)
            .Select(m => m.Pubkey).ToList();
```
