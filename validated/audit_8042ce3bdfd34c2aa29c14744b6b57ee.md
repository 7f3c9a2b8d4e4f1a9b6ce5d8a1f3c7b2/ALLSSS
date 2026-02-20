# Audit Report

## Title
Insufficient Alternative Candidates Allows Banned Miners to Remain in Consensus

## Summary
The AEDPoS consensus contract contains a critical logic error in its miner replacement mechanism. When generating the next consensus round, the replacement loop iterates based on the count of available alternative candidates rather than the count of evil miners to be replaced. This causes partial replacement when alternatives are insufficient, allowing unreplaced banned miners to continue producing blocks and earning rewards.

## Finding Description

During consensus round transitions on the main chain, the system attempts to replace evil miners (those who have missed ≥4320 time slots, representing 3 days of missed blocks) with alternative candidates. [1](#0-0) 

The replacement process calls `GetMinerReplacementInformation` from the Election contract to identify banned miners and find replacements. [2](#0-1) 

**Critical Flaw**: The replacement loop iterates based on `AlternativeCandidatePubkeys.Count` instead of `EvilMinerPubkeys.Count`: [3](#0-2) 

However, `GetMinerReplacementInformation` can legitimately return fewer alternatives than evil miners when the candidate pool is exhausted. It attempts to take candidates from the election snapshot (limited by availability): [4](#0-3) 

Then tries to fill the gap with initial miners, filtering out banned and currently active miners: [5](#0-4) 

The method returns both lists with potentially mismatched sizes: [6](#0-5) 

**Root Cause**: When `AlternativeCandidatePubkeys.Count < EvilMinerPubkeys.Count`, the loop only processes indices [0, AlternativeCandidatePubkeys.Count). Evil miners at indices ≥ AlternativeCandidatePubkeys.Count are never accessed and remain in `currentRound.RealTimeMinersInformation`. [7](#0-6) 

Subsequently, `Round.GenerateNextRoundInformation` generates the next round using whatever miners exist in `RealTimeMinersInformation` without filtering for banned status: [8](#0-7) 

The unreplaced banned miners propagate into the next round and can produce blocks because `MiningPermissionValidationProvider` only checks if the miner's pubkey exists in the current round's miner list, not whether they are banned: [9](#0-8) 

Miners are detected as evil and marked as banned when they miss too many time slots: [10](#0-9) 

The consensus contract reports evil miners to the Election contract: [11](#0-10) 

Which sets their banned status: [12](#0-11) 

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the fundamental security invariant that miners banned via `State.BannedPubkeyMap` for violating consensus rules (missing ≥4320 consecutive time slots) must be excluded from consensus participation.

**Consensus Integrity Violation**: Unreplaced evil miners continue producing blocks despite being penalized for persistent unavailability or malicious behavior, directly compromising the consensus mechanism's integrity and the blockchain's security guarantees.

**Reward Misallocation**: Banned miners continue earning block production rewards through the Treasury contract's mining reward distribution. This completely undermines the economic security model that relies on punishment to discourage misbehavior, as malicious miners can avoid the intended economic penalty while continuing to earn.

**Attack Amplification**: Multiple malicious miners can coordinate to simultaneously violate consensus rules (deliberately miss time slots). When the alternative candidate pool is shallow due to low election participation or most initial miners being already active or banned, several evil miners will remain in consensus. This enables sustained coordinated attacks against chain liveness and finality while the attackers continue earning rewards.

## Likelihood Explanation

**Likelihood: High**

**Automatically Triggered**: The vulnerability is part of the normal consensus block production flow executed during regular round transitions via `GenerateNextRoundInformation`. No special permissions or attacker-controlled transactions are required—the flaw manifests during routine consensus operation.

**Realistic Preconditions**:
1. Multiple miners marked as evil within the same term (commonly occurs through network issues, node failures, or coordinated attacks)
2. Limited alternative candidates in the election snapshot (frequent during periods of low voter participation in the election process)
3. Most initial miners already in the current miner list or also banned (typical scenario in mature blockchain networks)

**High Execution Practicality**: The scenario naturally occurs when election participation is low, multiple miners fail simultaneously due to network issues, or the initial miner set is exhausted. Attackers controlling multiple miner nodes can deliberately trigger this by causing time slot misses across their nodes. With shallow candidate pools (realistic in many blockchain networks), some malicious nodes will remain active despite being marked as evil.

**Detection Difficulty**: The mismatch is only visible through debug logs. Unreplaced evil miners continue normal block production operations, making the issue difficult to detect without explicitly monitoring the `BannedPubkeyMap` state against the active miner list in `RealTimeMinersInformation`.

## Recommendation

Modify the replacement loop to iterate over `EvilMinerPubkeys.Count` instead of `AlternativeCandidatePubkeys.Count`. When alternatives are exhausted, take appropriate action such as:

1. **Option A - Forced Removal**: Remove all evil miners even without replacements, accepting a reduced miner set temporarily
2. **Option B - Emergency Halt**: Halt consensus and require governance intervention when evil miners cannot be replaced
3. **Option C - Postponed Replacement**: Keep evil miners but flag them for priority replacement in subsequent rounds

Example fix for the replacement logic in `AEDPoSContract_ViewMethods.cs`:

```csharp
// Iterate over ALL evil miners, not just available alternatives
for (var i = 0; i < minerReplacementInformation.EvilMinerPubkeys.Count; i++)
{
    var evilMinerPubkey = minerReplacementInformation.EvilMinerPubkeys[i];
    
    // Update history information of evil node
    UpdateCandidateInformation(evilMinerPubkey,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].ProducedBlocks,
        currentRound.RealTimeMinersInformation[evilMinerPubkey].MissedTimeSlots, true);
    
    // Always remove the evil miner
    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
    
    // Add replacement only if available
    if (i < minerReplacementInformation.AlternativeCandidatePubkeys.Count)
    {
        var alternativeCandidatePubkey = minerReplacementInformation.AlternativeCandidatePubkeys[i];
        Context.Fire(new MinerReplaced { NewMinerPubkey = alternativeCandidatePubkey });
        
        var minerInRound = new MinerInRound
        {
            Pubkey = alternativeCandidatePubkey,
            ExpectedMiningTime = evilMinerInformation.ExpectedMiningTime,
            Order = evilMinerInformation.Order,
            PreviousInValue = Hash.Empty,
            IsExtraBlockProducer = evilMinerInformation.IsExtraBlockProducer
        };
        currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
    }
}
```

Additionally, add validation in `MiningPermissionValidationProvider` to check the banned status:

```csharp
public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
{
    var validationResult = new ValidationResult();
    
    if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
    {
        validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
        return validationResult;
    }
    
    // Add banned check
    if (State.ElectionContract.GetCandidateInformation.Call(new StringValue 
        { Value = validationContext.SenderPubkey }) == null || 
        State.BannedPubkeyMap[validationContext.SenderPubkey])
    {
        validationResult.Message = $"Sender {validationContext.SenderPubkey} is banned.";
        return validationResult;
    }
    
    validationResult.Success = true;
    return validationResult;
}
```

## Proof of Concept

```csharp
[Fact]
public async Task BannedMinersRemainActive_WhenInsufficientAlternatives()
{
    // Setup: 7 miners, 5 become evil, only 2 alternatives available
    var initialMiners = GenerateMinerList(7);
    await InitializeConsensus(initialMiners);
    
    // Simulate 5 miners missing 4320 time slots (becoming evil)
    var evilMiners = initialMiners.Take(5).ToList();
    foreach (var evilMiner in evilMiners)
    {
        await SimulateMissedTimeSlots(evilMiner, 4320);
    }
    
    // Setup only 2 alternative candidates in election
    var alternatives = GenerateMinerList(2);
    await SetupElectionCandidates(alternatives);
    
    // Execute round transition
    var currentRound = await GetCurrentRoundInformation();
    await GenerateNextRound(currentRound);
    
    // Verify vulnerability: 3 evil miners remain active
    var nextRound = await GetCurrentRoundInformation();
    var remainingEvilMiners = evilMiners.Where(m => 
        nextRound.RealTimeMinersInformation.ContainsKey(m.PublicKey.ToHex()));
    
    // Expected: 3 evil miners remain (5 evil - 2 replaced = 3)
    Assert.Equal(3, remainingEvilMiners.Count());
    
    // Verify these banned miners can still produce blocks
    foreach (var evilMiner in remainingEvilMiners)
    {
        var canMine = await CanProduceBlock(evilMiner, nextRound);
        Assert.True(canMine); // Vulnerability: banned miner can still mine
    }
    
    // Verify they continue earning rewards
    var initialBalance = await GetMinerBalance(remainingEvilMiners.First());
    await ProduceBlock(remainingEvilMiners.First());
    var finalBalance = await GetMinerBalance(remainingEvilMiners.First());
    Assert.True(finalBalance > initialBalance); // Vulnerability: banned miner earns rewards
}
```

## Notes

This vulnerability is particularly severe because it:

1. **Violates Core Invariants**: The banned miner exclusion mechanism is fundamental to consensus security
2. **Requires No Attack**: Naturally occurs during low election participation or network stress
3. **Persists Across Rounds**: Unreplaced evil miners remain active indefinitely until alternatives become available
4. **Undermines Incentives**: Completely bypasses the economic punishment mechanism designed to ensure miner reliability
5. **Enables Coordinated Attacks**: Multiple malicious miners can exploit this to maintain consensus influence despite misbehavior

The fix must ensure ALL evil miners are removed from consensus participation, even when insufficient alternatives are available. The system should accept a temporarily reduced miner set rather than allowing banned miners to continue operating.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```

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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L337-338)
```csharp
                    currentRound.RealTimeMinersInformation.Remove(evilMinerPubkey);
                    currentRound.RealTimeMinersInformation.Add(alternativeCandidatePubkey, minerInRound);
```

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L376-377)
```csharp
            var take = Math.Min(evilMinersPubKeys.Count, maybeNextCandidates.Count);
            alternativeCandidates.AddRange(maybeNextCandidates.Select(c => c.Key).Take(take));
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

**File:** contract/AElf.Contracts.Election/ViewMethods.cs (L394-398)
```csharp
        return new MinerReplacementInformation
        {
            EvilMinerPubkeys = { evilMinersPubKeys },
            AlternativeCandidatePubkeys = { alternativeCandidates }
        };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-23)
```csharp
    public void GenerateNextRoundInformation(Timestamp currentBlockTimestamp, Timestamp blockchainStartTimestamp,
        out Round nextRound, bool isMinerListChanged = false)
    {
        nextRound = new Round { IsMinerListJustChanged = isMinerListChanged };

        var minersMinedCurrentRound = GetMinedMiners();
        var minersNotMinedCurrentRound = GetNotMinedMiners();
        var minersCount = RealTimeMinersInformation.Count;

        var miningInterval = GetMiningInterval();
        nextRound.RoundNumber = RoundNumber + 1;
        nextRound.TermNumber = TermNumber;
        nextRound.BlockchainAge = RoundNumber == 1 ? 1 : (currentBlockTimestamp - blockchainStartTimestamp).Seconds;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L17-21)
```csharp
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }
```

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
