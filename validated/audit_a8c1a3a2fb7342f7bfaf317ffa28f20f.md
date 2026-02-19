# Audit Report

## Title
Off-By-One Error in MinersCountOfConsent Enables Term Change Denial-of-Service When Miner Count is Divisible by Three

## Summary
The `MinersCountOfConsent` threshold formula contains a mathematical inconsistency that requires one additional vote beyond the documented 2/3 majority when the total miner count is divisible by 3. This enables attackers controlling exactly 1/3 of miners to block term transitions by ceasing block production, preventing new miner elections and delaying treasury distributions.

## Finding Description

The consensus threshold calculation uses the formula `RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1)` [1](#0-0) , which computes as ⌊2n/3⌋ + 1 using integer division.

When the miner count is divisible by 3, this formula produces an inflated threshold:
- n=3: requires 3 votes (100%) vs. standard 2/3 = 2 votes (66.7%)
- n=6: requires 5 votes (83.3%) vs. standard 2/3 = 4 votes (66.7%)
- n=9: requires 7 votes (77.8%) vs. standard 2/3 = 6 votes (66.7%)

The `NeedToChangeTerm` method uses this threshold to determine if term transitions should occur [2](#0-1) . It filters only miners who have produced blocks (`ActualMiningTimes.Any()`) and counts how many agree it's time to change terms. The threshold, however, is based on the total miner count, not just active miners.

The code comment explicitly states "Change term if two thirds of miners latest ActualMiningTime meets threshold" [3](#0-2) , indicating the intended behavior is a standard 2/3 majority (≥66.7%), not the higher threshold implemented.

**Exploitation Path:**
1. Network configured with 6 miners (or any multiple of 3) via `SetMaximumMinersCount` [4](#0-3) 
2. Attacker controls 2 miners (exactly 1/3)
3. When the term period expires, the consensus behavior provider checks `NeedToChangeTerm` [5](#0-4) 
4. Attacker's 2 miners cease block production entirely
5. Only 4 honest miners have `ActualMiningTimes.Any()` evaluating to true
6. Count of 4 < `MinersCountOfConsent` of 5, so `NeedToChangeTerm` returns false
7. The system continues returning `NextRound` instead of `NextTerm`, blocking the term transition

## Impact Explanation

**Governance Disruption:**
- New miners elected through the election contract cannot join the active miner set because the miner list is only updated during term transitions [6](#0-5) 
- The old miner set (including attackers) remains in power indefinitely until evil miner detection triggers
- Election snapshots are not taken [7](#0-6) , breaking the democratic election cycle

**Economic Impact:**
- Treasury profit releases for the completed term are delayed [8](#0-7) 
- Current miners continue earning block rewards (initially 12,500,000 tokens per block [9](#0-8) ) that should go to newly elected miners
- Attackers who lost elections extend their tenure and reward earnings

**Severity Justification:**
Medium severity - while this does not enable direct fund theft, it constitutes a denial-of-service attack on the governance layer, disrupts democratic miner rotation, and delays economic distributions. Block production continues normally, preventing complete chain halt.

## Likelihood Explanation

**Attacker Capabilities:**
- Must control exactly n/3 miners when n is divisible by 3
- Attack execution is trivial: simply stop mining blocks

**Feasibility Conditions:**
- Network must have 3, 6, 9, 12, 15, 18, or 21 miners (multiples of 3)
- While default is 17 miners [10](#0-9) , the system is configurable through parliament-controlled `SetMaximumMinersCount` [4](#0-3) 
- No validation prevents setting counts divisible by 3 [11](#0-10) 

**Economic Rationality:**
- Attackers who are current miners and lost the recent election can delay replacement
- They continue earning block rewards for several days
- Evil miner detection only triggers after 4,320 missed time slots (~3 days) [12](#0-11) 
- Detection occurs in `TryToDetectEvilMiners` [13](#0-12) , but only after significant delay

**Detection:**
- Attack is observable through missed block production
- Eventually results in evil miner punishment after tolerance threshold is exceeded

## Recommendation

Replace the `MinersCountOfConsent` formula with a ceiling-based calculation to ensure consistent 2/3 majority behavior:

```csharp
public int MinersCountOfConsent => (RealTimeMinersInformation.Count.Mul(2).Add(2)).Div(3);
```

This computes ⌈2n/3⌉ which provides consistent "at least 2/3" semantics:
- n=3: requires 2 votes (66.7%)
- n=6: requires 4 votes (66.7%)
- n=9: requires 6 votes (66.7%)

Alternatively, if the intent is to require strictly more than 2/3 for BFT safety, update the comment to reflect this and add validation to prevent miner counts divisible by 3:

```csharp
/// <summary>
/// Change term if MORE than two thirds of miners agree (BFT safety requirement).
/// Note: When miner count is divisible by 3, this requires unanimous agreement from all non-Byzantine miners.
/// </summary>
```

And add validation:
```csharp
Assert(input.Value % 3 != 0, "Miner count must not be divisible by 3 to prevent governance deadlock.");
```

## Proof of Concept

```csharp
[Fact]
public async Task TermChangeBlockedWith6Miners_Test()
{
    // Setup: Configure network with 6 miners (divisible by 3)
    await SetMaximumMinersCount(6);
    await InitializeConsensusWithMiners(6);
    
    // Attacker controls 2 miners (1/3), honest miners control 4 (2/3)
    var attackerMiners = new[] { InitialCoreDataCenterKeyPairs[4], InitialCoreDataCenterKeyPairs[5] };
    var honestMiners = InitialCoreDataCenterKeyPairs.Take(4).ToList();
    
    // Advance time beyond term period
    var termSeconds = 604800; // 7 days
    BlockTimeProvider.SetBlockTime(BlockTimeProvider.GetBlockTime().AddSeconds(termSeconds + 1));
    
    // Honest miners produce blocks, attackers do not
    foreach (var miner in honestMiners)
    {
        await ProduceBlocksAsync(miner, 1);
    }
    
    // Attempt term transition
    var currentRound = await GetCurrentRoundInformation();
    var needsTermChange = currentRound.NeedToChangeTerm(
        await GetBlockchainStartTimestamp(),
        currentRound.TermNumber,
        termSeconds);
    
    // Verify: MinersCountOfConsent = 5 (requires 83.3%)
    // Only 4 honest miners voted, so term change is blocked
    currentRound.MinersCountOfConsent.ShouldBe(5);
    needsTermChange.ShouldBeFalse(); // Attack succeeds - term change blocked!
    
    // Verify old miners remain and treasury is not released
    var termNumber = await GetCurrentTermNumber();
    termNumber.ShouldBe(currentRound.TermNumber); // No term change occurred
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L210-210)
```csharp
    ///     Change term if two thirds of miners latest ActualMiningTime meets threshold of changing term.
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L216-224)
```csharp
    public bool NeedToChangeTerm(Timestamp blockchainStartTimestamp, long currentTermNumber, long periodSeconds)
    {
        return RealTimeMinersInformation.Values
                   .Where(m => m.ActualMiningTimes.Any())
                   .Select(m => m.ActualMiningTimes.Last())
                   .Count(t => IsTimeToChangeTerm(blockchainStartTimestamp,
                       t, currentTermNumber, periodSeconds))
               >= MinersCountOfConsent;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L10-28)
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
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MainChainConsensusBehaviourProvider.cs (L28-36)
```csharp
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return CurrentRound.RoundNumber == 1 || // Return NEXT_ROUND in first round.
                   !CurrentRound.NeedToChangeTerm(_blockchainStartTimestamp,
                       CurrentRound.TermNumber, _periodSeconds) ||
                   CurrentRound.RealTimeMinersInformation.Keys.Count == 1 // Return NEXT_ROUND for single node.
                ? AElfConsensusBehaviour.NextRound
                : AElfConsensusBehaviour.NextTerm;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L187-190)
```csharp
        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L203-211)
```csharp
        if (DonateMiningReward(previousRound))
        {
            State.TreasuryContract.Release.Send(new ReleaseInput
            {
                PeriodNumber = termNumber
            });

            Context.LogDebug(() => $"Released treasury profit for term {termNumber}");
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L213-218)
```csharp
        State.ElectionContract.TakeSnapshot.Send(new TakeElectionSnapshotInput
        {
            MinedBlocks = previousRound.GetMinedBlocks(),
            TermNumber = termNumber,
            RoundNumber = previousRound.RoundNumber
        });
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L7-7)
```csharp
    public const long InitialMiningRewardPerBlock = 12500000;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L9-9)
```csharp
    public const int SupposedMinersCount = 17;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContractConstants.cs (L11-11)
```csharp
    public const long TolerableMissedTimeSlotsCount = 60 * 24 * 3; // one time slot per minute and last 3 days.
```
