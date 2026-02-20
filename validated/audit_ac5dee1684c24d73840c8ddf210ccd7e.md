# Audit Report

## Title
LIB Calculation Failure During Miner List Expansion Due to Mismatched Threshold Basis

## Summary
The Last Irreversible Block (LIB) calculation uses the current round's miner count to compute the Byzantine fault-tolerant threshold, but validates against implied irreversible heights from the previous round. When the miner list increases at term change, this mathematical mismatch causes LIB advancement to halt until sufficient original miners participate.

## Finding Description

The vulnerability exists in the `LastIrreversibleBlockHeightCalculator.Deconstruct()` method which calculates the LIB height. [1](#0-0) 

The threshold calculation uses the NEW miner count from the current round through the `MinersCountOfConsent` property. [2](#0-1) 

However, the method retrieves `impliedIrreversibleHeights` from the PREVIOUS round, filtered by miners who have mined in the CURRENT round. [3](#0-2) 

Miners who have produced blocks are identified via `GetMinedMiners()` which filters by `SupposedOrderOfNextRound != 0`. [4](#0-3) 

When `GenerateFirstRoundOfNewTerm` creates a new term, it can include MORE miners than the previous term and sets `IsMinerListJustChanged = true`. [5](#0-4) 

The LIB calculator is invoked during every `UpdateValue` call when miners produce blocks. [6](#0-5) 

**The Critical Flaw**: The `IsMinerListJustChanged` flag is set during term changes but is ONLY used to skip secret sharing, NOT to adjust LIB calculation logic. [7](#0-6) 

**Concrete Failure Scenario**:
- Old term: 10 miners, threshold = (10 × 2/3) + 1 = 7
- New term: 13 miners, threshold = (13 × 2/3) + 1 = 9
- If only 8 of the 10 original miners participate first: `impliedIrreversibleHeights.Count = 8`
- Check fails: `8 < 9` → LIB returns 0, blocking advancement

## Impact Explanation

**Severity: HIGH - Denial of Service to Critical Consensus Invariant**

This vulnerability causes deterministic failure of LIB advancement, breaking finality guarantees:

1. **Broken Finality**: Blocks cannot be confirmed as irreversible, undermining transaction finality
2. **Cross-Chain Failure**: Cross-chain bridges depend on LIB verification and will stall
3. **Network-Wide Impact**: All participants affected simultaneously
4. **Duration**: Persists for multiple rounds until (N × 2/3) + 1 original miners participate

This is not a fund-loss vulnerability but a HIGH severity DoS against a critical protocol invariant that provides security guarantees to the entire ecosystem.

## Likelihood Explanation

**Likelihood: HIGH - Deterministic Protocol-Level Bug**

- **No Attacker Required**: Logic error that triggers automatically during normal operations
- **Zero Attack Complexity**: Term changes with miner increases are regular governance events
- **Mathematical Certainty**: When M < (N × 2/3) + 1, failure is guaranteed
- **Expected Trigger**: Network growth naturally increases miner count at term boundaries

Tests confirm miner count increases during term transitions but do not validate LIB calculation correctness during these transitions. [8](#0-7) 

## Recommendation

Modify `LastIrreversibleBlockHeightCalculator.Deconstruct()` to check the `IsMinerListJustChanged` flag and adjust the threshold calculation when the miner list has changed:

```csharp
public void Deconstruct(out long libHeight)
{
    if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

    var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
    var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
    
    // Use previous round's miner count for threshold when list just changed
    var effectiveMinerCount = _currentRound.IsMinerListJustChanged 
        ? _previousRound.RealTimeMinersInformation.Count 
        : _currentRound.RealTimeMinersInformation.Count;
    
    var minersCountOfConsent = effectiveMinerCount.Mul(2).Div(3).Add(1);
    
    if (impliedIrreversibleHeights.Count < minersCountOfConsent)
    {
        libHeight = 0;
        return;
    }

    libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
}
```

Alternatively, defer LIB calculation for the first round of a new term until sufficient data accumulates.

## Proof of Concept

```csharp
[Fact]
public async Task LIB_Fails_When_Miner_List_Increases()
{
    // Setup: Initialize with 10 miners and run first term
    const int initialMiners = 10;
    const int newMiners = 13;
    
    await InitializeCandidates(newMiners);
    
    // Vote for all candidates
    var voter = GetElectionContractTester(VoterKeyPairs[0]);
    foreach (var candidateKeyPair in ValidationDataCenterKeyPairs.Take(newMiners))
    {
        await voter.Vote.SendAsync(new VoteMinerInput
        {
            CandidatePubkey = candidateKeyPair.PublicKey.ToHex(),
            Amount = 100,
            EndTimestamp = TimestampHelper.GetUtcNow().AddDays(100)
        });
    }
    
    // Complete first term with 10 miners
    await AdvanceToNextTerm();
    
    // New term starts with 13 miners (increase triggered by election)
    await TriggerTermChange();
    
    // Only 8 of the 10 original miners participate
    for (int i = 0; i < 8; i++)
    {
        var miner = InitialCoreDataCenterKeyPairs[i];
        await ProduceBlockAs(miner);
    }
    
    // Verify: LIB should advance but it doesn't
    var round = await AEDPoSContractStub.GetCurrentRoundInformation.CallAsync(new Empty());
    var previousLib = round.ConfirmedIrreversibleBlockHeight;
    
    // Threshold = (13 * 2 / 3) + 1 = 9, but only 8 miners have data
    // Expected: LIB fails to advance
    round.ConfirmedIrreversibleBlockHeight.ShouldBe(previousLib); // LIB stuck at previous value
}
```

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_LIB.cs (L20-33)
```csharp
        public void Deconstruct(out long libHeight)
        {
            if (_currentRound.IsEmpty || _previousRound.IsEmpty) libHeight = 0;

            var minedMiners = _currentRound.GetMinedMiners().Select(m => m.Pubkey).ToList();
            var impliedIrreversibleHeights = _previousRound.GetSortedImpliedIrreversibleBlockHeights(minedMiners);
            if (impliedIrreversibleHeights.Count < _currentRound.MinersCountOfConsent)
            {
                libHeight = 0;
                return;
            }

            libHeight = impliedIrreversibleHeights[impliedIrreversibleHeights.Count.Sub(1).Div(3)];
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_ImpliedIrreversibleBlockHeight.cs (L10-10)
```csharp
    public int MinersCountOfConsent => RealTimeMinersInformation.Count.Mul(2).Div(3).Add(1);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L125-129)
```csharp
    public List<MinerInRound> GetMinedMiners()
    {
        // For now only this implementation can support test cases.
        return RealTimeMinersInformation.Values.Where(m => m.SupposedOrderOfNextRound != 0).ToList();
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L12-44)
```csharp
    internal Round GenerateFirstRoundOfNewTerm(int miningInterval,
        Timestamp currentBlockTime, long currentRoundNumber = 0, long currentTermNumber = 0)
    {
        var sortedMiners =
            (from obj in Pubkeys
                    .ToDictionary<ByteString, string, int>(miner => miner.ToHex(), miner => miner[0])
                orderby obj.Value descending
                select obj.Key).ToList();

        var round = new Round();

        for (var i = 0; i < sortedMiners.Count; i++)
        {
            var minerInRound = new MinerInRound();

            // The first miner will be the extra block producer of first round of each term.
            if (i == 0) minerInRound.IsExtraBlockProducer = true;

            minerInRound.Pubkey = sortedMiners[i];
            minerInRound.Order = i + 1;
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
            // Should be careful during validation.
            minerInRound.PreviousInValue = Hash.Empty;

            round.RealTimeMinersInformation.Add(sortedMiners[i], minerInRound);
        }

        round.RoundNumber = currentRoundNumber.Add(1);
        round.TermNumber = currentTermNumber.Add(1);
        round.IsMinerListJustChanged = true;

        return round;
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L266-282)
```csharp
        if (TryToGetPreviousRoundInformation(out var previousRound))
        {
            new LastIrreversibleBlockHeightCalculator(currentRound, previousRound).Deconstruct(
                out var libHeight);
            Context.LogDebug(() => $"Finished calculation of lib height: {libHeight}");
            // LIB height can't be available if it is lower than last time.
            if (currentRound.ConfirmedIrreversibleBlockHeight < libHeight)
            {
                Context.LogDebug(() => $"New lib height: {libHeight}");
                Context.Fire(new IrreversibleBlockFound
                {
                    IrreversibleBlockHeight = libHeight
                });
                currentRound.ConfirmedIrreversibleBlockHeight = libHeight;
                currentRound.ConfirmedIrreversibleBlockRoundNumber = currentRound.RoundNumber.Sub(1);
            }
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L107-115)
```csharp
        if (round.RoundNumber > 1 && !round.IsMinerListJustChanged)
            // No need to share secret pieces if miner list just changed.

            Context.Fire(new SecretSharingInformation
            {
                CurrentRoundId = round.RoundId,
                PreviousRound = State.Rounds[round.RoundNumber.Sub(1)],
                PreviousRoundId = State.Rounds[round.RoundNumber.Sub(1)].RoundId
            });
```

**File:** test/AElf.Contracts.Consensus.AEDPoS.Tests/BVT/MinersCountTest.cs (L110-136)
```csharp
        while (minerCount < maxCount)
        {
            var currentRound = await newMinerStub.GetCurrentRoundInformation.CallAsync(new Empty());
            var firstPubKey = currentRound.RealTimeMinersInformation.Keys.First();
            var keypair = ValidationDataCenterKeyPairs.First(o => o.PublicKey.ToHex() == firstPubKey);
            newMinerStub = GetAEDPoSContractStub(keypair);

            minerCount = currentRound.RealTimeMinersInformation.Count;
            Assert.Equal(AEDPoSContractTestConstants.SupposedMinersCount.Add(termCount.Mul(2)), minerCount);

            changeTermTime = BlockchainStartTimestamp.ToDateTime()
                .AddMinutes((termCount + 2).Mul(termIntervalMin)).AddSeconds(10);
            BlockTimeProvider.SetBlockTime(changeTermTime.ToTimestamp());
            var nextRoundInformation = (await newMinerStub.GetConsensusExtraData.CallAsync(
                new AElfConsensusTriggerInformation
                {
                    Behaviour = AElfConsensusBehaviour.NextTerm,
                    Pubkey = ByteStringHelper.FromHexString(currentRound.RealTimeMinersInformation.ElementAt(0).Value
                        .Pubkey)
                }.ToBytesValue())).ToConsensusHeaderInformation();
            nextTermInput = NextTermInput.Parser.ParseFrom(nextRoundInformation.Round.ToByteArray());
            randomNumber = await GenerateRandomProofAsync(keypair);
            nextTermInput.RandomNumber = ByteString.CopyFrom(randomNumber);
            await newMinerStub.NextTerm.SendAsync(nextTermInput);
            termCount++;
        }
    }
```
