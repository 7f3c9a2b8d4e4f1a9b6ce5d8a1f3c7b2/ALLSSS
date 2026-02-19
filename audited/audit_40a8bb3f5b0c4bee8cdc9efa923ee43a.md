### Title
Missing Miner List Validation in NextRound/NextTerm Enables Consensus DoS via Bloated RealTimeMinersInformation Dictionary

### Summary
The AEDPoS consensus contract fails to validate that the miner list in submitted `NextRound` or `NextTerm` inputs matches the current round's miner list. A malicious miner can inject a `Round` object with an arbitrarily large `RealTimeMinersInformation` dictionary, which persists in state and causes excessive gas consumption in `RevealSharedInValues()` during subsequent consensus operations, leading to potential denial of service.

### Finding Description

**Root Cause:**

The contract lacks validation of the miner list composition when processing `NextRound` and `NextTerm` inputs. The `RealTimeMinersInformation` dictionary in the submitted `Round` is stored directly into state without verifying that:
1. The miner keys match the current round's miners
2. The miner count is within expected bounds [1](#0-0) 

**Missing Validation:**

The `RoundTerminateValidationProvider` only validates round number increments and that InValues are null, but does not validate miner list composition: [2](#0-1) 

The `NextRoundMiningOrderValidationProvider` only validates internal consistency of the provided round, not comparison with the current round: [3](#0-2) 

**Exploitation Path:**

1. Malicious miner with block production rights calls `NextRound` with a crafted `NextRoundInput` containing a `Round` object with thousands of entries in `RealTimeMinersInformation`
2. The malicious `Round` passes validation and gets stored via `ProcessNextRound`: [4](#0-3) 

3. This malicious `Round` becomes `previousRound` in subsequent consensus operations
4. When `RevealSharedInValues` is called, it iterates through the entire bloated dictionary: [5](#0-4) 

The iteration at line 25 with `OrderBy` on potentially thousands of miners, combined with the nested `First()` search at lines 41-43 within the loop, creates O(n*m) complexity where n is the number of legitimate miners and m is the bloated dictionary size.

5. The malicious miner list persists because `GenerateNextRoundInformation` derives the next round from the current round's miners: [6](#0-5) 

### Impact Explanation

**Concrete Harm:**
- **Consensus DoS**: Excessive gas consumption in `RevealSharedInValues` prevents legitimate miners from successfully producing blocks for NextRound behavior
- **Protocol Disruption**: Blocks round transitions and consensus progression until NextTerm is called
- **Persistent Attack**: The malicious miner list propagates to all subsequent rounds within the term, causing sustained disruption

**Affected Parties:**
- All network participants: consensus operations halt or become extremely expensive
- Legitimate miners: unable to produce NextRound blocks efficiently
- Chain operations: potential chain halt if gas costs exceed limits

**Severity Justification:**
While transaction size limits may constrain the attack magnitude, the complete absence of miner list validation violates critical consensus integrity invariants. Even moderate dictionary inflation (e.g., 10-100x normal size) could significantly degrade performance. The contract must enforce its own invariants regardless of infrastructure protections.

### Likelihood Explanation

**Attacker Capabilities:**
- Must be a current miner with block production rights
- Can craft arbitrary `NextRoundInput` messages

**Attack Complexity:**
- Low: simply create a `Round` object with inflated `RealTimeMinersInformation` and submit via `NextRound`
- No special privileges beyond normal miner status required

**Feasibility Conditions:**
- Transaction size limits provide some bound on dictionary size but don't prevent the attack entirely
- Gas limits during `NextRound` execution may limit extremely large dictionaries, but moderate inflation is feasible
- Attack is more practical than it appears because:
  1. Minimal data per fake miner entry needed to pass validation
  2. Even 100-1000 fake miners could cause significant DoS
  3. No detection mechanism exists to identify malicious round data

**Economic Rationality:**
- Attacker gains ability to disrupt consensus at cost of one transaction
- Could be used for griefing, competitive advantage, or coordinated with other attacks

### Recommendation

**Immediate Fix:**

Add validation in `ProcessNextRound` and `ProcessNextTerm` to ensure miner list integrity:

```csharp
// In ProcessNextRound (AEDPoSContract_ProcessConsensusInformation.cs)
private void ProcessNextRound(NextRoundInput input)
{
    var nextRound = input.ToRound();
    
    TryToGetCurrentRoundInformation(out var currentRound);
    
    // VALIDATION: Ensure miner list matches current round
    Assert(nextRound.RealTimeMinersInformation.Count == currentRound.RealTimeMinersInformation.Count,
        "NextRound miner count must match current round.");
    
    foreach (var minerKey in nextRound.RealTimeMinersInformation.Keys)
    {
        Assert(currentRound.RealTimeMinersInformation.ContainsKey(minerKey),
            $"Invalid miner {minerKey} in next round - not in current round.");
    }
    
    // existing code...
}
```

**Additional Checks:**

1. In `AddRoundInformation`, validate miner count against `MaximumMinersCount`: [7](#0-6) 

2. For `NextTerm`, validate that miner list comes from Election Contract results

**Test Cases:**
1. Test that `NextRound` with extra miners is rejected
2. Test that `NextRound` with missing miners is rejected  
3. Test that `NextRound` with modified miner keys is rejected
4. Test that miner count exceeding `MaximumMinersCount` is rejected

### Proof of Concept

**Initial State:**
- Current round N with 17 legitimate miners (normal mainnet configuration)
- Attacker is one of the 17 miners with block production rights

**Attack Steps:**

1. Attacker crafts a malicious `NextRoundInput`:
```csharp
var maliciousRound = new Round 
{
    RoundNumber = currentRound.RoundNumber + 1,
    TermNumber = currentRound.TermNumber,
    // Add all 17 legitimate miners
    RealTimeMinersInformation = { /* 17 real miners */ }
};

// Add 1000 fake miners with minimal data
for (int i = 0; i < 1000; i++)
{
    maliciousRound.RealTimeMinersInformation.Add(
        $"fake_miner_{i}", 
        new MinerInRound { Pubkey = $"fake_miner_{i}", Order = 18 + i }
    );
}

var input = new NextRoundInput { /* maliciousRound data */ };
```

2. Attacker calls `NextRound(input)` during their block production slot

3. Validation passes because:
   - Round number is correct (N+1)
   - InValues are null
   - Internal consistency checks pass
   - No miner list composition validation exists

4. Malicious round stored in `State.Rounds[N+1]`

5. Next miner attempts to produce round N+2 block:
   - Calls `GetConsensusBlockExtraData` which triggers `RevealSharedInValues`
   - Function retrieves round N+1 as `previousRound` (1017 miners)
   - Line 25 iterates through all 1017 miners with `OrderBy`
   - For each legitimate miner, lines 41-43 search through 1017 miners
   - Gas consumption exceeds reasonable limits

**Expected vs Actual:**
- **Expected**: `NextRound` rejects invalid miner lists, maintains 17 miners
- **Actual**: `NextRound` accepts 1017 miners, subsequent consensus operations consume excessive gas and fail

**Success Condition:**
Monitoring shows failed block production or significantly increased gas costs for NextRound behavior after the malicious round is accepted.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_HelpMethods.cs (L103-105)
```csharp
    private void AddRoundInformation(Round round)
    {
        State.Rounds.Set(round.RoundNumber, round);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L22-35)
```csharp
    private ValidationResult ValidationForNextRound(ConsensusValidationContext validationContext)
    {
        // Is next round information correct?
        // Currently two aspects:
        //   Round Number
        //   In Values Should Be Null
        var extraData = validationContext.ExtraData;
        if (validationContext.BaseRound.RoundNumber.Add(1) != extraData.Round.RoundNumber)
            return new ValidationResult { Message = "Incorrect round number for next round." };

        return extraData.Round.RealTimeMinersInformation.Values.Any(m => m.InValue != null)
            ? new ValidationResult { Message = "Incorrect next round information." }
            : new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/NextRoundMiningOrderValidationProvider.cs (L9-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        // Miners that have determined the order of the next round should be equal to
        // miners that mined blocks during current round.
        var validationResult = new ValidationResult();
        var providedRound = validationContext.ProvidedRound;
        var distinctCount = providedRound.RealTimeMinersInformation.Values.Where(m => m.FinalOrderOfNextRound > 0)
            .Distinct().Count();
        if (distinctCount != providedRound.RealTimeMinersInformation.Values.Count(m => m.OutValue != null))
        {
            validationResult.Message = "Invalid FinalOrderOfNextRound.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L108-159)
```csharp
    private void ProcessNextRound(NextRoundInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        TryToGetCurrentRoundInformation(out var currentRound);

        // Do some other stuff during the first time to change round.
        if (currentRound.RoundNumber == 1)
        {
            // Set blockchain start timestamp.
            var actualBlockchainStartTimestamp =
                currentRound.FirstActualMiner()?.ActualMiningTimes.FirstOrDefault() ??
                Context.CurrentBlockTime;
            SetBlockchainStartTimestamp(actualBlockchainStartTimestamp);

            // Initialize current miners' information in Election Contract.
            if (State.IsMainChain.Value)
            {
                var minersCount = GetMinersCount(nextRound);
                if (minersCount != 0 && State.ElectionContract.Value != null)
                {
                    State.ElectionContract.UpdateMinersCount.Send(new UpdateMinersCountInput
                    {
                        MinersCount = minersCount
                    });
                }
            }
        }

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

        AddRoundInformation(nextRound);

        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_SecretSharing.cs (L25-44)
```csharp
        foreach (var pair in previousRound.RealTimeMinersInformation.OrderBy(m => m.Value.Order))
        {
            // Skip himself.
            if (pair.Key == publicKey) continue;

            if (!currentRound.RealTimeMinersInformation.Keys.Contains(pair.Key)) continue;

            var publicKeyOfAnotherMiner = pair.Key;
            var anotherMinerInPreviousRound = pair.Value;

            if (anotherMinerInPreviousRound.EncryptedPieces.Count < minimumCount) continue;
            if (anotherMinerInPreviousRound.DecryptedPieces.Count < minersCount) continue;

            // Reveal another miner's in value for target round:

            var orders = anotherMinerInPreviousRound.DecryptedPieces.Select((t, i) =>
                    previousRound.RealTimeMinersInformation.Values
                        .First(m => m.Pubkey ==
                                    anotherMinerInPreviousRound.DecryptedPieces.Keys.ToList()[i]).Order)
                .ToList();
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L16-37)
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
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_MaximumMinersCount.cs (L72-78)
```csharp
    public override Int32Value GetMaximumMinersCount(Empty input)
    {
        return new Int32Value
        {
            Value = Math.Min(GetAutoIncreasedMinersCount(), State.MaximumMinersCount.Value)
        };
    }
```
