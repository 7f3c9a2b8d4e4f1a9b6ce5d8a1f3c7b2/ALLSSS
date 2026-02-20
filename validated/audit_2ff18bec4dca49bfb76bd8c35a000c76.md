# Audit Report

## Title
Clock Skew Enables Premature Round Transitions Causing Chain Reorganizations on Side Chains

## Summary
The AEDPoS side chain consensus allows any miner to trigger round transitions based solely on their local clock time, without validation of whether the round should actually terminate. Combined with tolerated clock skew of up to 1 second, miners with different system clocks will independently produce competing NextRound blocks, creating chain forks that require reorganization to resolve.

## Finding Description

The vulnerability exists in the side chain round transition mechanism through multiple interconnected weaknesses:

**Root Cause: Unconditional NextRound Return**

The side chain consensus behavior provider unconditionally returns `NextRound` when determining how to terminate the current round, without any synchronization checks or timing validation: [1](#0-0) 

This method is invoked when the consensus behavior provider determines a miner's time slot has passed: [2](#0-1) 

**Time Slot Determination Based on Local Clock**

Each miner independently determines if their time slot has passed by comparing their expected mining time plus the mining interval against their local `currentBlockTime`: [3](#0-2) 

The `currentBlockTime` parameter represents the miner's local system clock, as documented in the public API: [4](#0-3) 

With clock skew, different miners reach the time slot passed condition at different real-world times.

**Insufficient Validation of NextRound Blocks**

When validating NextRound blocks, the system only checks structural correctness - whether the round number increments correctly and whether InValues are null - but does NOT validate whether it's actually time to advance rounds: [5](#0-4) 

The `CheckRoundTimeSlots()` method called during validation only verifies evenly-spaced time slots, not whether the timing of the round transition is appropriate: [6](#0-5) 

**No Extra Block Producer Enforcement**

While the system designates an extra block producer for each round, there is no validation that enforces only this designated producer can create NextRound blocks. The permission check only verifies the sender is in the miner list: [7](#0-6) [8](#0-7) 

Any miner in the current or previous round can produce NextRound blocks once their local clock indicates their time slot has passed.

**Clock Synchronization Limitations**

The system tolerates NTP clock drift up to 1000 milliseconds: [9](#0-8) 

This drift is checked only periodically (every 60 seconds by default), not continuously: [10](#0-9) [11](#0-10) 

**Attack Scenario**

Near the end of Round N:
1. Miner A has clock +500ms (fast), determines time slot passed at real-world time T
2. Miner B has clock -500ms (slow), still mining in Round N at real-world time T
3. Miner A produces NextRound block (Round N+1) with timestamp T+500ms
4. Miner B produces normal block (Round N) with timestamp T-500ms
5. Both blocks pass validation and are accepted by network nodes
6. Network now has competing forks: one in Round N, one in Round N+1
7. Fork resolution requires one chain to be discarded (reorganization)

## Impact Explanation

**Consensus Integrity Degradation**

The vulnerability breaks the consensus guarantee that all honest miners agree on round transitions. Instead, miners independently decide based on their local clocks, creating multiple competing versions of the chain state.

**Chain Reorganization Consequences**
- Transactions in discarded blocks must be re-executed or are temporarily lost
- Users experience uncertainty about transaction finality
- Cross-chain operations indexing the side chain may observe inconsistent state
- System reliability and predictability are significantly degraded

**Frequency and Severity**

The 1-second clock skew window is significant relative to typical mining intervals of 4-8 seconds (12.5% to 25% of interval). This creates frequent opportunities for disagreement, particularly on side chains with shorter round times, fewer miners, and higher network latency.

The impact is **Medium to High** as it affects consensus integrity and transaction finality without direct fund loss.

## Likelihood Explanation

**Natural Occurrence Without Attack**

This vulnerability manifests through normal operation:
- Miners run consensus honestly with independent system clocks
- Clock skew within the 1000ms NTP tolerance is expected and normal
- No malicious behavior is required

**Highly Feasible Preconditions**
- Multiple miners on a side chain (standard configuration)
- Clock skew approaching NTP threshold (realistic with normal NTP synchronization quality)
- Mining intervals of 4-8 seconds (typical configuration)
- Miners near the end of a round (occurs every round)

**Execution Path**
1. Any miner who has mined in the current round
2. Whose local clock indicates their time slot has passed
3. Will automatically attempt to produce NextRound
4. The NextRound block will pass all validations
5. Creates competing blocks with other miners still in current round

The likelihood is **Medium to High** depending on actual NTP synchronization quality in the deployment environment.

## Recommendation

Implement multiple safeguards to ensure coordinated round transitions:

1. **Add Timing Validation to NextRound**: Modify `RoundTerminateValidationProvider` to validate that the round has actually exceeded its expected duration before accepting NextRound blocks.

2. **Enforce Extra Block Producer**: Add validation in `PreCheck()` or `MiningPermissionValidationProvider` to ensure only the designated extra block producer can create NextRound blocks.

3. **Implement Consensus Threshold**: Require a minimum number of miners to have mined in the current round before allowing NextRound transitions.

4. **Reduce Clock Skew Tolerance**: Lower the `DefaultNtpDriftThreshold` from 1000ms to 250-500ms and enforce it more strictly.

5. **Add Round Extension Logic**: When clock disagreement is detected, allow the round to extend slightly to ensure all miners reach consensus on the transition timing.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a side chain with 3+ miners
2. Introducing 800ms clock skew between miners (within tolerance)
3. Observing that miners near the end of rounds will independently produce NextRound blocks
4. Verifying that both normal blocks and NextRound blocks pass validation simultaneously
5. Confirming that this creates competing chain branches requiring reorganization

The PoC would require integration testing with multiple nodes running with artificially skewed clocks to simulate the production environment where NTP synchronization quality varies.

## Notes

This is a consensus-level vulnerability that affects the fundamental security guarantees of the side chain. While it doesn't directly result in fund loss, it undermines transaction finality and chain reliability. The issue is particularly severe because:

1. It occurs naturally without malicious intent
2. It happens whenever miners have clock skew within the tolerated range
3. The frequency increases with shorter mining intervals
4. Side chains are more vulnerable due to fewer miners and potentially lower NTP synchronization quality

The vulnerability demonstrates a gap between the intended consensus model (coordinated round transitions) and the actual implementation (independent local-clock-based transitions).

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/SideChainConsensusBehaviourProvider.cs (L16-23)
```csharp
        /// <summary>
        ///     Simply return NEXT_ROUND for side chain.
        /// </summary>
        /// <returns></returns>
        protected override AElfConsensusBehaviour GetConsensusBehaviourToTerminateCurrentRound()
        {
            return AElfConsensusBehaviour.NextRound;
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/ConsensusBehaviourProviderBase.cs (L82-83)
```csharp
            return GetConsensusBehaviourToTerminateCurrentRound();
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L33-58)
```csharp
    public ValidationResult CheckRoundTimeSlots()
    {
        var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
        if (miners.Count == 1)
            // No need to check single node.
            return new ValidationResult { Success = true };

        if (miners.Any(m => m.ExpectedMiningTime == null))
            return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };

        for (var i = 1; i < miners.Count - 1; i++)
        {
            var miningInterval =
                (miners[i + 1].ExpectedMiningTime - miners[i].ExpectedMiningTime).Milliseconds();
            if (Math.Abs(miningInterval - baseMiningInterval) > baseMiningInterval)
                return new ValidationResult { Message = "Time slots are so different." };
        }

        return new ValidationResult { Success = true };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L83-99)
```csharp
    public bool IsTimeSlotPassed(string publicKey, Timestamp currentBlockTime)
    {
        var miningInterval = GetMiningInterval();
        if (!RealTimeMinersInformation.ContainsKey(publicKey)) return false;
        var minerInRound = RealTimeMinersInformation[publicKey];
        if (RoundNumber != 1)
            return minerInRound.ExpectedMiningTime + new Duration { Seconds = miningInterval.Div(1000) } <
                   currentBlockTime;

        var actualStartTimes = FirstMiner().ActualMiningTimes;
        if (actualStartTimes.Count == 0) return false;

        var actualStartTime = actualStartTimes.First();
        var runningTime = currentBlockTime - actualStartTime;
        var expectedOrder = runningTime.Seconds.Div(miningInterval.Div(1000)).Add(1);
        return minerInRound.Order < expectedOrder;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ACS4_ConsensusInformationProvider.cs (L12-13)
```csharp
    /// <summary>
    ///     In this method, `Context.CurrentBlockTime` is the time one miner start request his next consensus command.
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

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L316-331)
```csharp
    private bool PreCheck()
    {
        TryToGetCurrentRoundInformation(out var currentRound);
        TryToGetPreviousRoundInformation(out var previousRound);

        _processingBlockMinerPubkey = Context.RecoverPublicKey().ToHex();

        // Though we've already prevented related transactions from inserting to the transaction pool
        // via ConstrainedAEDPoSTransactionValidationProvider,
        // this kind of permission check is still useful.
        if (!currentRound.IsInMinerList(_processingBlockMinerPubkey) &&
            !previousRound.IsInMinerList(_processingBlockMinerPubkey)) // Case a failed miner performing NextTerm
            return false;

        return true;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/MiningPermissionValidationProvider.cs (L14-25)
```csharp
    public ValidationResult ValidateHeaderInformation(ConsensusValidationContext validationContext)
    {
        var validationResult = new ValidationResult();
        if (!validationContext.BaseRound.RealTimeMinersInformation.Keys.Contains(validationContext.SenderPubkey))
        {
            validationResult.Message = $"Sender {validationContext.SenderPubkey} is not a miner.";
            return validationResult;
        }

        validationResult.Success = true;
        return validationResult;
    }
```

**File:** src/AElf.OS.Core/Network/NetworkConstants.cs (L44-44)
```csharp
    public const int DefaultNtpDriftThreshold = 1_000;
```

**File:** src/AElf.OS/Worker/PeerReconnectionWorker.cs (L128-138)
```csharp
        void CheckNtpClockDrift()
        {
            try
            {
                _networkService.CheckNtpDrift();
            }
            catch (Exception)
            {
                // swallow any exception, we are not interested in anything else than valid checks. 
            }
        }
```

**File:** src/AElf.OS.Network.Grpc/GrpcNetworkServer.cs (L78-89)
```csharp
    public void CheckNtpDrift()
    {
        TimeSpan offset;
        using (var ntp = new NtpClient(Dns.GetHostAddresses("pool.ntp.org")[0]))
        {
            offset = ntp.GetCorrectionOffset();
        }

        if (offset.Duration().TotalMilliseconds > NetworkConstants.DefaultNtpDriftThreshold)
            Logger.LogWarning($"NTP clock drift is more that {NetworkConstants.DefaultNtpDriftThreshold} ms : " +
                              $"{offset.Duration().TotalMilliseconds} ms");
    }
```
