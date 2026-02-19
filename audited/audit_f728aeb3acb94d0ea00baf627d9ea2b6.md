### Title
Stale Future Timestamp in Round Generation Causes Unnecessary Mining Delays

### Summary
The `ArrangeNormalBlockMiningTime()` function uses `Max()` comparison between round's `ExpectedMiningTime` and current block time to determine when miners should produce blocks. When an extra block producer creates a round with a timestamp up to 4 seconds in the future (maximum allowed), subsequent miners query for commands using real-time timestamps, causing the `Max()` function to return the stale future time and forcing miners to wait unnecessarily, reducing chain throughput by up to 50% per affected round.

### Finding Description

**Root Cause:**

The vulnerability exists in the mining time arrangement logic where round scheduling data can be based on future timestamps while command queries use current real time. [1](#0-0) 

**Exploitation Path:**

1. **Future Timestamp Acceptance**: Block validation allows timestamps up to 4 seconds in the future: [2](#0-1) [3](#0-2) 

2. **Round Creation with Future Timestamp**: When extra block producer creates next round, `ExpectedMiningTime` is calculated based on the block's timestamp: [4](#0-3) [5](#0-4) 

3. **Command Query with Real Time**: When miners request consensus commands, `Context.CurrentBlockTime` is set to `GetUtcNow()` (current real time): [6](#0-5) [7](#0-6) 

4. **Timestamp Mismatch**: The round data contains future-based `ExpectedMiningTime` while queries use current time, causing `Max()` to return future time: [8](#0-7) 

5. **Unnecessary Wait**: Miners are scheduled to wait for the future timestamp: [9](#0-8) 

### Impact Explanation

**Operational Impact - Consensus DoS:**
- Chain throughput reduction: If mining interval is 4 seconds and attacker adds 4 seconds delay, throughput drops by ~50% for affected rounds
- All miners in the round must wait: The delay affects every block producer scheduled in that round
- Cumulative effect: If attacker is extra block producer for multiple consecutive rounds, delays compound
- Transaction confirmation delays: Users experience longer wait times for block confirmations

**Affected Parties:**
- All network miners who must respect the delayed schedule
- Users waiting for transaction confirmations
- dApps relying on consistent block times

**Severity Justification (Medium):**
- Does not directly steal funds or break consensus integrity
- Creates significant operational degradation
- Repeatable and sustainable attack vector
- Affects core network performance metric (throughput)

### Likelihood Explanation

**Attacker Capabilities:**
- Must be an extra block producer (achievable through normal election process)
- No special permissions beyond standard mining rights
- Can set block timestamps within allowed bounds (no bypass needed)

**Attack Complexity:**
- Simple execution: Just set block timestamp to maximum future threshold (current time + 4 seconds)
- No complex transaction sequences required
- Can occur accidentally through clock skew between nodes

**Feasibility Conditions:**
- Block validation explicitly allows 4-second future timestamps
- Extra block producers are rotated among miners, providing attack opportunities
- No detection mechanisms for timestamp manipulation within allowed bounds

**Probability Assessment:**
- High likelihood: Any miner can become extra block producer through standard election
- Can happen unintentionally due to system clock differences
- Sustainable: Repeatable every time attacker is selected as extra block producer

### Recommendation

**Code-Level Mitigation:**

Modify `ArrangeNormalBlockMiningTime()` to anchor scheduling to current real time rather than blindly trusting round data:

```csharp
public static Timestamp ArrangeNormalBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
{
    var expectedTime = round.GetExpectedMiningTime(pubkey);
    var roundStartTime = round.GetRoundStartTime();
    
    // If round schedule is stale (start time is past), rebase to current time
    if (roundStartTime < currentBlockTime)
    {
        var miningInterval = round.GetMiningInterval();
        var minerOrder = round.GetMiningOrder(pubkey);
        return currentBlockTime.AddMilliseconds(miningInterval.Mul(minerOrder));
    }
    
    return TimestampExtensions.Max(expectedTime, currentBlockTime);
}
```

**Alternative Solution:**

Add validation in `ProcessNextRound` to reject rounds with timestamps too far from current time: [10](#0-9) 

Add check before line 156:
```csharp
var currentTime = Context.CurrentBlockTime;
var roundStartTime = nextRound.GetRoundStartTime();
Assert(roundStartTime <= currentTime.AddSeconds(2), "Round start time too far in future");
```

**Invariant to Enforce:**
- Round scheduling must be anchored to current real time, not arbitrary future timestamps
- Mining delays should only occur when miner queries early, not due to stale round data

### Proof of Concept

**Initial State:**
- Chain operating normally with 3 miners: A, B, C
- Mining interval: 4000ms (4 seconds)
- Miner C is designated extra block producer for Round N

**Attack Sequence:**

1. **Normal blocks produced:**
   - T=0ms: Miner A produces block, timestamp=0
   - T=4000ms: Miner B produces block, timestamp=4000
   - T=8000ms: Miner C produces block, timestamp=8000

2. **Attacker (Miner C) produces extra block with maximum future timestamp:**
   - Real time: T=12000ms
   - Miner C sets block timestamp=16000ms (4 seconds future, maximum allowed)
   - Block passes validation (16000-12000=4000ms ≤ 4000ms)
   - Extra block executes `NextRound` transaction
   - `GenerateNextRoundInformation` called with `Context.CurrentBlockTime=16000ms`
   - Round N+1 created with Miner A's `ExpectedMiningTime=16000+4000=20000ms`

3. **Miner A queries for command immediately after:**
   - Real time: T=12001ms (1ms after extra block)
   - `TriggerConsensusAsync` sets `Context.CurrentBlockTime=GetUtcNow()=12001ms`
   - `ArrangeNormalBlockMiningTime`: `Max(20000ms, 12001ms) = 20000ms`
   - Miner A scheduled to mine at T=20000ms

4. **Unnecessary wait occurs:**
   - Expected: Miner A should mine at T=12000+4000=16000ms (normal interval)
   - Actual: Miner A must wait until T=20000ms
   - Delay: 20000-12001 ≈ 8 seconds instead of 4 seconds
   - **Result: 100% throughput reduction for this block (8s vs expected 4s)**

**Success Condition:**
Mining command returns `ArrangedMiningTime` significantly in the future despite current time being within normal mining window, causing observable delay in block production timing.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/MiningTimeArrangingService.cs (L17-20)
```csharp
        public static Timestamp ArrangeNormalBlockMiningTime(Round round, string pubkey, Timestamp currentBlockTime)
        {
            return TimestampExtensions.Max(round.GetExpectedMiningTime(pubkey), currentBlockTime);
        }
```

**File:** src/AElf.Kernel.Types/KernelConstants.cs (L19-19)
```csharp
    public static Duration AllowedFutureBlockTimeSpan = new() { Seconds = 4 };
```

**File:** src/AElf.Kernel.Core/Blockchain/Application/IBlockValidationProvider.cs (L133-139)
```csharp
        if (block.Header.Height != AElfConstants.GenesisBlockHeight &&
            block.Header.Time.ToDateTime() - TimestampHelper.GetUtcNow().ToDateTime() >
            KernelConstants.AllowedFutureBlockTimeSpan.ToTimeSpan())
        {
            Logger.LogDebug("Future block received {Block}, {BlockTime}", block, block.Header.Time.ToDateTime());
            return Task.FromResult(false);
        }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_GetConsensusBlockExtraData.cs (L173-177)
```csharp
    private AElfConsensusHeaderInformation GetConsensusExtraDataForNextRound(Round currentRound,
        string pubkey, AElfConsensusTriggerInformation triggerInformation)
    {
        GenerateNextRoundInformation(currentRound, Context.CurrentBlockTime, out var nextRound);

```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round_Generation.cs (L11-36)
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

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L59-76)
```csharp
    public async Task TriggerConsensusAsync(ChainContext chainContext)
    {
        var now = TimestampHelper.GetUtcNow();
        _blockTimeProvider.SetBlockTime(now, chainContext.BlockHash);

        Logger.LogDebug($"Block time of triggering consensus: {now.ToDateTime():hh:mm:ss.ffffff}.");

        var triggerInformation =
            _triggerInformationProvider.GetTriggerInformationForConsensusCommand(new BytesValue());

        Logger.LogDebug($"Mining triggered, chain context: {chainContext.BlockHeight} - {chainContext.BlockHash}");

        // Upload the consensus command.
        var contractReaderContext =
            await _consensusReaderContextService.GetContractReaderContextAsync(chainContext);
        _consensusCommand = await _contractReaderFactory
            .Create(contractReaderContext).GetConsensusCommand
            .CallAsync(triggerInformation);
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L86-108)
```csharp
        // Update next mining time, also block time of both getting consensus extra data and txs.
        _nextMiningTime = _consensusCommand.ArrangedMiningTime;
        var leftMilliseconds = _consensusCommand.ArrangedMiningTime - TimestampHelper.GetUtcNow();
        leftMilliseconds = leftMilliseconds.Seconds > ConsensusConstants.MaximumLeftMillisecondsForNextBlock
            ? new Duration { Seconds = ConsensusConstants.MaximumLeftMillisecondsForNextBlock }
            : leftMilliseconds;

        var configuredMiningTime = await _miningTimeProvider.GetLimitMillisecondsOfMiningBlockAsync(new BlockIndex
        {
            BlockHeight = chainContext.BlockHeight,
            BlockHash = chainContext.BlockHash
        });
        var limitMillisecondsOfMiningBlock = configuredMiningTime == 0
            ? _consensusCommand.LimitMillisecondsOfMiningBlock
            : configuredMiningTime;
        // Update consensus scheduler.
        var blockMiningEventData = new ConsensusRequestMiningEventData(chainContext.BlockHash,
            chainContext.BlockHeight,
            _nextMiningTime,
            TimestampHelper.DurationFromMilliseconds(limitMillisecondsOfMiningBlock),
            _consensusCommand.MiningDueTime);
        _consensusScheduler.CancelCurrentEvent();
        _consensusScheduler.NewEvent(leftMilliseconds.Milliseconds(), blockMiningEventData);
```

**File:** src/AElf.Kernel.Consensus.Core/Application/IConsensusReaderContextService.cs (L27-42)
```csharp
    public async Task<ContractReaderContext> GetContractReaderContextAsync(IChainContext chainContext)
    {
        var timestamp = _blockTimeProvider.GetBlockTime(chainContext.BlockHash);
        var sender = Address.FromPublicKey(await _accountService.GetPublicKeyAsync());
        var consensusContractAddress = await _smartContractAddressService.GetAddressByContractNameAsync(
            chainContext, ConsensusSmartContractAddressNameProvider.StringName);

        return new ContractReaderContext
        {
            BlockHash = chainContext.BlockHash,
            BlockHeight = chainContext.BlockHeight,
            ContractAddress = consensusContractAddress,
            Sender = sender,
            Timestamp = timestamp
        };
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L157-162)
```csharp
    public Timestamp GetExpectedMiningTime(string publicKey)
    {
        return RealTimeMinersInformation.ContainsKey(publicKey)
            ? RealTimeMinersInformation[publicKey].ExpectedMiningTime
            : new Timestamp { Seconds = long.MaxValue };
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
