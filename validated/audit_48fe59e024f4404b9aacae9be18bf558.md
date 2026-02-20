# Audit Report

## Title
Integer Division Vulnerability in Mining Interval Validation Enables Permanent Denial of Service

## Summary
The AEDPoS consensus validation logic accepts mining intervals as low as 1ms, which when combined with integer division calculations for block execution timeouts, results in all timeout limits becoming 0ms. A malicious miner producing a NextTerm block can craft consensus data with 1ms mining intervals that passes validation, causing immediate cancellation of all user transaction processing and permanently rendering the blockchain unusable.

## Finding Description

**Root Cause - Insufficient Validation:**

The `CheckRoundTimeSlots()` method only validates that the base mining interval is greater than zero, allowing intervals as low as 1ms. [1](#0-0) 

This validation is invoked by `TimeSlotValidationProvider` during block validation for new rounds. [2](#0-1) 

**Vulnerable Integer Division:**

Mining limit calculations use integer division without minimum threshold enforcement. The `Div` method performs standard C# integer division. [3](#0-2) 

Block mining limits are calculated as fractions of the mining interval: [4](#0-3) 

With a 1ms mining interval:
- `TinyBlockSlotInterval = 1.Div(8) = 0` (integer division)
- `DefaultBlockMiningLimit = 0.Mul(3).Div(5) = 0`
- `LastBlockOfCurrentTermMiningLimit = 1.Mul(3).Div(5) = 0`

**Attack Vector:**

When generating consensus extra data for a NextTerm block, the contract creates round information using `GenerateFirstRoundOfNextTerm`, which calculates `ExpectedMiningTime` values. [5](#0-4) 

The miner can modify the Round protobuf's `ExpectedMiningTime` values before including it in the block header. The only validations are term/round number increments and the weak time slot validation. [6](#0-5) 

**Execution Flow:**

The modified round is stored in state during NextTerm processing. [7](#0-6) 

Subsequent blocks calculate mining intervals from the stored Round's `ExpectedMiningTime` values. [8](#0-7) 

For NextTerm blocks, the limit is set to `LastBlockOfCurrentTermMiningLimit`, which will be 0ms. [9](#0-8) 

The consensus service converts this to `BlockExecutionTime`. [10](#0-9) 

When `BlockExecutionTime` is 0ms, the cancellation token is immediately cancelled since `expirationTime < currentTime`. [11](#0-10) 

Cancellable (user) transactions are skipped when the token is cancelled. [12](#0-11) 

The transaction execution loop breaks immediately when cancellation is requested. [13](#0-12) 

## Impact Explanation

**Severity: CRITICAL**

After the malicious NextTerm block is accepted:

- **All user transactions are permanently blocked** - The blockchain produces blocks but skips all user transactions due to immediate cancellation. Only system (non-cancellable) transactions execute.

- **No recovery without hard fork** - The malicious round is permanently stored in consensus state. Every subsequent block will calculate 0ms mining limits from the stored ExpectedMiningTime values.

- **Total economic impact** - Users cannot transfer tokens, interact with dApps, or perform any blockchain operations. The blockchain becomes economically worthless as no value transfer is possible.

- **Affects all network participants** - Every node following consensus rules will skip user transactions.

This breaks the fundamental security guarantee that legitimate user transactions will be processed by the blockchain.

## Likelihood Explanation

**Probability: MEDIUM to HIGH**

**Attacker Requirements:**
- Must be a legitimate miner in the active miner set
- Must be scheduled to produce a NextTerm block (occurs periodically based on PeriodSeconds configuration)

**Attack Complexity: LOW**
1. Wait for NextTerm block assignment
2. Call `GetConsensusExtraData()` to generate consensus data
3. Deserialize the returned `AElfConsensusHeaderInformation`
4. Modify the Round protobuf to set all `ExpectedMiningTime` values 1ms apart
5. Re-serialize and include modified data in block header
6. Sign and broadcast block

**Feasibility:**
- No cryptographic signatures prevent Round data modification - only the block header itself is signed
- Validation only checks `baseMiningInterval > 0`, which 1ms satisfies
- Attack is undetectable until after execution
- Economically rational for attackers seeking to disrupt competing chains or extort the network

## Recommendation

**Immediate Fix:**
Enforce a minimum mining interval threshold in `CheckRoundTimeSlots()`:

```csharp
public ValidationResult CheckRoundTimeSlots()
{
    var miners = RealTimeMinersInformation.Values.OrderBy(m => m.Order).ToList();
    if (miners.Count == 1)
        return new ValidationResult { Success = true };

    if (miners.Any(m => m.ExpectedMiningTime == null))
        return new ValidationResult { Message = $"Incorrect expected mining time.\n{this}" };

    var baseMiningInterval =
        (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

    // Add minimum threshold enforcement
    const int MinimumMiningInterval = 4000; // 4 seconds
    if (baseMiningInterval < MinimumMiningInterval)
        return new ValidationResult { Message = $"Mining interval must be at least {MinimumMiningInterval}ms.\n{this}" };

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

**Additional Hardening:**
- Add cryptographic commitment to Round data in consensus extra data
- Implement cross-validation of Round data against stored mining interval configuration
- Add minimum threshold checks in mining limit calculations to prevent zero values

## Proof of Concept

A valid test demonstrating this vulnerability would:

1. Set up a test chain with multiple miners
2. Simulate a miner producing a NextTerm block
3. Modify the consensus extra data's Round to have 1ms ExpectedMiningTime intervals
4. Verify the block passes validation
5. Verify subsequent blocks have 0ms BlockExecutionTime
6. Verify user transactions are skipped while system transactions execute
7. Confirm the chain is permanently in this state

The key validation failure occurs in `CheckRoundTimeSlots()` which only checks `> 0` rather than enforcing a practical minimum threshold, combined with integer division that floors fractional milliseconds to zero.

## Notes

This vulnerability demonstrates a critical flaw in the consensus validation logic where insufficient input validation combined with unsafe arithmetic operations can permanently disable user transaction processing. The attack is particularly severe because:

1. It requires only miner privileges, not consensus compromise
2. It's irreversible without a hard fork
3. It's undetectable until after execution
4. The validation gap (`> 0` vs practical minimum) is exploitable

The fix must enforce both a minimum mining interval during validation and add defensive checks in the mining limit calculations to prevent zero-valued timeouts.

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L43-47)
```csharp
        var baseMiningInterval =
            (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L70-81)
```csharp
    public int GetMiningInterval()
    {
        if (RealTimeMinersInformation.Count == 1)
            // Just appoint the mining interval for single miner.
            return 4000;

        var firstTwoMiners = RealTimeMinersInformation.Values.Where(m => m.Order == 1 || m.Order == 2)
            .ToList();

        return Math.Abs((int)(firstTwoMiners[1].ExpectedMiningTime - firstTwoMiners[0].ExpectedMiningTime)
            .Milliseconds());
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/TimeSlotValidationProvider.cs (L14-18)
```csharp
        if (validationContext.ProvidedRound.RoundId != validationContext.BaseRound.RoundId)
        {
            // Is new round information fits time slot rule?
            validationResult = validationContext.ProvidedRound.CheckRoundTimeSlots();
            if (!validationResult.Success) return validationResult;
```

**File:** src/AElf.CSharp.Core/SafeMath.cs (L21-24)
```csharp
    public static int Div(this int a, int b)
    {
        return a / b;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/CommandStrategyBase.cs (L42-60)
```csharp
        private int TinyBlockSlotInterval => MiningInterval.Div(TinyBlocksCount);

        protected int MinersCount => CurrentRound.RealTimeMinersInformation.Count;

        /// <summary>
        ///     Give 3/5 of producing time for mining by default.
        /// </summary>
        protected int DefaultBlockMiningLimit => TinyBlockSlotInterval.Mul(3).Div(5);

        /// <summary>
        ///     If this tiny block is the last one of current time slot, give half of producing time for mining.
        /// </summary>
        protected int LastTinyBlockMiningLimit => TinyBlockSlotInterval.Div(2);

        /// <summary>
        ///     If this block is of consensus behaviour NEXT_TERM, the producing time is MiningInterval,
        ///     so the limitation of mining is 8 times than DefaultBlockMiningLimit.
        /// </summary>
        protected int LastBlockOfCurrentTermMiningLimit => MiningInterval.Mul(3).Div(5);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/MinerList.cs (L32-33)
```csharp
            minerInRound.ExpectedMiningTime =
                currentBlockTime.AddMilliseconds(i.Mul(miningInterval).Add(miningInterval));
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-46)
```csharp
    private ValidationResult ValidationForNextTerm(ConsensusValidationContext validationContext)
    {
        var extraData = validationContext.ExtraData;
        var validationResult = ValidationForNextRound(validationContext);
        if (!validationResult.Success) return validationResult;

        // Is next term number correct?
        return validationContext.BaseRound.TermNumber.Add(1) != extraData.Round.TermNumber
            ? new ValidationResult { Message = "Incorrect term number for next round." }
            : new ValidationResult { Success = true };
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ProcessConsensusInformation.cs (L161-196)
```csharp
    private void ProcessNextTerm(NextTermInput input)
    {
        var nextRound = input.ToRound();
        
        RecordMinedMinerListOfCurrentRound();

        // Count missed time slot of current round.
        CountMissedTimeSlots();

        Assert(TryToGetTermNumber(out var termNumber), "Term number not found.");

        // Update current term number and current round number.
        Assert(TryToUpdateTermNumber(nextRound.TermNumber), "Failed to update term number.");
        Assert(TryToUpdateRoundNumber(nextRound.RoundNumber), "Failed to update round number.");

        UpdateMinersCountToElectionContract(nextRound);

        // Reset some fields of first two rounds of next term.
        foreach (var minerInRound in nextRound.RealTimeMinersInformation.Values)
        {
            minerInRound.MissedTimeSlots = 0;
            minerInRound.ProducedBlocks = 0;
        }

        UpdateProducedBlocksNumberOfSender(nextRound);

        // Update miners list.
        var miners = new MinerList();
        miners.Pubkeys.AddRange(nextRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
        if (!SetMinerList(miners, nextRound.TermNumber)) Assert(false, "Failed to update miner list.");

        // Update term number lookup. (Using term number to get first round number of related term.)
        State.FirstRoundNumberOfEachTerm[nextRound.TermNumber] = nextRound.RoundNumber;

        // Update rounds information of next two rounds.
        AddRoundInformation(nextRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusCommandGeneration/Strategies/TerminateRoundCommandStrategy.cs (L36-38)
```csharp
                LimitMillisecondsOfMiningBlock =
                    _isNewTerm ? LastBlockOfCurrentTermMiningLimit : DefaultBlockMiningLimit
            };
```

**File:** src/AElf.Kernel.Consensus.Core/Application/ConsensusService.cs (L98-106)
```csharp
        var limitMillisecondsOfMiningBlock = configuredMiningTime == 0
            ? _consensusCommand.LimitMillisecondsOfMiningBlock
            : configuredMiningTime;
        // Update consensus scheduler.
        var blockMiningEventData = new ConsensusRequestMiningEventData(chainContext.BlockHash,
            chainContext.BlockHeight,
            _nextMiningTime,
            TimestampHelper.DurationFromMilliseconds(limitMillisecondsOfMiningBlock),
            _consensusCommand.MiningDueTime);
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L51-54)
```csharp
            var expirationTime = blockTime + requestMiningDto.BlockExecutionTime;
            if (expirationTime < TimestampHelper.GetUtcNow())
            {
                cts.Cancel();
```

**File:** src/AElf.Kernel.SmartContractExecution/Application/BlockExecutingService.cs (L69-81)
```csharp
        if (!cancellationToken.IsCancellationRequested && cancellable.Count > 0)
        {
            cancellableReturnSets = await _transactionExecutingService.ExecuteAsync(
                new TransactionExecutingDto
                {
                    BlockHeader = blockHeader,
                    Transactions = cancellable,
                    PartialBlockStateSet = returnSetCollection.ToBlockStateSet()
                },
                cancellationToken);
            returnSetCollection.AddRange(cancellableReturnSets);
            Logger.LogTrace("Executed cancellable txs");
        }
```

**File:** src/AElf.Kernel.SmartContract/Application/PlainTransactionExecutingService.cs (L58-59)
```csharp
                if (cancellationToken.IsCancellationRequested)
                    break;
```
