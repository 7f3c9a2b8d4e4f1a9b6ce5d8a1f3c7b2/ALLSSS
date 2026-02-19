### Title
Integer Division Vulnerability in Mining Interval Validation Enables Complete Blockchain Halt

### Summary
The consensus validation logic accepts mining intervals as low as 1ms, which when used in integer division calculations for block execution timeouts, results in all timeout limits becoming 0ms. A malicious miner scheduled to produce a NextTerm block can craft a round with 1ms mining intervals that passes validation, causing immediate cancellation of all subsequent block executions and permanently halting the blockchain.

### Finding Description

**Root Cause:**
The `CheckRoundTimeSlots()` validation only enforces that `baseMiningInterval > 0`, allowing mining intervals as low as 1ms to be accepted. [1](#0-0) 

**Vulnerable Calculation:**
The `LastBlockOfCurrentTermMiningLimit` property calculates the block execution timeout using integer division: [2](#0-1) 

The `Div` method performs standard integer division with no rounding protection: [3](#0-2) 

**Integer Division Results:**
When `MiningInterval = 1ms`:
- `TinyBlockSlotInterval = MiningInterval.Div(8) = 1 / 8 = 0`
- `DefaultBlockMiningLimit = 0 * 3 / 5 = 0`
- `LastTinyBlockMiningLimit = 0 / 2 = 0`
- `LastBlockOfCurrentTermMiningLimit = 1 * 3 / 5 = 0` [4](#0-3) 

**Attack Vector:**
A malicious miner producing a NextTerm block can craft consensus header information with ExpectedMiningTime values 1ms apart. This is generated in `GenerateFirstRoundOfNextTerm()`, which for unchanged miner lists uses `currentRound.GetMiningInterval()`: [5](#0-4) 

The malicious round passes validation because `RoundTerminateValidationProvider` only checks round/term number increments: [6](#0-5) 

And `TimeSlotValidationProvider` only calls `CheckRoundTimeSlots()` which accepts the 1ms interval: [7](#0-6) 

**Execution Failure:**
The 0ms timeout is used to create a `CancellationTokenSource` in `MiningService.MineAsync()`. Since `expirationTime = blockTime + 0 = blockTime` is less than current time, the token is immediately cancelled: [8](#0-7) 

This cancelled token causes `ExecuteBlockAsync()` to throw `OperationCanceledException`, preventing any blocks from being produced: [9](#0-8) 

### Impact Explanation

**Operational Impact - Complete Blockchain Halt:**
After the malicious NextTerm block is accepted, ALL subsequent block production attempts fail immediately because all mining time limits (DefaultBlockMiningLimit, LastTinyBlockMiningLimit, LastBlockOfCurrentTermMiningLimit) are calculated as 0ms. The mining service immediately cancels block execution before any transactions can be processed.

**Affected Parties:**
- All network participants - no transactions can be processed
- All miners - cannot produce any blocks
- All dApps and contracts - become permanently unusable
- Token holders - cannot transfer or trade assets

**Severity Justification:**
CRITICAL - This is a permanent denial of service with no recovery path. Once triggered, the blockchain cannot produce any more blocks without hard fork intervention. The validation logic incorrectly assumes that mining intervals will always be reasonable values, but provides no minimum threshold enforcement.

### Likelihood Explanation

**Attacker Capabilities Required:**
The attacker must be a legitimate miner scheduled to produce a NextTerm block. This occurs periodically based on term duration (configured via PeriodSeconds, typically measured in days/weeks).

**Attack Complexity:**
LOW - The attacker needs to:
1. Wait until scheduled for a NextTerm block
2. Intercept the result of `GetConsensusBlockExtraData()` 
3. Modify the Round's ExpectedMiningTime values to be 1ms apart
4. Include modified consensus header in their block

The modification is trivial - simply set each miner's ExpectedMiningTime to `baseTime + (order * 1ms)`.

**Feasibility Conditions:**
- Attacker must be in the active miner set
- Term change must occur (happens regularly based on PeriodSeconds)
- No additional authorization checks prevent this manipulation

**Detection Difficulty:**
The malicious round appears valid in all validation checks since 1ms passes the `> 0` threshold. Post-attack detection is obvious (blockchain halted), but prevention relies entirely on the inadequate validation.

**Probability Assessment:**
MEDIUM to HIGH - While requiring attacker to be a scheduled miner, the attack is:
- Trivially executable once in position
- Undetectable until after execution
- Economically rational for attackers seeking to disrupt a competing chain or hold the network for ransom

### Recommendation

**Immediate Fix:**
Modify `CheckRoundTimeSlots()` to enforce a minimum safe mining interval:

```csharp
// In contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs
private const int MinimumMiningInterval = 1000; // 1 second minimum

var baseMiningInterval =
    (miners[1].ExpectedMiningTime - miners[0].ExpectedMiningTime).Milliseconds();

if (baseMiningInterval < MinimumMiningInterval)
    return new ValidationResult { 
        Message = $"Mining interval must be at least {MinimumMiningInterval}ms.\n{this}" 
    };
```

**Additional Safeguards:**
1. Add validation in `ProcessNextTerm()` and `ProcessNextRound()` to verify that the new round's mining interval matches expected values
2. Add assertion in mining time limit calculations to ensure non-zero results:
```csharp
var limit = MiningInterval.Mul(3).Div(5);
Assert(limit > 0, "Mining time limit cannot be zero");
```

**Test Cases:**
1. Test that rounds with mining interval < 1000ms are rejected
2. Test that mining time limits are always positive for all valid mining intervals
3. Test that NextTerm blocks with manipulated mining intervals fail validation
4. Add fuzz testing for extreme mining interval values (0, 1, Int.MaxValue)

### Proof of Concept

**Initial State:**
- Blockchain running normally with MiningInterval = 4000ms
- Attacker is legitimate miner scheduled for next NextTerm block
- Current term: T, Current round: R with 4000ms intervals

**Attack Sequence:**

1. **Attacker's Turn:** Block height reaches term boundary, attacker is scheduled for NextTerm block

2. **Consensus Header Manipulation:**
   - Node calls `GetConsensusBlockExtraData()` internally
   - Attacker intercepts and modifies returned Round object
   - Sets ExpectedMiningTime values: `baseTime + 1ms`, `baseTime + 2ms`, `baseTime + 3ms`, etc.

3. **Block Production:**
   - Attacker includes modified consensus header in block
   - Block is signed and broadcast

4. **Validation (Passes):**
   - `CheckRoundTimeSlots()`: `baseMiningInterval = 1 > 0` ✓
   - `RoundTerminateValidationProvider`: Term number = T+1 = T+1 ✓
   - All validation passes, block accepted

5. **State Update:**
   - `ProcessNextTerm()` executes
   - Malicious round stored as current round
   - `State.Rounds[newRoundNumber] = maliciousRound`

6. **Subsequent Block Attempt (Any Miner):**
   - Next scheduled miner attempts to produce block
   - Consensus command generated with `DefaultBlockMiningLimit = 0`
   - `MiningService.MineAsync()` creates CancellationTokenSource with 0ms timeout
   - Token immediately cancelled (expirationTime = blockTime <= now)
   - `ExecuteBlockAsync()` throws OperationCanceledException
   - Block production FAILS

7. **Result:**
   - No more blocks can be produced
   - Blockchain permanently halted
   - Network requires hard fork to recover

**Expected vs Actual:**
- **Expected:** Mining interval validation rejects unsafe values, blockchain continues operating
- **Actual:** Mining interval of 1ms accepted, all subsequent blocks fail with immediate timeout cancellation

### Citations

**File:** contract/AElf.Contracts.Consensus.AEDPoS/Types/Round.cs (L46-47)
```csharp
        if (baseMiningInterval <= 0)
            return new ValidationResult { Message = $"Mining interval must greater than 0.\n{this}" };
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

**File:** src/AElf.CSharp.Core/SafeMath.cs (L21-24)
```csharp
    public static int Div(this int a, int b)
    {
        return a / b;
    }
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/AEDPoSContract_ViewMethods.cs (L236-241)
```csharp
            // Miners of new round are same with current round.
            var miners = new MinerList();
            miners.Pubkeys.AddRange(
                currentRound.RealTimeMinersInformation.Keys.Select(k => ByteStringHelper.FromHexString(k)));
            newRound = miners.GenerateFirstRoundOfNewTerm(currentRound.GetMiningInterval(),
                Context.CurrentBlockTime, currentRound);
```

**File:** contract/AElf.Contracts.Consensus.AEDPoS/ConsensusHeaderInfoValidationProviders/RoundTerminateValidationProvider.cs (L37-47)
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

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L50-62)
```csharp
            using var cts = new CancellationTokenSource();
            var expirationTime = blockTime + requestMiningDto.BlockExecutionTime;
            if (expirationTime < TimestampHelper.GetUtcNow())
            {
                cts.Cancel();
            }
            else
            {
                var ts = (expirationTime - TimestampHelper.GetUtcNow()).ToTimeSpan();
                if (ts.TotalMilliseconds > int.MaxValue) ts = TimeSpan.FromMilliseconds(int.MaxValue);

                cts.CancelAfter(ts);
            }
```

**File:** src/AElf.Kernel/Miner/Application/MiningService.cs (L77-78)
```csharp
            var blockExecutedSet = await _blockExecutingService.ExecuteBlockAsync(block.Header,
                systemTransactions, pending, cts.Token);
```
